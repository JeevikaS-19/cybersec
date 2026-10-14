"""Record checks (Layer 2, Check A on the server side).

The witness asks the agent for record #N as the bank holds it *now* (rebuilt from the bank's own row) and
compares it field by field with the sealed copy it accepted earlier. A rolling sweep covers every record over
time; the first mismatch triggers a full sweep so every tampered record is listed.
"""

import json
import random

from layers.common.config import get as cfg
from shared import hash_entry
from witness.store import add_alert, get_state, log_activity, set_state

RECORD_FIELDS = ("txn_id", "txn_time", "from_account", "to_account", "amount_paise",
                 "from_balance_paise", "to_balance_paise")
SWEEP_SECONDS = cfg("layer2", "sweep_seconds", 15.0, "SWEEP_SECONDS")
SWEEP_BATCH = cfg("layer2", "sweep_batch", 200, "SWEEP_BATCH")
FULL_SWEEP_CAP = 5000


def _accepted_seqs(conn):
    return [r["seq"] for r in conn.execute("SELECT seq FROM entries WHERE accepted = 1 ORDER BY seq")]


def stored_entry(conn, seq):
    row = conn.execute("SELECT * FROM entries WHERE accepted = 1 AND seq = ? ORDER BY id LIMIT 1", (seq,)).fetchone()
    if row is None:
        return None
    return {k: row[k] for k in row.keys() if k not in ("id", "accepted")}  # noqa: SIM118 (sqlite3.Row)


def random_record(conn):
    seqs = _accepted_seqs(conn)
    return {"type": "record", "seq": random.choice(seqs)} if seqs else None


def due_sweep(conn, now_ts):
    """A sweep challenge if one is due (full sweep after a mismatch, else the next rolling batch)."""
    seqs = _accepted_seqs(conn)
    if not seqs:
        return None
    if get_state(conn, "full_sweep"):
        set_state(conn, "full_sweep", None)
        return {"type": "sweep", "seqs": seqs[-FULL_SWEEP_CAP:], "full": True}
    last = get_state(conn, "last_sweep") or 0
    if now_ts - last < SWEEP_SECONDS:
        return None
    cursor = get_state(conn, "sweep_cursor") or 0
    batch = [s for s in seqs if s > cursor][:SWEEP_BATCH] or seqs[:SWEEP_BATCH]
    set_state(conn, "sweep_cursor", batch[-1] if batch[-1] < seqs[-1] else 0)
    set_state(conn, "last_sweep", now_ts)
    return {"type": "sweep", "seqs": batch, "full": False}


def label(challenge):
    if challenge["type"] == "record":
        return f"record #{challenge['seq']}"
    s = challenge["seqs"]
    return f"{'full ' if challenge.get('full') else ''}sweep #{s[0]}-#{s[-1]}"


def compare(conn, seq, server, now_ts, caught_by):
    """Compare the server's record with the sealed copy. Returns the changed field names ([] = match)."""
    sealed = stored_entry(conn, seq)
    if sealed is None:
        return []
    if server is None:
        changed = ["(record missing on server)"]
        tamper, detail = "entry_deleted", f"#{seq} missing on the server"
    else:
        changed = [f for f in RECORD_FIELDS if sealed.get(f) != server.get(f)]
        if not changed:
            return []
        tamper = "entry_edited"
        detail = f"#{seq} " + ", ".join(f"{f}: {sealed.get(f)} -> {server.get(f)}" for f in changed)
    found = dict(sealed, **(server or {}))
    server_hash = hash_entry({k: v for k, v in found.items() if k not in ("hash", "signature")}) if server else None
    with conn:
        conn.execute(
            "INSERT OR IGNORE INTO mismatches (seq, caught_time, caught_by, fields, witness_copy, server_copy, "
            "witness_hash, server_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (seq, now_ts, caught_by, json.dumps(changed), json.dumps(sealed), json.dumps(server),
             sealed["hash"], server_hash),
        )
    add_alert(conn, "record_mismatch", seq, tamper, detail, now_ts)
    return changed


def answer(conn, pending, body, now_ts):
    """Handle a verified record/sweep reply. Returns {"status": ...}."""
    what = label(pending)
    if pending["type"] == "record":
        if body.get("seq") != pending["seq"]:
            return None  # not an answer to this question; keep it pending
        replies = [(pending["seq"], body.get("record"))]
    else:
        replies = [(r.get("seq"), r.get("record")) for r in body.get("records") or [] if isinstance(r, dict)]
        if sorted(s for s, _ in replies) != sorted(pending["seqs"]):
            return None
    known = {r["seq"] for r in conn.execute("SELECT seq FROM mismatches")}
    bad = [seq for seq, rec in replies if compare(conn, seq, rec, now_ts, f"{what} ({pending['id']})")]
    if bad:
        if not pending.get("full") and set(bad) - known:
            set_state(conn, "full_sweep", True)  # a NEW tampered record: list every one, once
        log_activity(conn, "challenge_failed", f"{pending['id']} {what}: tampered " +
                     ", ".join(f"#{s}" for s in bad[:10]) + (" ..." if len(bad) > 10 else ""), now_ts)
        return {"status": "mismatch"}
    log_activity(conn, "challenge_ok", f"{pending['id']} {what} matches", now_ts)
    return {"status": "ok"}


def list_mismatches(conn):
    out = []
    for r in conn.execute("SELECT * FROM mismatches ORDER BY caught_time, seq"):
        d = dict(r)
        for k in ("fields", "witness_copy", "server_copy"):
            d[k] = json.loads(d[k]) if d[k] else None
        out.append(d)
    return out
