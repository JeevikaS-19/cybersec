"""Witness logic for Check A (sealed chain) and Check B (outside witness). No HTTP here."""

import random
import secrets
import time
from datetime import datetime

from shared import GENESIS_PREV_HASH, hash_entry, verify_signature
from witness.store import add_alert, get_state, set_state

ENTRY_FIELDS = (
    "seq", "timestamp", "event_type", "txn_id", "from_account", "to_account",
    "amount_paise", "from_balance_paise", "to_balance_paise", "prev_hash", "key_id", "hash",
)
SILENCE_SECONDS = 15
CHALLENGE_SECONDS = 5
CHALLENGE_CHANCE = 0.2
ALERT_WINDOW_SECONDS = 60
A_KINDS = {
    "sequence_gap", "chain_break", "bad_signature", "unknown_key_id", "entry_edited",
    "entry_deleted", "entries_reordered", "challenge_mismatch", "bad_challenge_signature",
}
B_KINDS = {"non_monotonic_timestamp", "silence", "missed_challenge", "bad_heartbeat", "replayed_heartbeat"}
C_KINDS = {"balance_misreported", "db_edited_without_log"}

TAMPER_FOR_REASON = {
    "bad_signature": "forged",
    "unknown_key_id": "forged",
    "chain_break": "entries_reordered",
    "non_monotonic_timestamp": "backdated",
}

def now():
    return time.time()

def _parse_ts(value):
    return datetime.fromisoformat(value)

def _public_key(conn, key_id):
    row = conn.execute("SELECT public_key FROM agents WHERE key_id = ?", (key_id,)).fetchone()
    return row["public_key"] if row else None

def _last_accepted(conn):
    return conn.execute(
        "SELECT seq, timestamp, hash FROM entries WHERE accepted = 1 ORDER BY id DESC LIMIT 1"
    ).fetchone()

def _reject_reason(conn, entry, last):
    pub = _public_key(conn, entry.get("key_id"))
    if pub is None:
        return "unknown_key_id"
    body = {k: v for k, v in entry.items() if k != "signature"}
    if not verify_signature(pub, body, entry.get("signature", "")):
        return "bad_signature"
    if hash_entry(entry) != entry.get("hash"):
        return "bad_signature"
    expected_seq = last["seq"] + 1 if last else 1
    expected_prev = last["hash"] if last else GENESIS_PREV_HASH
    if entry.get("seq") != expected_seq:
        return "sequence_gap"
    if entry.get("prev_hash") != expected_prev:
        return "chain_break"
    if last and _parse_ts(entry["timestamp"]) < _parse_ts(last["timestamp"]):
        return "non_monotonic_timestamp"
    return None

def _replay_balances(conn, entry, now_ts):
    # Check C: the witness keeps its own balances and compares the reported ones.
    # Opening balance is inferred from the first entry seen per account (trust on first use).
    seq, amount = entry["seq"], entry["amount_paise"]
    for account, reported, delta in (
        (entry["from_account"], entry["from_balance_paise"], -amount),
        (entry["to_account"], entry["to_balance_paise"], amount),
    ):
        row = conn.execute("SELECT balance_paise FROM balances WHERE account = ?", (account,)).fetchone()
        before = row["balance_paise"] if row else reported - delta
        expected = before + delta
        if reported != expected:
            add_alert(conn, "balance_misreported", f"{seq}:{account}", "balance_misreported",
                      f"{account} reported {reported}, witness replay {expected}", now_ts)
        with conn:
            conn.execute("INSERT OR REPLACE INTO balances (account, balance_paise) VALUES (?, ?)", (account, expected))

def submit_entry(conn, entry, now_ts, check_c=True):
    last = _last_accepted(conn)
    reason = _reject_reason(conn, entry, last)
    accepted = reason is None
    columns = ", ".join(ENTRY_FIELDS + ("signature", "accepted"))
    placeholders = ", ".join("?" for _ in ENTRY_FIELDS + ("signature", "accepted"))
    values = [entry.get(f) for f in ENTRY_FIELDS] + [entry.get("signature"), int(accepted)]
    with conn:
        conn.execute(f"INSERT INTO entries ({columns}) VALUES ({placeholders})", values)
    if accepted:
        if check_c:
            _replay_balances(conn, entry, now_ts)
        return {"status": "accepted"}

    seq = entry.get("seq")
    tamper = TAMPER_FOR_REASON.get(reason)
    if reason == "sequence_gap":
        last_seq = last["seq"] if last else 0
        tamper = "entry_replayed" if isinstance(seq, int) and seq <= last_seq else "entry_deleted"
    add_alert(conn, reason, seq, tamper, f"entry {seq} rejected: {reason}", now_ts)
    return {"status": "rejected", "reason": reason}

def self_check(conn, now_ts):
    prev = None
    for row in conn.execute("SELECT * FROM entries WHERE accepted = 1 ORDER BY id"):
        entry = {f: row[f] for f in ENTRY_FIELDS}
        if hash_entry(entry) != row["hash"]:
            add_alert(conn, "entry_edited", row["seq"], "entry_edited", "stored fields no longer match hash", now_ts)
        elif prev is not None and row["seq"] != prev["seq"] + 1:
            add_alert(conn, "entry_deleted", row["seq"], "entry_deleted", f"seq jumps from {prev['seq']} to {row['seq']}", now_ts)
        elif prev is not None and row["prev_hash"] != prev["hash"]:
            add_alert(conn, "entries_reordered", row["seq"], "entries_reordered", "prev_hash does not link", now_ts)
        prev = row

def record_heartbeat(conn, body, now_ts):
    platform_id = body.get("platform_id")
    ts = body.get("timestamp")
    row = conn.execute("SELECT public_key FROM agents WHERE platform_id = ?", (platform_id,)).fetchone()
    reason = None
    if row is None:
        reason = "unknown_key_id"
    elif not verify_signature(row["public_key"], {"platform_id": platform_id, "timestamp": ts}, body.get("signature", "")):
        reason = "bad_signature"
    else:
        hb = get_state(conn, "last_heartbeat") or {}
        if hb.get("ts") and _parse_ts(ts) <= _parse_ts(hb["ts"]):
            reason = "replayed_heartbeat"
    if reason:
        kind = "replayed_heartbeat" if reason == "replayed_heartbeat" else "bad_heartbeat"
        tamper = "entry_replayed" if kind == "replayed_heartbeat" else "forged"
        add_alert(conn, kind, f"{platform_id}:{ts}", tamper, reason, now_ts)
        return {"status": "rejected", "reason": reason}
    set_state(conn, "last_heartbeat", {"ts": ts, "recv": now_ts})
    return {"status": "ok"}

def silence_check(conn, now_ts):
    hb = get_state(conn, "last_heartbeat")
    if hb and now_ts - hb["recv"] > SILENCE_SECONDS:
        add_alert(conn, "silence", hb["recv"], "agent_silenced", "no valid heartbeat for over 15 s", now_ts)

def poll_challenge(conn, platform_id, now_ts, state_allowed=True):
    row = conn.execute("SELECT key_id FROM agents WHERE platform_id = ?", (platform_id,)).fetchone()
    if row is None:
        return None
    pending = get_state(conn, "challenge")
    if pending is None and random.random() < CHALLENGE_CHANCE:
        accounts = [r["account"] for r in conn.execute("SELECT account FROM balances ORDER BY account")]
        pending = {
            "id": "c-" + secrets.token_hex(4),
            "type": "hash",
            "key_id": row["key_id"],
            "deadline": now_ts + CHALLENGE_SECONDS,
        }
        if state_allowed and accounts and random.random() < 0.5:
            pending["type"] = "state"
            pending["account"] = random.choice(accounts)
        set_state(conn, "challenge", pending)
    if pending is None:
        return None
    if pending["type"] == "state":
        return {"id": pending["id"], "type": "state", "account": pending["account"]}
    return {"id": pending["id"], "type": pending["type"]}

def answer_challenge(conn, body, now_ts):
    pending = get_state(conn, "challenge")
    if not pending or pending["id"] != body.get("challenge_id") or now_ts > pending["deadline"]:
        return {"status": "mismatch"}
    set_state(conn, "challenge", None)
    if body.get("type") != pending["type"]:
        return {"status": "mismatch"}
    if pending["type"] == "state":
        fields = ("challenge_id", "type", "account", "balance_paise", "last_seq")
    else:
        fields = ("challenge_id", "type", "latest_hash", "last_seq")
    payload = {k: body.get(k) for k in fields}
    if not verify_signature(_public_key(conn, pending["key_id"]), payload, body.get("signature", "")):
        add_alert(conn, "bad_challenge_signature", pending["id"], "forged", "challenge response signature invalid", now_ts)
        return {"status": "mismatch"}
    last = _last_accepted(conn)
    last_seq = last["seq"] if last else 0
    last_hash = last["hash"] if last else GENESIS_PREV_HASH
    if body.get("last_seq") != last_seq:
        # Agent is ahead or behind a queued send; not evidence of tampering.
        return {"status": "mismatch"}
    if pending["type"] == "state":
        row = conn.execute("SELECT balance_paise FROM balances WHERE account = ?", (body.get("account"),)).fetchone()
        if row is None:
            return {"status": "mismatch"}
        if body.get("balance_paise") != row["balance_paise"]:
            add_alert(conn, "db_edited_without_log", pending["id"], "db_edited_without_log",
                      f"{body.get('account')} bank balance {body.get('balance_paise')}, witness replay {row['balance_paise']}",
                      now_ts)
            return {"status": "mismatch"}
        return {"status": "ok"}
    if body.get("latest_hash") != last_hash:
        add_alert(conn, "challenge_mismatch", pending["id"], "entry_edited", "agent and witness disagree on latest hash", now_ts)
        return {"status": "mismatch"}
    return {"status": "ok"}

def challenge_check(conn, now_ts):
    pending = get_state(conn, "challenge")
    if pending and now_ts > pending["deadline"]:
        add_alert(conn, "missed_challenge", pending["id"], "agent_silenced", "no answer to hash challenge", now_ts)
        set_state(conn, "challenge", None)

def verify_range(conn, from_seq, to_seq):
    rows = conn.execute(
        "SELECT * FROM entries WHERE accepted = 1 AND seq BETWEEN ? AND ? ORDER BY id", (from_seq, to_seq)
    ).fetchall()
    results = []
    prev = None
    for row in rows:
        entry = {f: row[f] for f in ENTRY_FIELDS}
        linked = prev is None or row["prev_hash"] == prev["hash"]
        ok = hash_entry(entry) == row["hash"] and linked
        results.append({"seq": row["seq"], "ok": ok})
        prev = row
    passed = sum(1 for r in results if r["ok"])
    return {
        "results": results,
        "summary": {"checked": len(results), "passed": passed, "failed": len(results) - passed},
    }

def status(conn, layers):
    kinds = {r["kind"] for r in conn.execute("SELECT kind FROM alerts WHERE time > ?", (now() - ALERT_WINDOW_SECONDS,))}
    last = _last_accepted(conn)
    hb = get_state(conn, "last_heartbeat") or {}
    return {
        "checks": {
            "A": "red" if kinds & A_KINDS else "green",
            "B": "red" if kinds & B_KINDS else "green",
            "C": "red" if kinds & C_KINDS else "green",
        },
        "layers": {str(n): ("on" if layers.get(n) else "off") for n in (1, 2, 3)},
        "state": "alert" if kinds else "normal",
        "last_entry_seq": last["seq"] if last else 0,
        "last_seen": hb.get("ts") or "",
    }

def list_alerts(conn):
    return [dict(r) for r in conn.execute("SELECT kind, ref, tamper_type, detail, time FROM alerts ORDER BY id")]
