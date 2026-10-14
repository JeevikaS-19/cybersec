"""Witness logic for Check A (sealed chain) and Check B (outside witness). No HTTP here."""

import os
import random
import secrets
import time
from datetime import datetime

from shared import GENESIS_PREV_HASH, hash_entry, verify_signature
from witness import records
from witness.classify import for_rejection
from witness.store import add_alert, get_state, log_activity, set_state

ENTRY_FIELDS = (
    "seq", "timestamp", "event_type", "txn_id", "from_account", "to_account",
    "amount_paise", "from_balance_paise", "to_balance_paise", "prev_hash", "key_id", "hash",
)
SILENCE_SECONDS = 15
CHALLENGE_SECONDS = 5
CHALLENGE_CHANCE = float(os.environ.get("CHALLENGE_CHANCE", "0.2"))
STATE_SHARE = float(os.environ.get("STATE_SHARE", "0.3"))
RECORD_SHARE = float(os.environ.get("RECORD_SHARE", "0.4"))
A_KINDS = {
    "sequence_gap", "chain_break", "bad_signature", "unknown_key_id", "entry_edited",
    "entry_deleted", "entries_reordered", "entry_replayed", "late_entry", "challenge_mismatch",
    "bad_challenge_signature", "record_mismatch",
}
B_KINDS = {"non_monotonic_timestamp", "silence", "missed_challenge", "bad_heartbeat", "replayed_heartbeat"}
C_KINDS = {"balance_misreported", "db_edited_without_log"}

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

def _resolve(conn, kinds):
    # Only alerts whose problem has ended are resolved; tamper evidence stays red.
    marks = ",".join("?" for _ in kinds)
    with conn:
        conn.execute(f"UPDATE alerts SET resolved = 1 WHERE resolved = 0 AND kind IN ({marks})", tuple(kinds))

def _replay_balances(conn, entry, now_ts):
    # Check C: the witness keeps its own balances and compares the reported ones.
    # Opening balance is inferred from the first entry seen per account (trust on first use).
    amount = entry["amount_paise"]
    for account, reported, delta in (
        (entry["from_account"], entry["from_balance_paise"], -amount),
        (entry["to_account"], entry["to_balance_paise"], amount),
    ):
        row = conn.execute("SELECT balance_paise FROM balances WHERE account = ?", (account,)).fetchone()
        before = row["balance_paise"] if row else reported - delta
        expected = before + delta
        if reported != expected:
            offset = reported - expected
            add_alert(conn, "balance_misreported", f"{account}:{offset}", "balance_misreported",
                      f"{account} reported {reported}, witness replay {expected}, offset {offset}", now_ts)
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
        if conn.execute("SELECT 1 FROM alerts WHERE kind = 'sequence_gap' AND ref = ?", (str(entry.get("seq")),)).fetchone():
            # This seq was rejected earlier as a gap, so it arrived late.
            add_alert(conn, "late_entry", entry.get("seq"), "entries_reordered",
                      f"entry {entry.get('seq')} accepted after an earlier gap rejection", now_ts)
        if check_c:
            _replay_balances(conn, entry, now_ts)
        return {"status": "accepted"}

    seq = entry.get("seq")
    tamper = for_rejection(reason, seq, last["seq"] if last else 0)
    add_alert(conn, reason, seq, tamper, f"entry {seq} rejected: {reason}", now_ts)
    return {"status": "rejected", "reason": reason}

def self_check(conn, now_ts):
    rows = list(conn.execute("SELECT * FROM entries WHERE accepted = 1 ORDER BY id"))
    seqs = {r["seq"] for r in rows}
    # Deletions: any seq missing from 1..max, whatever order the rest are stored in.
    for missing in sorted(set(range(1, max(seqs, default=0) + 1)) - seqs):
        add_alert(conn, "entry_deleted", missing, "entry_deleted", f"seq {missing} missing from stored chain", now_ts)
    prev = None
    for row in rows:
        entry = {f: row[f] for f in ENTRY_FIELDS}
        if hash_entry(entry) != row["hash"]:
            add_alert(conn, "entry_edited", row["seq"], "entry_edited", "stored fields no longer match hash", now_ts)
        elif prev is not None and row["seq"] == prev["seq"]:
            add_alert(conn, "entry_replayed", row["seq"], "entry_replayed", f"seq {row['seq']} stored twice", now_ts)
        elif prev is not None and row["seq"] < prev["seq"]:
            add_alert(conn, "entries_reordered", row["seq"], "entries_reordered", f"seq {row['seq']} stored after {prev['seq']}", now_ts)
        elif prev is not None and row["seq"] == prev["seq"] + 1 and row["prev_hash"] != prev["hash"]:
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
        log_activity(conn, "heartbeat_rejected", f"{platform_id} {ts}: {reason}", now_ts)
        return {"status": "rejected", "reason": reason}
    set_state(conn, "last_heartbeat", {"ts": ts, "recv": now_ts})
    _resolve(conn, ["silence", "bad_heartbeat", "replayed_heartbeat"])
    log_activity(conn, "heartbeat", f"{platform_id} {ts}", now_ts)
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
    if pending is None:
        pending = records.due_sweep(conn, now_ts)
        if pending is None and random.random() < CHALLENGE_CHANCE:
            accounts = [r["account"] for r in conn.execute("SELECT account FROM balances ORDER BY account")]
            r = random.random()
            if state_allowed and accounts and r < STATE_SHARE:
                pending = {"type": "state", "account": random.choice(accounts)}
            elif r < STATE_SHARE + RECORD_SHARE:
                pending = records.random_record(conn)
            pending = pending or {"type": "hash"}
        if pending is not None:
            pending.update(id="c-" + secrets.token_hex(4), key_id=row["key_id"],
                           deadline=now_ts + CHALLENGE_SECONDS * (3 if pending["type"] == "sweep" else 1))
            set_state(conn, "challenge", pending)
            log_activity(conn, "challenge_issued", f"{pending['id']} {_describe(pending)}", now_ts)
    if pending is None:
        return None
    return {k: v for k, v in pending.items() if k in ("id", "type", "account", "seq", "seqs")}


def _describe(pending):
    if pending["type"] in ("record", "sweep"):
        return records.label(pending)
    return "state " + pending["account"] if pending["type"] == "state" else "hash (latest record)"


SIGNED_FIELDS = {
    "hash": ("challenge_id", "type", "latest_hash", "last_seq"),
    "state": ("challenge_id", "type", "account", "balance_paise", "last_seq"),
    "record": ("challenge_id", "type", "seq", "record"),
    "sweep": ("challenge_id", "type", "records"),
}


def answer_challenge(conn, body, now_ts):
    pending = get_state(conn, "challenge")
    # Wrong, late or unsigned replies leave the challenge pending: only its deadline fails it.
    if not pending or pending["id"] != body.get("challenge_id") or now_ts > pending["deadline"]:
        return {"status": "mismatch"}
    if body.get("type") != pending["type"]:
        return {"status": "mismatch"}
    payload = {k: body.get(k) for k in SIGNED_FIELDS[pending["type"]]}
    if not verify_signature(_public_key(conn, pending["key_id"]), payload, body.get("signature", "")):
        add_alert(conn, "bad_challenge_signature", pending["id"], "forged", "challenge response signature invalid", now_ts)
        return {"status": "mismatch"}
    if pending["type"] in ("record", "sweep"):
        result = records.answer(conn, pending, body, now_ts)
        if result is None:
            return {"status": "mismatch"}  # not an answer to this question; keep waiting
        set_state(conn, "challenge", None)
        _resolve(conn, ["missed_challenge"])
        return result
    last = _last_accepted(conn)
    last_seq = last["seq"] if last else 0
    last_hash = last["hash"] if last else GENESIS_PREV_HASH
    if body.get("last_seq") != last_seq:
        # Agent is ahead or behind a queued send; keep waiting until the deadline.
        return {"status": "mismatch"}
    # From here the reply is valid and answers the challenge.
    set_state(conn, "challenge", None)
    if pending["type"] == "state":
        account = body.get("account")
        row = conn.execute("SELECT balance_paise FROM balances WHERE account = ?", (account,)).fetchone()
        if row is None:
            return {"status": "mismatch"}
        reported, replay = body.get("balance_paise"), row["balance_paise"]
        if reported != replay:
            offset = reported - replay
            add_alert(conn, "db_edited_without_log", f"{account}:{offset}", "db_edited_without_log",
                      f"{account} bank balance {reported}, witness replay {replay}, offset {offset}", now_ts)
            log_activity(conn, "challenge_failed", f"{pending['id']} state {account}: bank {reported} vs replay {replay}", now_ts)
            return {"status": "mismatch"}
        _resolve(conn, ["missed_challenge"])
        log_activity(conn, "challenge_ok", f"{pending['id']} state {account} = {reported}", now_ts)
        return {"status": "ok"}
    if body.get("latest_hash") != last_hash:
        add_alert(conn, "challenge_mismatch", pending["id"], "entry_edited", "agent and witness disagree on latest hash", now_ts)
        log_activity(conn, "challenge_failed", f"{pending['id']} hash mismatch at seq {last_seq}", now_ts)
        return {"status": "mismatch"}
    _resolve(conn, ["missed_challenge"])
    log_activity(conn, "challenge_ok", f"{pending['id']} hash at seq {last_seq}", now_ts)
    return {"status": "ok"}

def challenge_check(conn, now_ts):
    pending = get_state(conn, "challenge")
    if pending and now_ts > pending["deadline"]:
        add_alert(conn, "missed_challenge", pending["id"], "agent_silenced", f"no answer to {_describe(pending)} challenge", now_ts)
        log_activity(conn, "challenge_missed", f"{pending['id']} {pending['type']}", now_ts)
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
    kinds = {r["kind"] for r in conn.execute("SELECT kind FROM alerts WHERE resolved = 0")}
    last = _last_accepted(conn)
    hb = get_state(conn, "last_heartbeat") or {}
    agent = conn.execute("SELECT platform_id FROM agents ORDER BY rowid LIMIT 1").fetchone()
    age = now() - hb["recv"] if hb.get("recv") is not None and hb.get("ts") else None
    connection = "waiting" if age is None else ("connected" if age <= SILENCE_SECONDS else "lost")
    return {
        "checks": {
            "A": "red" if kinds & A_KINDS else "green",
            "B": "red" if kinds & B_KINDS else "green",
            "C": "red" if kinds & C_KINDS else "green",
        },
        "layers": {
            "1": ("tripped" if "layer1_tripwire" in kinds else "on") if layers.get(1) else "off",
            "2": "on" if layers.get(2) else "off",
            "3": "on" if layers.get(3) else "off",
        },
        "state": "alert" if kinds else "normal",
        "last_entry_seq": last["seq"] if last else 0,
        "last_seen": hb.get("ts") or "",
        # Screen 0 of the auditor view
        "platform_id": agent["platform_id"] if agent else None,
        "connection": connection,
        "heartbeat_age": round(age, 1) if age is not None else None,
        "records_verified": conn.execute("SELECT COUNT(*) FROM entries WHERE accepted = 1").fetchone()[0],
        "last_verified": {"seq": last["seq"], "time": last["timestamp"]} if last else None,
        "last_sweep": get_state(conn, "last_sweep"),
        "server_time": now(),
        "quarantine": get_state(conn, "quarantine"),  # filled by Layer 3
    }

def list_alerts(conn):
    return [dict(r) for r in conn.execute("SELECT kind, ref, tamper_type, detail, time, resolved FROM alerts ORDER BY id")]
