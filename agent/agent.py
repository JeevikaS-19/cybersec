"""Agent: turns new bank transactions into signed, chained entries and sends them to the witness.

No balance logic here. The witness does the checking.
"""

import base64
import json
import os
import sqlite3
import time
from datetime import UTC, datetime

import requests
from cryptography.hazmat.primitives.asymmetric import ed25519

from layers.common import events as layer_events
from layers.l3_quarantine import quarantine as l3
from shared import (
    GENESIS_PREV_HASH,
    export_public_key,
    generate_keypair,
    hash_entry,
    sign_payload,
    verify_signature,
)

WITNESS_URL = os.environ.get("WITNESS_URL", "http://127.0.0.1:8000")
BANK_DB_PATH = os.environ.get("BANK_DB_PATH", "bank.db")
AGENT_DB_PATH = os.environ.get("AGENT_DB_PATH", "agent_state.db")
PLATFORM_ID = os.environ.get("PLATFORM_ID", "log-server-1")
HEARTBEAT_SECONDS = 5
CHALLENGE_SECONDS = 2
TIMEOUT = 5
# Cap work per loop pass so heartbeats keep their 5 s rhythm.
SEND_BATCH = 50

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS entries (
    seq INTEGER PRIMARY KEY,
    body TEXT NOT NULL,
    sent INTEGER NOT NULL DEFAULT 0,
    accepted INTEGER NOT NULL DEFAULT 0
);
"""


def open_db():
    conn = sqlite3.connect(AGENT_DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript(SCHEMA)
    return conn


def meta_get(conn, key):
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row[0] if row else None


def meta_set(conn, key, value):
    with conn:
        conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, value))


def now_iso():
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def load_or_create_key(conn):
    raw = meta_get(conn, "private_key")
    if raw is None:
        priv, _ = generate_keypair()
        meta_set(conn, "private_key", base64.b64encode(priv.private_bytes_raw()).decode("utf-8"))
        return priv
    return ed25519.Ed25519PrivateKey.from_private_bytes(base64.b64decode(raw))


def register(conn, priv):
    resp = requests.post(
        f"{WITNESS_URL}/register/agent",
        json={"platform_id": PLATFORM_ID, "public_key": export_public_key(priv)},
        timeout=TIMEOUT,
    )
    resp.raise_for_status()
    meta_set(conn, "key_id", resp.json()["key_id"])
    if resp.json().get("witness_public_key"):
        meta_set(conn, "witness_public_key", resp.json()["witness_public_key"])  # verifies Layer 3 unlocks


def last_local_entry(conn):
    row = conn.execute("SELECT body FROM entries ORDER BY seq DESC LIMIT 1").fetchone()
    return json.loads(row[0]) if row else None


def last_accepted_entry(conn):
    row = conn.execute("SELECT body FROM entries WHERE accepted = 1 ORDER BY seq DESC LIMIT 1").fetchone()
    return json.loads(row[0]) if row else None


def sync_bank(conn, priv):
    if not os.path.exists(BANK_DB_PATH):
        return
    key_id = meta_get(conn, "key_id")
    bank = sqlite3.connect(BANK_DB_PATH)
    try:
        last_txn = int(meta_get(conn, "last_txn_id") or 0)
        rows = bank.execute(
            "SELECT id, txn_id, timestamp, from_account, to_account, amount_paise, "
            "from_balance_paise, to_balance_paise FROM transactions WHERE id > ? ORDER BY id LIMIT ?",
            (last_txn, SEND_BATCH),
        ).fetchall()
    finally:
        bank.close()

    for row in rows:
        prev = last_local_entry(conn)
        seq = prev["seq"] + 1 if prev else 1
        entry = {
            "seq": seq,
            "timestamp": row[2],
            "event_type": "transaction",
            "txn_id": row[1],
            "from_account": row[3],
            "to_account": row[4],
            "amount_paise": row[5],
            "from_balance_paise": row[6],
            "to_balance_paise": row[7],
            "prev_hash": prev["hash"] if prev else GENESIS_PREV_HASH,
            "key_id": key_id,
        }
        entry["hash"] = hash_entry(entry)
        entry["signature"] = sign_payload(priv, {k: v for k, v in entry.items() if k != "signature"})
        with conn:
            conn.execute("INSERT INTO entries (seq, body) VALUES (?, ?)", (seq, json.dumps(entry)))
            conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", ("last_txn_id", str(row[0])))


def send_pending(conn):
    rows = conn.execute("SELECT seq, body FROM entries WHERE sent = 0 ORDER BY seq LIMIT ?", (SEND_BATCH,)).fetchall()
    for seq, body in rows:
        resp = requests.post(f"{WITNESS_URL}/entries", json=json.loads(body), timeout=TIMEOUT)
        resp.raise_for_status()
        result = resp.json()
        accepted = result.get("status") == "accepted"
        with conn:
            conn.execute("UPDATE entries SET sent = 1, accepted = ? WHERE seq = ?", (int(accepted), seq))
        if not accepted:
            print(f"witness rejected seq {seq}: {result.get('reason')}")
    return len(rows)


def ship_events(conn, priv):
    # Layer hook: sign spooled layer events with the agent key and send them (POST /events).
    key_id = meta_get(conn, "key_id")
    for path in layer_events.pending():
        event = json.loads(path.read_text(encoding="utf-8"))
        event["key_id"] = key_id
        event["signature"] = sign_payload(priv, {k: v for k, v in event.items() if k != "signature"})
        resp = requests.post(f"{WITNESS_URL}/events", json=event, timeout=TIMEOUT)
        resp.raise_for_status()
        if resp.json().get("status") == "accepted":
            path.unlink()
        else:
            path.rename(path.with_suffix(".rejected"))


def send_heartbeat(priv):
    timestamp = now_iso()
    body = {
        "platform_id": PLATFORM_ID,
        "timestamp": timestamp,
        "signature": sign_payload(priv, {"platform_id": PLATFORM_ID, "timestamp": timestamp}),
    }
    requests.post(f"{WITNESS_URL}/heartbeat", json=body, timeout=TIMEOUT).raise_for_status()


def bank_balance_at(account, txn_id):
    # Bank balance as of txn_id: current balance minus the effect of later transfers.
    bank = sqlite3.connect(BANK_DB_PATH)
    try:
        row = bank.execute("SELECT balance_paise FROM accounts WHERE account_id = ?", (account,)).fetchone()
        at = bank.execute("SELECT id FROM transactions WHERE txn_id = ?", (txn_id,)).fetchone()
        if row is None or at is None:
            return None
        later = bank.execute(
            "SELECT from_account, to_account, amount_paise FROM transactions WHERE id > ?", (at[0],)
        ).fetchall()
    finally:
        bank.close()
    balance = row[0]
    for src, dst, amount in later:
        if src == account:
            balance += amount
        if dst == account:
            balance -= amount
    return balance


RECORD_FIELDS = ("txn_id", "timestamp", "from_account", "to_account", "amount_paise",
                 "from_balance_paise", "to_balance_paise")


def server_records(conn, seqs):
    # Record #seq as the bank holds it now, rebuilt from the bank's own row (None if the row is gone).
    txn_ids = {}
    for seq in seqs:
        row = conn.execute("SELECT body FROM entries WHERE seq = ?", (seq,)).fetchone()
        txn_ids[seq] = json.loads(row[0])["txn_id"] if row else None
    bank = sqlite3.connect(BANK_DB_PATH)
    try:
        out = []
        for seq in seqs:
            row = bank.execute(f"SELECT {', '.join(RECORD_FIELDS)} FROM transactions WHERE txn_id = ?",
                               (txn_ids[seq],)).fetchone() if txn_ids[seq] else None
            out.append({"seq": seq, "record": dict(zip(RECORD_FIELDS, row, strict=True)) if row else None})
        return out
    finally:
        bank.close()


def answer_challenge(conn, priv):
    resp = requests.get(f"{WITNESS_URL}/challenge/poll", params={"platform_id": PLATFORM_ID}, timeout=TIMEOUT)
    challenge = resp.json().get("challenge")
    if not challenge:
        return
    last = last_accepted_entry(conn)
    last_seq = last["seq"] if last else 0
    if challenge["type"] == "hash":
        payload = {
            "challenge_id": challenge["id"],
            "type": "hash",
            "latest_hash": last["hash"] if last else GENESIS_PREV_HASH,
            "last_seq": last_seq,
        }
    elif challenge["type"] == "state" and last:
        balance = bank_balance_at(challenge["account"], last["txn_id"])
        if balance is None:
            return
        payload = {
            "challenge_id": challenge["id"],
            "type": "state",
            "account": challenge["account"],
            "balance_paise": balance,
            "last_seq": last_seq,
        }
    elif challenge["type"] == "record":
        (rec,) = server_records(conn, [challenge["seq"]])
        payload = {"challenge_id": challenge["id"], "type": "record", "seq": challenge["seq"], "record": rec["record"]}
    elif challenge["type"] == "sweep":
        payload = {"challenge_id": challenge["id"], "type": "sweep", "records": server_records(conn, challenge["seqs"])}
    else:
        return
    body = dict(payload, signature=sign_payload(priv, payload))
    requests.post(f"{WITNESS_URL}/challenge/response", json=body, timeout=TIMEOUT).raise_for_status()


def check_quarantine(conn, last_contact):
    # Layer 3 trigger: no successful contact with the witness for after_seconds.
    if meta_get(conn, "quarantine") or not layer_events.layer_enabled(3):
        return
    after = l3.settings()["after_seconds"]
    if time.monotonic() - last_contact < after:
        return
    from layers.l1_tripwire.trip import settings as l1_settings
    record = l3.quarantine(f"no contact with the witness for {after:.0f} s", l1_settings()["protected_paths"])
    record["reported"] = False
    meta_set(conn, "quarantine", json.dumps(record))
    print(f"QUARANTINED {record['id']}: {record['reason']}")


def quarantine_contact(conn, priv):
    # Once the witness is reachable again: report (stay locked) and wait for a witness-signed unlock.
    raw = meta_get(conn, "quarantine")
    if not raw:
        return
    record = json.loads(raw)
    if not record.get("reported"):
        unverified = conn.execute("SELECT COUNT(*) FROM entries WHERE sent = 0").fetchone()[0]
        _report(priv, record, "quarantined", unverified)
        record["reported"] = True
        meta_set(conn, "quarantine", json.dumps(record))
    resp = requests.get(f"{WITNESS_URL}/quarantine/poll", params={"platform_id": PLATFORM_ID}, timeout=TIMEOUT)
    cmd = resp.json().get("command")
    if not cmd or cmd.get("action") != "unlock" or cmd.get("quarantine_id") != record["id"]:
        return
    witness_key = meta_get(conn, "witness_public_key")
    signed = {k: cmd.get(k) for k in ("command_id", "action", "platform_id", "quarantine_id", "issued_at")}
    if not witness_key or not verify_signature(witness_key, signed, cmd.get("signature", "")):
        print("unlock command rejected: bad witness signature")
        return
    l3.release(record)
    meta_set(conn, "quarantine", "")
    _report(priv, record, "released", 0)
    print(f"RELEASED {record['id']}")


def _report(priv, record, state, unverified):
    payload = {"platform_id": PLATFORM_ID, "quarantine_id": record["id"], "state": state,
               "started_at": record["started_at"], "unverified": unverified, "evidence_hash": record["evidence_hash"]}
    body = dict(payload, signature=sign_payload(priv, payload))
    requests.post(f"{WITNESS_URL}/quarantine/report", json=body, timeout=TIMEOUT).raise_for_status()


def main():
    conn = open_db()
    priv = load_or_create_key(conn)
    last_heartbeat = last_poll = 0.0
    last_contact = time.monotonic()
    while True:
        backlog = False
        if meta_get(conn, "key_id"):
            sync_bank(conn, priv)  # sealing is local: it keeps going while the network is cut
        try:
            if meta_get(conn, "key_id") is None or meta_get(conn, "witness_public_key") is None:
                register(conn, priv)
            now = time.monotonic()
            if now - last_heartbeat >= HEARTBEAT_SECONDS:
                send_heartbeat(priv)
                last_heartbeat = now
                last_contact = now
            quarantine_contact(conn, priv)
            backlog = send_pending(conn) == SEND_BATCH
            ship_events(conn, priv)
            if now - last_poll >= CHALLENGE_SECONDS:
                answer_challenge(conn, priv)
                last_poll = now
        except requests.RequestException as exc:
            print(f"witness unreachable: {exc.__class__.__name__}")
        check_quarantine(conn, last_contact)
        if not backlog:  # catch up at full speed, idle at 1 s
            time.sleep(1)


if __name__ == "__main__":
    main()
