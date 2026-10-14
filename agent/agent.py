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

from shared import (
    GENESIS_PREV_HASH,
    export_public_key,
    generate_keypair,
    hash_entry,
    sign_payload,
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


def send_heartbeat(priv):
    timestamp = now_iso()
    body = {
        "platform_id": PLATFORM_ID,
        "timestamp": timestamp,
        "signature": sign_payload(priv, {"platform_id": PLATFORM_ID, "timestamp": timestamp}),
    }
    requests.post(f"{WITNESS_URL}/heartbeat", json=body, timeout=TIMEOUT).raise_for_status()


def answer_challenge(conn, priv):
    resp = requests.get(f"{WITNESS_URL}/challenge/poll", params={"platform_id": PLATFORM_ID}, timeout=TIMEOUT)
    challenge = resp.json().get("challenge")
    if not challenge or challenge["type"] != "hash":
        return
    last = last_accepted_entry(conn)
    payload = {
        "challenge_id": challenge["id"],
        "type": challenge["type"],
        "latest_hash": last["hash"] if last else GENESIS_PREV_HASH,
        "last_seq": last["seq"] if last else 0,
    }
    body = dict(payload, signature=sign_payload(priv, payload))
    requests.post(f"{WITNESS_URL}/challenge/response", json=body, timeout=TIMEOUT).raise_for_status()


def main():
    conn = open_db()
    priv = load_or_create_key(conn)
    last_heartbeat = last_poll = 0.0
    while True:
        try:
            if meta_get(conn, "key_id") is None:
                register(conn, priv)
            now = time.monotonic()
            if now - last_heartbeat >= HEARTBEAT_SECONDS:
                send_heartbeat(priv)
                last_heartbeat = now
            sync_bank(conn, priv)
            send_pending(conn)
            if now - last_poll >= CHALLENGE_SECONDS:
                answer_challenge(conn, priv)
                last_poll = now
        except requests.RequestException as exc:
            print(f"witness unreachable: {exc.__class__.__name__}")
        time.sleep(1)


if __name__ == "__main__":
    main()
