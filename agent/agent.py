"""Agent: turns a platform's transactions into signed, chained entries and sends them to the witness.

Where the transactions come from is config/platform.yaml (agent/source.py). No balance logic here beyond
answering the witness's questions; the witness does the checking.
"""

import sys
from pathlib import Path

if __name__ == "__main__" and not __package__:
    # Run as `python agent/agent.py`: put the repo root first, or `agent` would resolve to this file.
    sys.path[0] = str(Path(__file__).resolve().parents[1])

import base64
import json
import os
import sqlite3
import time
from datetime import UTC, datetime
from pathlib import Path

import requests
import yaml
from cryptography.hazmat.primitives.asymmetric import ed25519

from agent import source as platform_source
from layers.common import events as layer_events
from layers.common.config import get as cfg
from layers.l3_quarantine import quarantine as l3
from shared import (
    GENESIS_PREV_HASH,
    export_public_key,
    generate_keypair,
    hash_entry,
    sign_payload,
    verify_signature,
)

REPO = Path(__file__).resolve().parents[1]


def load_platform():
    path = Path(os.environ.get("COC_PLATFORM_CONFIG") or REPO / "config" / "platform.yaml")
    try:
        cfg = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except OSError:
        cfg = {}
    src = dict(cfg.get("source") or {})
    src.setdefault("kind", "sqlite")
    src.setdefault("path", "bank.db")
    src.setdefault("transactions", {"table": "transactions", "columns": {
        "row_id": "id", "txn_id": "txn_id", "time": "timestamp", "from_account": "from_account",
        "to_account": "to_account", "amount": "amount_paise", "from_balance": "from_balance_paise",
        "to_balance": "to_balance_paise"}})
    src.setdefault("accounts", {"table": "accounts", "id": "account_id", "balance": "balance_paise"})
    if src["kind"] == "sqlite" and os.environ.get("BANK_DB_PATH"):
        src["path"] = os.environ["BANK_DB_PATH"]
    if os.environ.get("COC_DB_DSN"):
        src["dsn"] = os.environ["COC_DB_DSN"]
    elif str(src.get("dsn", "")).startswith("env:"):
        src["dsn"] = os.environ.get(src["dsn"][4:], "")
    return {
        "platform_id": os.environ.get("PLATFORM_ID") or cfg.get("platform_id", "log-server-1"),
        "witness_url": os.environ.get("WITNESS_URL") or cfg.get("witness_url", "http://127.0.0.1:8000"),
        "source": src,
    }


PLATFORM = load_platform()
WITNESS_URL = PLATFORM["witness_url"]
PLATFORM_ID = PLATFORM["platform_id"]
AGENT_DB_PATH = os.environ.get("AGENT_DB_PATH", "agent_state.db")
GAP_SECONDS = float(PLATFORM["source"].get("gap_seconds", 60))
MAX_GAPS = 1000
_source = None


def source():
    global _source
    if _source is None:
        _source = platform_source.build(PLATFORM["source"])
    return _source

HEARTBEAT_SECONDS = cfg("layer2", "heartbeat_seconds", 5.0, "HEARTBEAT_SECONDS")
CHALLENGE_SECONDS = cfg("layer2", "challenge_poll_seconds", 2.0, "CHALLENGE_POLL")
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
CREATE TABLE IF NOT EXISTS sealed_rows (row_id INTEGER PRIMARY KEY, seq INTEGER NOT NULL);
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


def seal(conn, priv, row):
    """Turn one platform row into the next signed, chained entry. Written atomically with its row id."""
    prev = last_local_entry(conn)
    seq = prev["seq"] + 1 if prev else 1
    stamp = now_iso()
    if prev and stamp < prev["timestamp"]:
        stamp = prev["timestamp"]  # sealing time never goes backwards, even if the clock does
    entry = {
        "seq": seq,
        "timestamp": stamp,
        "event_type": "transaction",
        "txn_id": row["txn_id"],
        "txn_time": row["txn_time"],
        "from_account": row["from_account"],
        "to_account": row["to_account"],
        "amount_paise": row["amount_paise"],
        "from_balance_paise": row["from_balance_paise"],
        "to_balance_paise": row["to_balance_paise"],
        "prev_hash": prev["hash"] if prev else GENESIS_PREV_HASH,
        "key_id": meta_get(conn, "key_id"),
    }
    entry["hash"] = hash_entry(entry)
    entry["signature"] = sign_payload(priv, {k: v for k, v in entry.items() if k != "signature"})
    with conn:
        conn.execute("INSERT INTO entries (seq, body) VALUES (?, ?)", (seq, json.dumps(entry)))
        conn.execute("INSERT INTO sealed_rows (row_id, seq) VALUES (?, ?)", (row["row_id"], seq))


def sync_bank(conn, priv):
    """Seal new platform rows. Rows can commit out of id order, so skipped ids are re-checked for a while."""
    try:
        src = source()
        last = int(meta_get(conn, "last_row_id") or 0)
        gaps = json.loads(meta_get(conn, "gaps") or "{}")
        rows = src.new_rows(last, SEND_BATCH)
        late = src.rows_by_ids([int(k) for k in gaps]) if gaps else []
    except (sqlite3.Error, OSError, ImportError) as exc:
        print(f"platform source unavailable: {exc.__class__.__name__}: {exc}")
        return
    except Exception as exc:  # noqa: BLE001 - e.g. psycopg.OperationalError: retry next loop
        print(f"platform source error: {exc.__class__.__name__}: {exc}")
        return
    now = time.time()
    expected = last + 1
    for r in rows:
        for missing in range(expected, r["row_id"]):
            if len(gaps) < MAX_GAPS:
                gaps.setdefault(str(missing), now)
        expected = r["row_id"] + 1
    already = {row_id for (row_id,) in conn.execute("SELECT row_id FROM sealed_rows WHERE row_id >= ?",
                                                    (min([r["row_id"] for r in rows + late], default=0),))}
    for r in late + rows:
        gaps.pop(str(r["row_id"]), None)
        if r["row_id"] not in already:
            seal(conn, priv, r)
            already.add(r["row_id"])
    gaps = {k: t for k, t in gaps.items() if now - t < GAP_SECONDS}  # rolled-back ids never appear
    meta_set(conn, "last_row_id", str(max(last, rows[-1]["row_id"] if rows else last)))
    meta_set(conn, "gaps", json.dumps(gaps))


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


RECORD_FIELDS = ("txn_id", "txn_time", "from_account", "to_account", "amount_paise",
                 "from_balance_paise", "to_balance_paise")


def balance_for_witness(conn, account):
    """The platform's balance for `account` as of the last entry the witness accepted."""
    accepted = {r for (r,) in conn.execute(
        "SELECT s.row_id FROM sealed_rows s JOIN entries e ON e.seq = s.seq WHERE e.accepted = 1")}
    top = max(accepted, default=0)
    pending = [r for (r,) in conn.execute(
        "SELECT s.row_id FROM sealed_rows s JOIN entries e ON e.seq = s.seq WHERE e.accepted = 0 AND s.row_id < ?", (top,))]
    gaps = [int(k) for k in json.loads(meta_get(conn, "gaps") or "{}")]
    return source().balance_as_of(account, top, pending + gaps, accepted)


def server_records(conn, seqs):
    """Record #seq as the platform holds it now, rebuilt from its own row (None if the row is gone)."""
    txn_ids = {}
    for seq in seqs:
        row = conn.execute("SELECT body FROM entries WHERE seq = ?", (seq,)).fetchone()
        txn_ids[seq] = json.loads(row[0])["txn_id"] if row else None
    rows = source().rows_by_txn_ids(list(txn_ids.values()))
    out = []
    for seq in seqs:
        r = rows.get(txn_ids[seq])
        out.append({"seq": seq, "record": {f: r[f] for f in RECORD_FIELDS} if r else None})
    return out


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
        balance = balance_for_witness(conn, challenge["account"])
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
