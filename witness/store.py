import json
import sqlite3

from witness.classify import TAMPER_TYPES

SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
    key_id TEXT PRIMARY KEY,
    platform_id TEXT UNIQUE NOT NULL,
    public_key TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    seq INTEGER,
    timestamp TEXT,
    event_type TEXT,
    txn_id TEXT,
    from_account TEXT,
    to_account TEXT,
    amount_paise INTEGER,
    from_balance_paise INTEGER,
    to_balance_paise INTEGER,
    prev_hash TEXT,
    key_id TEXT,
    hash TEXT,
    signature TEXT,
    accepted INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    ref TEXT NOT NULL,
    tamper_type TEXT,
    detail TEXT,
    time REAL NOT NULL,
    resolved INTEGER NOT NULL DEFAULT 0,
    UNIQUE (kind, ref)
);
CREATE TABLE IF NOT EXISTS balances (
    account TEXT PRIMARY KEY,
    balance_paise INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    layer INTEGER NOT NULL,
    trigger TEXT NOT NULL,
    time TEXT NOT NULL,
    body TEXT NOT NULL,
    received REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS state (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""

def connect(db_path):
    # One connection per request; FastAPI may open it and use it on different threadpool threads.
    conn = sqlite3.connect(db_path, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(db_path):
    conn = connect(db_path)
    try:
        # WAL lets the periodic self-check read while requests write.
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.executescript(SCHEMA)
        # Databases created before the resolved column existed get it added here.
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(alerts)")}
        if "resolved" not in cols:
            conn.execute("ALTER TABLE alerts ADD COLUMN resolved INTEGER NOT NULL DEFAULT 0")
            conn.commit()
    finally:
        conn.close()

def get_state(conn, key):
    row = conn.execute("SELECT value FROM state WHERE key = ?", (key,)).fetchone()
    return json.loads(row["value"]) if row else None

def set_state(conn, key, value):
    with conn:
        conn.execute("INSERT OR REPLACE INTO state (key, value) VALUES (?, ?)", (key, json.dumps(value)))

def add_alert(conn, kind, ref, tamper_type, detail, now_ts):
    if tamper_type is not None and tamper_type not in TAMPER_TYPES:
        print(f"WARNING: unknown tamper_type {tamper_type!r} on alert {kind} ref {ref}")
    # One alert per (kind, ref): repeated self-checks never duplicate it.
    with conn:
        conn.execute(
            "INSERT OR IGNORE INTO alerts (kind, ref, tamper_type, detail, time) VALUES (?, ?, ?, ?, ?)",
            (kind, str(ref), tamper_type, detail, now_ts),
        )
