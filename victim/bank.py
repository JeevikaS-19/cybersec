import os
import random
import sqlite3
import sys
import time
from datetime import UTC, datetime

DB_PATH = os.environ.get("BANK_DB_PATH", "bank.db")

def init_db(conn):
    with conn:
        conn.execute("CREATE TABLE IF NOT EXISTS accounts (account_id TEXT PRIMARY KEY, balance_paise INTEGER NOT NULL)")
        conn.execute("""CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            txn_id TEXT,
            timestamp TEXT,
            from_account TEXT,
            to_account TEXT,
            amount_paise INTEGER,
            from_balance_paise INTEGER,
            to_balance_paise INTEGER
        )""")
        for acc in ["acc-1", "acc-2", "acc-3"]:
            conn.execute("INSERT OR IGNORE INTO accounts VALUES (?, 10000000)", (acc,))

def transfer_step(conn):
    from_acc, to_acc = random.sample(["acc-1", "acc-2", "acc-3"], 2)
    amount = random.randint(100, 5000) * 100
    ts = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    with conn:
        conn.execute("UPDATE accounts SET balance_paise = balance_paise - ? WHERE account_id = ?", (amount, from_acc))
        conn.execute("UPDATE accounts SET balance_paise = balance_paise + ? WHERE account_id = ?", (amount, to_acc))
        from_bal = conn.execute("SELECT balance_paise FROM accounts WHERE account_id = ?", (from_acc,)).fetchone()[0]
        to_bal = conn.execute("SELECT balance_paise FROM accounts WHERE account_id = ?", (to_acc,)).fetchone()[0]
        cur = conn.execute(
            "INSERT INTO transactions (timestamp, from_account, to_account, amount_paise, from_balance_paise, to_balance_paise) VALUES (?, ?, ?, ?, ?, ?)",
            (ts, from_acc, to_acc, amount, from_bal, to_bal)
        )
        txn_id = f"txn-{cur.lastrowid:05d}"
        conn.execute("UPDATE transactions SET txn_id = ? WHERE id = ?", (txn_id, cur.lastrowid))
    return txn_id

def main():
    fast = "--fast" in sys.argv
    max_txns = int(sys.argv[sys.argv.index("--count") + 1]) if "--count" in sys.argv else None
    conn = sqlite3.connect(DB_PATH)
    init_db(conn)
    count = 0
    try:
        while max_txns is None or count < max_txns:
            transfer_step(conn)
            count += 1
            if not fast:
                time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        conn.close()

if __name__ == "__main__":
    main()
