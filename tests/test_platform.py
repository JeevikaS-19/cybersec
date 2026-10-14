"""Platform adapter (agent/source.py): latching onto a bank by config, not code."""

import json
import os
import sqlite3
from decimal import Decimal

import pytest
import requests

from agent import source as ps
from shared import GENESIS_PREV_HASH, hash_entry, sign_payload
from tests.helpers import Agent, ts

# A bank shaped like the team's PostgreSQL app: integer ids, DECIMAL rupees, NULL side for deposits,
# no txn_id column, no balance-after columns, a status column.
TEAM_SCHEMA = """
CREATE TABLE accounts (id INTEGER PRIMARY KEY, balance TEXT NOT NULL);
CREATE TABLE transactions (id INTEGER PRIMARY KEY, from_account_id INTEGER, to_account_id INTEGER,
  amount TEXT NOT NULL, type TEXT, status TEXT NOT NULL DEFAULT 'completed', timestamp TEXT NOT NULL);
"""
TEAM_CFG = {
    "kind": "sqlite",
    "transactions": {"table": "transactions", "where": "status = 'completed'", "amount_unit": "rupees",
                     "txn_id_prefix": "bank-txn-",
                     "columns": {"row_id": "id", "time": "timestamp", "from_account": "from_account_id",
                                 "to_account": "to_account_id", "amount": "amount"}},
    "accounts": {"table": "accounts", "id": "id", "balance": "balance", "balance_unit": "rupees"},
}


@pytest.fixture
def team_bank(tmp_path):
    db = tmp_path / "team.db"
    conn = sqlite3.connect(db)
    conn.executescript(TEAM_SCHEMA)
    conn.executemany("INSERT INTO accounts VALUES (?, ?)", [(1, "5000.00"), (2, "250.50")])
    conn.executemany("INSERT INTO transactions (id, from_account_id, to_account_id, amount, type, status, timestamp) "
                     "VALUES (?, ?, ?, ?, ?, ?, ?)", [
                         (1, None, 1, "1000.00", "deposit", "completed", "2026-10-14 10:00:00"),
                         (2, 1, 2, "120.25", "transfer", "completed", "2026-10-14 10:00:05"),
                         (3, 2, None, "50.00", "withdrawal", "completed", "2026-10-14 10:00:09"),
                         (4, 1, 2, "9.99", "transfer", "pending", "2026-10-14 10:00:11"),
                     ])
    conn.commit()
    conn.close()
    return db


def _src(db):
    return ps.build(dict(TEAM_CFG, path=str(db)))


def test_team_bank_rows_normalized(team_bank):
    rows = _src(team_bank).new_rows(0, 50)
    assert [r["row_id"] for r in rows] == [1, 2, 3]  # pending row 4 filtered by `where`
    dep, tr, wd = rows
    assert dep["from_account"] == "external" and dep["to_account"] == "1" and dep["amount_paise"] == 100000
    assert tr["txn_id"] == "bank-txn-2" and tr["amount_paise"] == 12025
    assert wd["to_account"] == "external"
    assert tr["from_balance_paise"] is None and tr["to_balance_paise"] is None  # platform doesn't store them
    assert _src(team_bank).balance("2") == 25050
    assert set(_src(team_bank).rows_by_txn_ids(["bank-txn-3", "bank-txn-99", None])) == {"bank-txn-3"}


def test_amount_conversion_is_exact():
    assert ps.to_paise(Decimal("120.25"), "rupees") == 12025
    assert ps.to_paise("0.10", "rupees") == 10
    with pytest.raises(ValueError):
        ps.to_paise("1.005", "rupees")  # never round money silently
    with pytest.raises(TypeError):
        ps.to_paise(1.5, "paise")


def test_unsafe_identifier_in_config_is_refused(team_bank):
    bad = json.loads(json.dumps(TEAM_CFG))
    bad["transactions"]["table"] = "transactions; DROP TABLE accounts"
    with pytest.raises(ValueError):
        ps.build(dict(bad, path=str(team_bank)))


@pytest.fixture
def agent_on_team_bank(team_bank, tmp_path, monkeypatch, witness):
    from agent import agent as agent_mod

    monkeypatch.setattr(agent_mod, "WITNESS_URL", witness.url)
    monkeypatch.setattr(agent_mod, "AGENT_DB_PATH", str(tmp_path / "agent.db"))
    monkeypatch.setattr(agent_mod, "_source", _src(team_bank))
    conn = agent_mod.open_db()
    priv = agent_mod.load_or_create_key(conn)
    agent_mod.register(conn, priv)
    yield agent_mod, conn, priv
    conn.close()


def test_agent_seals_team_bank_and_witness_accepts(agent_on_team_bank, witness):
    agent_mod, conn, priv = agent_on_team_bank
    agent_mod.sync_bank(conn, priv)
    agent_mod.send_pending(conn)
    s = requests.get(f"{witness.url}/status", timeout=5).json()
    assert s["records_verified"] == 3 and s["checks"] == {"A": "green", "B": "green", "C": "green"}
    assert requests.get(f"{witness.url}/alerts", timeout=5).json()["alerts"] == []
    first = json.loads(conn.execute("SELECT body FROM entries WHERE seq = 1").fetchone()[0])
    assert first["txn_time"] == "2026-10-14 10:00:00" and first["timestamp"].endswith("Z")  # bank time vs seal time
    agent_mod.sync_bank(conn, priv)  # running again seals nothing twice
    assert conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0] == 3


def test_row_committed_out_of_order_is_sealed_late(agent_on_team_bank, team_bank):
    agent_mod, conn, priv = agent_on_team_bank
    db = sqlite3.connect(team_bank)
    db.execute("INSERT INTO transactions VALUES (6, 1, 2, '1.00', 'transfer', 'completed', '2026-10-14 10:00:20')")
    db.commit()
    agent_mod.sync_bank(conn, priv)  # sees 1, 2, 3, 6: ids 4 (pending) and 5 (not committed yet) are gaps
    assert set(json.loads(agent_mod.meta_get(conn, "gaps"))) == {"4", "5"}
    db.execute("INSERT INTO transactions VALUES (5, 2, 1, '2.00', 'transfer', 'completed', '2026-10-14 10:00:15')")
    db.commit()
    db.close()
    agent_mod.sync_bank(conn, priv)
    sealed = [json.loads(b)["txn_id"] for (b,) in conn.execute("SELECT body FROM entries ORDER BY seq")]
    assert sealed == ["bank-txn-1", "bank-txn-2", "bank-txn-3", "bank-txn-6", "bank-txn-5"]
    assert set(json.loads(agent_mod.meta_get(conn, "gaps"))) == {"4"}
    monkeypatch_gap = agent_mod.GAP_SECONDS
    try:
        agent_mod.GAP_SECONDS = 0  # a rolled-back id never shows up: it is dropped after gap_seconds
        agent_mod.sync_bank(conn, priv)
    finally:
        agent_mod.GAP_SECONDS = monkeypatch_gap
    assert json.loads(agent_mod.meta_get(conn, "gaps")) == {}


def test_record_check_rebuilds_from_team_bank_row(agent_on_team_bank, team_bank):
    agent_mod, conn, priv = agent_on_team_bank
    agent_mod.sync_bank(conn, priv)
    (rec,) = agent_mod.server_records(conn, [2])
    assert rec["record"]["amount_paise"] == 12025 and rec["record"]["txn_time"] == "2026-10-14 10:00:05"
    db = sqlite3.connect(team_bank)
    db.execute("UPDATE transactions SET amount = '1.25' WHERE id = 2")
    db.execute("DELETE FROM transactions WHERE id = 3")
    db.commit()
    db.close()
    recs = {r["seq"]: r["record"] for r in agent_mod.server_records(conn, [2, 3])}
    assert recs[2]["amount_paise"] == 125 and recs[3] is None


def _entry(a, seq, prev, frm, to, amount, fb=None, tb=None):
    e = {"seq": seq, "timestamp": ts(seq), "event_type": "transaction", "txn_id": f"t-{seq}", "txn_time": ts(seq),
         "from_account": frm, "to_account": to, "amount_paise": amount, "from_balance_paise": fb,
         "to_balance_paise": tb, "prev_hash": prev, "key_id": a.key_id}
    e["hash"] = hash_entry(e)
    e["signature"] = sign_payload(a.priv, {k: v for k, v in e.items() if k != "signature"})
    return e


def test_witness_seeds_balances_from_state_checks_when_platform_stores_none(witness, monkeypatch):
    from witness import checks, records

    a = Agent(witness.url)
    e1 = _entry(a, 1, GENESIS_PREV_HASH, "external", "1", 100000)
    e2 = _entry(a, 2, e1["hash"], "1", "2", 12025)
    assert a.send(e1)["status"] == "accepted" and a.send(e2)["status"] == "accepted"
    monkeypatch.setattr(checks, "CHALLENGE_CHANCE", 1.0)
    monkeypatch.setattr(checks, "STATE_SHARE", 1.0)
    monkeypatch.setattr(records, "SWEEP_SECONDS", float("inf"))

    def ask():
        ch = requests.get(f"{a.url}/challenge/poll", params={"platform_id": a.platform_id}, timeout=5).json()["challenge"]
        assert ch["type"] == "state" and ch["account"] in ("1", "2")  # "external" is never asked about
        return ch

    def answer(ch, bal):
        body = {"challenge_id": ch["id"], "type": "state", "account": ch["account"], "balance_paise": bal, "last_seq": 2}
        body["signature"] = sign_payload(a.priv, dict(body))
        return requests.post(f"{a.url}/challenge/response", json=body, timeout=5).json()

    truth = {"1": 487975, "2": 37075}
    seeded = set()
    while seeded != {"1", "2"}:
        ch = ask()
        assert answer(ch, truth[ch["account"]]) == {"status": "ok"}
        seeded.add(ch["account"])
    ch = ask()  # seeded now: a later balance that doesn't match the replay is Check C red
    assert answer(ch, truth[ch["account"]] + 1000000) == {"status": "mismatch"}
    s = requests.get(f"{witness.url}/status", timeout=5).json()
    assert s["checks"]["C"] == "red"


def test_entry_missing_a_sealed_field_is_rejected(witness):
    a = Agent(witness.url)
    e = _entry(a, 1, GENESIS_PREV_HASH, "acc-1", "acc-2", 100)
    del e["txn_time"]
    e["hash"] = hash_entry(e)
    e["signature"] = sign_payload(a.priv, {k: v for k, v in e.items() if k != "signature"})
    assert a.send(e) == {"status": "rejected", "reason": "malformed_entry"}


@pytest.mark.docker
@pytest.mark.skipif(not os.environ.get("COC_TEST_PG_DSN"), reason="set COC_TEST_PG_DSN to a test PostgreSQL")
def test_postgres_source_against_real_postgres():
    import psycopg

    dsn = os.environ["COC_TEST_PG_DSN"]
    with psycopg.connect(dsn, autocommit=True) as c:
        c.execute("DROP TABLE IF EXISTS transactions; DROP TABLE IF EXISTS accounts;")
        c.execute("CREATE TABLE accounts (id SERIAL PRIMARY KEY, balance DECIMAL(18,2) NOT NULL)")
        c.execute("CREATE TABLE transactions (id SERIAL PRIMARY KEY, from_account_id INT NULL, to_account_id INT NULL, "
                  "amount DECIMAL(18,2) NOT NULL, type VARCHAR(20), status VARCHAR(20) NOT NULL DEFAULT 'completed', "
                  "timestamp TIMESTAMP NOT NULL DEFAULT NOW())")
        c.execute("INSERT INTO accounts (balance) VALUES (5000.00), (250.50)")
        c.execute("INSERT INTO transactions (from_account_id, to_account_id, amount, type) VALUES "
                  "(NULL, 1, 1000.00, 'deposit'), (1, 2, 120.25, 'transfer')")
    src = ps.build(dict(TEAM_CFG, kind="postgres", dsn=dsn))
    rows = src.new_rows(0, 10)
    assert [(r["from_account"], r["to_account"], r["amount_paise"]) for r in rows] == [
        ("external", "1", 100000), ("1", "2", 12025)]
    assert rows[0]["txn_time"].endswith("Z")
    assert src.balance("2") == 25050
    assert set(src.rows_by_txn_ids(["bank-txn-2"])) == {"bank-txn-2"}
