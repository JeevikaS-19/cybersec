import time

import requests

from tests.helpers import Agent, ts
from witness import checks
from witness.store import connect


def _alert_kinds(db):
    conn = connect(db)
    try:
        return [r["kind"] for r in conn.execute("SELECT kind FROM alerts ORDER BY id")]
    finally:
        conn.close()


def _silence_check(db):
    conn = connect(db)
    try:
        checks.silence_check(conn, checks.now())
        checks.challenge_check(conn, checks.now())
    finally:
        conn.close()


def test_t2a_no_heartbeat_fires_silence_alert(witness, clock):
    Agent(witness.url)  # registration starts the silence clock; no heartbeat is ever sent
    clock["seconds"] = 16
    _silence_check(witness.db)
    assert _alert_kinds(witness.db) == ["silence"]


def test_t2c_older_entry_is_non_monotonic(witness):
    a = Agent(witness.url)
    a.send(a.next_entry())
    a.send(a.next_entry())
    backdated = a.make(3, a.chain[1]["hash"], ts(0))
    assert a.send(backdated) == {"status": "rejected", "reason": "non_monotonic_timestamp"}
    conn = connect(witness.db)
    try:
        row = conn.execute("SELECT kind, tamper_type FROM alerts").fetchone()
    finally:
        conn.close()
    assert (row["kind"], row["tamper_type"]) == ("non_monotonic_timestamp", "backdated")


def test_t2e_unsigned_and_replayed_heartbeats_do_not_count(witness, clock):
    a = Agent(witness.url)
    assert a.heartbeat(ts(10), sign=False)["status"] == "rejected"
    assert a.heartbeat(ts(11))["status"] == "ok"
    assert a.heartbeat(ts(11))["status"] == "rejected"  # replay of the same signed heartbeat
    clock["seconds"] = 16  # no valid heartbeat for 15 s from the accepted one
    _silence_check(witness.db)
    assert "silence" in _alert_kinds(witness.db)


def test_t2f_unanswered_hash_challenge_is_missed(witness, clock):
    a = Agent(witness.url)
    challenge = None
    for _ in range(200):
        challenge = requests.get(f"{witness.url}/challenge/poll", params={"platform_id": a.platform_id}, timeout=5).json()["challenge"]
        if challenge:
            break
        time.sleep(0.01)
    assert challenge is not None, "no challenge was issued"
    clock["seconds"] = 6  # past the 5 s answer window; do not answer
    _silence_check(witness.db)
    assert _alert_kinds(witness.db) == ["missed_challenge"]


def test_auditor_view_shows_heartbeats_and_challenges(witness, monkeypatch):
    a = Agent(witness.url)
    a.send(a.next_entry())
    assert a.heartbeat(ts(1))["status"] == "ok"
    monkeypatch.setattr(checks, "CHALLENGE_CHANCE", 1.0)
    requests.get(f"{witness.url}/challenge/poll", params={"platform_id": a.platform_id}, timeout=5)
    kinds = [r["kind"] for r in requests.get(f"{witness.url}/activity", timeout=5).json()["activity"]]
    assert kinds == ["heartbeat", "challenge_issued"]
    page = requests.get(witness.url + "/", timeout=5)
    assert page.status_code == 200 and "auditor view" in page.text


def test_status_reports_connection_and_verified_records(witness):
    a = Agent(witness.url)
    s = requests.get(f"{witness.url}/status", timeout=5).json()
    assert s["connection"] == "waiting" and s["records_verified"] == 0 and s["last_verified"] is None
    a.send(a.next_entry())
    a.send(a.next_entry())
    a.heartbeat(ts(3))
    s = requests.get(f"{witness.url}/status", timeout=5).json()
    assert s["connection"] == "connected" and s["platform_id"] == "log-server-1"
    assert s["records_verified"] == 2 and s["last_verified"] == {"seq": 2, "time": ts(2)}
