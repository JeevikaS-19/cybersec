import requests

from shared import GENESIS_PREV_HASH, hash_entry, sign_payload
from tests.helpers import Agent, ts
from witness import checks, records

OPENING = {"acc-1": 100_000, "acc-2": 50_000}


class Ledger:
    """Bank-side truth: post-transaction balances, as victim/bank.py writes them."""

    def __init__(self, agent):
        self.agent = agent
        self.balances = dict(OPENING)
        self.seq = 0
        self.prev = GENESIS_PREV_HASH

    def transfer(self, src, dst, amount, lie_from=None, lie_to=None):
        self.balances[src] -= amount
        self.balances[dst] += amount
        self.seq += 1
        entry = {
            "seq": self.seq, "timestamp": ts(self.seq), "event_type": "transaction",
            "txn_id": f"txn-{self.seq:05d}", "from_account": src, "to_account": dst,
            "amount_paise": amount,
            "from_balance_paise": self.balances[src] if lie_from is None else lie_from,
            "to_balance_paise": self.balances[dst] if lie_to is None else lie_to,
            "prev_hash": self.prev, "key_id": self.agent.key_id,
        }
        entry["hash"] = hash_entry(entry)
        entry["signature"] = sign_payload(self.agent.priv, {k: v for k, v in entry.items() if k != "signature"})
        self.prev = entry["hash"]
        return self.agent.send(entry)


def _status(url):
    return requests.get(f"{url}/status", timeout=5).json()


def _tamper_types(url):
    return [a.get("tamper_type") for a in requests.get(f"{url}/alerts", timeout=5).json()["alerts"]]


def _answer_hash(agent, ledger, ch):
    body = {"challenge_id": ch["id"], "type": "hash", "latest_hash": ledger.prev, "last_seq": ledger.seq}
    body["signature"] = sign_payload(agent.priv, body)
    return requests.post(f"{agent.url}/challenge/response", json=body, timeout=5).json()


def _state_challenge(agent, ledger, monkeypatch):
    # Force issuance; answer any hash challenges honestly until a state one arrives.
    monkeypatch.setattr(checks, "CHALLENGE_CHANCE", 1.0)
    monkeypatch.setattr(checks, "RECORD_SHARE", 0.0)  # record checks have their own tests
    monkeypatch.setattr(records, "SWEEP_SECONDS", float("inf"))
    for _ in range(100):
        ch = requests.get(f"{agent.url}/challenge/poll", params={"platform_id": agent.platform_id}, timeout=5).json()["challenge"]
        assert ch is not None, "witness issued no challenge with CHALLENGE_CHANCE=1.0"
        if ch["type"] == "state":
            assert ch.get("account") in ledger.balances, f"state challenge names unknown account: {ch}"
            return ch
        assert _answer_hash(agent, ledger, ch) == {"status": "ok"}
    raise AssertionError("witness never issued a state challenge in 100 polls")


def _answer_state(agent, ledger, ch, balance):
    body = {"challenge_id": ch["id"], "type": "state", "account": ch["account"],
            "balance_paise": balance, "last_seq": ledger.seq}
    body["signature"] = sign_payload(agent.priv, body)
    return requests.post(f"{agent.url}/challenge/response", json=body, timeout=5).json()


def _honest_run(witness):
    agent = Agent(witness.url)
    ledger = Ledger(agent)
    for src, dst, amt in [("acc-1", "acc-2", 1_000), ("acc-2", "acc-1", 250), ("acc-1", "acc-2", 4_000)]:
        assert ledger.transfer(src, dst, amt)["status"] == "accepted"
    return agent, ledger


def test_t3_control_honest_balances_stay_green(witness, monkeypatch):
    agent, ledger = _honest_run(witness)
    ch = _state_challenge(agent, ledger, monkeypatch)
    assert _answer_state(agent, ledger, ch, ledger.balances[ch["account"]]) == {"status": "ok"}
    assert _status(witness.url)["checks"] == {"A": "green", "B": "green", "C": "green"}
    assert _tamper_types(witness.url) == []


def test_t3a_wrong_reported_balance_is_replay_mismatch(witness):
    _, ledger = _honest_run(witness)
    true_from = ledger.balances["acc-1"] - 500
    ledger.transfer("acc-1", "acc-2", 500, lie_from=true_from + 99_999)
    assert _status(witness.url)["checks"]["C"] == "red"
    assert "balance_misreported" in _tamper_types(witness.url)


def test_t3a_wrong_to_balance_also_caught(witness):
    _, ledger = _honest_run(witness)
    ledger.transfer("acc-2", "acc-1", 300, lie_to=1)
    assert _status(witness.url)["checks"]["C"] == "red"
    assert "balance_misreported" in _tamper_types(witness.url)


def test_t3b_db_edit_without_log_caught_by_state_challenge(witness, monkeypatch):
    agent, ledger = _honest_run(witness)
    ch = _state_challenge(agent, ledger, monkeypatch)
    edited = ledger.balances[ch["account"]] + 1_000_000  # A6: root edits bank.db, writes no log entry
    assert _answer_state(agent, ledger, ch, edited) == {"status": "mismatch"}
    checks_now = _status(witness.url)["checks"]
    assert checks_now == {"A": "green", "B": "green", "C": "red"}
    assert _tamper_types(witness.url) == ["db_edited_without_log"]
