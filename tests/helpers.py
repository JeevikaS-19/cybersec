from datetime import UTC, datetime, timedelta

import requests

from shared import GENESIS_PREV_HASH, generate_keypair, hash_entry, sign_payload

BASE = datetime(2026, 10, 14, 8, 0, 0, tzinfo=UTC)


def ts(n):
    return (BASE + timedelta(seconds=n)).strftime("%Y-%m-%dT%H:%M:%SZ")


class Agent:
    def __init__(self, url, platform_id="log-server-1"):
        self.url = url
        self.platform_id = platform_id
        self.priv, pub = generate_keypair()
        resp = requests.post(f"{url}/register/agent", json={"platform_id": platform_id, "public_key": pub}, timeout=5)
        resp.raise_for_status()
        self.key_id = resp.json()["key_id"]
        self.chain = []

    def make(self, seq, prev_hash, timestamp, priv=None):
        entry = {
            "seq": seq, "timestamp": timestamp, "event_type": "transaction",
            "txn_id": f"txn-{seq:05d}", "from_account": "acc-1", "to_account": "acc-2",
            "amount_paise": 100, "from_balance_paise": 1000, "to_balance_paise": 2000,
            "prev_hash": prev_hash, "key_id": self.key_id,
        }
        entry["hash"] = hash_entry(entry)
        entry["signature"] = sign_payload(priv or self.priv, {k: v for k, v in entry.items() if k != "signature"})
        return entry

    def next_entry(self):
        prev = self.chain[-1]["hash"] if self.chain else GENESIS_PREV_HASH
        n = len(self.chain) + 1
        entry = self.make(n, prev, ts(n))
        self.chain.append(entry)
        return entry

    def send(self, entry):
        return requests.post(f"{self.url}/entries", json=entry, timeout=5).json()

    def heartbeat(self, timestamp, sign=True):
        body = {"platform_id": self.platform_id, "timestamp": timestamp}
        if sign:
            body["signature"] = sign_payload(self.priv, {"platform_id": self.platform_id, "timestamp": timestamp})
        return requests.post(f"{self.url}/heartbeat", json=body, timeout=5).json()
