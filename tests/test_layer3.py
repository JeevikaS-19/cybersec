import json

import pytest
import requests

from layers.common import events as layer_events
from layers.l3_quarantine import quarantine as l3
from shared import sign_payload, verify_signature
from tests.helpers import Agent, ts
from witness import quarantine as wq
from witness.store import connect

PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
jeevika:x:1000:1000::/home/jeevika:/bin/bash
attacker:x:1001:1001::/home/attacker:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
"""


@pytest.fixture
def l3env(tmp_path, monkeypatch):
    (tmp_path / "passwd").write_text(PASSWD)
    (tmp_path / "log").mkdir()
    (tmp_path / "log" / "app.log").write_text("txn-1\n")
    monkeypatch.setenv("COC_SPOOL", str(tmp_path / "spool"))
    monkeypatch.setenv("COC_EVIDENCE_DIR", str(tmp_path / "vault"))
    monkeypatch.setenv("COC_L3_DRY_RUN", "1")
    return tmp_path


def test_interactive_users_include_root_and_skip_service_accounts(l3env):
    assert l3.interactive_users(str(l3env / "passwd")) == ["root", "jeevika", "attacker"]


def test_quarantine_runs_in_fixed_order_and_seals_evidence(l3env):
    rec = l3.quarantine("no contact for 45 s", [str(l3env / "log")], passwd=str(l3env / "passwd"))
    triggers = [json.loads(p.read_text())["trigger"] for p in layer_events.pending()]
    assert triggers == ["quarantine:captured", "quarantine:locked", "quarantine:quarantined"]
    assert rec["users"] == ["root", "jeevika", "attacker"]
    # lockout covers every interactive user, root included, and ends their sessions
    assert "passwd -l root" in rec["actions"] and "loginctl terminate-user attacker" in rec["actions"]
    assert rec["actions"].index("touch /etc/nologin") < rec["actions"].index("passwd -l root")
    assert not any(n in " ".join(rec["actions"]) for n in ("reboot", "shutdown", "poweroff"))
    vault = l3env / "vault" / rec["id"]
    body = (vault / "evidence.json").read_text()
    assert json.loads(body)["log_hashes"]  # protected logs hashed at capture time
    assert (vault / "evidence.sha256").read_text() == rec["evidence_hash"]


def test_reboot_in_config_is_refused():
    with pytest.raises(ValueError):
        l3._expand(["systemctl reboot"], ["root"])


def _report(a, state, qid, unverified=3):
    body = {"platform_id": a.platform_id, "quarantine_id": qid, "state": state, "started_at": 1,
            "unverified": unverified, "evidence_hash": "abc"}
    body["signature"] = sign_payload(a.priv, dict(body))
    return requests.post(f"{a.url}/quarantine/report", json=body, timeout=5).json()


def _status(url):
    return requests.get(f"{url}/status", timeout=5).json()


def test_witness_quarantine_flow_two_of_three_signed_unlock(witness, clock):
    a = Agent(witness.url)
    reg = requests.post(f"{witness.url}/register/agent", json={"platform_id": a.platform_id,
                        "public_key": __import__("shared").export_public_key(a.priv)}, timeout=5).json()
    a.send(a.next_entry())
    a.heartbeat(ts(1))
    clock["seconds"] = 46  # network cut: no heartbeat for 46 s
    conn = connect(witness.db)
    wq.presume(conn, __import__("witness.checks", fromlist=["now"]).now(), {"layer3": {"after_seconds": 45}})
    conn.close()
    s = _status(witness.url)
    assert s["state"] == "quarantined" and s["layers"]["3"] == "quarantined"
    assert s["quarantine"]["active"] and s["quarantine"]["unverified"] is None  # unknown while cut
    # network back: the server reports, and stays locked
    assert _report(a, "quarantined", "q-1234") == {"status": "ok"}
    q = _status(witness.url)["quarantine"]
    assert q["confirmed"] and q["unverified"] == 3 and not q["unlock_issued"]
    poll = lambda: requests.get(f"{witness.url}/quarantine/poll", params={"platform_id": a.platform_id}, timeout=5).json()["command"]
    requests.post(f"{witness.url}/quarantine/approve", json={"holder": 0}, timeout=5)
    assert poll() is None  # one approval is not enough
    requests.post(f"{witness.url}/quarantine/approve", json={"holder": 2}, timeout=5)
    cmd = poll()
    assert cmd["action"] == "unlock" and cmd["quarantine_id"] == "q-1234"
    signed = {k: cmd[k] for k in ("command_id", "action", "platform_id", "quarantine_id", "issued_at")}
    assert verify_signature(reg["witness_public_key"], signed, cmd["signature"])
    assert _report(a, "released", "q-1234") == {"status": "ok"}
    s = _status(witness.url)
    assert s["quarantine"] is None and s["layers"]["3"] == "on"


def test_forged_quarantine_report_is_rejected(witness):
    a = Agent(witness.url)
    body = {"platform_id": a.platform_id, "quarantine_id": "q-x", "state": "released", "started_at": 1,
            "unverified": 0, "evidence_hash": "abc", "signature": "AAAA"}
    assert requests.post(f"{witness.url}/quarantine/report", json=body, timeout=5).json() == {"status": "rejected"}
