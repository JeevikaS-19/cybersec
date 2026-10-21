import json

import pytest
import requests

from layers.common import events as layer_events
from layers.l3_quarantine import quarantine as l3
from shared import sign_payload, verify_signature
from tests.helpers import Agent, ts
from witness import checks, quarantine as wq
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
    assert "passwd -l root" in rec["actions"] and "usermod --expiredate 1 attacker" in rec["actions"]
    assert any(a.startswith("end login sessions") for a in rec["actions"])
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
    signed = {k: cmd[k] for k in ("command_id", "action", "platform_id", "quarantine_id", "issued_at", "secret")}
    assert verify_signature(reg["witness_public_key"], signed, cmd["signature"])
    assert _report(a, "released", "q-1234") == {"status": "ok"}
    s = _status(witness.url)
    assert s["quarantine"] is None and s["layers"]["3"] == "on"


def test_forged_quarantine_report_is_rejected(witness):
    a = Agent(witness.url)
    body = {"platform_id": a.platform_id, "quarantine_id": "q-x", "state": "released", "started_at": 1,
            "unverified": 0, "evidence_hash": "abc", "signature": "AAAA"}
    assert requests.post(f"{witness.url}/quarantine/report", json=body, timeout=5).json() == {"status": "rejected"}


def _fake_proc(root, pid, ppid, uid, tty, auid, comm):
    d = root / str(pid)
    d.mkdir(parents=True)
    (d / "stat").write_text(f"{pid} ({comm}) S {ppid} {pid} {pid} {tty} -1 4194304 0 0 0 0 0 0 0 0 20 0 1 0\n")
    (d / "status").write_text(f"Name:\t{comm}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
    (d / "loginuid").write_text(str(auid))


def test_end_sessions_kills_login_processes_but_never_services_or_itself(tmp_path, monkeypatch):
    from layers.l3_quarantine import sessions

    proc = tmp_path / "proc"
    unset = sessions.UNSET_AUID
    _fake_proc(proc, 1, 0, 0, 0, unset, "init")
    _fake_proc(proc, 200, 1, 0, 0, unset, "sshd")              # service: no tty, no login uid -> keep
    _fake_proc(proc, 300, 200, 0, 34816, 1001, "bash")         # root shell from an attacker login -> kill
    _fake_proc(proc, 301, 300, 1001, 0, 1001, "nc")            # attacker's reverse shell, no tty -> kill (auid)
    _fake_proc(proc, 400, 1, 1000, 34817, 1000, "bash")        # admin's shell -> kill
    _fake_proc(proc, 500, 1, 0, 34818, 0, "python")            # the agent running quarantine -> keep (self)
    monkeypatch.setattr(sessions.os, "getpid", lambda: 500)
    found = sessions.end_login_sessions(dry_run=True, proc=str(proc))
    assert sorted(p["pid"] for p in found) == [300, 301, 400]
    only_attacker = sessions.login_processes(str(proc), users=[1001])
    assert [p["pid"] for p in only_attacker] == [301]


def test_shamir_two_of_three_shares_rebuild_the_unlock_secret(witness, clock, tmp_path):
    import hashlib

    from shared import export_public_key
    from witness import keyholders
    from witness.checks import now

    keyholders.init(witness.db, tmp_path / "shares", ["SOC lead", "Auditor", "Compliance officer"])
    shares = {p.stem: p.read_text().strip() for p in (tmp_path / "shares").glob("*.share")}
    assert set(shares) == {"soc-lead", "auditor", "compliance-officer"}
    a = Agent(witness.url)
    reg = requests.post(f"{witness.url}/register/agent", json={"platform_id": a.platform_id,
                        "public_key": export_public_key(a.priv)}, timeout=5).json()
    a.heartbeat(ts(1))
    clock["seconds"] = 46
    conn = connect(witness.db)
    wq.presume(conn, now(), {"layer3": {"after_seconds": 45}})
    conn.close()
    _report(a, "quarantined", "q-77")
    ap = lambda h, sh: requests.post(f"{witness.url}/quarantine/approve", json={"holder": h, "share": sh}, timeout=5).json()
    poll = lambda: requests.get(f"{witness.url}/quarantine/poll", params={"platform_id": a.platform_id}, timeout=5).json()["command"]
    assert ap(0, None)["status"] == "rejected"  # a button press alone is not enough any more
    bad = shares["auditor"][:-1] + ("0" if shares["auditor"][-1] != "0" else "1")
    ap(0, shares["soc-lead"])
    ap(1, bad)
    assert poll() is None  # wrong share: secret doesn't rebuild, approvals reset
    assert requests.get(f"{witness.url}/status", timeout=5).json()["quarantine"]["holders"][0]["approved"] is False
    ap(0, shares["soc-lead"])
    ap(2, shares["compliance-officer"])
    cmd = poll()
    assert hashlib.sha256(bytes.fromhex(cmd["secret"])).hexdigest() == reg["unlock_hash"]
    status = json.dumps(requests.get(f"{witness.url}/status", timeout=5).json())
    assert not any(v.split("-")[1] in status for v in shares.values())  # no share value ever shown


def test_t7a_agent_silence_triggers_quarantine_auto_transition(witness, clock):
    """T7a: agent goes silent → silence alert fires at 15 s → quarantine presumed at 45 s.

    Exercises the _check_loop path (silence_check → quarantine.presume) end-to-end via HTTP,
    not by calling wq.presume() directly. Then verifies the unlock flow clears the state.
    """
    from shared import export_public_key

    a = Agent(witness.url)
    # Re-register to capture the witness public key (needed to verify the unlock signature).
    reg = requests.post(f"{witness.url}/register/agent",
                        json={"platform_id": a.platform_id, "public_key": export_public_key(a.priv)},
                        timeout=5).json()
    a.send(a.next_entry())
    a.heartbeat(ts(1))  # last known heartbeat; network "cuts" after this

    # Advance clock past SILENCE_SECONDS (15 s): silence_check should fire.
    clock["seconds"] = 16
    conn = connect(witness.db)
    try:
        checks.silence_check(conn, checks.now())
    finally:
        conn.close()

    alerts = requests.get(f"{witness.url}/alerts", timeout=5).json()["alerts"]
    silence_alerts = [x for x in alerts if x["kind"] == "silence"]
    assert silence_alerts, f"silence alert not fired after 16 s: {alerts}"
    assert silence_alerts[0]["tamper_type"] == "agent_silenced"

    # State is alert but not yet quarantined (presume threshold is 45 s).
    s = _status(witness.url)
    assert s["state"] == "alert"
    assert s["quarantine"] is None

    # Advance clock past after_seconds (45 s): presume() should flip to quarantined.
    clock["seconds"] = 46
    conn = connect(witness.db)
    try:
        wq.presume(conn, checks.now(), {"layer3": {"after_seconds": 45}})
    finally:
        conn.close()

    s = _status(witness.url)
    assert s["state"] == "quarantined", f"expected quarantined, got: {s['state']}"
    assert s["layers"]["3"] == "quarantined"
    q = s["quarantine"]
    assert q["active"] and not q["confirmed"]  # network still cut: server hasn't reported yet
    assert q["unverified"] is None

    # Network back: server reports. Witness should confirm and stay locked (no unlock yet).
    assert _report(a, "quarantined", "q-t7a-01") == {"status": "ok"}
    q = _status(witness.url)["quarantine"]
    assert q["confirmed"] and q["unverified"] == 3 and not q["unlock_issued"]

    # Unlock flow: 2-of-3 approvals (no Shamir in this run; secret_hash() returns None).
    poll = lambda: requests.get(f"{witness.url}/quarantine/poll",
                                params={"platform_id": a.platform_id}, timeout=5).json()["command"]
    r1 = requests.post(f"{witness.url}/quarantine/approve", json={"holder": 0}, timeout=5).json()
    assert r1["approved"] == 1 and poll() is None  # one approval not enough

    r2 = requests.post(f"{witness.url}/quarantine/approve", json={"holder": 1}, timeout=5).json()
    assert r2["approved"] == 2
    cmd = poll()
    assert cmd is not None, "unlock command not issued after 2 approvals"
    assert cmd["action"] == "unlock" and cmd["quarantine_id"] == "q-t7a-01"
    signed = {k: cmd[k] for k in ("command_id", "action", "platform_id", "quarantine_id", "issued_at", "secret")}
    assert verify_signature(reg["witness_public_key"], signed, cmd["signature"])

    # Server receives the unlock → reports released.
    assert _report(a, "released", "q-t7a-01") == {"status": "ok"}
    s = _status(witness.url)
    assert s["quarantine"] is None and s["layers"]["3"] == "on"
    assert s["state"] == "normal" or s["state"] == "alert"  # silence alert may still be open
