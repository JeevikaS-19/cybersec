import json
import subprocess
import sys
from pathlib import Path

import requests

from layers.common import events as layer_events
from shared import sign_payload
from tests.helpers import Agent

REPO = Path(__file__).resolve().parents[1]


def _signed(agent, **overrides):
    event = layer_events.make_event(1, "wrapper:nano", {"cmd": "nano /var/log/bank/app.log", "mode": "deception"})
    event.update(overrides)
    event["key_id"] = agent.key_id
    event["signature"] = sign_payload(agent.priv, {k: v for k, v in event.items() if k != "signature"})
    return event


def _post(url, event):
    return requests.post(f"{url}/events", json=event, timeout=5).json()


def _alerts(url):
    return requests.get(f"{url}/alerts", timeout=5).json()["alerts"]


def test_cli_emit_writes_one_spool_file(tmp_path):
    env = {"COC_SPOOL": str(tmp_path), "PYTHONPATH": str(REPO), "SYSTEMROOT": "C:\\Windows", "PATH": ""}
    out = subprocess.run([sys.executable, "-m", "layers.common.events", "emit", "--layer", "1",
                          "--trigger", "wrapper:rm", "--detail", '{"cmd": "rm app.log"}'],
                         cwd=REPO, env=env, capture_output=True, text=True, timeout=30, check=False)
    assert out.returncode == 0, out.stderr
    files = list(tmp_path.glob("ev-*.json"))
    assert len(files) == 1
    event = json.loads(files[0].read_text())
    assert event["trigger"] == "wrapper:rm" and event["detail"] == {"cmd": "rm app.log"}
    assert "signature" not in event and "key_id" not in event  # producers never sign


def test_switched_off_layer_emits_nothing(tmp_path, monkeypatch):
    cfg = tmp_path / "layers.yaml"
    cfg.write_text("layers:\n  1: false\n  2: true\n  3: true\n")
    monkeypatch.setattr(layer_events, "LAYERS_CONFIG", cfg)
    monkeypatch.setenv("COC_SPOOL", str(tmp_path / "spool"))
    assert layer_events.emit(layer_events.make_event(1, "wrapper:nano")) is None
    assert layer_events.pending() == []


def test_signed_event_trips_layer1(witness):
    a = Agent(witness.url)
    event = _signed(a)
    assert _post(witness.url, event) == {"status": "accepted"}
    status = requests.get(f"{witness.url}/status", timeout=5).json()
    assert status["layers"]["1"] == "tripped"
    assert status["state"] == "alert"
    assert status["checks"] == {"A": "green", "B": "green", "C": "green"}  # Layer 1 is not a Layer 2 check
    alerts = _alerts(witness.url)
    assert [(x["kind"], x["ref"], x["tamper_type"]) for x in alerts] == [("layer1_tripwire", event["event_id"], None)]
    assert "deception" in alerts[0]["detail"]
    timeline = requests.get(f"{witness.url}/timeline", timeout=5).json()["events"]
    assert [e["event_id"] for e in timeline] == [event["event_id"]]


def test_resent_event_alerts_once(witness):
    a = Agent(witness.url)
    event = _signed(a)
    _post(witness.url, event)
    assert _post(witness.url, event) == {"status": "accepted"}
    assert len(_alerts(witness.url)) == 1


def test_tampered_event_is_rejected_as_forged(witness):
    a = Agent(witness.url)
    event = _signed(a)
    event["trigger"] = "coc-view"  # attacker rewrites the event after signing
    assert _post(witness.url, event) == {"status": "rejected", "reason": "bad_signature"}
    assert [(x["kind"], x["tamper_type"]) for x in _alerts(witness.url)] == [("forged_event", "forged")]
    assert requests.get(f"{witness.url}/status", timeout=5).json()["layers"]["1"] == "on"


def test_unknown_key_is_rejected(witness):
    a = Agent(witness.url)
    event = _signed(a)
    event["key_id"] = "agent-key-99"
    event["signature"] = sign_payload(a.priv, {k: v for k, v in event.items() if k != "signature"})
    assert _post(witness.url, event)["reason"] == "unknown_key_id"


def test_agent_ships_spooled_events(witness, tmp_path, monkeypatch):
    from agent import agent as agent_mod

    monkeypatch.setenv("COC_SPOOL", str(tmp_path / "spool"))
    monkeypatch.setattr(agent_mod, "WITNESS_URL", witness.url)
    monkeypatch.setattr(agent_mod, "AGENT_DB_PATH", str(tmp_path / "agent.db"))
    conn = agent_mod.open_db()
    priv = agent_mod.load_or_create_key(conn)
    agent_mod.register(conn, priv)
    path = layer_events.emit(layer_events.make_event(1, "wrapper:vim", {"cmd": "vim app.log"}))
    agent_mod.ship_events(conn, priv)
    conn.close()
    assert not path.exists()
    assert [x["kind"] for x in _alerts(witness.url)] == ["layer1_tripwire"]


def test_only_protected_paths_trip_file_commands(tmp_path):
    from layers.l1_tripwire import trip

    log_dir = tmp_path / "log"
    log_dir.mkdir()
    (log_dir / "app.log").write_text("x")
    roots = [str(log_dir)]
    assert trip.protected_targets(["-f", str(log_dir / "app.log"), str(tmp_path / "other.txt")], roots) == [
        str(log_dir / "app.log")]
    assert trip.protected_targets([str(tmp_path / "other.txt")], roots) == []
    assert trip.under(str(log_dir / ".." / "log" / "app.log"), roots)  # ../ tricks resolve first


def test_guarded_commands_come_from_config(tmp_path, monkeypatch):
    from layers.l1_tripwire import trip

    cfg = tmp_path / "layers.yaml"
    cfg.write_text("layer1:\n  editors: [micro]\n  file_commands: [rm, rm]\n")
    monkeypatch.setattr(layer_events, "LAYERS_CONFIG", cfg)
    assert trip.guarded_commands() == ["micro", "rm"]


def _l1_env(tmp_path, monkeypatch, mode):
    log = tmp_path / "log" / "app.log"
    log.parent.mkdir()
    log.write_text("txn-1\n")
    monkeypatch.setenv("COC_PROTECTED", str(log.parent))
    monkeypatch.setenv("COC_L1_MODE", mode)
    monkeypatch.setenv("COC_SPOOL", str(tmp_path / "spool"))
    monkeypatch.setenv("COC_PROFILES", str(tmp_path / "profiles"))
    return log


def test_intruder_rm_is_deceived_and_block_mode_refuses(tmp_path, monkeypatch):
    from layers.l1_tripwire import trip

    log = _l1_env(tmp_path, monkeypatch, "deception")
    assert trip.run("rm", [str(log)]) == 0
    assert log.read_text() == "txn-1\n"
    monkeypatch.setenv("COC_L1_MODE", "block")
    assert trip.run("truncate", ["-s", "0", str(log)]) == 1
    assert log.read_text() == "txn-1\n"
    states = [json.loads(p.read_text())["state"] for p in layer_events.pending()]
    assert states == ["alert", "alert"]


def test_profile_id_authorizes_and_is_never_logged(tmp_path, monkeypatch):
    from layers.l1_tripwire import profiles, trip

    log = _l1_env(tmp_path, monkeypatch, "deception")
    profiles.add("demo-bank", "bank-7f3a9c2e")
    assert "bank-7f3a9c2e" not in (tmp_path / "profiles").read_text()
    assert profiles.match("bank-7f3a9c2e") == "demo-bank" and profiles.match("wrong-guess") is None
    monkeypatch.setattr(trip, "run_real", lambda name, args: 0)
    monkeypatch.setattr(trip, "exec_real", lambda name, args: 0)
    assert trip.run("rm", ["--bank-7f3a9c2e", str(log)]) == 0
    (event,) = [json.loads(p.read_text()) for p in layer_events.pending()]
    assert event["trigger"] == "authorized:rm" and event["state"] == "normal"
    assert event["detail"]["profile"] == "demo-bank"
    assert "bank-7f3a9c2e" not in json.dumps(event)


def test_editors_scope_protected_only_trips_inside_protected_paths(tmp_path, monkeypatch):
    from layers.l1_tripwire import trip

    log = _l1_env(tmp_path, monkeypatch, "deception")
    cfg = tmp_path / "layers.yaml"
    cfg.write_text("layer1:\n  editors: [nano]\n  file_commands: [rm]\n  editors_scope: protected\n")
    monkeypatch.setattr(layer_events, "LAYERS_CONFIG", cfg)
    monkeypatch.setattr(trip, "run_real", lambda name, args: 0)
    monkeypatch.setattr(trip, "deceive_editor", lambda name, args, target: 0)
    assert trip.run("nano", [str(tmp_path / "notes.txt")]) == 0
    assert layer_events.pending() == []  # everyday editing elsewhere: no alert
    trip.run("nano", [str(log)])
    assert [json.loads(p.read_text())["trigger"] for p in layer_events.pending()] == ["wrapper:nano"]
