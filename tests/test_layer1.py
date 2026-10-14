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


def test_only_log_paths_trip_file_commands(tmp_path):
    from layers.l1_tripwire import trip

    log_dir = tmp_path / "log"
    log_dir.mkdir()
    (log_dir / "app.log").write_text("x")
    assert trip.log_targets(["-f", str(log_dir / "app.log"), str(tmp_path / "other.txt")], str(log_dir)) == [
        str(log_dir / "app.log")]
    assert trip.log_targets([str(tmp_path / "other.txt")], str(log_dir)) == []
    assert trip.under(str(log_dir / ".." / "log" / "app.log"), str(log_dir))  # ../ tricks resolve first


def test_deception_rm_reports_success_and_changes_nothing(tmp_path, monkeypatch):
    from layers.l1_tripwire import trip

    log = tmp_path / "log" / "app.log"
    log.parent.mkdir()
    log.write_text("txn-1\n")
    monkeypatch.setenv("COC_LOG_DIR", str(log.parent))
    monkeypatch.setenv("COC_L1_MODE", "deception")
    monkeypatch.setenv("COC_SPOOL", str(tmp_path / "spool"))
    assert trip.run("rm", [str(log)]) == 0
    assert log.read_text() == "txn-1\n"
    assert len(layer_events.pending()) == 1
    monkeypatch.setenv("COC_L1_MODE", "block")
    assert trip.run("truncate", ["-s", "0", str(log)]) == 1
    assert log.read_text() == "txn-1\n"


def test_revert_key_stored_only_as_hash(tmp_path, monkeypatch):
    from layers.l1_tripwire import coc

    monkeypatch.setenv("COC_ETC", str(tmp_path))
    coc.set_key("correct horse")
    assert "correct horse" not in coc.hash_file().read_text()
    assert coc.check_key("correct horse") and not coc.check_key("wrong")
