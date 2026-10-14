import os
import socket
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import pytest
import requests

REPO = Path(__file__).resolve().parents[1]
COUNT = int(os.environ.get("T0_COUNT", "10000"))


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.mark.slow
def test_t0_clean_run_has_zero_alerts(tmp_path):
    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    env = dict(os.environ, PYTHONPATH=str(REPO), WITNESS_URL=url, CHALLENGE_CHANCE="1.0",
               WITNESS_DB_PATH=str(tmp_path / "w.db"), BANK_DB_PATH=str(tmp_path / "bank.db"),
               AGENT_DB_PATH=str(tmp_path / "agent.db"), COC_SPOOL=str(tmp_path / "spool"),
               COC_EVIDENCE_DIR=str(tmp_path / "vault"))
    log = open(tmp_path / "procs.log", "w")  # noqa: SIM115 (held open across child processes)
    procs = []

    def start(*args):
        p = subprocess.Popen([sys.executable, *args], cwd=REPO, env=env, stdout=log, stderr=log)
        procs.append(p)
        return p

    try:
        start("-m", "uvicorn", "--factory", "witness.app:create_app", "--port", str(port), "--log-level", "warning")
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                requests.get(f"{url}/status", timeout=1)
                break
            except requests.RequestException:
                time.sleep(0.2)
        assert start("victim/bank.py", "--fast", "--count", str(COUNT)).wait(120) == 0
        start("agent/agent.py")
        deadline = time.time() + max(120, COUNT / 20)
        accepted = 0
        while time.time() < deadline:
            accepted = requests.get(f"{url}/status", timeout=5).json()["last_entry_seq"]
            if accepted >= COUNT:
                break
            time.sleep(2)
        assert accepted == COUNT, f"only {accepted}/{COUNT} entries reached the witness"
        time.sleep(7)  # one more self-check, heartbeat and challenge round
        status = requests.get(f"{url}/status", timeout=5).json()
        alerts = requests.get(f"{url}/alerts", timeout=5).json()["alerts"]
        assert alerts == [], f"false alarms: {alerts[:5]}"
        assert status["checks"] == {"A": "green", "B": "green", "C": "green"}
        assert status["state"] == "normal"
        bank = sqlite3.connect(tmp_path / "bank.db")
        assert bank.execute("SELECT COUNT(*) FROM transactions").fetchone()[0] == COUNT
        bank.close()
    finally:
        for p in procs:
            p.terminate()
        log.close()
