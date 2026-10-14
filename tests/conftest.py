import socket
import threading
import time
from dataclasses import dataclass

import pytest
import uvicorn

from witness import checks
from witness.app import create_app


@dataclass
class WitnessServer:
    url: str
    db: str


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def witness(tmp_path):
    db = str(tmp_path / "witness.db")
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(create_app(db), host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    assert server.started, "witness did not start"
    yield WitnessServer(f"http://127.0.0.1:{port}", db)
    server.should_exit = True
    thread.join(5)


@pytest.fixture
def clock(monkeypatch):
    # Moves the witness clock forward so silence and challenge timeouts fire without waiting.
    offset = {"seconds": 0.0}
    monkeypatch.setattr(checks, "now", lambda: time.time() + offset["seconds"])
    return offset
