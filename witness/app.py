"""Witness HTTP API. Logic lives in witness/checks.py."""

import os
import threading
from contextlib import asynccontextmanager
from pathlib import Path

import yaml
from fastapi import Body, Depends, FastAPI, HTTPException

from witness import checks
from witness.store import connect, get_state, init_db, set_state

DEFAULT_LAYERS = Path(__file__).resolve().parents[1] / "config" / "layers.yaml"


def load_config(path):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def _check_loop(db_path, config, stop):
    tick = 0
    while not stop.is_set():
        conn = connect(db_path)
        try:
            if config["checks"]["A"] and tick % 5 == 0:
                checks.self_check(conn, checks.now())
            if config["checks"]["B"]:
                checks.silence_check(conn, checks.now())
                checks.challenge_check(conn, checks.now())
        finally:
            conn.close()
        tick += 1
        stop.wait(1)


def create_app(db_path=None, layers_path=DEFAULT_LAYERS):
    db_path = db_path or os.environ.get("WITNESS_DB_PATH", "witness.db")
    init_db(db_path)
    config = load_config(layers_path)
    stop = threading.Event()

    @asynccontextmanager
    async def lifespan(_app):
        thread = threading.Thread(target=_check_loop, args=(db_path, config, stop), daemon=True)
        thread.start()
        yield
        stop.set()

    app = FastAPI(lifespan=lifespan)

    def get_conn():
        conn = connect(db_path)
        try:
            yield conn
        finally:
            conn.close()

    @app.post("/register/agent")
    def register_agent(body: dict = Body(...), conn=Depends(get_conn)):
        platform_id = body.get("platform_id")
        public_key = body.get("public_key")
        if not platform_id or not public_key:
            raise HTTPException(400, "platform_id and public_key are required")
        with conn:
            row = conn.execute(
                "SELECT key_id, public_key FROM agents WHERE platform_id = ?", (platform_id,)
            ).fetchone()
            if row:
                if row["public_key"] != public_key:
                    raise HTTPException(409, "platform already registered with another key")
                key_id = row["key_id"]
            else:
                count = conn.execute("SELECT COUNT(*) FROM agents").fetchone()[0]
                key_id = f"agent-key-{count}"
                conn.execute("INSERT INTO agents (key_id, platform_id, public_key) VALUES (?, ?, ?)",
                             (key_id, platform_id, public_key))
        if get_state(conn, "last_heartbeat") is None:
            set_state(conn, "last_heartbeat", {"ts": None, "recv": checks.now()})
        return {"status": "registered", "platform_id": platform_id, "key_id": key_id, "witness_public_key": None}

    @app.post("/entries")
    def post_entry(entry: dict = Body(...), conn=Depends(get_conn)):
        return checks.submit_entry(conn, entry, checks.now(), config["checks"]["C"])

    @app.post("/heartbeat")
    def post_heartbeat(body: dict = Body(...), conn=Depends(get_conn)):
        return checks.record_heartbeat(conn, body, checks.now())

    @app.get("/challenge/poll")
    def poll_challenge(platform_id: str, conn=Depends(get_conn)):
        if not config["checks"]["B"]:
            return {"challenge": None}
        return {"challenge": checks.poll_challenge(conn, platform_id, checks.now(), config["checks"]["C"])}

    @app.post("/challenge/response")
    def post_challenge_response(body: dict = Body(...), conn=Depends(get_conn)):
        return checks.answer_challenge(conn, body, checks.now())

    @app.get("/status")
    def get_status(conn=Depends(get_conn)):
        return checks.status(conn, config["layers"])

    @app.get("/alerts")
    def get_alerts(conn=Depends(get_conn)):
        return {"alerts": checks.list_alerts(conn)}

    @app.get("/verify")
    def get_verify(from_seq: int = 0, to_seq: int = 10**9, conn=Depends(get_conn)):
        return checks.verify_range(conn, from_seq, to_seq)

    return app
