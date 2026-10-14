"""Witness HTTP API. Logic lives in witness/checks.py."""

import os
import threading
from contextlib import asynccontextmanager
from pathlib import Path

import yaml
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import Body, Depends, FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from shared import export_public_key
from witness import checks, events, quarantine, records
from witness.store import connect, get_state, init_db, set_state

DEFAULT_LAYERS = Path(__file__).resolve().parents[1] / "config" / "layers.yaml"
AUDITOR_HTML = Path(__file__).resolve().parent / "auditor.html"


def load_config(path):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_or_create_key(path):
    # Witness signing key (Layer 3 commands). Raw 32 bytes on disk, never printed or sent.
    if os.path.exists(path):
        with open(path, "rb") as f:
            return ed25519.Ed25519PrivateKey.from_private_bytes(f.read())
    priv = ed25519.Ed25519PrivateKey.generate()
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(priv.private_bytes_raw())
    return priv


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
                if config["layers"].get(3):
                    quarantine.presume(conn, checks.now(), config)
        finally:
            conn.close()
        tick += 1
        stop.wait(1)


def create_app(db_path=None, layers_path=DEFAULT_LAYERS):
    db_path = db_path or os.environ.get("WITNESS_DB_PATH", "witness.db")
    init_db(db_path)
    config = load_config(layers_path)
    key_path = os.environ.get("WITNESS_KEY_PATH") or os.path.splitext(db_path)[0] + ".key"
    witness_key = load_or_create_key(key_path)  # signs Layer 3 unlock commands; never printed or sent
    witness_public_key = export_public_key(witness_key)
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
        return {"status": "registered", "platform_id": platform_id, "key_id": key_id, "witness_public_key": witness_public_key}

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

    @app.post("/events")
    def post_event(event: dict = Body(...), conn=Depends(get_conn)):
        return events.submit_event(conn, event, checks.now())

    @app.get("/timeline")
    def get_timeline(since: float = 0, conn=Depends(get_conn)):
        return {"events": events.timeline(conn, since)}

    @app.post("/quarantine/report")
    def post_quarantine_report(body: dict = Body(...), conn=Depends(get_conn)):
        return quarantine.report(conn, body, checks.now(), config, witness_key)

    @app.post("/quarantine/approve")
    def post_quarantine_approve(body: dict = Body(...), conn=Depends(get_conn)):
        return quarantine.approve(conn, body.get("holder"), checks.now(), witness_key)

    @app.get("/quarantine/poll")
    def get_quarantine_poll(platform_id: str, conn=Depends(get_conn)):
        return {"command": quarantine.poll(conn, platform_id)}

    @app.get("/mismatches")
    def get_mismatches(conn=Depends(get_conn)):
        return {"mismatches": records.list_mismatches(conn)}

    @app.get("/activity")
    def get_activity(since_id: int = 0, limit: int = 200, conn=Depends(get_conn)):
        rows = conn.execute("SELECT id, time, kind, detail FROM activity WHERE id > ? ORDER BY id DESC LIMIT ?",
                            (since_id, min(limit, 500))).fetchall()
        return {"activity": [dict(r) for r in reversed(rows)]}

    @app.get("/", response_class=HTMLResponse)
    def auditor_view():
        return AUDITOR_HTML.read_text(encoding="utf-8")

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
