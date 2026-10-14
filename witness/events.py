"""Witness side of POST /events: verify the agent's signature, store, alert. Never UPDATE or DELETE."""

import json

from shared import verify_signature
from witness.store import add_alert

EVENT_FIELDS = ("event_id", "layer", "trigger", "tamper_type", "time", "who", "detail",
                "bundle_key", "bundle_hash", "state", "key_id")


def _public_key(conn, key_id):
    row = conn.execute("SELECT public_key FROM agents WHERE key_id = ?", (key_id,)).fetchone()
    return row["public_key"] if row else None


def submit_event(conn, event, now_ts):
    missing = [f for f in EVENT_FIELDS if f not in event]
    if missing or event.get("layer") not in (1, 2, 3) or not isinstance(event.get("event_id"), str):
        return {"status": "rejected", "reason": "malformed_event"}
    pub = _public_key(conn, event["key_id"])
    payload = {k: v for k, v in event.items() if k != "signature"}
    if pub is None or not verify_signature(pub, payload, event.get("signature", "")):
        reason = "unknown_key_id" if pub is None else "bad_signature"
        add_alert(conn, "forged_event", event["event_id"], "forged", f"layer event rejected: {reason}", now_ts)
        return {"status": "rejected", "reason": reason}
    with conn:
        cur = conn.execute(
            "INSERT OR IGNORE INTO events (event_id, layer, trigger, time, body, received) VALUES (?, ?, ?, ?, ?, ?)",
            (event["event_id"], event["layer"], event["trigger"], event["time"], json.dumps(event), now_ts),
        )
    if cur.rowcount == 0:
        return {"status": "accepted"}  # resend of an event we already hold
    if event["layer"] == 1 and event.get("state") == "alert":
        d = event.get("detail") or {}
        what = d.get("cmd") or event["trigger"]
        mode = f" ({d['mode']})" if d.get("mode") else ""
        add_alert(conn, "layer1_tripwire", event["event_id"], event.get("tamper_type"),
                  f"{event['trigger']}{mode}: {what}", now_ts)
    return {"status": "accepted"}


def timeline(conn, since=0):
    rows = conn.execute("SELECT body FROM events WHERE received > ? ORDER BY received", (since,))
    return [json.loads(r["body"]) for r in rows]
