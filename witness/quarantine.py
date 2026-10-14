"""Witness side of Layer 3. The witness never locks anything (the network is cut); it reports, collects
key-holder approvals, and issues one signed unlock for the server's quarantine id."""

import os
import secrets
from datetime import UTC, datetime

from shared import sign_payload, verify_signature
from witness.store import add_alert, get_state, log_activity, set_state

REPORT_FIELDS = ("platform_id", "quarantine_id", "state", "started_at", "unverified", "evidence_hash")
COMMAND_FIELDS = ("command_id", "action", "platform_id", "quarantine_id", "issued_at")


def _cfg(config):
    c = config.get("layer3") or {}
    after = os.environ.get("COC_QUARANTINE_AFTER") or c.get("after_seconds", 45)
    return {"after": float(after), "needed": int(c.get("approvals_needed", 2)),
            "holders": list(c.get("key_holders") or ["SOC lead", "Auditor", "Compliance officer"])}


def _fresh(cfg, since, platform_id):
    return {"active": True, "since": since, "confirmed": False, "id": None, "platform_id": platform_id,
            "unverified": None, "after": cfg["after"], "needed": cfg["needed"], "can_approve": True,
            "holders": [{"name": n, "approved": False} for n in cfg["holders"]], "command": None}


def presume(conn, now_ts, config):
    """No heartbeat for after_seconds: the server's policy says it has quarantined itself."""
    cfg = _cfg(config)
    q = get_state(conn, "quarantine")
    hb = get_state(conn, "last_heartbeat") or {}
    if (q and q.get("active")) or not hb.get("ts") or now_ts - hb["recv"] < cfg["after"]:
        return
    agent = conn.execute("SELECT platform_id FROM agents ORDER BY rowid LIMIT 1").fetchone()
    set_state(conn, "quarantine", _fresh(cfg, hb["recv"], agent["platform_id"] if agent else None))
    add_alert(conn, "quarantine", f"presumed:{hb['recv']}", None,
              f"no contact for {cfg['after']:.0f} s: server policy is to quarantine itself", now_ts)
    log_activity(conn, "quarantine", "no contact: server presumed quarantined", now_ts)


def _issue_if_ready(conn, q, witness_key, now_ts):
    if q["command"] or not q["id"] or sum(h["approved"] for h in q["holders"]) < q["needed"]:
        return
    cmd = {"command_id": "u-" + secrets.token_hex(4), "action": "unlock", "platform_id": q["platform_id"],
           "quarantine_id": q["id"], "issued_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")}
    cmd["signature"] = sign_payload(witness_key, cmd)
    q["command"] = cmd
    log_activity(conn, "quarantine", f"unlock {q['id']} signed after {q['needed']} approvals", now_ts)


def report(conn, body, now_ts, config, witness_key):
    row = conn.execute("SELECT public_key FROM agents WHERE platform_id = ?", (body.get("platform_id"),)).fetchone()
    payload = {k: body.get(k) for k in REPORT_FIELDS}
    if row is None or not verify_signature(row["public_key"], payload, body.get("signature", "")):
        add_alert(conn, "forged_quarantine_report", str(body.get("quarantine_id")), "forged",
                  "quarantine report signature invalid", now_ts)
        return {"status": "rejected"}
    cfg = _cfg(config)
    q = get_state(conn, "quarantine")
    if body["state"] == "quarantined":
        if not q or not q.get("active"):
            q = _fresh(cfg, body.get("started_at") or now_ts, body["platform_id"])
        q.update(confirmed=True, id=body["quarantine_id"], platform_id=body["platform_id"],
                 unverified=body.get("unverified"), evidence_hash=body.get("evidence_hash"),
                 since=min(q["since"], body.get("started_at") or q["since"]))
        add_alert(conn, "quarantine", body["quarantine_id"], None,
                  f"server reports QUARANTINED: users locked out, {body.get('unverified')} records sealed during the cut",
                  now_ts)
        log_activity(conn, "quarantine", f"server confirms {body['quarantine_id']}, {body.get('unverified')} unverified", now_ts)
        _issue_if_ready(conn, q, witness_key, now_ts)
        set_state(conn, "quarantine", q)
        return {"status": "ok"}
    if body["state"] == "released" and q and q.get("id") == body["quarantine_id"]:
        set_state(conn, "last_quarantine", dict(q, active=False, released_at=now_ts))
        set_state(conn, "quarantine", None)
        with conn:
            conn.execute("UPDATE alerts SET resolved = 1 WHERE kind = 'quarantine'")
        log_activity(conn, "quarantine", f"server released {body['quarantine_id']}: connected", now_ts)
        return {"status": "ok"}
    return {"status": "ignored"}


def approve(conn, holder, now_ts, witness_key):
    q = get_state(conn, "quarantine")
    if not q or not q.get("active") or not isinstance(holder, int) or not 0 <= holder < len(q["holders"]):
        return {"status": "rejected"}
    q["holders"][holder]["approved"] = True
    log_activity(conn, "quarantine", f"{q['holders'][holder]['name']} approved unlock", now_ts)
    _issue_if_ready(conn, q, witness_key, now_ts)
    set_state(conn, "quarantine", q)
    return {"status": "ok", "approved": sum(h["approved"] for h in q["holders"]), "needed": q["needed"]}


def poll(conn, platform_id):
    q = get_state(conn, "quarantine")
    if q and q.get("active") and q.get("command") and q["platform_id"] == platform_id:
        return q["command"]
    return None


def public_view(conn):
    q = get_state(conn, "quarantine")
    if not q:
        return None
    return {k: v for k, v in q.items() if k != "command"} | {"unlock_issued": bool(q.get("command"))}
