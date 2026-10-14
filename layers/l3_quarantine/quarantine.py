"""Layer 3 quarantine: the log server locks itself down when it loses the witness.

Trigger: no successful contact with the witness for layer3.after_seconds (default 45). We assume the attacker
cut the network to work unseen. Order is fixed, and nothing here ever reboots:
    1 capture  -> 2 seal locally -> 3 site down -> 4 lock out every interactive user (incl. root) -> 5 QUARANTINED
Unlock: only a witness-signed command (issued after 2 of 3 key holders approve) for this quarantine id.
All commands come from config/layers.yaml (layer3). dry_run records them instead of running them.
"""

import hashlib
import json
import os
import secrets
import shlex
import subprocess
import time
from pathlib import Path

from layers.common import events

DEFAULTS = {
    "after_seconds": 45, "dry_run": True, "evidence_dir": "/var/lib/coc/quarantine", "users": "auto",
    "capture": [], "site_down": [], "site_up": [], "lockout": [], "unlock": [],
}
NEVER = ("reboot", "shutdown", "poweroff", "halt", "init 0", "init 6", "systemctl kexec")


def settings():
    cfg = dict(DEFAULTS)
    try:
        import yaml
        with open(events.LAYERS_CONFIG, encoding="utf-8") as f:
            cfg.update((yaml.safe_load(f) or {}).get("layer3") or {})
    except Exception:  # noqa: BLE001, S110 - no config: safe defaults (dry run, no commands)
        pass
    if os.environ.get("COC_QUARANTINE_AFTER"):
        cfg["after_seconds"] = float(os.environ["COC_QUARANTINE_AFTER"])
    if os.environ.get("COC_L3_DRY_RUN"):
        cfg["dry_run"] = os.environ["COC_L3_DRY_RUN"] not in ("0", "false", "no")
    if os.environ.get("COC_EVIDENCE_DIR"):
        cfg["evidence_dir"] = os.environ["COC_EVIDENCE_DIR"]
    return cfg


def interactive_users(passwd="/etc/passwd"):
    """root plus every account with a login shell. Service accounts (nologin/false) are left alone."""
    users = []
    try:
        for line in Path(passwd).read_text().splitlines():
            parts = line.split(":")
            if len(parts) < 7:
                continue
            name, uid, shell = parts[0], int(parts[2]), parts[6]
            if name == "root" or (uid >= 1000 and not shell.endswith(("nologin", "false")) and name != "nobody"):
                users.append(name)
    except OSError:
        import getpass
        users = ["root", getpass.getuser()]  # no /etc/passwd (dry run on a dev machine)
    return users


def _expand(templates, users):
    out = []
    for t in templates:
        if any(n in t for n in NEVER):
            raise ValueError(f"refusing a reboot-style command in layer3 config: {t!r}")
        out.extend(t.format(user=u) for u in users) if "{user}" in t else out.append(t)
    return out


def _run(cmds, dry_run):
    results = []
    for cmd in cmds:
        if dry_run:
            results.append({"cmd": cmd, "ran": False, "rc": None})
            continue
        try:
            p = subprocess.run(shlex.split(cmd), capture_output=True, text=True, timeout=20, check=False)
            results.append({"cmd": cmd, "ran": True, "rc": p.returncode, "out": (p.stdout + p.stderr)[-2000:]})
        except (OSError, subprocess.TimeoutExpired) as exc:
            results.append({"cmd": cmd, "ran": False, "rc": None, "error": str(exc)})
    return results


def _hash_files(roots):
    out = {}
    for root in roots:
        for p in sorted(Path(root).rglob("*")) if Path(root).is_dir() else []:
            if p.is_file():
                try:
                    out[str(p)] = hashlib.sha256(p.read_bytes()).hexdigest()
                except OSError:
                    out[str(p)] = None
    return out


def _step(name, detail, quarantine_id, state="alert"):
    events.emit(events.make_event(3, f"quarantine:{name}", dict(detail, quarantine_id=quarantine_id), state=state,
                                  process="coc-quarantine"))


def quarantine(reason, protected_paths=(), passwd="/etc/passwd"):
    """Run the fixed quarantine sequence. Returns the record to keep until unlock."""
    cfg = settings()
    qid = "q-" + secrets.token_hex(4)
    started = int(time.time())  # integer: signed payloads refuse floats
    users = interactive_users(passwd) if cfg["users"] == "auto" else list(cfg["users"])
    dry = bool(cfg["dry_run"])
    # 1 capture
    captured = _run(_expand(cfg["capture"], users), dry)
    evidence = {"quarantine_id": qid, "reason": reason, "started_at": started, "users": users, "dry_run": dry,
                "capture": captured, "log_hashes": _hash_files(protected_paths)}
    # 2 seal locally (append-only where the filesystem allows it)
    vault = Path(cfg["evidence_dir"]) / qid
    vault.mkdir(parents=True, exist_ok=True)
    body = json.dumps(evidence, sort_keys=True)
    (vault / "evidence.json").write_text(body)
    evidence_hash = hashlib.sha256(body.encode()).hexdigest()
    (vault / "evidence.sha256").write_text(evidence_hash)
    sealed = _run([f"chattr +a {vault}"], dry)
    _step("captured", {"reason": reason, "evidence_hash": evidence_hash, "users": users, "dry_run": dry,
                       "sealed": sealed}, qid)
    # 3 site down for customers
    site = _run(_expand(cfg["site_down"], users), dry)
    # 4 lock out every interactive user, root included, and end their sessions
    locked = _run(_expand(cfg["lockout"], users), dry)
    _step("locked", {"site_down": site, "lockout": locked, "dry_run": dry}, qid)
    # 5 report
    record = {"id": qid, "reason": reason, "started_at": started, "evidence_hash": evidence_hash,
              "users": users, "dry_run": dry, "actions": [r["cmd"] for r in site + locked]}
    _step("quarantined", {"actions": record["actions"], "dry_run": dry}, qid)
    return record


def release(record):
    """Reverse steps 4 and 3 after a verified unlock. Returns the commands run (or recorded)."""
    cfg = settings()
    users = record.get("users") or []
    done = _run(_expand(cfg["unlock"], users) + _expand(cfg["site_up"], users), bool(cfg["dry_run"]))
    _step("released", {"actions": [r["cmd"] for r in done], "dry_run": bool(cfg["dry_run"])}, record["id"], state="normal")
    return done
