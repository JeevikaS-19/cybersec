"""One event format for every layer. Producers drop events in a spool; the agent signs and ships them.

Producers (wrappers, auditd hook) never hold the agent's private key: they only write unsigned
events to the spool, and the agent adds key_id + signature before POST /events.

CLI (called by the Layer 1 wrappers):
    python -m layers.common.events emit --layer 1 --trigger wrapper:nano --detail '{"cmd": "..."}'
"""

import argparse
import json
import os
import secrets
import sys
from datetime import UTC, datetime
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
DEFAULT_SPOOL = "/var/spool/coc" if os.name == "posix" else str(REPO / "coc-spool")
LAYERS_CONFIG = Path(os.environ.get("COC_LAYERS_CONFIG", REPO / "config" / "layers.yaml"))


def spool_dir():
    return Path(os.environ.get("COC_SPOOL", DEFAULT_SPOOL))


def layer_enabled(layer):
    try:
        with open(LAYERS_CONFIG, encoding="utf-8") as f:
            return bool(yaml.safe_load(f)["layers"].get(layer, False))
    except (OSError, KeyError, TypeError):
        return True  # a missing or broken config must not silence the tripwire


def who(process=None):
    info = {"auid": None, "uid": None, "process": process, "exe": None, "src_ip": None}
    if hasattr(os, "getuid"):
        info["uid"] = os.getuid()
    try:
        auid = int(Path("/proc/self/loginuid").read_text().strip())
        info["auid"] = None if auid == 4294967295 else auid  # login uid survives sudo/su
    except (OSError, ValueError):
        pass
    ssh = os.environ.get("SSH_CONNECTION", "").split()
    if ssh:
        info["src_ip"] = ssh[0]
    return info


def make_event(layer, trigger, detail=None, tamper_type=None, state="alert", process=None, exe=None):
    w = who(process)
    w["exe"] = exe
    return {
        "event_id": "ev-" + secrets.token_hex(6),
        "layer": layer,
        "trigger": trigger,
        "tamper_type": tamper_type,
        "time": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "who": w,
        "detail": detail or {},
        "bundle_key": None,   # filled once the vault exists (Step 7)
        "bundle_hash": None,
        "state": state,
    }


def emit(event):
    """Write the event to the spool atomically. Returns its path, or None if the layer is switched off."""
    if not layer_enabled(event["layer"]):
        return None
    spool = spool_dir()
    spool.mkdir(parents=True, exist_ok=True)
    final = spool / f"{event['event_id']}.json"
    tmp = spool / f".{event['event_id']}.tmp"
    tmp.write_text(json.dumps(event), encoding="utf-8")
    os.replace(tmp, final)
    return final


def pending(limit=50):
    spool = spool_dir()
    if not spool.is_dir():
        return []
    return sorted(spool.glob("ev-*.json"), key=lambda p: p.stat().st_mtime)[:limit]


def main(argv=None):
    parser = argparse.ArgumentParser(prog="layers.common.events")
    sub = parser.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("emit")
    e.add_argument("--layer", type=int, required=True, choices=(1, 2, 3))
    e.add_argument("--trigger", required=True)
    e.add_argument("--detail", default="{}")
    e.add_argument("--process")
    e.add_argument("--exe")
    args = parser.parse_args(argv)
    try:
        detail = json.loads(args.detail)
    except json.JSONDecodeError:
        detail = {"raw": args.detail}
    path = emit(make_event(args.layer, args.trigger, detail, process=args.process, exe=args.exe))
    print(path.stem if path else "layer disabled")
    return 0


if __name__ == "__main__":
    sys.exit(main())
