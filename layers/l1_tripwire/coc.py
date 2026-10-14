"""The team's own command set: coc-view, coc-status, coc-verify, coc-unlock, coc-setkey. Stdlib only.

Legitimate read-only work uses these and fires no event. coc-unlock checks the revert key against a
stored scrypt hash (never the key itself) and opens one shell with the original commands, logged.
"""

import base64
import getpass
import hashlib
import hmac
import json
import os
import secrets
import sys
import urllib.request
from pathlib import Path

from layers.common import events

WITNESS_URL = os.environ.get("WITNESS_URL", "http://127.0.0.1:8000")


def hash_file():
    return Path(os.environ.get("COC_ETC", "/etc/coc")) / "revert.hash"


def _scrypt(key, salt):
    return hashlib.scrypt(key.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)


def set_key(key):
    salt = secrets.token_bytes(16)
    path = hash_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(_scrypt(key, salt)).decode())
    os.chmod(path, 0o600)


def check_key(key):
    try:
        _, salt, digest = hash_file().read_text().strip().split("$")
    except (OSError, ValueError):
        return False
    return hmac.compare_digest(_scrypt(key, base64.b64decode(salt)), base64.b64decode(digest))


def _get(route):
    with urllib.request.urlopen(f"{WITNESS_URL}{route}", timeout=5) as r:
        return json.loads(r.read())


def view(args):
    for name in args:
        sys.stdout.write(Path(name).read_text(errors="replace"))
    return 0


def status(_args):
    s = _get("/status")
    print("  ".join(f"Check {c}: {v}" for c, v in s["checks"].items()),
          " ".join(f"L{n}:{v}" for n, v in s["layers"].items()), f"state={s['state']}")
    return 0


def verify(_args):
    print(json.dumps(_get("/verify"), indent=2))
    return 0


def unlock(_args):
    key = os.environ.pop("COC_REVERT_KEY", None) or getpass.getpass("revert key: ")
    ok = check_key(key)
    del key
    events.emit(events.make_event(1, "coc-unlock:" + ("ok" if ok else "failed"),
                                  {"cmd": "coc-unlock", "session_only": True},
                                  state="normal" if ok else "alert", process="coc-unlock"))
    if not ok:
        print("coc-unlock: wrong key (logged)", file=sys.stderr)
        return 1
    trip_dir = os.environ.get("COC_TRIP_BIN", "")
    env = dict(os.environ)
    env["PATH"] = os.pathsep.join(p for p in env.get("PATH", "").split(os.pathsep) if p and p != trip_dir)
    env.pop("COC_TRIP_BIN", None)
    env["PS1"] = "[coc-unlocked] \\u@\\h:\\w\\$ "
    if os.environ.get("COC_UNLOCK_NO_SHELL"):  # tests: report the session PATH instead of opening a shell
        print(env["PATH"])
        return 0
    shell = os.environ.get("SHELL", "/bin/bash")
    print("Original commands restored for this shell only. Type 'exit' to lock again.")
    os.execvpe(shell, [shell, "--norc", "-i"], env)
    return 0


def setkey(_args):
    key = os.environ.pop("COC_REVERT_KEY", None) or getpass.getpass("new revert key: ")
    set_key(key)
    print(f"revert key hash stored in {hash_file()}")
    return 0


COMMANDS = {"coc-view": view, "coc-status": status, "coc-verify": verify, "coc-unlock": unlock, "coc-setkey": setkey}


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        print("usage: coc <" + "|".join(COMMANDS) + "> [args]", file=sys.stderr)
        return 2
    return COMMANDS[sys.argv[1]](sys.argv[2:])


if __name__ == "__main__":
    sys.exit(main())
