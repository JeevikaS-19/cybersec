"""Layer 1 backstop: catches changes to protected paths that bypass the wrappers (full path, another tool,
temp file + rename) and names who did it. Runs as root.

auditd is the first choice, but the audit subsystem isn't available inside containers, so this uses
inotify (`inotifywait`) plus /proc for attribution: user, login uid, terminal, program, source IP.

Authorized edits (`nano --<profile-id> ...`) are not alerts. The wrapper leaves a marker encrypted to the
backstop's public key (X25519 + AES-GCM): it proves the profile-id without storing it in plain text, only
root can read it, and nobody without the profile-id can forge one.

    python -m layers.l1_tripwire.backstop init     # root: create the backstop key pair (once)
    python -m layers.l1_tripwire.backstop run      # root: watch the protected paths
"""

import base64
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path

from layers.common import events

KEY_DIR = Path(os.environ.get("COC_BACKSTOP_DIR", "/etc/coc"))
ALLOW_DIR = Path(os.environ.get("COC_ALLOW_DIR", "/run/coc/allow"))
INFO = b"coc-backstop-marker-v1"
DEBOUNCE = 3.0


def settings():
    from layers.l1_tripwire.trip import settings as l1
    cfg = l1()
    b = cfg.get("backstop") or {}
    return {"watch": b.get("watch") or cfg["protected_paths"], "allowed_writers": b.get("allowed_writers") or [],
            "enabled": b.get("enabled", True)}


# ---------- authorization markers (written by the wrapper as the user, read by the backstop as root) ----------

def _aead_key(shared):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=INFO).derive(shared)


def write_marker(profile_id, targets, pid=None):
    """Called by the wrapper on an authorized command, just before it becomes the real command (same pid)."""
    pub_path = KEY_DIR / "backstop.pub"
    if not pub_path.exists():
        return None
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    eph = X25519PrivateKey.generate()
    shared = eph.exchange(X25519PublicKey.from_public_bytes(base64.b64decode(pub_path.read_text())))
    body = json.dumps({"profile_id": profile_id, "targets": [str(Path(t).resolve()) for t in targets],
                       "pid": pid or os.getpid(), "uid": os.getuid() if hasattr(os, "getuid") else None,
                       "time": time.time()}).encode()
    nonce = secrets.token_bytes(12)
    blob = eph.public_key().public_bytes_raw() + nonce + AESGCM(_aead_key(shared)).encrypt(nonce, body, None)
    ALLOW_DIR.mkdir(parents=True, exist_ok=True)
    path = ALLOW_DIR / f"{secrets.token_hex(8)}.bin"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(blob)
    return path


def _read_marker(path, priv):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    blob = path.read_bytes()
    shared = priv.exchange(X25519PublicKey.from_public_bytes(blob[:32]))
    return json.loads(AESGCM(_aead_key(shared)).decrypt(blob[32:44], blob[44:], None))


def _alive(pid):
    return Path(f"/proc/{pid}").exists()


class Markers:
    """Valid authorizations: right profile-id, written by the same uid that owns the marker file, and its
    process still running (or ended less than 5 s ago, for quick commands like sed)."""

    def __init__(self, priv):
        self.priv, self.valid = priv, {}

    def refresh(self):
        from layers.l1_tripwire import profiles
        if not ALLOW_DIR.is_dir():
            return
        for p in ALLOW_DIR.glob("*.bin"):
            try:
                m = _read_marker(p, self.priv)
                owner = p.stat().st_uid
            except Exception:  # noqa: BLE001 - unreadable or forged marker: ignore it
                p.unlink(missing_ok=True)
                continue
            p.unlink(missing_ok=True)
            platform = profiles.match(m.pop("profile_id", ""))
            if platform and m.get("uid") == owner:
                self.valid[p.name] = dict(m, platform=platform, ended=None)
        now = time.time()
        for k, m in list(self.valid.items()):
            if m["ended"] is None and not _alive(m["pid"]):
                m["ended"] = now
            if m["ended"] is not None and now - m["ended"] > 5:
                del self.valid[k]

    def covers(self, path, uids):
        for m in self.valid.values():
            if (not uids or m["uid"] in uids) and any(path == t or path.startswith(str(Path(t).parent) + "/") for t in m["targets"]):
                return m
        return None


# ---------- attribution from /proc ----------

def _read(p, binary=False):
    try:
        return p.read_bytes() if binary else p.read_text()
    except OSError:
        return b"" if binary else ""


def suspects(path):
    """Processes that have the path (or its folder) open, sit in it, or name it on their command line."""
    folder = str(Path(path).parent)
    out = []
    for d in Path("/proc").iterdir():
        if not d.name.isdigit() or int(d.name) == os.getpid():
            continue
        cmd = _read(d / "cmdline", True).replace(b"\0", b" ").decode(errors="replace").strip()
        try:
            cwd = os.readlink(d / "cwd")
        except OSError:
            cwd = ""
        hit = path in cmd or cwd == folder
        if not hit:
            try:
                hit = any(os.readlink(fd) in (path, folder) for fd in (d / "fd").iterdir())
            except OSError:
                pass
        if hit and cmd:
            out.append(_who(d, cmd))
    return out


def _who(d, cmd):
    status = dict(line.split(":\t", 1) for line in _read(d / "status").splitlines() if ":\t" in line)
    uid = int(status.get("Uid", "0").split()[0])
    try:
        import pwd
        user = pwd.getpwuid(uid).pw_name
    except (ImportError, KeyError):
        user = str(uid)
    env = dict(e.split("=", 1) for e in _read(d / "environ", True).decode(errors="replace").split("\0") if "=" in e)
    auid = _read(d / "loginuid").strip()
    try:
        exe = os.readlink(d / "exe")
    except OSError:
        exe = None
    return {"pid": int(d.name), "uid": uid, "user": user, "auid": None if auid in ("", "4294967295") else int(auid),
            "exe": exe, "cmd": cmd[:300], "src_ip": (env.get("SSH_CONNECTION", "").split() or [None])[0],
            "tty": os.path.basename(_ttyname(d))}


def _ttyname(d):
    try:
        return os.readlink(d / "fd" / "0")
    except OSError:
        return ""


# ---------- the watcher ----------

def init_keys():
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    key = KEY_DIR / "backstop.key"
    if not key.exists():
        priv = X25519PrivateKey.generate()
        fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(priv.private_bytes_raw())
        (KEY_DIR / "backstop.pub").write_text(base64.b64encode(priv.public_key().public_bytes_raw()).decode())
        os.chmod(KEY_DIR / "backstop.pub", 0o644)
    ALLOW_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(ALLOW_DIR, 0o1733)  # anyone can drop a marker, nobody can list or read others'


def handle(path, ev, markers, cfg, recent):
    markers.refresh()
    found = suspects(path)
    writers = [s for s in found if not any(a in s["cmd"] for a in cfg["allowed_writers"])]
    if found and not writers:
        return None  # the platform's own logger / app
    auth = markers.covers(path, {s["uid"] for s in writers})
    who = writers[0] if writers else None
    key = (path, who["pid"] if who else None)
    if auth or time.time() - recent.get(key, 0) < DEBOUNCE:
        return None
    recent[key] = time.time()
    detail = {"cmd": who["cmd"] if who else f"(process already gone) {ev} {path}", "target": path, "event": ev,
              "mode": "backstop", "result": "changed the real file",
              "rule": f"{path} changed outside the tripwire (full path, another tool or temp-file rename)",
              "suspects": writers[:5]}
    e = events.make_event(1, "backstop:write", detail, process=who["cmd"].split()[0] if who else None,
                          exe=who["exe"] if who else None)
    if who:
        e["who"].update({k: who[k] for k in ("uid", "user", "auid", "src_ip")})
    events.emit(e)
    return e


def run():
    cfg = settings()
    if not cfg["enabled"]:
        return 0
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    priv = X25519PrivateKey.from_private_bytes((KEY_DIR / "backstop.key").read_bytes())
    markers, recent = Markers(priv), {}
    tool = shutil.which("inotifywait")
    if not tool:
        sys.exit("inotifywait not installed (apt install inotify-tools)")
    watch = [w for w in cfg["watch"] if Path(w).exists()]
    print(f"backstop watching {watch}", flush=True)
    proc = subprocess.Popen([tool, "-m", "-r", "-q", "-e", "modify,create,delete,moved_to,attrib",
                             "--format", "%e|%w%f", *watch], stdout=subprocess.PIPE, text=True)
    for line in proc.stdout:
        ev, _, path = line.strip().partition("|")
        if path:
            handle(path, ev, markers, cfg, recent)
    return proc.wait()


if __name__ == "__main__":
    arg = sys.argv[1] if len(sys.argv) > 1 else ""
    if arg == "init":
        init_keys()
    elif arg == "run":
        sys.exit(run())
    else:
        print(__doc__)
