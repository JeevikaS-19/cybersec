"""End every login session during quarantine without killing ourselves.

A process belongs to a login session if it has a controlling terminal, or a login uid (auid) set by PAM at
login (services started by the init system have none). Every such process is killed, root's included, except
this process and its ancestors (the agent that is running the quarantine). Works without systemd/loginctl,
so it also works inside containers.
"""

import os
import signal
from pathlib import Path

UNSET_AUID = 4294967295


def _ancestors(proc, pid):
    seen = set()
    while pid and pid not in seen:
        seen.add(pid)
        try:
            pid = int(_stat(proc, pid)[3])
        except (OSError, ValueError, IndexError):
            break
    return seen


def _stat(proc, pid):
    raw = (Path(proc) / str(pid) / "stat").read_text()
    # comm can contain spaces/brackets: split after the last ')'
    return [raw[: raw.index("(")].strip(), raw[raw.index("(") + 1: raw.rindex(")")]] + raw[raw.rindex(")") + 2:].split()


def _uid(proc, pid):
    for line in (Path(proc) / str(pid) / "status").read_text().splitlines():
        if line.startswith("Uid:"):
            return int(line.split()[1])
    return None


def login_processes(proc="/proc", users=None, exclude=()):
    """[{pid, uid, cmd, tty, auid}] for processes in login sessions of `users` (uid list; None = everyone)."""
    keep = _ancestors(proc, os.getpid()) | set(exclude)
    out = []
    root = Path(proc)
    if not root.is_dir():
        return out
    for d in root.iterdir():
        if not d.name.isdigit() or int(d.name) in keep or int(d.name) == 1:
            continue
        pid = int(d.name)
        try:
            st = _stat(proc, pid)
            tty = int(st[6])
            uid = _uid(proc, pid)
            try:
                auid = int((d / "loginuid").read_text().strip())
            except (OSError, ValueError):
                auid = UNSET_AUID
        except (OSError, ValueError, IndexError):
            continue  # process exited while we looked
        if users is not None and uid not in users:
            continue
        if tty != 0 or auid != UNSET_AUID:
            out.append({"pid": pid, "uid": uid, "cmd": st[1], "tty": tty, "auid": None if auid == UNSET_AUID else auid})
    return out


def end_login_sessions(dry_run, users=None, proc="/proc", exclude=()):
    found = login_processes(proc, users, exclude)
    if not dry_run:
        for p in found:
            try:
                os.kill(p["pid"], signal.SIGKILL)
            except (ProcessLookupError, PermissionError) as exc:
                p["error"] = exc.__class__.__name__
    return found
