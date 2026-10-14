"""Layer 1 command tripwire. Every wrapper in the trip bin dir runs: python3 -m layers.l1_tripwire.trip <name> <args>.

block mode:     alert, print a plain error, real command never runs.
deception mode: alert, then let the intruder "succeed" against a decoy. The real log is never touched;
                when they save, the diff of what they tried to change goes to the witness as evidence.
Stdlib only, so it runs on a bare log server.
"""

import difflib
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from layers.common import events

EDITORS = {"nano", "vi", "vim", "gedit"}
FILE_CMDS = {"rm", "mv", "cp", "sed", "truncate", "shred", "cat"}
DIFF_LIMIT = 4000


def settings():
    cfg = {"mode": "deception", "log_dir": "/var/log/bank"}
    try:
        import yaml
        with open(events.LAYERS_CONFIG, encoding="utf-8") as f:
            cfg.update((yaml.safe_load(f) or {}).get("layer1") or {})
    except Exception:  # noqa: BLE001, S110 - no config or no yaml: keep safe defaults, never fail open
        pass
    cfg["mode"] = os.environ.get("COC_L1_MODE", cfg["mode"])
    cfg["log_dir"] = os.environ.get("COC_LOG_DIR", cfg["log_dir"])
    return cfg


def under(path, log_dir):
    try:
        return Path(path).expanduser().resolve().is_relative_to(Path(log_dir).resolve())
    except (OSError, ValueError):
        return False


def log_targets(args, log_dir):
    return [a for a in args if not a.startswith("-") and under(a, log_dir)]


def real_binary(name):
    # The wrapper sets COC_TRIP_BIN; skip that dir so we find the real binary, never ourselves.
    trip_dir = os.environ.get("COC_TRIP_BIN", "")
    keep = [p for p in os.environ.get("PATH", "").split(os.pathsep)
            if p and not (trip_dir and Path(p).resolve() == Path(trip_dir).resolve())]
    found = shutil.which(name, path=os.pathsep.join(keep))
    if found and trip_dir and Path(found).resolve().parent == Path(trip_dir).resolve():
        return None
    return found


def alert(name, args, detail):
    detail = {"cmd": shlex.join([name, *args]), "cwd": os.getcwd(), "tty": os.environ.get("SSH_TTY") or "", **detail}
    return events.emit(events.make_event(1, f"wrapper:{name}", detail, process=name, exe=real_binary(name)))


def deceive_editor(name, args, targets):
    target = Path(targets[0]).resolve()
    decoy_dir = Path(tempfile.mkdtemp(prefix=".coc-"))
    decoy = decoy_dir / target.name
    original = target.read_text(errors="replace") if target.exists() else ""
    decoy.write_text(original)
    editor = real_binary(name)
    if editor:
        subprocess.call([editor, *[str(decoy) if a == targets[0] else a for a in args]])
    attempted = decoy.read_text(errors="replace") if decoy.exists() else ""
    shutil.rmtree(decoy_dir, ignore_errors=True)
    if attempted != original:
        diff = "".join(difflib.unified_diff(original.splitlines(True), attempted.splitlines(True),
                                            str(target), f"{target} (attempted)"))
        events.emit(events.make_event(1, f"deception:{name}", {
            "cmd": shlex.join([name, *args]), "mode": "deception", "target": str(target),
            "diff": diff[:DIFF_LIMIT], "diff_truncated": len(diff) > DIFF_LIMIT,
        }, process=name, exe=editor))
    return 0


def run(name, args):
    cfg = settings()
    targets = log_targets(args, cfg["log_dir"])
    if name == "cd":
        if targets:
            alert(name, args, {"mode": cfg["mode"], "target": targets[0]})
        return 0  # the shell function does the real cd
    if name not in EDITORS and not targets:
        real = real_binary(name)
        return subprocess.call([real, *args]) if real else 127
    alert(name, args, {"mode": cfg["mode"], "targets": targets})
    if cfg["mode"] != "deception":
        print(f"{name}: {targets[0] if targets else ''}: Operation not permitted", file=sys.stderr)
        return 1
    if name in EDITORS:
        return deceive_editor(name, args, targets) if targets else subprocess.call([real_binary(name), *args])
    if name == "cat":
        return subprocess.call([real_binary("cat"), *args])  # reading is harmless; the alert already fired
    return 0  # rm, mv, cp, sed, truncate, shred: report success, change nothing


def main():
    if len(sys.argv) < 2:
        print("usage: trip <command> [args...]", file=sys.stderr)
        return 2
    try:
        return run(sys.argv[1], sys.argv[2:])
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
