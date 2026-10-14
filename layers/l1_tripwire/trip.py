"""Layer 1 command tripwire. Each wrapper runs: python3 -m layers.l1_tripwire.trip <name> <args>.

The team runs a guarded command with its platform's secret profile-id as the first argument:
    nano --<profile-id> /var/log/bank/app.log
The flag is checked against stored hashes, stripped, and the real command runs; the use is logged (no alert).
Without it, the command trips:
    deception mode: alert, then the intruder "succeeds" against a decoy. The real file is never touched;
                    on save, the diff of what they tried to change goes to the witness as evidence.
    block mode:     alert, plain error, the real command never runs.
Which commands and paths are guarded comes from config/layers.yaml (layer1). Stdlib + pyyaml only.
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

DIFF_LIMIT = 4000
DEFAULTS = {"mode": "deception", "protected_paths": ["/var/log/bank"], "editors": [], "file_commands": [],
            "watch_cd": True, "profiles_file": "/etc/coc/profiles"}


def settings():
    cfg = dict(DEFAULTS)
    try:
        import yaml
        with open(events.LAYERS_CONFIG, encoding="utf-8") as f:
            cfg.update((yaml.safe_load(f) or {}).get("layer1") or {})
    except Exception:  # noqa: BLE001, S110 - no config or no yaml: keep safe defaults, never fail open
        pass
    cfg["mode"] = os.environ.get("COC_L1_MODE", cfg["mode"])
    if os.environ.get("COC_PROTECTED"):
        cfg["protected_paths"] = os.environ["COC_PROTECTED"].split(os.pathsep)
    return cfg


def guarded_commands(cfg=None):
    cfg = cfg or settings()
    return list(dict.fromkeys([*cfg["editors"], *cfg["file_commands"]]))


def under(path, roots):
    try:
        p = Path(path).expanduser().resolve()
        return any(p.is_relative_to(Path(r).resolve()) for r in roots)
    except (OSError, ValueError):
        return False


def protected_targets(args, roots):
    return [a for a in args if not a.startswith("-") and under(a, roots)]


def real_binary(name):
    # The wrapper sets COC_TRIP_BIN; skip that dir so we find the real binary, never ourselves.
    trip_dir = os.environ.get("COC_TRIP_BIN", "")
    keep = [p for p in os.environ.get("PATH", "").split(os.pathsep)
            if p and not (trip_dir and Path(p).resolve() == Path(trip_dir).resolve())]
    found = shutil.which(name, path=os.pathsep.join(keep))
    if found and trip_dir and Path(found).resolve().parent == Path(trip_dir).resolve():
        return None
    return found


def authorized(args):
    """(platform, remaining args) if the first argument is a valid --<profile-id>, else (None, args)."""
    if not args or not args[0].startswith("--") or len(args[0]) < 4:
        return None, args
    from layers.l1_tripwire import profiles
    platform = profiles.match(args[0][2:])
    return (platform, args[1:]) if platform else (None, args)


def emit(name, trigger, args, detail, state="alert"):
    detail = {"cmd": shlex.join([name, *args]), "cwd": os.getcwd(), **detail}
    return events.emit(events.make_event(1, trigger, detail, state=state, process=name, exe=real_binary(name)))


def deceive_editor(name, args, target):
    target_path = Path(target).resolve()
    decoy_dir = Path(tempfile.mkdtemp(prefix=".coc-"))
    decoy = decoy_dir / target_path.name
    original = target_path.read_text(errors="replace") if target_path.exists() else ""
    decoy.write_text(original)
    editor = real_binary(name)
    if editor:
        subprocess.call([editor, *[str(decoy) if a == target else a for a in args]])
    attempted = decoy.read_text(errors="replace") if decoy.exists() else ""
    shutil.rmtree(decoy_dir, ignore_errors=True)
    if attempted != original:
        diff = "".join(difflib.unified_diff(original.splitlines(True), attempted.splitlines(True),
                                            str(target_path), f"{target_path} (attempted)"))
        emit(name, f"deception:{name}", args, {"mode": "deception", "target": str(target_path),
                                               "diff": diff[:DIFF_LIMIT], "diff_truncated": len(diff) > DIFF_LIMIT,
                                               "result": "edit captured, real file untouched"})
    return 0


def run_real(name, args):
    real = real_binary(name)
    return subprocess.call([real, *args]) if real else 127


def exec_real(name, args):
    """Become the real command (same pid): the profile-id leaves the process list immediately."""
    real = real_binary(name)
    if not real:
        return 127
    if os.name == "posix":
        os.execv(real, [name, *args])
    return run_real(name, args)


def run(name, args):
    cfg = settings()
    if name == "cd":
        targets = protected_targets(args, cfg["protected_paths"])
        if cfg["watch_cd"] and targets:
            emit(name, "wrapper:cd", args, {"mode": cfg["mode"], "target": targets[0], "result": "allowed (reported)",
                                            "rule": f"Entered protected path {targets[0]}"})
        return 0  # the shell function does the real cd
    is_editor = name in cfg["editors"]
    platform, rest = authorized(args)
    targets = protected_targets(rest, cfg["protected_paths"])
    if not is_editor and not targets and platform is None:
        return run_real(name, args)  # ordinary use outside the protected paths
    if platform:
        # rest never contains the profile-id, so it is never logged or sent
        emit(name, f"authorized:{name}", rest, {"profile": platform, "targets": targets,
                                                "result": f"allowed (profile {platform})"}, state="normal")
        if targets:
            try:  # tell the root backstop this write is authorized (encrypted to its key, see backstop.py)
                from layers.l1_tripwire import backstop
                backstop.write_marker(args[0][2:], targets)
            except Exception:  # noqa: BLE001, S110 - no backstop installed: nothing to tell
                pass
        return exec_real(name, rest)
    rule = (f"Write to protected path {targets[0]} without a profile-id" if targets and not is_editor
            else f"Editor '{name}' used without a profile-id")
    result = "blocked" if cfg["mode"] != "deception" else ("allowed (read only)" if name == "cat" else "deceived (decoy)")
    emit(name, f"wrapper:{name}", args, {"mode": cfg["mode"], "targets": targets, "rule": rule, "result": result})
    if cfg["mode"] != "deception":
        print(f"{name}: {targets[0] if targets else ''}: Operation not permitted", file=sys.stderr)
        return 1
    if is_editor:
        return deceive_editor(name, args, targets[0]) if targets else run_real(name, args)
    if name == "cat":
        return run_real(name, args)  # reading is harmless; the alert already fired
    return 0  # file-changing commands report success and change nothing


def main():
    if sys.argv[1:] == ["--list-commands"]:
        print(" ".join(guarded_commands()))
        return 0
    if sys.argv[1:] == ["--watch-cd"]:
        return 0 if settings()["watch_cd"] else 1
    if len(sys.argv) < 2:
        print("usage: trip <command> [args...]", file=sys.stderr)
        return 2
    try:
        return run(sys.argv[1], sys.argv[2:])
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
