"""Demo controls for the Docker stack. Run from anywhere:

    python docker/ctl.py up              build + start (first time: python docker/fetch_wheels.py for offline builds)
    python docker/ctl.py intruder        attacker SSHes in with stolen 'ops' password and edits/deletes the log  (Layer 1)
    python docker/ctl.py admin           admin edits with nano --<profile-id>: allowed, logged                     (Layer 1)
    python docker/ctl.py tamper-record   change a transaction amount directly in the bank database                (Layer 2)
    python docker/ctl.py tamper-balance  change a balance with no transaction                                     (Check C)
    python docker/ctl.py cut             unplug the log server from the network: quarantine after 45 s           (Layer 3)
    python docker/ctl.py restore         plug it back in, then approve 2 of 3 on http://127.0.0.1:8000/
    python docker/ctl.py status | logs | down | reset
"""
import json
import os
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT, NET, SERVER = "chain-of-custody", "chain-of-custody_custody", "chain-of-custody-log-server-1"


def docker():
    found = shutil.which("docker")
    if found:
        return found
    for guess in (Path(os.environ.get("LOCALAPPDATA", "")) / "Programs/DockerDesktop/resources/bin/docker.exe",
                  Path("C:/Program Files/Docker/Docker/resources/bin/docker.exe")):
        if guess.exists():
            return str(guess)
    sys.exit("docker CLI not found: start Docker Desktop and open a new terminal")


def env():
    vals = {}
    path = HERE / ".env"
    if not path.exists():
        shutil.copy(HERE / ".env.example", path)
        print("created docker/.env from .env.example (demo values)")
    for line in path.read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            vals[k.strip()] = v.strip()
    return vals


def run(*args, check=True, quiet=False):
    exe = docker()
    # Docker's helpers (credentials, compose) live next to docker.exe; make sure they're found too.
    child_env = dict(os.environ, PATH=str(Path(exe).parent) + os.pathsep + os.environ.get("PATH", ""))
    out = subprocess.run([exe, *args], cwd=HERE, capture_output=quiet, text=True, check=False, env=child_env)
    if check and out.returncode != 0:
        sys.exit(out.stderr if quiet else f"failed: docker {' '.join(args)}")
    return out


def compose(*args, **kw):
    return run("compose", *args, **kw)


def ssh(user, password, command):
    compose("exec", "-T", "attacker", "sshpass", "-p", password, "ssh", "-q", "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=5", f"{user}@log-server",
            f"bash -lc {json.dumps(command)}", check=False)


def bank_sql(code):
    compose("exec", "-T", "log-server", "python", "-c",
            "import sqlite3; c = sqlite3.connect('/var/lib/bank/bank.db'); " + code + "; c.commit()")


def main():
    sys.stdout.reconfigure(line_buffering=True)
    cmd = sys.argv[1] if len(sys.argv) > 1 else "help"
    e = env()
    if cmd == "up":
        compose("up", "-d", "--build")
        print("auditor view: http://127.0.0.1:8000/  (green in ~10 s)")
    elif cmd == "intruder":
        print("attacker: ssh ops@log-server (stolen password), vim + rm on /var/log/bank/app.log")
        ssh("ops", e["OPS_PASSWORD"], "vim -es -c '%s/2500.00/250000.00/' -c wq /var/log/bank/app.log </dev/null; "
            "rm /var/log/bank/app.log; echo \"attacker thinks it worked. real log still says: $(/bin/cat /var/log/bank/app.log | head -1)\"")
    elif cmd == "admin":
        print("admin: nano --<profile-id> on the log (allowed, logged)")
        ssh("admin", e["ADMIN_PASSWORD"], f"nano --{e['COC_PROFILE_ID']} --version | head -1")
    elif cmd == "tamper-record":
        bank_sql("n = c.execute('select count(*) from transactions').fetchone()[0]; t = max(1, n // 3); "
                 "r = c.execute('select txn_id, amount_paise from transactions where id = ?', (t,)).fetchone(); "
                 "c.execute('update transactions set amount_paise = ? where id = ?', (max(1, r[1] // 100), t)); "
                 "print('attacker changed', r[0], r[1] / 100, '->', max(1, r[1] // 100) / 100)")
    elif cmd == "tamper-balance":
        bank_sql("c.execute(\"update accounts set balance_paise = balance_paise + 1000000 where account_id = 'acc-2'\"); "
                 "print('attacker added Rs 10,000 to acc-2 with no transaction')")
    elif cmd == "cut":
        run("network", "disconnect", NET, SERVER)
        print("network cut: the log server quarantines itself after 45 s")
    elif cmd == "restore":
        run("network", "connect", "--alias", "log-server", NET, SERVER)
        print("network back: server reports in and stays locked until 2 of 3 approve on the auditor view")
    elif cmd == "status":
        with urllib.request.urlopen("http://127.0.0.1:8000/status", timeout=5) as r:
            s = json.load(r)
        print(json.dumps({k: s[k] for k in ("state", "connection", "checks", "layers", "records_verified")}, indent=1))
    elif cmd == "logs":
        compose("logs", "--tail", "40", "log-server")
    elif cmd == "down":
        compose("down")
    elif cmd == "reset":
        compose("down")
        # Quarantine evidence is append-only: not even Docker may delete it. Wiping it for a demo reset is a
        # deliberate, privileged step, done here in the open.
        run("run", "--rm", "--cap-add", "LINUX_IMMUTABLE", "-v", f"{PROJECT}_coc-evidence:/evidence",
            "--entrypoint", "chattr", f"{PROJECT}-log-server", "-R", "-a", "/evidence", check=False, quiet=True)
        print("cleared the append-only flag on old quarantine evidence (demo reset only)")
        compose("down", "-v")
        compose("up", "-d", "--build")
        print("fresh stack (all volumes wiped): http://127.0.0.1:8000/")
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
