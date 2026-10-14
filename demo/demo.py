"""One-command demo: fresh witness + bank + agent, a 'network cable' you can cut, and a menu of attacks.

    python demo/demo.py            # then open http://127.0.0.1:8000/ (opens automatically)

Everything runs from demo/.run/ (wiped on start and on reset). Layer 1 attacks run in WSL Ubuntu.
"""

import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
RUN = REPO / "demo" / ".run"
WITNESS_PORT, CABLE_PORT = 8000, 8001
PROFILE_ID = "bank-demo-7f3a9c"  # the team's demo profile-id (stored as a hash only)
WSL_DISTRO = os.environ.get("COC_WSL_DISTRO", "Ubuntu-24.04")


class Cable:
    """TCP pass-through between the log server and the witness. cut() = unplug, plug() = reconnect."""

    def __init__(self):
        self.up, self.conns, self.srv = False, [], None

    def plug(self):
        if self.up:
            return
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", CABLE_PORT))
        self.srv.listen(50)
        self.up = True
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while self.up:
            try:
                c, _ = self.srv.accept()
                s = socket.create_connection(("127.0.0.1", WITNESS_PORT))
            except OSError:
                return
            self.conns += [c, s]
            for a, b in ((c, s), (s, c)):
                threading.Thread(target=self._pipe, args=(a, b), daemon=True).start()

    @staticmethod
    def _pipe(a, b):
        try:
            while data := a.recv(65536):
                b.sendall(data)
        except OSError:
            pass
        for x in (a, b):
            try:
                x.close()
            except OSError:
                pass

    def cut(self):
        self.up = False
        if self.srv:
            self.srv.close()
        for c in self.conns:
            try:
                c.close()
            except OSError:
                pass
        self.conns = []


def wsl_path(p):
    p = str(p)
    return "/mnt/" + p[0].lower() + p[2:].replace("\\", "/")


class Demo:
    def __init__(self):
        self.procs, self.cable = [], Cable()

    def env(self):
        return dict(os.environ, PYTHONPATH=str(REPO), WITNESS_URL=f"http://127.0.0.1:{CABLE_PORT}",
                    WITNESS_DB_PATH=str(RUN / "witness.db"), BANK_DB_PATH=str(RUN / "bank.db"),
                    AGENT_DB_PATH=str(RUN / "agent.db"), COC_SPOOL=str(RUN / "spool"),
                    COC_EVIDENCE_DIR=str(RUN / "vault"), COC_PROFILES=str(RUN / "profiles"),
                    COC_L3_DRY_RUN=os.environ.get("COC_L3_DRY_RUN", "1"),
                    CHALLENGE_CHANCE=os.environ.get("CHALLENGE_CHANCE", "0.5"),
                    SWEEP_SECONDS=os.environ.get("SWEEP_SECONDS", "10"))

    def start(self):
        self.stop()
        shutil.rmtree(RUN, ignore_errors=True)
        RUN.mkdir(parents=True)
        env = self.env()
        log = open(RUN / "processes.log", "w")  # noqa: SIM115 (held by the child processes)
        subprocess.run([sys.executable, "-m", "layers.l1_tripwire.profiles", "add", "demo-bank"], cwd=REPO,
                       env=dict(env, COC_PROFILE_ID=PROFILE_ID), capture_output=True, check=True)
        self.procs.append(subprocess.Popen([sys.executable, "-m", "uvicorn", "--factory", "witness.app:create_app",
                                            "--port", str(WITNESS_PORT), "--log-level", "warning"],
                                           cwd=REPO, env=env, stdout=log, stderr=log))
        time.sleep(2.5)
        self.cable.plug()
        self.procs.append(subprocess.Popen([sys.executable, "victim/bank.py"], cwd=REPO, env=env, stdout=log, stderr=log))
        time.sleep(1)
        self.procs.append(subprocess.Popen([sys.executable, "-u", "agent/agent.py"], cwd=REPO, env=env,
                                           stdout=log, stderr=log))
        print(f"\n  Witness auditor view: http://127.0.0.1:{WITNESS_PORT}/   (all green in ~10 s)\n")

    def stop(self):
        for p in self.procs:
            p.terminate()
        for p in self.procs:
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                p.kill()
        self.procs = []
        self.cable.cut()

    def wsl(self, mode):
        script = wsl_path(REPO / "demo" / "wsl_layer1.sh")
        cmd = ["wsl.exe", "-d", WSL_DISTRO, "--", "bash", script, mode, wsl_path(RUN / "spool"),
               wsl_path(RUN / "profiles"), PROFILE_ID]
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
            print(out.stdout.strip() or out.stderr.strip())
        except (OSError, subprocess.TimeoutExpired) as exc:
            print(f"  WSL not available ({exc}). Layer 1 needs WSL Ubuntu or the log-server container.")

    def bank(self, sql, *params):
        db = sqlite3.connect(RUN / "bank.db")
        try:
            row = db.execute(sql, params)
            db.commit()
            return row
        finally:
            db.close()

    def tamper_record(self):
        db = sqlite3.connect(RUN / "bank.db")
        try:
            n = db.execute("SELECT COUNT(*) FROM transactions").fetchone()[0]
            tid = max(1, n // 3)
            old = db.execute("SELECT txn_id, amount_paise FROM transactions WHERE id = ?", (tid,)).fetchone()
            db.execute("UPDATE transactions SET amount_paise = ? WHERE id = ?", (max(1, old[1] // 100), tid))
            db.commit()
        finally:
            db.close()
        print(f"  Attacker changed {old[0]} amount {old[1] / 100:.2f} -> {max(1, old[1] // 100) / 100:.2f} "
              "directly in bank.db. Watch Layer 2 (sweep within ~15 s).")

    def tamper_balance(self):
        self.bank("UPDATE accounts SET balance_paise = balance_paise + 1000000 WHERE account_id = 'acc-2'")
        print("  Attacker added Rs 10,000 to acc-2 in bank.db with no transaction. Watch Check C.")


MENU = """
  1  Layer 1  intruder edits the log with vim (no profile-id)  -> decoy, attempted diff captured
  2  Layer 1  admin edits with vim --<profile-id>               -> allowed, logged, no alert
  3  Layer 2  attacker edits a transaction row in bank.db      -> record #N side by side
  4  Layer 2  attacker changes a balance with no transaction   -> Check C
  5  Layer 3  cut the network (quarantine after 45 s)
  6  Layer 3  plug the network back in (then approve 2 of 3 on the page)
  r  reset everything fresh      q  quit
"""


def main():
    demo = Demo()
    demo.start()
    if "--no-browser" not in sys.argv:
        webbrowser.open(f"http://127.0.0.1:{WITNESS_PORT}/")
    actions = {
        "1": lambda: demo.wsl("intruder"), "2": lambda: demo.wsl("admin"),
        "3": demo.tamper_record, "4": demo.tamper_balance,
        "5": lambda: (demo.cable.cut(), print("  Network cut. Server quarantines itself after 45 s.")),
        "6": lambda: (demo.cable.plug(), print("  Network back. Server reports in and stays locked until 2 approvals.")),
        "r": demo.start,
    }
    try:
        while True:
            print(MENU)
            try:
                choice = input("  > ").strip().lower()
            except EOFError:
                break
            if choice == "q":
                break
            if choice in actions:
                actions[choice]()
            elif choice.startswith("wait "):
                time.sleep(float(choice.split()[1]))
    finally:
        demo.stop()


if __name__ == "__main__":
    main()
