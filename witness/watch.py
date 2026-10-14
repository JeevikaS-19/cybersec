"""Terminal alert watcher: the Round 1 demo screen. Polls the witness every second."""

import os
import time

import requests

WITNESS_URL = os.environ.get("WITNESS_URL", "http://127.0.0.1:8000")
GREEN, RED, DIM, RESET = "\033[32m", "\033[31m", "\033[2m", "\033[0m"


def colour(value):
    return f"{GREEN if value == 'green' else RED}{value}{RESET}"


def main():
    os.system("")  # turns on ANSI colours in the Windows console
    seen = set()
    last_key = None
    while True:
        try:
            status = requests.get(f"{WITNESS_URL}/status", timeout=3).json()
            alerts = requests.get(f"{WITNESS_URL}/alerts", timeout=3).json()["alerts"]
        except requests.RequestException as exc:
            print(f"{RED}witness unreachable{RESET} ({exc.__class__.__name__})")
            time.sleep(1)
            continue

        # Print only when checks or state change; seq is left out so it can't trigger a reprint.
        key = (tuple(sorted(status["checks"].items())), status["state"])
        if key != last_key:
            line = "  ".join(f"Check {c}: {colour(v)}" for c, v in status["checks"].items())
            print(f"{line}  {DIM}state={status['state']}{RESET}")
            last_key = key

        for alert in alerts:
            key = (alert["kind"], alert["ref"])
            if key in seen:
                continue
            seen.add(key)
            when = time.strftime("%H:%M:%S", time.localtime(alert["time"]))
            print(f"{RED}ALERT{RESET} {when} {alert['kind']} ref={alert['ref']} "
                  f"tamper_type={RED}{alert['tamper_type']}{RESET} {DIM}{alert['detail']}{RESET}")

        time.sleep(1)


if __name__ == "__main__":
    main()
