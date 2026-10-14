#!/bin/bash
# Layer 1 demo actor, run inside WSL by demo/demo.py.  Usage: wsl_layer1.sh intruder|admin SPOOL PROFILES PROFILE_ID
set -u
MODE="$1"; export COC_SPOOL="$2" COC_PROFILES="$3"; PROFILE_ID="$4"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
export COC_PROTECTED=/tmp/coc-demo/log
LOG="$COC_PROTECTED/app.log"
mkdir -p "$COC_PROTECTED"
[ -f "$LOG" ] || printf 'txn-00012 acc-1 -> acc-3 2500.00\ntxn-00013 acc-2 -> acc-1 120.00\n' > "$LOG"
sh "$REPO/layers/l1_tripwire/install.sh" /tmp/coc-demo/trip >/dev/null
. /tmp/coc-demo/trip/profile.sh
if [ "$MODE" = admin ]; then
  vim "--$PROFILE_ID" -es -c '%s/120.00/125.00/' -c wq "$LOG" </dev/null
  echo "  admin: vim --<profile-id> app.log -> real log edited, logged as allowed"
else
  vim -es -c '%s/2500.00/250000.00/' -c wq "$LOG" </dev/null
  rm "$LOG"
  echo "  intruder: vim app.log + rm app.log -> both 'worked' (decoy); real log: $(/bin/cat "$LOG" | head -1)"
fi
