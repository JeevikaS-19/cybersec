#!/bin/bash
# Layer 1 smoke test, no root needed: installs into a temp prefix, plays the team and the intruder.
set -u
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
T="$(mktemp -d)"
export COC_SPOOL="$T/spool" COC_PROTECTED="$T/log" COC_PROFILES="$T/etc/profiles" PYTHONPATH="$REPO"
LOG="$COC_PROTECTED/app.log"
mkdir -p "$COC_PROTECTED"; printf 'txn-1 acc-1 -> acc-2 1000\ntxn-2 acc-2 -> acc-3 250\n' > "$LOG"
COC_PROFILE_ID="bank-7f3a9c2e" python3 -m layers.l1_tripwire.profiles add demo-bank >/dev/null
sh "$REPO/layers/l1_tripwire/install.sh" "$T/trip" >/dev/null
. "$T/trip/profile.sh"
pass=0; fail=0
ok() { if eval "$2"; then echo "PASS $1"; pass=$((pass+1)); else echo "FAIL $1"; fail=$((fail+1)); fi; }
n() { ls "$COC_SPOOL"/ev-*.json 2>/dev/null | wc -l; }
alerts() { grep -l '"state": "alert"' "$COC_SPOOL"/ev-*.json 2>/dev/null | wc -l; }
before="$(/bin/cat "$LOG")"

ok "wrappers built from config" '[ -x "$T/trip/bin/nano" ] && [ -x "$T/trip/bin/shred" ] && [ ! -e "$T/trip/bin/coc-view" ]'
rm "$LOG"; rc=$?
ok "intruder rm on log: pretends success, log intact, alert" '[ $rc = 0 ] && [ -f "$LOG" ] && [ $(alerts) = 1 ]'
vim -es -c '%s/1000/999999/' -c 'wq' "$LOG" </dev/null
ok "intruder vim: real log unchanged" '[ "$(/bin/cat "$LOG")" = "$before" ]'
ok "intruder vim: alert + attempted diff captured" '[ $(alerts) = 3 ] && grep -l 999999 "$COC_SPOOL"/ev-*.json >/dev/null'
COC_L1_MODE=block sed -i 's/acc/xxx/' "$LOG" 2>/dev/null; rc=$?
ok "block mode: sed refused, log intact" '[ $rc = 1 ] && [ "$(/bin/cat "$LOG")" = "$before" ] && [ $(alerts) = 4 ]'
cp /etc/hostname "$T/x"; rm "$T/x"
ok "normal files: real commands run, no event" '[ ! -f "$T/x" ] && [ $(n) = 4 ]'
cd "$COC_PROTECTED"; cd - >/dev/null
ok "cd into protected path: alert" '[ $(alerts) = 5 ]'
vim --bank-7f3a9c2e -es -c '%s/250/260/' -c 'wq' "$LOG" </dev/null
ok "admin vim --<profile-id>: real log edited" 'grep -q "acc-3 260" "$LOG"'
ok "admin use: logged, no alert" '[ $(n) = 6 ] && [ $(alerts) = 5 ] && grep -l "authorized:vim" "$COC_SPOOL"/ev-*.json >/dev/null'
ok "profile-id never stored or sent in plain text" '! grep -rq "bank-7f3a9c2e" "$T/etc" "$COC_SPOOL"'
vim --wrong-guess-123 -es -c 'q' "$LOG" </dev/null 2>/dev/null
ok "wrong profile-id: treated as intruder" '[ $(alerts) = 6 ]'
/usr/bin/sed -n 1p "$LOG" >/dev/null
ok "full-path bypass not seen by wrappers (auditd's job, Step 9)" '[ $(alerts) = 6 ]'
echo "triggers:"; for f in "$COC_SPOOL"/ev-*.json; do python3 -c "import json,sys; e=json.load(open(sys.argv[1])); print(' ', e['trigger'], e['state'], e['detail'].get('profile', ''))" "$f"; done | sort
echo "$pass passed, $fail failed"; rm -rf "$T"; [ $fail = 0 ]
