#!/bin/bash
# Layer 1 smoke test, no root needed: installs into a temp prefix and plays the intruder.
set -u
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
T="$(mktemp -d)"; export COC_SPOOL="$T/spool" COC_LOG_DIR="$T/log" COC_ETC="$T/etc"
mkdir -p "$COC_LOG_DIR"; printf 'txn-1 acc-1 -> acc-2 1000\ntxn-2 acc-2 -> acc-3 250\n' > "$COC_LOG_DIR/app.log"
sh "$REPO/layers/l1_tripwire/install.sh" "$T/trip" >/dev/null
. "$T/trip/profile.sh"
pass=0; fail=0
ok() { if eval "$2"; then echo "PASS $1"; pass=$((pass+1)); else echo "FAIL $1"; fail=$((fail+1)); fi; }
n() { ls "$COC_SPOOL"/ev-*.json 2>/dev/null | wc -l; }
before="$(/bin/cat "$COC_LOG_DIR/app.log")"

rm "$COC_LOG_DIR/app.log"; rc=$?
ok "rm on log: pretends success, log intact, 1 event" '[ $rc = 0 ] && [ -f "$COC_LOG_DIR/app.log" ] && [ $(n) = 1 ]'
vim -es -c '%s/1000/999999/' -c 'wq' "$COC_LOG_DIR/app.log" </dev/null
ok "vim on log: real log unchanged" '[ "$(/bin/cat "$COC_LOG_DIR/app.log")" = "$before" ]'
ok "vim on log: alert + attempted diff captured" '[ $(n) = 3 ] && grep -l "999999" "$COC_SPOOL"/ev-*.json >/dev/null'
COC_L1_MODE=block sed -i 's/acc/xxx/' "$COC_LOG_DIR/app.log" 2>/dev/null; rc=$?
ok "block mode: sed refused, log intact" '[ $rc = 1 ] && [ "$(/bin/cat "$COC_LOG_DIR/app.log")" = "$before" ] && [ $(n) = 4 ]'
cat /etc/hostname >/dev/null; cp /etc/hostname "$T/x"; rm "$T/x"
ok "normal files: real commands run, no event" '[ ! -f "$T/x" ] && [ $(n) = 4 ]'
cd "$COC_LOG_DIR"; cd - >/dev/null
ok "cd into log dir: event" '[ $(n) = 5 ]'
coc-view "$COC_LOG_DIR/app.log" >/dev/null
ok "coc-view: works, no event" '[ $? = 0 ] && [ $(n) = 5 ]'
COC_REVERT_KEY="correct horse" coc-setkey >/dev/null
COC_REVERT_KEY="wrong" coc-unlock 2>/dev/null; rc=$?
ok "coc-unlock wrong key: refused + logged" '[ $rc = 1 ] && [ $(n) = 6 ]'
p="$(COC_REVERT_KEY="correct horse" COC_UNLOCK_NO_SHELL=1 coc-unlock)"
ok "coc-unlock right key: session PATH has no trip dir, logged" 'case ":$p:" in *":$T/trip/bin:"*) false;; *) true;; esac && [ $(n) = 7 ]'
ok "revert key never stored in plain text" '! grep -rq "correct horse" "$COC_ETC" "$COC_SPOOL"'
/usr/bin/sed -n 1p "$COC_LOG_DIR/app.log" >/dev/null
ok "full-path bypass not seen by wrappers (auditd's job, Step 9)" '[ $(n) = 7 ]'
echo "triggers:"; for f in "$COC_SPOOL"/ev-*.json; do python3 -c "import json,sys; e=json.load(open(sys.argv[1])); print(' ', e['trigger'], e['state'])" "$f"; done | sort
echo "$pass passed, $fail failed"; rm -rf "$T"; [ $fail = 0 ]
