#!/bin/bash
# Real Layer 3 lockout test, run as root inside the l3-test container:
#   docker build -t coc-l3-test -f docker/l3-test/Dockerfile .  &&  docker run --rm coc-l3-test
set -u
cd /opt/coc
export PYTHONPATH=/opt/coc COC_L3_DRY_RUN=0 COC_SPOOL=/tmp/spool COC_EVIDENCE_DIR=/var/lib/coc/quarantine
pass=0; fail=0
ok() { if eval "$2"; then echo "PASS $1"; pass=$((pass+1)); else echo "FAIL $1"; fail=$((fail+1)); fi; }

# users: an admin and an attacker, both with SSH keys; root too
for u in admin attacker; do useradd -m -s /bin/bash "$u"; echo "$u:pw-$u" | chpasswd; done
echo "root:pw-root" | chpasswd
ssh-keygen -q -t ed25519 -N "" -f /tmp/key
for h in /root /home/admin /home/attacker; do
  mkdir -p "$h/.ssh"; cp /tmp/key.pub "$h/.ssh/authorized_keys"; chmod 700 "$h/.ssh"; chmod 600 "$h/.ssh/authorized_keys"
done
chown -R admin:admin /home/admin/.ssh; chown -R attacker:attacker /home/attacker/.ssh
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
/usr/sbin/sshd
sshto() { ssh -q -i /tmp/key -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=5 "$1@127.0.0.1" true; }
mkdir -p /var/log/bank; echo "txn-1 acc-1 -> acc-2 1000" > /var/log/bank/app.log

ok "before: attacker SSH key login works" 'sshto attacker'
ok "before: root SSH key login works" 'sshto root'

# live sessions: attacker and admin shells with a terminal, and root's own terminal shell
su - attacker -c 'setsid script -qc "sleep 600" /dev/null' >/dev/null 2>&1 &
su - admin -c 'setsid script -qc "sleep 600" /dev/null' >/dev/null 2>&1 &
setsid script -qc "sleep 600" /dev/null >/dev/null 2>&1 &
sleep 1
ok "before: 3 terminal sleeps running" '[ $(pgrep -c -x sleep) -ge 3 ]'

python3 - <<'PY'
import json
from layers.l3_quarantine import quarantine as l3
rec = l3.quarantine("test: no contact with the witness", ["/var/log/bank"])
json.dump(rec, open("/tmp/record.json", "w"))
print("quarantined:", rec["id"], "users:", rec["users"])
PY
ok "agent (this script) survived its own lockout" 'true'
ok "/etc/nologin present" '[ -f /etc/nologin ]'
ok "every interactive account password-locked (root, admin, attacker)" \
   'for u in root admin attacker; do passwd -S $u | grep -q " L " || exit 1; done'
ok "every interactive account expired" \
   'for u in root admin attacker; do chage -l $u | grep -q "Account expires.*1970" || exit 1; done'
ok "service account untouched" '! chage -l daemon | grep -q 1970'
ok "all terminal sessions ended (root's included)" '! pgrep -x sleep >/dev/null'
ok "sshd itself still running (a service, not a session)" 'pgrep -x sshd >/dev/null'
ok "attacker SSH key login refused" '! sshto attacker'
ok "root SSH key login refused" '! sshto root'
ok "su to admin refused" '! su admin -c true </dev/null 2>/dev/null'
ok "evidence sealed with hash" 'ls /var/lib/coc/quarantine/*/evidence.json >/dev/null && ls /var/lib/coc/quarantine/*/evidence.sha256 >/dev/null'
ok "no reboot command in the layer3 config" '! grep -qiE "^ *- *(reboot|poweroff|shutdown|halt)" /opt/coc/config/layers.yaml'

python3 - <<'PY'
import json
from layers.l3_quarantine import quarantine as l3
l3.release(json.load(open("/tmp/record.json")))
print("released")
PY
ok "after unlock: /etc/nologin gone" '[ ! -f /etc/nologin ]'
ok "after unlock: accounts usable again" 'for u in root admin attacker; do passwd -S $u | grep -q " P " || exit 1; done'
ok "after unlock: admin SSH key login works" 'sshto admin'
echo "chattr +a on the evidence folder: $(lsattr -d /var/lib/coc/quarantine/* 2>&1 | head -1)"
echo "$pass passed, $fail failed"
[ $fail = 0 ]
