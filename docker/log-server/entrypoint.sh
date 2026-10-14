#!/bin/bash
# Log server start-up: people, the team's profile-id, the tripwire, sshd, the bank, then the agent.
set -euo pipefail
cd /opt/coc
mkdir -p /var/lib/bank /var/lib/coc /var/log/bank /etc/coc

# Logins: the admin (team) and ops (an account whose password the attacker has stolen).
for u in admin ops; do
  id "$u" >/dev/null 2>&1 || useradd -m -s /bin/bash "$u"
done
echo "admin:${ADMIN_PASSWORD:?set ADMIN_PASSWORD}" | chpasswd
echo "ops:${OPS_PASSWORD:?set OPS_PASSWORD}" | chpasswd
sed -i -e 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' -e 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config

# The bank's application log (what an intruder wants to edit).
[ -s /var/log/bank/app.log ] || printf '%s\n' \
  "2026-10-14 09:12:03 txn-00012 acc-1 -> acc-3 2500.00 ok" \
  "2026-10-14 09:12:07 txn-00013 acc-2 -> acc-1 120.00 ok" \
  "2026-10-14 09:13:44 txn-00014 acc-3 -> acc-2 75.50 ok" > /var/log/bank/app.log

# Layer 1: the team's profile-id (stored as a hash only), then the tripwire for every login shell.
COC_PROFILE_ID="${COC_PROFILE_ID:?set COC_PROFILE_ID}" python -m layers.l1_tripwire.profiles add "${PLATFORM_ID:-bank-server}" >/dev/null
unset COC_PROFILE_ID
chmod 644 /etc/coc/profiles  # admins run `nano --<profile-id>` as themselves; the file holds scrypt hashes only
sh layers/l1_tripwire/install.sh /opt/trip
# Wrappers must reach the agent's spool and repo from any login shell.
cat > /etc/profile.d/coc-env.sh <<ENV
export COC_SPOOL=/var/spool/coc COC_LAYERS_CONFIG=$COC_LAYERS_CONFIG PYTHONPATH=/opt/coc
ENV

/usr/sbin/sshd
python victim/bank.py >/var/log/bank/bank-stdout.log 2>&1 &
for _ in $(seq 1 50); do [ -s "$BANK_DB_PATH" ] && break; sleep 0.2; done
echo "log-server ready: witness=${WITNESS_URL}"
exec python -u agent/agent.py
