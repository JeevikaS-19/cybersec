#!/bin/bash
# Install Chain of Custody on a real log server (as root). The platform itself is not modified.
#   sudo COC_PLATFORM_CONFIG=/opt/coc/config/platform.team-bank.yaml WITNESS_URL=https://witness:8000 \
#        bash deploy/install-log-server.sh
# Then: sudo python3 -m layers.l1_tripwire.profiles add <platform>   (asks for the team's profile-id)
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
SRC="$(cd "$(dirname "$0")/.." && pwd)"
apt-get install -y --no-install-recommends python3 python3-venv inotify-tools e2fsprogs procps passwd >/dev/null
mkdir -p /opt/coc /etc/coc /var/lib/coc /var/spool/coc
cp -r "$SRC"/{shared,agent,layers,config,witness} /opt/coc/
python3 -m venv /opt/coc/venv
/opt/coc/venv/bin/pip install -q -r "$SRC/requirements.txt"
cat > /etc/coc/coc.env <<ENV
PYTHONPATH=/opt/coc
COC_PLATFORM_CONFIG=${COC_PLATFORM_CONFIG:-/opt/coc/config/platform.yaml}
WITNESS_URL=${WITNESS_URL:?set WITNESS_URL}
AGENT_DB_PATH=/var/lib/coc/agent.db
COC_SPOOL=/var/spool/coc
COC_L3_DRY_RUN=${COC_L3_DRY_RUN:-0}
ENV
[ -n "${COC_DB_DSN:-}" ] && echo "COC_DB_DSN=$COC_DB_DSN" >> /etc/coc/coc.env
chmod 600 /etc/coc/coc.env                       # holds the read-only DB DSN; root only
PYTHONPATH=/opt/coc /opt/coc/venv/bin/python -m layers.l1_tripwire.backstop init
sh /opt/coc/layers/l1_tripwire/install.sh /opt/trip    # wrappers for every login shell
install -m 644 "$SRC/deploy/coc-agent.service" "$SRC/deploy/coc-backstop.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now coc-agent coc-backstop
echo "installed. Next: python3 -m layers.l1_tripwire.profiles add <platform>, then check the auditor view."
