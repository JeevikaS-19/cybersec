#!/bin/bash
# Install Chain of Custody on a real log server (as root). The platform itself is not modified.
#   sudo COC_PLATFORM_CONFIG=/opt/coc/config/platform.team-bank.yaml WITNESS_URL=https://custody.example \
#        COC_DB_DSN=postgresql://coc_reader:...@127.0.0.1:5432/bankingsystem \
#        COC_PROTECTED_PATH=/var/log/bank-demo COC_L3_DRY_RUN=1 bash deploy/install-log-server.sh
# COC_L3_DRY_RUN=1 (default): quarantine is detected and reported; lockout commands are only recorded.
# Then: sudo bash -c 'cd /opt/coc && PYTHONPATH=/opt/coc venv/bin/python -m layers.l1_tripwire.profiles add <platform>'
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
SRC="$(cd "$(dirname "$0")/.." && pwd)"
apt-get update -qq && apt-get install -y -qq --no-install-recommends python3 python3-venv inotify-tools e2fsprogs procps passwd >/dev/null
mkdir -p /opt/coc /etc/coc /var/lib/coc /var/spool/coc
cp -r "$SRC"/{shared,agent,layers,config} /opt/coc/

# This server's config: the repo's, with its protected folder and the Layer 3 mode.
PROTECTED="${COC_PROTECTED_PATH:-/var/log/bank-demo}"
mkdir -p "$PROTECTED"
DRY=true
[ "${COC_L3_DRY_RUN:-1}" = 0 ] && DRY=false
sed -e "s|^    - /var/log/bank[[:space:]]*$|    - $PROTECTED|" -e "s|^  dry_run: true.*|  dry_run: $DRY|" \
    /opt/coc/config/layers.yaml > /opt/coc/config/layers.server.yaml
grep -q -- "- $PROTECTED" /opt/coc/config/layers.server.yaml || { echo "could not set the protected path"; exit 1; }

python3 -m venv /opt/coc/venv
WHEELS=""; ls "$SRC"/docker/wheels/*.whl >/dev/null 2>&1 && WHEELS="--no-index --find-links $SRC/docker/wheels"  # offline
/opt/coc/venv/bin/pip install -q $WHEELS PyYAML==6.0.3 cryptography==50.0.2 requests==2.33.1 "psycopg[binary]==3.2.13"
cat > /etc/coc/coc.env <<ENV
PYTHONPATH=/opt/coc
COC_PLATFORM_CONFIG=${COC_PLATFORM_CONFIG:-/opt/coc/config/platform.yaml}
COC_LAYERS_CONFIG=/opt/coc/config/layers.server.yaml
WITNESS_URL=${WITNESS_URL:?set WITNESS_URL}
AGENT_DB_PATH=/var/lib/coc/agent.db
COC_SPOOL=/var/spool/coc
ENV
if [ -n "${COC_DB_DSN:-}" ]; then echo "COC_DB_DSN=$COC_DB_DSN" >> /etc/coc/coc.env; fi
chmod 600 /etc/coc/coc.env                      # holds the read-only DB DSN; root only

COC_LAYERS_CONFIG=/opt/coc/config/layers.server.yaml PYTHONPATH=/opt/coc /opt/coc/venv/bin/python -m layers.l1_tripwire.backstop init
COC_PYTHON=/opt/coc/venv/bin/python COC_LAYERS_CONFIG=/opt/coc/config/layers.server.yaml sh /opt/coc/layers/l1_tripwire/install.sh /opt/trip
ls /opt/trip/bin | grep -q . || { echo "tripwire built no wrappers"; exit 1; }
echo "export COC_LAYERS_CONFIG=/opt/coc/config/layers.server.yaml COC_SPOOL=/var/spool/coc" > /etc/profile.d/coc-env.sh
install -m 644 "$SRC/deploy/coc-agent.service" "$SRC/deploy/coc-backstop.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now coc-agent coc-backstop
echo "installed: protected $PROTECTED, Layer 3 dry_run=$DRY. Next: register the team's profile-id (see top of this file)."
