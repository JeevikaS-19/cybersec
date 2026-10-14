#!/bin/bash
# Install the Chain of Custody witness on its own machine (Oracle VPS), next to anything already there.
#   sudo PORT=8810 bash deploy/install-witness.sh
# Listens on 127.0.0.1:$PORT only; publish it through your tunnel (e.g. custody.jrushvj.dev -> 127.0.0.1:8810).
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
SRC="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${PORT:-8810}"
PREFIX="${PREFIX:-}"   # e.g. /custody when it shares a hostname (path route)
apt-get update -qq && apt-get install -y -qq --no-install-recommends python3 python3-venv >/dev/null
getent passwd custody-witness >/dev/null || useradd --system --home /var/lib/custody-witness --shell /usr/sbin/nologin custody-witness
install -d -o custody-witness -g custody-witness -m 700 /var/lib/custody-witness
install -d -m 755 /opt/custody-witness
cp -r "$SRC"/{shared,witness,config} /opt/custody-witness/
install -d /opt/custody-witness/layers && cp -r "$SRC/layers/common" "$SRC/layers/__init__.py" /opt/custody-witness/layers/
python3 -m venv /opt/custody-witness/venv
WHEELS=""; ls "$SRC"/docker/wheels/*.whl >/dev/null 2>&1 && WHEELS="--no-index --find-links $SRC/docker/wheels"  # offline
/opt/custody-witness/venv/bin/pip install -q $WHEELS fastapi==0.115.12 uvicorn==0.34.0 PyYAML==6.0.3 cryptography==50.0.2 pycryptodome==3.23.0
if [ ! -d /var/lib/custody-witness/shares ]; then
  runuser -u custody-witness -- env PYTHONPATH=/opt/custody-witness /opt/custody-witness/venv/bin/python -m witness.keyholders init \
    /var/lib/custody-witness/witness.db /var/lib/custody-witness/shares "SOC lead" "Auditor" "Compliance officer"
fi
sed -e "s/{{PORT}}/$PORT/" -e "s|{{PREFIX}}|$PREFIX|" "$SRC/deploy/custody-witness.service" > /etc/systemd/system/custody-witness.service
systemctl daemon-reload
systemctl enable --now custody-witness
sleep 3; /opt/custody-witness/venv/bin/python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:$PORT$PREFIX/status', timeout=5)" && echo "witness up on 127.0.0.1:$PORT"
echo "Key-holder shares: /var/lib/custody-witness/shares/*.share - hand one to each holder, then delete them."
