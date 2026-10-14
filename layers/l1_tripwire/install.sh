#!/bin/sh
# Install the Layer 1 tripwire.  Usage: install.sh [PREFIX]   (default /opt/trip; system-wide needs root)
# Creates PREFIX/bin wrappers + coc-* commands and PREFIX/profile.sh (PATH first + cd function).
# As root with the default prefix, also links the profile into /etc/profile.d so every login shell gets it.
set -eu
PREFIX="${1:-/opt/trip}"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
PY="$(command -v python3)"
BIN="$PREFIX/bin"
mkdir -p "$BIN"

for name in nano vi vim gedit rm mv cp sed truncate shred cat; do
  cat > "$BIN/$name" <<EOF
#!/bin/sh
COC_TRIP_BIN="$BIN" PYTHONPATH="$REPO" exec "$PY" -m layers.l1_tripwire.trip $name "\$@"
EOF
  chmod 755 "$BIN/$name"
done

for name in coc-view coc-status coc-verify coc-unlock coc-setkey; do
  cat > "$BIN/$name" <<EOF
#!/bin/sh
COC_TRIP_BIN="$BIN" PYTHONPATH="$REPO" exec "$PY" -m layers.l1_tripwire.coc $name "\$@"
EOF
  chmod 755 "$BIN/$name"
done

cat > "$PREFIX/profile.sh" <<EOF
# Chain of Custody Layer 1: tripwire first in PATH, cd into the log dir alerts.
case ":\$PATH:" in *":$BIN:"*) ;; *) PATH="$BIN:\$PATH" ;; esac
export PATH
cd() {
  case ":\$PATH:" in
    *":$BIN:"*) COC_TRIP_BIN="$BIN" PYTHONPATH="$REPO" "$PY" -m layers.l1_tripwire.trip cd "\$@" ;;
  esac
  builtin cd "\$@"
}
EOF

if [ "$(id -u)" = 0 ] && [ "$PREFIX" = /opt/trip ]; then
  ln -sf "$PREFIX/profile.sh" /etc/profile.d/coc-trip.sh
  mkdir -p /var/spool/coc && chmod 1733 /var/spool/coc   # anyone can drop events, nobody can list or read others'
  echo "installed system-wide: new login shells get the tripwire"
else
  echo "installed in $PREFIX: run '. $PREFIX/profile.sh' to activate in this shell"
fi
