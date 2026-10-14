#!/bin/sh
# Install the Layer 1 tripwire.  Usage: install.sh [PREFIX]   (default /opt/trip; system-wide needs root)
# Wraps every command listed under layer1 in config/layers.yaml. Re-run after changing that list.
# As root with the default prefix, also links the profile into /etc/profile.d so every login shell gets it.
set -eu
PREFIX="${1:-/opt/trip}"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
PY="$(command -v python3)"
BIN="$PREFIX/bin"
TRIP="env COC_TRIP_BIN=$BIN PYTHONPATH=$REPO $PY -m layers.l1_tripwire.trip"
mkdir -p "$BIN"
rm -f "$BIN"/*

COMMANDS="$($TRIP --list-commands)"
for name in $COMMANDS; do
  cat > "$BIN/$name" <<EOF
#!/bin/sh
COC_TRIP_BIN="$BIN" PYTHONPATH="$REPO" exec "$PY" -m layers.l1_tripwire.trip $name "\$@"
EOF
  chmod 755 "$BIN/$name"
done

{
  echo "# Chain of Custody Layer 1: tripwire first in PATH."
  echo "case \":\$PATH:\" in *\":$BIN:\"*) ;; *) PATH=\"$BIN:\$PATH\" ;; esac"
  echo "export PATH"
  if $TRIP --watch-cd; then
    echo "cd() { COC_TRIP_BIN=\"$BIN\" PYTHONPATH=\"$REPO\" \"$PY\" -m layers.l1_tripwire.trip cd \"\$@\"; builtin cd \"\$@\"; }"
  fi
} > "$PREFIX/profile.sh"

if [ "$(id -u)" = 0 ] && [ "$PREFIX" = /opt/trip ]; then
  ln -sf "$PREFIX/profile.sh" /etc/profile.d/coc-trip.sh
  mkdir -p /var/spool/coc && chmod 1733 /var/spool/coc   # anyone can drop events, nobody can list or read others'
  echo "installed system-wide for: $COMMANDS"
else
  echo "installed in $PREFIX for: $COMMANDS  (run '. $PREFIX/profile.sh' to activate)"
fi
