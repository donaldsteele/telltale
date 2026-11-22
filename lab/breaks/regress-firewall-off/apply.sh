#!/bin/sh
# Switches ufw off (ENABLED=no in /etc/ufw/ufw.conf); the hardened variant ships it on.
# Runs as root inside a lab machine.
set -eu
f=/etc/ufw/ufw.conf
grep -q '^ENABLED=yes' "$f" || { echo "$0: ufw is not enabled here; use the hardened variant" >&2; exit 1; }
sed -i 's/^ENABLED=.*/ENABLED=no/' "$f"
