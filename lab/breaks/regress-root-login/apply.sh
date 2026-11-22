#!/bin/sh
# Turns SSH root login back on in the lab's sshd drop-in.
# Runs as root inside a lab machine. Stand-ins are expected in /lab/standins.
set -eu
SI=/lab/standins
need() { [ -e "$SI/$1" ] || { echo "$0: $SI/$1 is missing (copy the stand-ins in first)" >&2; exit 1; }; }
f=/etc/ssh/sshd_config.d/00-lab.conf
grep -q '^PermitRootLogin' "$f"
sed -i 's/^PermitRootLogin.*/PermitRootLogin yes/' "$f"
/usr/sbin/sshd -t
pkill -HUP -x sshd || true
