#!/bin/sh
# Turns SSH root login back on in the lab's sshd drop-in.
# Runs as root inside a lab machine.
set -eu
f=/etc/ssh/sshd_config.d/00-lab.conf
grep -q '^PermitRootLogin' "$f"
sed -i 's/^PermitRootLogin.*/PermitRootLogin yes/' "$f"
/usr/sbin/sshd -t
pkill -HUP -x sshd || true
