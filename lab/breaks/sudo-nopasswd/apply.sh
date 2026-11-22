#!/bin/sh
# Adds a passwordless sudo rule for the lab user.
# Runs as root inside a lab machine. Stand-ins are expected in /lab/standins.
set -eu
SI=/lab/standins
need() { [ -e "$SI/$1" ] || { echo "$0: $SI/$1 is missing (copy the stand-ins in first)" >&2; exit 1; }; }
echo 'lab ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/90-lab-svc
chmod 440 /etc/sudoers.d/90-lab-svc
visudo -cf /etc/sudoers.d/90-lab-svc
