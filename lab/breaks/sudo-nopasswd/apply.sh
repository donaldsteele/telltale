#!/bin/sh
# Adds a passwordless sudo rule for the lab user.
# Runs as root inside a lab machine.
set -eu
echo 'lab ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/90-lab-svc
chmod 440 /etc/sudoers.d/90-lab-svc
visudo -cf /etc/sudoers.d/90-lab-svc
