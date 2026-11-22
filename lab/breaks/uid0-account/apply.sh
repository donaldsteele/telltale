#!/bin/sh
# Adds a second account with user id 0.
# Runs as root inside a lab machine.
set -eu
useradd -o -u 0 -g 0 -M -d /root -s /bin/bash toor
passwd -l toor >/dev/null
