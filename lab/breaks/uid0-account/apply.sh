#!/bin/sh
# Adds a second account with user id 0.
# Runs as root inside a lab machine. Stand-ins are expected in /lab/standins.
set -eu
SI=/lab/standins
need() { [ -e "$SI/$1" ] || { echo "$0: $SI/$1 is missing (copy the stand-ins in first)" >&2; exit 1; }; }
useradd -o -u 0 -g 0 -M -d /root -s /bin/bash toor
passwd -l toor >/dev/null
