#!/bin/sh
# A cron job that runs the callback stand-in (one connection to sink:4444) every minute.
# Runs as root inside a lab machine. Stand-ins are expected in /lab/standins.
set -eu
SI=/lab/standins
need() { [ -e "$SI/$1" ] || { echo "$0: $SI/$1 is missing (copy the stand-ins in first)" >&2; exit 1; }; }
need callback.sh
install -m 755 "$SI/callback.sh" /usr/local/bin/.lab-sync
echo '* * * * * root /usr/local/bin/.lab-sync' > /etc/cron.d/lab-update
chmod 644 /etc/cron.d/lab-update
