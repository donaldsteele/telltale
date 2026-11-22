#!/bin/sh
# A process whose program file was deleted after it started.
# Runs as root inside a lab machine. Stand-ins are expected in /lab/standins.
set -eu
SI=/lab/standins
need() { [ -e "$SI/$1" ] || { echo "$0: $SI/$1 is missing (copy the stand-ins in first)" >&2; exit 1; }; }
cp /usr/bin/sleep /usr/local/bin/lab-ghost
setsid nohup /usr/local/bin/lab-ghost 100000 </dev/null >/dev/null 2>&1 &
sleep 1
rm -f /usr/local/bin/lab-ghost
