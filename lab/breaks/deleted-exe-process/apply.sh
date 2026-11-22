#!/bin/sh
# A process whose program file was deleted after it started.
# Runs as root inside a lab machine.
set -eu
cp /usr/bin/sleep /usr/local/bin/lab-ghost
setsid nohup /usr/local/bin/lab-ghost 100000 </dev/null >/dev/null 2>&1 &
sleep 1
pgrep -x lab-ghost >/dev/null || { echo "$0: lab-ghost did not start" >&2; exit 1; }
rm -f /usr/local/bin/lab-ghost
