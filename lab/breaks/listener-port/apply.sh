#!/bin/sh
# A program with no package listening on TCP 8081 (accepts and closes).
# Runs as root inside a lab machine. Stand-ins are expected in /lab/standins.
set -eu
SI=/lab/standins
need() { [ -e "$SI/$1" ] || { echo "$0: $SI/$1 is missing (copy the stand-ins in first)" >&2; exit 1; }; }
need listener
install -m 755 "$SI/listener" /usr/local/sbin/lab-svcd
setsid nohup /usr/local/sbin/lab-svcd 8081 </dev/null >/dev/null 2>&1 &
sleep 1
pgrep -x lab-svcd >/dev/null || { echo "$0: lab-svcd did not start" >&2; exit 1; }
ss -ltn | grep -q ':8081 ' || { echo "$0: nothing listens on 8081" >&2; exit 1; }
