#!/bin/sh
# A process running a program from /dev/shm.
# Runs as root inside a lab machine. Stand-ins are expected in /lab/standins.
set -eu
SI=/lab/standins
need() { [ -e "$SI/$1" ] || { echo "$0: $SI/$1 is missing (copy the stand-ins in first)" >&2; exit 1; }; }
cp /usr/bin/sleep /dev/shm/lab-dsleep
setsid nohup /dev/shm/lab-dsleep 100000 </dev/null >/dev/null 2>&1 &
sleep 1
