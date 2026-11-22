#!/bin/sh
# A process running a program from /dev/shm.
# Runs as root inside a lab machine.
set -eu
cp /usr/bin/sleep /dev/shm/lab-dsleep
setsid nohup /dev/shm/lab-dsleep 100000 </dev/null >/dev/null 2>&1 &
sleep 1
pgrep -x lab-dsleep >/dev/null || { echo "$0: lab-dsleep did not start" >&2; exit 1; }
