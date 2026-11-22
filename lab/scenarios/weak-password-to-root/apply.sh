#!/bin/sh
# A break-in story: a guessed password for the lab user, then a root key, a cron
# callback hidden with ld.so.preload, and root login turned back on.
# Runs as root inside a lab machine; /lab/breaks and /lab/standins are in place.
set -eu
B=/lab/breaks
echo 'lab:password123' | chpasswd
sh $B/root-key/apply.sh
sh $B/cron-callback/apply.sh
sh $B/hider-rootkit/apply.sh
sh $B/regress-root-login/apply.sh
