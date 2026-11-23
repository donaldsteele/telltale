#!/bin/sh
# A break-in story: a guessed password for the lab user, then a root key, a cron
# callback hidden with ld.so.preload, and root login turned back on.
#
# Step by step (the project site tells the story with these lines):
# - The account "lab" has a weak password, password123, and the attacker
#   guesses it over SSH.
# - They get root (the story skips how) and add their own SSH key to root's
#   authorized_keys, so they can come back without the password.
# - They add a cron job, /etc/cron.d/lab-update, that connects out to their
#   machine every minute.
# - They load a small library from /etc/ld.so.preload that hides their
#   listening program, lab-hidden on port 31337, from ps and ss.
# - They turn SSH root login back on, so their key lets them straight in as
#   root.
#
# Runs as root inside a lab machine; /lab/breaks and /lab/standins are in place.
set -eu
B=/lab/breaks
echo 'lab:password123' | chpasswd
sh $B/root-key/apply.sh
sh $B/cron-callback/apply.sh
sh $B/hider-rootkit/apply.sh
sh $B/regress-root-login/apply.sh
