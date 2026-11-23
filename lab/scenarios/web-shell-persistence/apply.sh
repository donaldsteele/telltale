#!/bin/sh
# A break-in story: a world-writable script dropped under /var/www, a systemd
# timer that calls the sink, and a setuid copy of a shell in /var/tmp. The script is inert
# text; telltale's file inventory does not cover /var/www.
#
# Step by step (the project site tells the story with these lines):
# - The attacker uploads a script through the web site, /var/www/html/upload.php,
#   writable by anyone. telltale does not look inside /var/www, so this file
#   is not in the report; what the attacker did next is.
# - They add a systemd service and timer, lab-sync, that connect out to their
#   machine every five minutes, and enable the timer.
# - They leave a setuid copy of bash at /var/tmp/.s: any account that runs it
#   becomes root.
#
# Runs as root inside a lab machine; /lab/breaks and /lab/standins are in place.
set -eu
B=/lab/breaks
install -d -m 755 /var/www/html
printf '<?php /* lab stand-in: runs nothing */ ?>\n' > /var/www/html/upload.php
chmod 666 /var/www/html/upload.php
sh $B/systemd-callback/apply.sh
sh $B/setuid-shell/apply.sh
