#!/bin/sh
# A break-in story: a world-writable script dropped under /var/www, a systemd
# timer that calls the sink, and a setuid copy of a shell in /var/tmp. The script is inert
# text; telltale's file inventory does not cover /var/www.
# Runs as root inside a lab machine; /lab/breaks and /lab/standins are in place.
set -eu
B=/lab/breaks
install -d -m 755 /var/www/html
printf '<?php /* lab stand-in: runs nothing */ ?>\n' > /var/www/html/upload.php
chmod 666 /var/www/html/upload.php
sh $B/systemd-callback/apply.sh
sh $B/setuid-shell/apply.sh
