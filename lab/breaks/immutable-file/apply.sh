#!/bin/sh
# A file marked immutable on the ext4 volume, bind-mounted under /usr/local/lib so the file scan sees it.
# Runs as root inside a lab machine.
set -eu
[ -d /lab-ext4 ] || { echo "$0: /lab-ext4 is missing (start the machine with Ext4Volume)" >&2; exit 1; }
d=/lab-ext4/lab-cache
mkdir -p "$d" /usr/local/lib/lab-cache
echo 'lab stand-in: nothing here' > "$d/.helper"
mount --bind "$d" /usr/local/lib/lab-cache
chattr +i /usr/local/lib/lab-cache/.helper
