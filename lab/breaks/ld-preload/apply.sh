#!/bin/sh
# Lists a library that exists (the inert PAM stand-in, which exports nothing a program calls) in /etc/ld.so.preload.
# Runs as root inside a lab machine. Stand-ins are expected in /lab/standins.
set -eu
SI=/lab/standins
need() { [ -e "$SI/$1" ] || { echo "$0: $SI/$1 is missing (copy the stand-ins in first)" >&2; exit 1; }; }
need pam_lab.so
install -m 644 "$SI/pam_lab.so" /usr/local/lib/libsync.so
echo /usr/local/lib/libsync.so > /etc/ld.so.preload
