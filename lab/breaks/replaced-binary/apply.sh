#!/bin/sh
# Appends one byte to /usr/bin/id (still runs, different hash).
# Runs as root inside a lab machine. Stand-ins are expected in /lab/standins.
set -eu
SI=/lab/standins
need() { [ -e "$SI/$1" ] || { echo "$0: $SI/$1 is missing (copy the stand-ins in first)" >&2; exit 1; }; }
printf 'X' >> /usr/bin/id
