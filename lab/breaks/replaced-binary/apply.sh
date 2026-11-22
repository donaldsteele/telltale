#!/bin/sh
# Appends one byte to /usr/bin/id (still runs, different hash).
# Runs as root inside a lab machine.
set -eu
printf 'X' >> /usr/bin/id
