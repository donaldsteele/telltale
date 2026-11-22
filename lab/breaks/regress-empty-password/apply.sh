#!/bin/sh
# Gives the lab user an empty password.
# Runs as root inside a lab machine.
set -eu
passwd -d lab >/dev/null
