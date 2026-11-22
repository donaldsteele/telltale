#!/bin/sh
# Installs lighttpd, which listens on TCP 80. Needs network access to the package snapshot.
# Runs as root inside a lab machine. Stand-ins are expected in /lab/standins.
set -eu
SI=/lab/standins
need() { [ -e "$SI/$1" ] || { echo "$0: $SI/$1 is missing (copy the stand-ins in first)" >&2; exit 1; }; }
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y lighttpd
ss -ltn | grep -q ':80 ' || lighttpd -f /etc/lighttpd/lighttpd.conf
sleep 1
