#!/bin/sh
# Installs lighttpd and the dependencies the image lacks, offline from /var/cache/telltale-lab/debs/lighttpd (fetched at image build); it listens on TCP 80.
# Runs as root inside a lab machine. Stand-ins are expected in /lab/standins.
set -eu
SI=/lab/standins
need() { [ -e "$SI/$1" ] || { echo "$0: $SI/$1 is missing (copy the stand-ins in first)" >&2; exit 1; }; }
D=/var/cache/telltale-lab/debs/lighttpd
dpkg -i "$D"/*.deb
ss -ltn | grep -q ':80 ' || lighttpd -f /etc/lighttpd/lighttpd.conf
sleep 1
