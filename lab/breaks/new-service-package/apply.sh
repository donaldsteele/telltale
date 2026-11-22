#!/bin/sh
# Installs lighttpd and the dependencies the image lacks, offline from /var/cache/telltale-lab/debs/lighttpd (fetched at image build); it listens on TCP 80.
# Runs as root inside a lab machine.
set -eu
D=/var/cache/telltale-lab/debs/lighttpd
dpkg -i "$D"/*.deb
ss -ltn | grep -q ':80 ' || lighttpd -f /etc/lighttpd/lighttpd.conf
sleep 1
ss -ltn | grep -q ':80 ' || { echo "$0: nothing listens on 80" >&2; exit 1; }
