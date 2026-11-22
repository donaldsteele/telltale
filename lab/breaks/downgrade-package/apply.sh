#!/bin/sh
# Downgrades openssl and its library to the older pinned snapshot's versions, installed offline from /var/cache/telltale-lab/debs/openssl (fetched at image build). Needs a machine at the newer snapshot: run prepare.sh first.
# Runs as root inside a lab machine. Stand-ins are expected in /lab/standins.
set -eu
SI=/lab/standins
need() { [ -e "$SI/$1" ] || { echo "$0: $SI/$1 is missing (copy the stand-ins in first)" >&2; exit 1; }; }
D=/var/cache/telltale-lab/debs/openssl
cur=$(dpkg-query -W -f '${Version}' openssl)
old=$(dpkg-deb -f "$D"/openssl_*.deb Version)
dpkg --compare-versions "$old" lt "$cur" || { echo "$0: the cached openssl $old is not older than the installed $cur (run prepare.sh first)" >&2; exit 1; }
dpkg -i "$D"/*.deb
