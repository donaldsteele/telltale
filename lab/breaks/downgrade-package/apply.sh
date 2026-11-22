#!/bin/sh
# Downgrades openssl and its library to the older pinned snapshot's versions, installed offline from /var/cache/telltale-lab/debs/openssl (fetched at image build). Needs a machine at the newer snapshot (an image built with LAB_NEWER=1).
# Runs as root inside a lab machine.
set -eu
D=/var/cache/telltale-lab/debs/openssl
cur=$(dpkg-query -W -f '${Version}' openssl)
old=$(dpkg-deb -f "$D"/openssl_*.deb Version)
dpkg --compare-versions "$old" lt "$cur" || { echo "$0: the cached openssl $old is not older than the installed $cur (use an image built with LAB_NEWER=1)" >&2; exit 1; }
dpkg -i "$D"/*.deb
