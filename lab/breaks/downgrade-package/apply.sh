#!/bin/sh
# Downgrades openssl to the version in the older package snapshot. Needs network access to the snapshot hosts and a machine at the newer snapshot (run prepare.sh first).
# Runs as root inside a lab machine. Stand-ins are expected in /lab/standins.
set -eu
SI=/lab/standins
need() { [ -e "$SI/$1" ] || { echo "$0: $SI/$1 is missing (copy the stand-ins in first)" >&2; exit 1; }; }
. /lab/os
. /lab/common/pins.env
if [ "$LAB_FAMILY" = debian ]; then ts=$DEBIAN_SNAPSHOT; else ts=$UBUNTU_SNAPSHOT; fi
cur=$(dpkg-query -W -f '${Version}' openssl)
/lab/common/set-snapshot.sh "$ts"
apt-get update
old=
for v in $(apt-cache madison openssl | awk '{print $3}'); do
  if dpkg --compare-versions "$v" lt "$cur"; then old=$v; break; fi
done
[ -n "$old" ] || { echo "$0: no openssl older than $cur in snapshot $ts" >&2; exit 1; }
DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades "openssl=$old"
