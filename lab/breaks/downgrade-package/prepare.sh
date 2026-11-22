#!/bin/sh
# Brings a machine from the older package snapshot up to the newer one, so
# apply.sh has something to downgrade from (and installs openssl, which the image
# lacks). Run before the clean snapshot is taken; needs network access to the
# snapshot hosts, so start the machine on a networked bridge for this step only.
set -eu
. /lab/os
. /lab/common/pins.env
if [ "$LAB_FAMILY" = debian ]; then ts=$DEBIAN_SNAPSHOT_NEWER; else ts=$UBUNTU_SNAPSHOT_NEWER; fi
/lab/common/set-snapshot.sh "$ts"
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssl
