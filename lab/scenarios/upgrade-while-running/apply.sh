#!/bin/sh
# A legitimate event that looks like trouble: a packaged program is running when
# its package is upgraded. lab-vendor 1.0 (installed by the thirdparty variant
# from the vendor's signed repository) is started, then apt upgrades it to 2.0
# from that repository, which replaces /opt/lab-vendor/bin/lab-vendord.
# Nothing here is a backdoor; see manifest.json.
set -eu
export DEBIAN_FRONTEND=noninteractive
setsid nohup /opt/lab-vendor/bin/lab-vendord 100000 </dev/null >/dev/null 2>&1 &
sleep 1
# The vendor's repository is the only one the lab network reaches.
apt-get update -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/lab-vendor.list \
  -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0
apt-get install -y --no-install-recommends lab-vendor=2.0
test "$(dpkg-query -W -f '${Version}' lab-vendor)" = 2.0
