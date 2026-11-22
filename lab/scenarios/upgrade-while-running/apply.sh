#!/bin/sh
# A legitimate event that looks like trouble: a packaged program is running when
# its package is upgraded. lab-vendor 1.0 (installed by the thirdparty variant)
# is started, then lab-vendor 2.0 replaces /opt/lab-vendor/bin/lab-vendord.
# Nothing here is a backdoor; see manifest.json.
set -eu
arch=$(dpkg --print-architecture)
setsid nohup /opt/lab-vendor/bin/lab-vendord 100000 </dev/null >/dev/null 2>&1 &
sleep 1
dpkg -i "/lab/debs/lab-vendor_2.0_$arch.deb"
