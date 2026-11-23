#!/bin/sh
# A third-party repository and its key are swapped together. After the
# snapshot the machine reaches, under the vendor's address, a copy of the
# repository signed with another key (here by pointing the name at another
# server; a hijacked mirror or DNS does the same), the keyring the APT source
# names is replaced with that key, and lab-vendor is upgraded from it. apt is
# satisfied: the machine's own keyring vouches for the new packages. A vendor
# rotating its key looks the same from the machine. The vendor's program is
# running throughout, as in upgrade-while-running. See manifest.json.
set -eu
export DEBIAN_FRONTEND=noninteractive
setsid nohup /opt/lab-vendor/bin/lab-vendord 100000 </dev/null >/dev/null 2>&1 &
sleep 1
ip=$(getent hosts telltale-lab-repo-swapped | awk '{print $1; exit}')
[ -n "$ip" ]
printf '%s telltale-lab-repo\n' "$ip" >> /etc/hosts
cp /lab/keys/lab-vendor-swapped.asc /usr/share/keyrings/lab-vendor.asc
apt-get update -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/lab-vendor.list \
  -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0
apt-get install -y --no-install-recommends lab-vendor=2.0
test "$(dpkg-query -W -f '${Version}' lab-vendor)" = 2.0
