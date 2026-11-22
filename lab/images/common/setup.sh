#!/bin/sh
# Shared image setup: setup.sh FAMILY CODENAME (debian|ubuntu)
set -eu
family=$1
codename=$2
. /lab/common/pins.env
if [ "$family" = debian ]; then ts=$DEBIAN_SNAPSHOT; else ts=$UBUNTU_SNAPSHOT; fi
printf 'LAB_FAMILY=%s\nLAB_CODENAME=%s\n' "$family" "$codename" > /lab/os
chmod +x /lab/common/*.sh

cat > /etc/apt/apt.conf.d/99lab <<EOT
Acquire::Check-Valid-Until "false";
Acquire::Retries "5";
APT::Install-Recommends "false";
APT::Install-Suggests "false";
EOT
export DEBIAN_FRONTEND=noninteractive
# Bootstrap: the snapshot hosts redirect to https and the base image has no CA
# bundle yet, so fetch ca-certificates once over the stock http sources
# (GPG-signed) before switching to the pinned snapshot.
apt-get update
apt-get install -y --no-install-recommends ca-certificates
/lab/common/set-snapshot.sh "$ts"
apt-get update
# Bring every package to the pinned snapshot, downgrading what the base image
# or the bootstrap above has newer, so the machine is at the pin as a whole
# (and packages that need an exact version of another one can be installed).
cat > /etc/apt/preferences.d/00lab-pin <<EOT
Package: *
Pin: origin "snapshot.$family.org"
Pin-Priority: 1001
EOT
[ "$family" = debian ] || sed -i 's/snapshot.ubuntu.org/snapshot.ubuntu.com/' /etc/apt/preferences.d/00lab-pin
apt-get -y --allow-downgrades dist-upgrade
rm -f /etc/apt/preferences.d/00lab-pin
apt-get install -y --no-install-recommends \
  openssh-server iproute2 procps kmod ca-certificates sudo cron e2fsprogs

# Packages for the offline break scripts (the build has network, the machines
# do not): this snapshot's openssl and its library, which the downgrade break
# installs over a newer pair, and lighttpd with the dependencies this image
# lacks, for the new-service break.
D=/var/cache/telltale-lab/debs
mkdir -p $D/openssl $D/lighttpd
# The library is libssl3 or libssl3t64 by release: take the installed one.
ssl=$(dpkg-query -W -f '${db:Status-Abbrev} ${Package}\n' 'libssl3*' | awk '$1 == "ii" {print $2}')
[ -n "$ssl" ]
# Take the pinned snapshot's version by name.
sslver=$(apt-cache madison openssl | awk -F'|' 'NR == 1 {gsub(/ /, "", $2); print $2}')
[ -n "$sslver" ]
(cd $D/openssl && apt-get download "openssl=$sslver" "$ssl=$sslver")
apt-get install -y --download-only lighttpd
cp /var/cache/apt/archives/*.deb $D/lighttpd/
# LAB_NEWER=1: the machine itself sits at the newer snapshot (upgraded, with
# openssl installed), so the downgrade break has the older .debs above to go
# back to without any network at run time.
if [ "${LAB_NEWER:-0}" = 1 ]; then
  if [ "$family" = debian ]; then newer=$DEBIAN_SNAPSHOT_NEWER; else newer=$UBUNTU_SNAPSHOT_NEWER; fi
  /lab/common/set-snapshot.sh "$newer"
  apt-get update
  apt-get -y upgrade
  apt-get install -y --no-install-recommends openssl
fi
# LAB_SYSTEMD=1: systemd as PID 1 (labkit Opts.Systemd), for the live unit test.
if [ "${LAB_SYSTEMD:-0}" = 1 ]; then
  apt-get install -y --no-install-recommends systemd systemd-sysv dbus
fi
apt-get clean
rm -rf /var/lib/apt/lists/*

# Accounts: a normal user with key-only login, root without a usable password.
useradd -m -s /bin/bash lab
usermod -p '*' lab
passwd -l root >/dev/null

# sshd: host keys at build time, root login off.
mkdir -p /run/sshd
ssh-keygen -A
cat > /etc/ssh/sshd_config.d/00-lab.conf <<EOT
PermitRootLogin no
EOT
grep -qs '^Include /etc/ssh/sshd_config.d' /etc/ssh/sshd_config ||
  sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config
/usr/sbin/sshd -t
