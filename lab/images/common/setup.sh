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
apt-get install -y --no-install-recommends \
  openssh-server iproute2 procps kmod ca-certificates sudo cron e2fsprogs
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
