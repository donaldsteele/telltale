#!/bin/sh
# Owner-added third-party APT source with its own key: Tailscale.
set -eu
. /lab/os
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends curl
curl -fsSL "https://pkgs.tailscale.com/stable/$LAB_FAMILY/$LAB_CODENAME.noarmor.gpg" \
  -o /usr/share/keyrings/tailscale-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/tailscale-archive-keyring.gpg] https://pkgs.tailscale.com/stable/$LAB_FAMILY $LAB_CODENAME main" \
  > /etc/apt/sources.list.d/tailscale.list
apt-get update
apt-get install -y --no-install-recommends tailscale
apt-get purge -y curl
rm -rf /var/lib/apt/lists/*
