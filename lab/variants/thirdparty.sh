#!/bin/sh
# Owner-added third-party APT sources, each with its own key: Tailscale, and
# the lab's own signed repository.
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
apt-get install -y --no-install-recommends tailscale=1.104.7

# Real-world patterns that are not backdoors (false-positive controls).
#
# (a) A vendor's own signed APT repository, added the way an owner adds one:
# the vendor's key in a keyring the source names with signed-by, then the
# package through apt. The repository is the lab's (lab/repo, served as
# telltale-lab-repo; the image build reaches it through --add-host) and the
# package, lab-vendor, links a cron job into /etc/cron.daily from its
# postinst, the way Chrome's package does. Version 1.0 is installed; 2.0 is
# in the repository for the upgrade scenarios.
curl -fsS http://telltale-lab-repo/keys/lab-vendor.asc -o /usr/share/keyrings/lab-vendor.asc
echo "deb [signed-by=/usr/share/keyrings/lab-vendor.asc] http://telltale-lab-repo/lab-vendor stable main" \
  > /etc/apt/sources.list.d/lab-vendor.list
# The key a swapped copy of the repository is signed with, for the
# repo-key-swapped scenario (the machines have no way to fetch it later).
mkdir -p /lab/keys
curl -fsS http://telltale-lab-repo/keys/lab-vendor-swapped.asc -o /lab/keys/lab-vendor-swapped.asc
apt-get update
apt-get install -y --no-install-recommends lab-vendor=1.0
test -L /etc/cron.daily/lab-vendor
test -x /opt/lab-vendor/bin/lab-vendord

apt-get purge -y curl
rm -rf /var/lib/apt/lists/*

# (b) A user unit the way `systemctl --user enable` leaves it: the unit file in
# the user's home and the enabled link next to it, owned by the user (the lab
# user comes from the base image).
u=/home/lab/.config/systemd/user
install -d -o lab -g lab -m 755 /home/lab/.config /home/lab/.config/systemd "$u" "$u/default.target.wants"
cat > "$u/lab-agent.service" <<'EOT'
[Unit]
Description=Lab agent

[Service]
ExecStart=/usr/bin/sleep infinity

[Install]
WantedBy=default.target
EOT
chown lab:lab "$u/lab-agent.service"
chmod 644 "$u/lab-agent.service"
ln -s ../lab-agent.service "$u/default.target.wants/lab-agent.service"
chown -h lab:lab "$u/default.target.wants/lab-agent.service"
