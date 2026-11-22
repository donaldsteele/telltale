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
apt-get install -y --no-install-recommends tailscale=1.104.7
apt-get purge -y curl
rm -rf /var/lib/apt/lists/*

# Real-world patterns that are not backdoors (false-positive controls).
#
# (a) A local package that links a cron job into /etc/cron.daily from its
# postinst, the way Chrome's package does. Version 1.0 is installed; version
# 2.0 stays in /lab/debs for the upgrade-while-running scenario. lab-vendord is
# a copy of sleep (a real long-running program), with a byte more in 2.0.
arch=$(dpkg --print-architecture)
mkdir -p /lab/debs
build_vendor() {
  v=$1
  root=$(mktemp -d)
  mkdir -p "$root/DEBIAN" "$root/opt/lab-vendor/bin" "$root/opt/lab-vendor/cron"
  cat > "$root/DEBIAN/control" <<EOT
Package: lab-vendor
Version: $v
Architecture: $arch
Maintainer: Lab Vendor <vendor@lab.invalid>
Description: Lab stand-in for a vendor package that adds a daily cron job
EOT
  cp /usr/bin/sleep "$root/opt/lab-vendor/bin/lab-vendord"
  [ "$v" = 1.0 ] || printf '\n' >> "$root/opt/lab-vendor/bin/lab-vendord"
  printf '#!/bin/sh\nexit 0\n' > "$root/opt/lab-vendor/cron/lab-vendor"
  chmod 755 "$root/opt/lab-vendor/bin/lab-vendord" "$root/opt/lab-vendor/cron/lab-vendor"
  cat > "$root/DEBIAN/postinst" <<'EOT'
#!/bin/sh
set -e
ln -sf /opt/lab-vendor/cron/lab-vendor /etc/cron.daily/lab-vendor
EOT
  cat > "$root/DEBIAN/postrm" <<'EOT'
#!/bin/sh
set -e
if [ "$1" = remove ] || [ "$1" = purge ]; then rm -f /etc/cron.daily/lab-vendor; fi
EOT
  chmod 755 "$root/DEBIAN/postinst" "$root/DEBIAN/postrm"
  dpkg-deb --root-owner-group --build "$root" "/lab/debs/lab-vendor_${v}_$arch.deb" >/dev/null
  rm -rf "$root"
}
build_vendor 1.0
build_vendor 2.0
dpkg -i "/lab/debs/lab-vendor_1.0_$arch.deb"
test -L /etc/cron.daily/lab-vendor

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
