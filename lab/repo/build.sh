#!/bin/sh
# Builds the lab's third-party APT repository inside the image build:
# lab-vendor 1.0 and 2.0, two signing keys generated here (so no key is ever
# in git), and two trees holding the same packages:
#
#   /repo/a  signed with the vendor's key
#   /repo/b  signed with a second key: the repository as a machine sees it
#            after it was pointed at a swapped copy
#
# Each tree is served as the site root: /lab-vendor is the repository
# (dists/stable, pool) and /keys holds both public keys, armored.
set -eu
arch=$(dpkg --print-architecture)

# lab-vendor: a stand-in for a vendor package that links a cron job into
# /etc/cron.daily from its postinst, the way Chrome's package does, and ships
# a long-running program. 2.0 differs from 1.0 by one byte of that program
# and by a line of the cron job, so an upgrade changes a file telltale
# records on every machine (the job the cron link runs).
mkdir -p /tmp/debs
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
  cp /src/lab-vendord "$root/opt/lab-vendor/bin/lab-vendord"
  [ "$v" = 1.0 ] || printf '\n' >> "$root/opt/lab-vendor/bin/lab-vendord"
  printf '#!/bin/sh\n# lab-vendor %s daily job\nexit 0\n' "$v" > "$root/opt/lab-vendor/cron/lab-vendor"
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
  dpkg-deb --root-owner-group --build "$root" "/tmp/debs/lab-vendor_${v}_$arch.deb" >/dev/null
  rm -rf "$root"
}
build_vendor 1.0
build_vendor 2.0

GNUPGHOME=$(mktemp -d)
export GNUPGHOME
chmod 700 "$GNUPGHOME"
key_a=lab-vendor@lab.invalid
key_b=lab-vendor-replacement@lab.invalid
gpg --batch --quiet --pinentry-mode loopback --passphrase '' --quick-generate-key "Lab Vendor repository <$key_a>" rsa3072 sign never
gpg --batch --quiet --pinentry-mode loopback --passphrase '' --quick-generate-key "Lab Vendor repository (replacement) <$key_b>" rsa3072 sign never

tree() {
  t=$1
  key=$2
  r=/repo/$t/lab-vendor
  mkdir -p "$r/pool/main/l/lab-vendor" "$r/dists/stable/main/binary-$arch" "/repo/$t/keys"
  cp /tmp/debs/*.deb "$r/pool/main/l/lab-vendor/"
  (cd "$r" && apt-ftparchive packages pool > "dists/stable/main/binary-$arch/Packages")
  gzip -9nk "$r/dists/stable/main/binary-$arch/Packages"
  # No Valid-Until, like many vendor repositories.
  apt-ftparchive \
    -o APT::FTPArchive::Release::Origin="Lab Vendor" \
    -o APT::FTPArchive::Release::Label="Lab Vendor" \
    -o APT::FTPArchive::Release::Suite=stable \
    -o APT::FTPArchive::Release::Codename=stable \
    -o APT::FTPArchive::Release::Architectures="$arch" \
    -o APT::FTPArchive::Release::Components=main \
    release "$r/dists/stable" > /tmp/Release
  mv /tmp/Release "$r/dists/stable/Release"
  gpg --batch --quiet --pinentry-mode loopback --passphrase '' --local-user "$key" --digest-algo SHA256 \
    --clearsign -o "$r/dists/stable/InRelease" "$r/dists/stable/Release"
  gpg --batch --quiet --pinentry-mode loopback --passphrase '' --local-user "$key" --digest-algo SHA256 \
    --armor --detach-sign -o "$r/dists/stable/Release.gpg" "$r/dists/stable/Release"
  gpg --batch --armor --export "$key_a" > "/repo/$t/keys/lab-vendor.asc"
  gpg --batch --armor --export "$key_b" > "/repo/$t/keys/lab-vendor-swapped.asc"
}
tree a "$key_a"
tree b "$key_b"
gpgconf --kill all 2>/dev/null || true
rm -rf "$GNUPGHOME" /tmp/debs
find /repo -type d -exec chmod 755 {} + && find /repo -type f -exec chmod 644 {} +
