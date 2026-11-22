#!/bin/sh
# Point apt at a snapshot archive: set-snapshot.sh TIMESTAMP
# Reads the family and codename that setup.sh recorded in /lab/os.
set -eu
ts=$1
. /lab/os
rm -f /etc/apt/sources.list /etc/apt/sources.list.d/debian.sources /etc/apt/sources.list.d/ubuntu.sources
if [ "$LAB_FAMILY" = debian ]; then
  cat > /etc/apt/sources.list.d/lab-snapshot.sources <<EOT
Types: deb
URIs: http://snapshot.debian.org/archive/debian/$ts/
Suites: $LAB_CODENAME $LAB_CODENAME-updates
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg

Types: deb
URIs: http://snapshot.debian.org/archive/debian-security/$ts/
Suites: $LAB_CODENAME-security
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
EOT
else
  cat > /etc/apt/sources.list.d/lab-snapshot.sources <<EOT
Types: deb
URIs: http://snapshot.ubuntu.com/ubuntu/$ts/
Suites: $LAB_CODENAME $LAB_CODENAME-updates $LAB_CODENAME-security
Components: main restricted universe
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
EOT
fi
