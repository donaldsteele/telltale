#!/bin/sh
# Moves a package's directory out of the system paths (to /srv), leaves a
# link in its place, replaces one of the package's programs behind the link
# and turns another into a link to a file elsewhere. Nothing under /usr
# changed but the directory itself.
# Runs as root inside a lab machine.
set -eu
mv /usr/lib/openssh /srv/ssh-data
ln -s /srv/ssh-data /usr/lib/openssh
cp /bin/bash /srv/ssh-data/sftp-server
mkdir -p /var/lib/x
cp /bin/true /var/lib/x/evil
ln -sf /var/lib/x/evil /srv/ssh-data/ssh-pkcs11-helper
