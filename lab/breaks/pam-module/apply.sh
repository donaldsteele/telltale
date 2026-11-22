#!/bin/sh
# Installs the inert PAM stand-in and lists it in /etc/pam.d/common-auth.
# Runs as root inside a lab machine. Stand-ins are expected in /lab/standins.
set -eu
SI=/lab/standins
need() { [ -e "$SI/$1" ] || { echo "$0: $SI/$1 is missing (copy the stand-ins in first)" >&2; exit 1; }; }
need pam_lab.so
dir=$(dirname "$(find /usr/lib /lib -name pam_unix.so 2>/dev/null | head -n 1)")
[ -d "$dir" ] || { echo "$0: no PAM module directory found" >&2; exit 1; }
install -m 644 "$SI/pam_lab.so" "$dir/pam_lab.so"
echo 'auth optional pam_lab.so' >> /etc/pam.d/common-auth
