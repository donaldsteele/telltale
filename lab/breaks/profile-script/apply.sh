#!/bin/sh
# A login script in /etc/profile.d that runs the callback stand-in.
# Runs as root inside a lab machine. Stand-ins are expected in /lab/standins.
set -eu
SI=/lab/standins
need() { [ -e "$SI/$1" ] || { echo "$0: $SI/$1 is missing (copy the stand-ins in first)" >&2; exit 1; }; }
need callback.sh
install -m 755 "$SI/callback.sh" /usr/local/bin/.lab-sync
cat > /etc/profile.d/lab-motd.sh <<'EOT'
/usr/local/bin/.lab-sync >/dev/null 2>&1 &
EOT
chmod 644 /etc/profile.d/lab-motd.sh
