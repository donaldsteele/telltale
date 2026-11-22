#!/bin/sh
# A systemd service and timer that run the callback stand-in, with the enabled link.
# Runs as root inside a lab machine. Stand-ins are expected in /lab/standins.
set -eu
SI=/lab/standins
need() { [ -e "$SI/$1" ] || { echo "$0: $SI/$1 is missing (copy the stand-ins in first)" >&2; exit 1; }; }
need callback.sh
install -m 755 "$SI/callback.sh" /usr/local/bin/.lab-sync
cat > /etc/systemd/system/lab-sync.service <<'EOT'
[Unit]
Description=Lab sync

[Service]
Type=oneshot
ExecStart=/usr/local/bin/.lab-sync
EOT
cat > /etc/systemd/system/lab-sync.timer <<'EOT'
[Unit]
Description=Lab sync timer

[Timer]
OnBootSec=1min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
EOT
chmod 644 /etc/systemd/system/lab-sync.service /etc/systemd/system/lab-sync.timer
# What `systemctl enable lab-sync.timer` creates.
mkdir -p /etc/systemd/system/timers.target.wants
ln -s /etc/systemd/system/lab-sync.timer /etc/systemd/system/timers.target.wants/lab-sync.timer
