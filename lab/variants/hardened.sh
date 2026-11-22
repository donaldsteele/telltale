#!/bin/sh
# Hardened machine: meant to pass the whole checklist.
set -eu
cat > /etc/ssh/sshd_config.d/00-lab.conf <<EOT
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
AllowAgentForwarding no
AllowTcpForwarding no
PermitUserEnvironment no
HostbasedAuthentication no
IgnoreRhosts yes
LogLevel VERBOSE
EOT
/usr/sbin/sshd -t
# Password ageing and umask defaults.
sed -i -E 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t90/; s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t1/; s/^PASS_WARN_AGE.*/PASS_WARN_AGE\t7/; s/^UMASK.*/UMASK\t\t027/' /etc/login.defs
# Tighten cron and sudo access.
chmod 600 /etc/crontab
chmod 700 /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly
echo root > /etc/cron.allow
chmod 600 /etc/cron.allow
echo "Authorized use only." > /etc/issue.net
