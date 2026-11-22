#!/bin/sh
# Container main process: cron in the background, sshd in the foreground.
mkdir -p /run/sshd
cron
exec /usr/sbin/sshd -D -e
