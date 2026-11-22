#!/bin/sh
# Locally built software: a program in /usr/local/bin and a setuid helper in /usr/local/sbin.
# False-positive controls for the exception handling.
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends gcc libc6-dev
cd "$(mktemp -d)"
cat > hello.c <<'EOT'
#include <stdio.h>
int main(void) { puts("lab-hello 1.0"); return 0; }
EOT
cat > helper.c <<'EOT'
#include <stdio.h>
#include <unistd.h>
int main(void) { printf("lab-helper running as euid %d\n", (int)geteuid()); return 0; }
EOT
gcc -O2 -o /usr/local/bin/lab-hello hello.c
gcc -O2 -o /usr/local/sbin/lab-helper helper.c
chown root:root /usr/local/bin/lab-hello /usr/local/sbin/lab-helper
chmod 755 /usr/local/bin/lab-hello
chmod 4755 /usr/local/sbin/lab-helper
apt-get purge -y gcc libc6-dev
apt-get autoremove -y --purge
rm -rf /var/lib/apt/lists/*
