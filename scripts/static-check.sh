#!/usr/bin/env bash
# Fails if an ELF binary is dynamically linked (has a PT_INTERP segment).
# Usage: scripts/static-check.sh <binary>...
set -euo pipefail
[ "$#" -ge 1 ] || { echo "usage: static-check.sh <binary>..." >&2; exit 2; }
rc=0
for bin in "$@"; do
  if [ ! -f "$bin" ]; then
    echo "static-check: $bin: no such file" >&2
    rc=1
    continue
  fi
  if readelf -lW "$bin" | grep -qw INTERP; then
    echo "static-check: $bin is dynamically linked" >&2
    rc=1
  else
    echo "static-check: $bin is static"
  fi
done
exit "$rc"
