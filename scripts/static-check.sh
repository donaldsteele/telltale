#!/usr/bin/env bash
# Fails if an ELF binary is dynamically linked (has a PT_INTERP segment).
# Fails closed: a missing readelf, a non-ELF or unreadable file, or any
# readelf error is a failure, never a pass.
# Usage: scripts/static-check.sh <binary>...
set -euo pipefail
[ "$#" -ge 1 ] || { echo "usage: static-check.sh <binary>..." >&2; exit 2; }
if ! command -v readelf >/dev/null 2>&1; then
  echo "static-check: readelf not found" >&2
  exit 1
fi
rc=0
for bin in "$@"; do
  if [ ! -f "$bin" ]; then
    echo "static-check: $bin: no such file" >&2
    rc=1
    continue
  fi
  if ! hdr="$(readelf -hW "$bin" 2>&1)"; then
    echo "static-check: $bin: not a readable ELF file (readelf failed)" >&2
    rc=1
    continue
  fi
  if ! phdrs="$(readelf -lW "$bin" 2>&1)"; then
    echo "static-check: $bin: readelf -l failed" >&2
    rc=1
    continue
  fi
  case "$hdr" in
    *"Class:"*) ;;
    *)
      echo "static-check: $bin: no ELF header found" >&2
      rc=1
      continue
      ;;
  esac
  if grep -qw INTERP <<<"$phdrs"; then
    echo "static-check: $bin is dynamically linked" >&2
    rc=1
  else
    echo "static-check: $bin is static"
  fi
done
exit "$rc"
