#!/usr/bin/env bash
# repro_tar OUT DIR NAME...  writes OUT, a gzipped tar of the named files in
# DIR, the same bytes for the same content whoever builds it and whenever:
#
#   - names in sorted order (--sort=name orders what is inside a directory;
#     the names given are sorted here);
#   - every entry dated SOURCE_DATE_EPOCH (seconds since 1970; 0 when unset);
#   - root as owner and group, by number;
#   - modes 0755 for what is executable and 0644 for the rest, whatever the
#     builder's umask;
#   - no file name or time in the gzip header (gzip -n).
#
# Meant to be sourced: . scripts/repro-tar.sh
repro_tar() {
  local out=$1 dir=$2 names
  shift 2
  mapfile -t names < <(printf '%s\n' "$@" | LC_ALL=C sort)
  LC_ALL=C tar -C "$dir" --sort=name --mtime="@${SOURCE_DATE_EPOCH:-0}" \
    --owner=0 --group=0 --numeric-owner --mode='u+rw,go+rX,go-w,a-st' \
    --format=gnu -cf - -- "${names[@]}" | gzip -n -9 > "$out"
}
