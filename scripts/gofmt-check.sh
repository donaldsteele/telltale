#!/usr/bin/env bash
# Lists Go files that are not gofmt-clean and exits 1 if there are any.
# Every directory that holds Go code is checked: the commands, the packages,
# the lab, the tools, the scripts' tests and the embedded web files. Build
# output (dist/) is not source and is left out.
set -euo pipefail
cd "$(dirname "$0")/.."

dirs=()
for d in cmd internal lab tools scripts web e2e; do
  [ -d "$d" ] && dirs+=("$d")
done
[ "${#dirs[@]}" -eq 0 ] && exit 0

offending="$(gofmt -l "${dirs[@]}")"
if [ -n "$offending" ]; then
  echo "$offending"
  echo "gofmt: the files above need formatting (run: gofmt -w <file>)" >&2
  exit 1
fi
