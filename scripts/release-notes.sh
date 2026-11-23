#!/usr/bin/env bash
# Prints the changelog entry for a version: the lines under its
# "## vX.Y.Z" heading, up to the next "## " heading, without the blank
# lines around them. Fails when the changelog has no entry for the version
# (or an empty one): the release workflow uses it, so a release cannot go
# out without its notes.
#
# Usage: bash scripts/release-notes.sh VERSION [CHANGELOG]   (VERSION with or without the "v")
set -euo pipefail
v=${1:-}
changelog=${2:-"$(dirname "$0")/../CHANGELOG.md"}
v=${v#v}
case "$v" in
  "" | *[!0-9A-Za-z.+-]*)
    echo "release-notes.sh: '${1:-}' is not a version; the CHANGELOG entry cannot be found" >&2
    exit 1
    ;;
esac
notes=$(awk -v want="## v$v" '
  index($0, "## ") == 1 {
    if (found) exit
    split($0, w, " ")
    if (w[1] " " w[2] == want) { found = 1; next }
  }
  found { print }
' "$changelog")
# Trim leading and trailing blank lines.
notes=$(printf '%s\n' "$notes" | sed -e '/./,$!d')
if [ -z "$notes" ]; then
  echo "release-notes.sh: CHANGELOG has no entry for v$v ($changelog)" >&2
  exit 1
fi
printf '%s\n' "$notes"
