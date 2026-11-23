#!/usr/bin/env bash
# Checks what scripts/build.sh wrote before it is published: SHA256SUMS
# matches and names every tarball and package, each tarball and package
# holds what it should, every binary is static (scripts/static-check.sh)
# and built for the right architecture, and each is the right flavour: the
# collector build links none of the server's modules, the full build does.
# Fails closed: anything missing or unexpected is an error.
#
# Usage: bash scripts/check-dist.sh [DIR]     (default dist)
#        REQUIRE_DEB=1 bash scripts/check-dist.sh   (the .deb packages must be there)
#
# Needs readelf, go (go version -m reads the build information) and, when
# there are packages, dpkg-deb.
set -euo pipefail
cd "$(dirname "$0")/.."
DIST=${1:-dist}
case "$DIST" in -*) DIST=./$DIST ;; esac
ARCHES="amd64 arm64"
# Modules only the server and mcp commands use.
SERVER_MODULES="modernc.org/sqlite github.com/modelcontextprotocol/go-sdk github.com/donaldsteele/bubbles"

fail() {
  echo "check-dist: $*" >&2
  exit 1
}
for tool in readelf go; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is not installed"
done
[ -d "$DIST" ] || fail "$DIST is not a directory"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# check_binary FILE ARCH FLAVOUR (full or collector)
check_binary() {
  local f=$1 arch=$2 flavour=$3 machine info m
  bash scripts/static-check.sh "$f" >/dev/null || fail "$f is not a static binary"
  machine=$(readelf -hW "$f" | sed -n 's/^ *Machine: *//p')
  case "$arch:$machine" in
    amd64:*X86-64*| arm64:AArch64) ;;
    *) fail "$f is built for \"$machine\", not $arch" ;;
  esac
  info=$(go version -m "$f") || fail "go version -m $f failed"
  for m in $SERVER_MODULES; do
    if grep -q "^[[:space:]]*dep[[:space:]]*${m}[[:space:]]" <<<"$info"; then
      [ "$flavour" = full ] || fail "$f is meant to be the collector build but links $m"
    else
      [ "$flavour" = collector ] || fail "$f is meant to be the full build but does not link $m"
    fi
  done
  echo "ok  $f ($arch, $flavour)"
}

# one PATTERN: the single file in DIST matching PATTERN.
one() {
  local matches=()
  shopt -s nullglob
  # shellcheck disable=SC2206 # the pattern is meant to expand
  matches=("$DIST"/$1)
  shopt -u nullglob
  [ "${#matches[@]}" = 1 ] || fail "want exactly one $1 in $DIST, found ${#matches[@]}"
  printf '%s\n' "${matches[0]}"
}

[ -f "$DIST/SHA256SUMS" ] || fail "$DIST has no SHA256SUMS"
(cd "$DIST" && sha256sum --check --strict --quiet SHA256SUMS) || fail "SHA256SUMS does not match"

listed=$(awk '{print $2}' "$DIST/SHA256SUMS" | sort)
want=()
debs=0
for arch in $ARCHES; do
  want+=("$(basename "$(one "telltale_*_linux_$arch.tar.gz")")")
  want+=("$(basename "$(one "telltale-carry_*_linux_$arch.tar.gz")")")
  if [ "${REQUIRE_DEB:-}" = 1 ] || compgen -G "$DIST/telltale_*_$arch.deb" >/dev/null; then
    want+=("$(basename "$(one "telltale_*_$arch.deb")")")
    debs=1
  fi
done
[ "$listed" = "$(printf '%s\n' "${want[@]}" | sort)" ] ||
  fail "SHA256SUMS lists $(echo "$listed" | tr '\n' ' ')but $DIST holds $(printf '%s ' "${want[@]}")"
[ "$debs" = 0 ] || command -v dpkg-deb >/dev/null 2>&1 || fail "dpkg-deb is not installed"

for arch in $ARCHES; do
  check_binary "$DIST/bin/telltale-linux-$arch" "$arch" full
  check_binary "$DIST/collector/telltale-linux-$arch" "$arch" collector

  for flavour in full collector; do
    if [ "$flavour" = full ]; then
      tarball=$(one "telltale_*_linux_$arch.tar.gz")
    else
      tarball=$(one "telltale-carry_*_linux_$arch.tar.gz")
    fi
    out="$tmp/$flavour-$arch"
    mkdir -p "$out"
    tar -C "$out" -xzf "$tarball"
    [ "$(cd "$out" && find . -mindepth 1 | sort | tr '\n' ' ')" = "./LICENSE ./NOTICE ./README.md ./telltale " ] ||
      fail "$tarball holds $(cd "$out" && find . -mindepth 1 | sort | tr '\n' ' ')"
    check_binary "$out/telltale" "$arch" "$flavour"
  done

  [ "$debs" = 1 ] || continue
  deb=$(one "telltale_*_$arch.deb")
  [ "$(dpkg-deb -f "$deb" Package Architecture | tr '\n' ' ')" = "Package: telltale Architecture: $arch " ] ||
    fail "$deb: control says $(dpkg-deb -f "$deb" Package Architecture | tr '\n' ' ')"
  files=$(dpkg-deb -c "$deb" | awk '{print $1, $2, $NF}')
  for want in \
    "-rwxr-xr-x root/root ./usr/bin/telltale" \
    "-rwxr-xr-x root/root ./usr/lib/telltale/telltale-linux-amd64" \
    "-rwxr-xr-x root/root ./usr/lib/telltale/telltale-linux-arm64" \
    "-rw-r--r-- root/root ./lib/systemd/system/telltale.service" \
    "-rw-r--r-- root/root ./etc/telltale/telltale.toml.example" \
    "-rw-r--r-- root/root ./usr/share/doc/telltale/copyright"; do
    grep -qxF -- "$want" <<<"$files" || fail "$deb lacks $want"
  done
  out="$tmp/deb-$arch"
  dpkg-deb -x "$deb" "$out"
  check_binary "$out/usr/bin/telltale" "$arch" full
  for a in $ARCHES; do
    check_binary "$out/usr/lib/telltale/telltale-linux-$a" "$a" collector
  done
done
echo "check-dist: $DIST is complete"
