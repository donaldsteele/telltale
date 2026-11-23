#!/usr/bin/env bash
# Builds telltale for linux/amd64 and linux/arm64, in two flavours, all
# static (CGO disabled):
#
#   full       every command, the server and mcp included
#   collector  go build -tags collector: version, collect, scan, snapshot,
#              accept and fetch-refs, without the server's code (web UI,
#              database, alerts, MCP). A server copies it to machines on each
#              visit; it is also the carry-mode download.
#
# It writes, in dist/:
#
#   telltale_<version>_linux_<arch>.tar.gz        the full binary, README.md, LICENSE, NOTICE
#   telltale-carry_<version>_linux_<arch>.tar.gz  the collector binary and the same files
#   telltale_<version>-1_<arch>.deb               the server package (below)
#   SHA256SUMS                                    for every tarball and package
#   bin/telltale-linux-<arch>                     the full binaries, unpacked
#   collector/telltale-linux-<arch>               the collector binaries, unpacked
#
# The .deb holds /usr/bin/telltale (full, for its architecture), the two
# collectors in /usr/lib/telltale/, the systemd unit and the example
# configuration. It is built with dpkg-deb in a Debian container, so it
# needs Docker; without Docker the packages are skipped with a warning (an
# error with RELEASE=1). TELLTALE_DEB=0 skips them on purpose.
#
# Usage: bash scripts/build.sh                     (VERSION from git describe)
#        VERSION=0.1.0 bash scripts/build.sh       (a leading "v" is dropped)
#        RELEASE=1 VERSION=v0.1.0 bash scripts/build.sh
#        TELLTALE_DIST_DIR=/tmp/out bash scripts/build.sh   (writes there, not dist/)
#
# The output directory, dist/ or the one given (a relative one is relative
# to the repository), is emptied first, but only when it is missing, empty
# or a previous build's output (scripts/dist-dir.sh); anything else is
# refused.
#
# LICENSE and NOTICE are always required. A missing README.md is a warning,
# or an error with RELEASE=1. scripts/check-dist.sh checks the result.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
VERSION="${VERSION#v}"
case "$VERSION" in
  "" | *[!A-Za-z0-9._+-]*)
    echo "build.sh: VERSION '$VERSION' may only contain letters, digits and . _ + -" >&2
    exit 2
    ;;
esac
# A Debian version starts with a digit and has no "_"; a build that is not
# from a version tag sorts below every release.
case "$VERSION" in
  [0-9]*.[0-9]*) DEBVERSION="$VERSION-1" ;;
  *) DEBVERSION="0.0.0~${VERSION}-1" ;;
esac
DEBVERSION="${DEBVERSION//_/+}"

MODULE=github.com/donaldsteele/telltale
LDFLAGS="-s -w -X $MODULE/internal/version.Version=$VERSION"
ARCHES="amd64 arm64"
# The lab's Debian 12 base image, pinned by digest; dpkg-deb runs in it.
DEB_IMAGE="debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc"
DIST="${TELLTALE_DIST_DIR:-dist}"
case "$DIST" in
  "" | / | . | .. | ./ | ../)
    echo "build.sh: TELLTALE_DIST_DIR '$DIST' would empty more than an output directory" >&2
    exit 2
    ;;
esac
# A relative name starting with "-" would read as an option to mkdir and cd.
case "$DIST" in
  -*) DIST=./$DIST ;;
esac

docs=()
for f in README.md LICENSE NOTICE; do
  if [ -f "$f" ]; then
    docs+=("$f")
  elif [ "$f" != README.md ] || [ "${RELEASE:-}" = 1 ]; then
    echo "build.sh: missing $f" >&2
    exit 1
  else
    echo "build.sh: warning: $f is missing; the tarballs will not include it" >&2
  fi
done

debs=1
if [ "${TELLTALE_DEB:-}" = 0 ]; then
  debs=0
elif ! docker version >/dev/null 2>&1; then
  if [ "${RELEASE:-}" = 1 ]; then
    echo "build.sh: Docker is needed to build the .deb packages (dpkg-deb runs in a container)" >&2
    exit 1
  fi
  echo "build.sh: warning: Docker is not usable here; the .deb packages are skipped" >&2
  debs=0
fi

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$@"
  else
    shasum -a 256 "$@"
  fi
}

. scripts/dist-dir.sh
prepare_dist "$DIST" || exit 2
mkdir -p "$DIST/bin" "$DIST/collector"
dist_abs="$(cd "$DIST" && pwd)"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT

echo "telltale version: $VERSION"
for arch in $ARCHES; do
  echo "building linux/$arch"
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
    go build -trimpath -ldflags "$LDFLAGS" -o "$dist_abs/bin/telltale-linux-$arch" ./cmd/telltale
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
    go build -trimpath -tags collector -ldflags "$LDFLAGS" -o "$dist_abs/collector/telltale-linux-$arch" ./cmd/telltale

  for flavour in full carry; do
    pkg="$stage/tar-$flavour-$arch"
    mkdir -p "$pkg"
    if [ "$flavour" = full ]; then
      cp "$dist_abs/bin/telltale-linux-$arch" "$pkg/telltale"
      tarname="telltale_${VERSION}_linux_${arch}.tar.gz"
    else
      cp "$dist_abs/collector/telltale-linux-$arch" "$pkg/telltale"
      tarname="telltale-carry_${VERSION}_linux_${arch}.tar.gz"
    fi
    cp "${docs[@]}" "$pkg/"
    tar -C "$pkg" -czf "$dist_abs/$tarname" telltale "${docs[@]}"
    echo "wrote $DIST/$tarname"
  done
done

# stage_deb ARCH lays out the server package for ARCH in $stage/deb-ARCH.
stage_deb() {
  local arch=$1 root="$stage/deb-$1" a size
  install -d -m 0755 "$root/DEBIAN" "$root/usr/bin" "$root/usr/lib/telltale" \
    "$root/lib/systemd/system" "$root/etc/telltale" "$root/usr/share/doc/telltale"
  install -m 0755 "$dist_abs/bin/telltale-linux-$arch" "$root/usr/bin/telltale"
  for a in $ARCHES; do
    install -m 0755 "$dist_abs/collector/telltale-linux-$a" "$root/usr/lib/telltale/telltale-linux-$a"
  done
  install -m 0644 deploy/systemd/telltale.service "$root/lib/systemd/system/telltale.service"
  install -m 0644 deploy/telltale.toml.example "$root/etc/telltale/telltale.toml.example"
  if [ -f README.md ]; then
    install -m 0644 README.md "$root/usr/share/doc/telltale/README.md"
  fi
  cat LICENSE NOTICE > "$root/usr/share/doc/telltale/copyright"
  chmod 0644 "$root/usr/share/doc/telltale/copyright"
  install -m 0755 deploy/debian/postinst deploy/debian/prerm deploy/debian/postrm "$root/DEBIAN/"
  install -m 0644 deploy/debian/conffiles "$root/DEBIAN/conffiles"
  size=$(du -sk "$root/usr" "$root/lib" "$root/etc" | awk '{s += $1} END {print s}')
  sed -e "s/@VERSION@/$DEBVERSION/" -e "s/@ARCH@/$arch/" -e "s/@SIZE@/$size/" \
    deploy/debian/control.in > "$root/DEBIAN/control"
}

if [ "$debs" = 1 ]; then
  for arch in $ARCHES; do
    stage_deb "$arch"
  done
  mkdir -p "$stage/out"
  # The container has no network, runs as the calling user and is removed
  # afterwards; --root-owner-group makes every file root's in the package.
  # Its label is its own, not the lab's: the lab's reaper removes every
  # telltale-lab container and must never stop a package build.
  # shellcheck disable=SC2086 # ARCHES is a list
  docker run --rm --network none --label telltale-build=1 \
    --user "$(id -u):$(id -g)" -v "$stage:/work" -w /work "$DEB_IMAGE" \
    sh -euc 'v=$1; shift; for a in "$@"; do dpkg-deb --root-owner-group -Zxz --build "deb-$a" "out/telltale_${v}_$a.deb"; done' \
    sh "$DEBVERSION" $ARCHES >/dev/null
  for arch in $ARCHES; do
    cp "$stage/out/telltale_${DEBVERSION}_${arch}.deb" "$dist_abs/"
    echo "wrote $DIST/telltale_${DEBVERSION}_${arch}.deb"
  done
fi

(
  cd "$DIST"
  shopt -s nullglob
  sha256 telltale_*.tar.gz telltale-carry_*.tar.gz telltale_*.deb > SHA256SUMS
)
echo "wrote $DIST/SHA256SUMS"
