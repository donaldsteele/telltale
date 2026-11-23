#!/usr/bin/env bash
# Builds static telltale binaries for linux/amd64 and linux/arm64.
# Writes dist/telltale_<version>_linux_<arch>.tar.gz (binary + README.md +
# LICENSE + NOTICE), the unpacked binaries dist/bin/telltale-linux-<arch>,
# and dist/SHA256SUMS.
#
# Usage: bash scripts/build.sh                     (VERSION from git describe)
#        VERSION=0.1.0 bash scripts/build.sh       (a leading "v" is dropped)
#        RELEASE=1 VERSION=v0.1.0 bash scripts/build.sh
#        TELLTALE_DIST_DIR=/tmp/out bash scripts/build.sh   (writes there, not dist/)
#
# The output directory is emptied first, dist/ or the one given (a relative
# one is relative to the repository).
#
# LICENSE and NOTICE are always required. A missing README.md is a warning,
# or an error with RELEASE=1.
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

MODULE=github.com/donaldsteele/telltale
LDFLAGS="-s -w -X $MODULE/internal/version.Version=$VERSION"
ARCHES="amd64 arm64"
DIST="${TELLTALE_DIST_DIR:-dist}"
case "$DIST" in
  "" | / | . | .. | ./ | ../)
    echo "build.sh: TELLTALE_DIST_DIR '$DIST' would empty more than an output directory" >&2
    exit 2
    ;;
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

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$@"
  else
    shasum -a 256 "$@"
  fi
}

rm -rf "$DIST"
mkdir -p "$DIST/bin"
dist_abs="$(cd "$DIST" && pwd)"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT

echo "telltale version: $VERSION"
for arch in $ARCHES; do
  pkg="$stage/linux-$arch"
  mkdir -p "$pkg"
  echo "building linux/$arch"
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
    go build -trimpath -ldflags "$LDFLAGS" -o "$pkg/telltale" ./cmd/telltale
  cp "${docs[@]}" "$pkg/"
  cp "$pkg/telltale" "$dist_abs/bin/telltale-linux-$arch"

  tarname="telltale_${VERSION}_linux_${arch}.tar.gz"
  tar -C "$pkg" -czf "$dist_abs/$tarname" telltale "${docs[@]}"
  echo "wrote $DIST/$tarname"
done

(cd "$DIST" && sha256 telltale_*.tar.gz > SHA256SUMS)
echo "wrote $DIST/SHA256SUMS"
