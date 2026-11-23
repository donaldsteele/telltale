#!/usr/bin/env bash
# Makes the real reports the project site shows, in site/reports/: builds
# telltale as a release build is made (static, trimmed paths, the version
# linked in), runs the lab's TestGenerateSiteReports with it, and checks that
# every report is there. The test runs the two break-in scenarios, a clean
# machine and a scan without a snapshot on Debian 12 lab machines with the
# made-up names web01, files02 and build03, and fails if a report holds
# anything that identifies the computer running it (host name, user, home
# directory, addresses). Then, when Chrome or Chromium is at hand, it takes
# the screenshots of an HTML report the site's home page shows
# (site/assets/report-*.png).
#
# Needs Docker, like the lab. The Pages workflow runs it for every release
# tag and publishes the result, so the site shows what the release's
# telltale prints; a push to main runs it as a check. site/reports/ is not
# committed.
#
# Usage: bash scripts/site-reports.sh
#        VERSION=0.1.0 bash scripts/site-reports.sh        (default: git describe)
#        SITE_SCREENSHOTS=require bash scripts/site-reports.sh   (fail without Chrome)
#        SITE_SCREENSHOTS=skip bash scripts/site-reports.sh      (keep the committed ones)
set -euo pipefail
cd "$(dirname "$0")/.."

MODULE=github.com/donaldsteele/telltale
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
VERSION="${VERSION#v}"
case "$VERSION" in
  "" | *[!A-Za-z0-9._+-]*)
    echo "site-reports.sh: VERSION '$VERSION' may only contain letters, digits and . _ + -" >&2
    exit 1
    ;;
esac
arch="${TELLTALE_LAB_ARCH:-amd64}"
out=site/reports
names="weak-password-to-root no-snapshot web-shell-persistence clean"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

echo "site-reports.sh: telltale $VERSION, collector build for linux/$arch"
CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -tags collector \
  -ldflags "-s -w -X $MODULE/internal/version.Version=$VERSION" \
  -o "$work/telltale" ./cmd/telltale

mkdir -p "$out"
TELLTALE_SITE_BIN="$work/telltale" TELLTALE_SITE_REPORTS="$PWD/$out" \
  go test -tags 'lab site' -count=1 -timeout 40m ./lab/ -run '^TestGenerateSiteReports$'

# The lab skips everything, and passes, when Docker is short of disk space:
# only the files say whether the reports were made.
missing=0
for f in index.json $(for n in $names; do echo "$n.html $n.txt $n.json"; done); do
  [ -s "$out/$f" ] || { echo "site-reports.sh: $out/$f is missing" >&2; missing=1; }
done
if [ "$missing" != 0 ]; then
  echo "site-reports.sh: the site's reports could not all be made" >&2
  exit 1
fi
echo "site-reports.sh: wrote the reports in $out"

# Screenshots of the break-in report, light and dark, for the home page.
mode="${SITE_SCREENSHOTS:-auto}"
if [ "$mode" = skip ]; then
  exit 0
fi
chrome=""
for c in google-chrome google-chrome-stable chromium chromium-browser; do
  if command -v "$c" >/dev/null 2>&1; then
    chrome=$(command -v "$c")
    break
  fi
done
if [ -z "$chrome" ]; then
  if [ "$mode" = require ]; then
    echo "site-reports.sh: no Chrome or Chromium for the screenshots" >&2
    exit 1
  fi
  echo "site-reports.sh: no Chrome or Chromium: the screenshots in site/assets are left as they are"
  exit 0
fi
# shot REPORT SCHEME OUT: SCHEME 1 is light, 0 dark. The sandbox is tried
# first; some CI machines only run Chrome without it, and the page is our own
# file with no scripts.
shot() {
  local args=(--headless=new --disable-gpu --no-first-run --no-default-browser-check
    --user-data-dir="$work/chrome" --hide-scrollbars --force-device-scale-factor=2
    "--window-size=960,720" --blink-settings="preferredColorScheme=$2"
    --screenshot="$work/shot.png" "file://$PWD/$out/$1.html")
  rm -f "$work/shot.png"
  "$chrome" "${args[@]}" >/dev/null 2>&1 || "$chrome" --no-sandbox "${args[@]}" >/dev/null 2>&1 || true
  if [ ! -s "$work/shot.png" ]; then
    echo "site-reports.sh: Chrome made no screenshot of $1" >&2
    exit 1
  fi
  mv "$work/shot.png" "$3"
}
shot weak-password-to-root 1 site/assets/report-light.png
shot weak-password-to-root 0 site/assets/report-dark.png
echo "site-reports.sh: wrote site/assets/report-light.png and report-dark.png"
