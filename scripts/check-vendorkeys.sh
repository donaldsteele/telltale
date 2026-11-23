#!/usr/bin/env bash
# Pre-release check of the vendor keys built into telltale
# (internal/pkgverify/vendorkeys). Fetches each vendor's key again from its
# official address and compares it with the pinned fingerprints.
#
# Fails (exit 1) when a pinned key has expired: such a key verifies nothing,
# and the vendor's current key must be fetched and checked against the
# vendor's published fingerprint before a release.
# Warns (exit 0) when a pinned key expires within 90 days, when the key a
# vendor serves no longer matches its pin (a rotation), or when a key
# address cannot be fetched.
#
# Needs network access. Usage: bash scripts/check-vendorkeys.sh
set -euo pipefail
cd "$(dirname "$0")/.."
exec go run ./tools/vendorkeys check
