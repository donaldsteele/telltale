// Package keys holds the archive signing keys built into telltale. Package
// verification checks archive indexes against these keys only, never against
// the keyring of the machine being examined.
//
// Provenance (the keys themselves fall under no copyright):
//
//   - debian-archive-keyring.pgp: /usr/share/keyrings/debian-archive-keyring.pgp
//     from the debian-archive-keyring package, version 2025.1 (Debian 13),
//     SHA-256 506b815cbb32d9b6066b4a2aa524071e071761e7e7f68c3ac74f3061ba852017.
//     It holds the bullseye, bookworm and trixie archive, security and stable
//     release keys.
//   - ubuntu-archive-keyring.pgp: /usr/share/keyrings/ubuntu-archive-keyring.gpg
//     from the ubuntu-keyring package, version 2023.11.28.1 (Ubuntu 24.04),
//     SHA-256 80a36b0a6de2f69f49d2df75ef473ccde121e9e190b9ea01d20a4f63778d5c31.
//     It holds the 2012 and 2018 archive keys and the 2012 CD image key.
//
// Replacing either file changes which archives telltale trusts; the pinned
// fingerprints in the pkgverify tests must change with it.
package keys

import _ "embed"

// Debian is the binary OpenPGP keyring of the Debian archive keys.
//
//go:embed debian-archive-keyring.pgp
var Debian []byte

// Ubuntu is the binary OpenPGP keyring of the Ubuntu archive keys.
//
//go:embed ubuntu-archive-keyring.pgp
var Ubuntu []byte
