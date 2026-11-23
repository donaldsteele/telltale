# Changelog

## v0.1.1 (2026-11-23)

Two fixes in the server's web UI, and the site now shows it.

- **Fixed: weak settings counted as changes.** A checklist item that already
  failed when the snapshot was taken was offered as a change since the
  snapshot, so the page of a machine that had not changed at all said, for
  example, "9 findings are changes since the snapshot", and the changes page
  listed its standing weak settings for acceptance. Only an item that held
  in the snapshot and fails now is a change. Carry mode was not affected:
  `telltale accept` records an exception.
- **Fixed:** on the machines page, the Check now cell's bottom border did
  not line up with the rest of its row.
- **Site:** screenshots and a recorded walk-through of the web UI and the
  alerts it sends to bubbles, made with the server in the test lab. In the
  numbered steps on How it works and Install, inline code no longer drops
  into a narrow column of its own.

The downloads are as in v0.1.0, named for 0.1.1.

## v0.1.0 (2026-11-23)

The first release.

- **Carry mode**: `telltale scan`, `snapshot`, `accept`, `collect` and
  `fetch-refs` check a Debian 12 or 13 or Ubuntu 22.04 or 24.04 machine
  (amd64 or arm64) against a known-good snapshot, the distribution's signed
  packages, a 44-item hardening checklist and the suspicious-on-any-machine
  checks, and print a ranked report as text, JSON or one HTML file. Every
  finding has the evidence and the command that would fix it; telltale
  never fixes anything itself.
- **The regression rule**: a checklist item that held in the snapshot and
  fails now is reported as tampering.
- **Package verification** against the official archives with archive keys
  built into telltale, older versions from the snapshot archives and
  Launchpad, third-party repositories with built-in vendor keys, keys
  recorded in the snapshot or keys you add, and reference bundles for
  isolated machines.
- **Cross-view checks**: processes, ports, files and modules that the
  machine's own `ps`, `ss`, `ls` and `lsmod` hide are reported as tampering.
- **The server**: visits enrolled machines over SSH on a schedule, keeps the
  snapshots and reports encrypted, and has a web UI for enrolment, review,
  accepting changes and exceptions, and an audit log. Alerts go to bubbles,
  and `telltale mcp` gives an AI assistant read-only tools and visit
  requests.
- **Downloads**: the collector build for carry mode
  (`telltale-carry_0.1.0_linux_<arch>.tar.gz`), the full build
  (`telltale_0.1.0_linux_<arch>.tar.gz`), and the server package
  (`telltale_0.1.0-1_<arch>.deb`), for amd64 and arm64. Each file is
  listed in `SHA256SUMS` and has a signed build provenance attestation
  (`gh attestation verify`); the tarballs are reproducible.
- **The test lab**: Docker machines with inert backdoors planted, checked
  against manifests in CI, on Debian 12 and Ubuntu 24.04, and on Debian 12
  arm64 under emulation.

Known limits are listed in the README under "What it cannot tell you".
