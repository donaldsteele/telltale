# How telltale works

telltale has two halves. **Collection** runs on the machine and reads
everything it needs into one record. **Judging** compares that record with
the snapshot, with the distribution's signed packages, with the checklist
and with the suspicious-on-any-machine rules, and ranks what it finds. In
carry mode both halves run on the machine. In server mode only collection
runs there: the server copies the collector over, reads the record back over
SSH, and does all the judging itself, so the machine needs no internet access
and the judging logic and the package cache stay on the trusted side.

## The trust model: the machine may lie

A machine worth checking may already belong to someone else, and whoever
has root on it can change any file, program or database on it. telltale is
built around that.

- **It brings its own code.** telltale is one static binary (built without
  cgo) that loads none of the machine's libraries, so a replaced libc or an
  `/etc/ld.so.preload` entry cannot hook it. It uses Go's own DNS resolver
  and TLS.
- **It reads the kernel's and the filesystem's view directly.** Processes
  come from `/proc`, sockets from `/proc/net`, files from the filesystem,
  packages from `/var/lib/dpkg/status`. It never runs the machine's
  programs, with one exception: the cross-view check below.
- **It compares with the machine's own tools.** telltale runs `ps`, `ss`,
  `ls` and `lsmod` (only from `/usr/bin`, `/usr/sbin`, `/bin` and `/sbin`,
  with a clean environment) and compares what they print with what it
  reads itself. A process, port, file or module that telltale sees and a
  tool hides is reported as tampering: it is what a userland rootkit does.
  The comparison is built to avoid false alarms: things that appear or go
  away while it runs are read again, and a hidden file whose directory keeps
  changing (one that is being written to) is not reported, because that is
  not something telltale can tell apart from normal activity reliably.
- **The snapshot never lives on the machine.** In carry mode you keep the
  snapshot file somewhere else, encrypted with a passphrase. In server mode
  the server keeps it, encrypted at rest, and hands it to nothing: the
  collector on the machine never sees it, and it is never written to the
  machine's disk.
- **Keys are built in, never taken from the machine.** The Debian and Ubuntu
  archive keys are built into telltale. The machine's keyrings and the
  checksums in its package database are never used as proof of anything
  (root can edit both); the one exception is `scan --offline`, which says so
  at the top of the report.
- **Third-party repositories are trusted only with a key bound to them.**
  telltale has the keys of ten well-known vendors built in (Google Chrome,
  Microsoft, Docker, GitHub CLI, PostgreSQL PGDG, Grafana, Elastic,
  Mozilla, Brave and 1Password; the list is in
  `internal/pkgverify/vendorkeys/vendors.json`), each pinned by fingerprint
  to its vendor's repository addresses, and added only when the key served
  on the vendor's site matched a fingerprint the vendor publishes somewhere
  else. HashiCorp's key is not among them, because its fingerprint could
  not be confirmed that way; to trust HashiCorp's repository, add its key
  as an owner key in the server's settings, or pass it with `--keys` in
  carry mode. The snapshot records the keys the
  machine trusted for each third-party repository when it was clean, and
  later upgrades from that repository are verified with those keys (key
  continuity); if the machine trusts a different key now, that is reported.
  And you can add a key yourself (`--keys`, or on the server, where a key is
  bound to the repository address you give with it).
- **The machine's clock is not trusted either.** Signature dates and the
  "valid until" dates of the archive's signed indexes are checked against
  the newest date the archive itself signed, not against the machine's
  clock, which root can set. A clock far off is reported as a note.
- **No secrets are kept.** Password hashes are reduced to a keyed digest
  (so a changed password still shows as a change), private key files are
  recorded by hash, permissions and owner only, and in the text telltale
  keeps from startup files, secrets (`Environment=` values, exported
  tokens, `password=...`, the password in a URL) are replaced by keyed
  digests. Reports and alerts carry only redacted lines.
- **A user's link cannot aim the scan at root's files.** The scan runs as
  root and reads startup files that ordinary users own (shell start-up
  files, systemd user units). Where one of those is a symbolic link, the
  text behind it is kept only when the link's owner could have read it
  anyway: root owns the link, or the link's owner owns the target, or
  everyone may read it. A link on the way that a non-root account owns is
  not followed (except a user's own link on the way to that user's own
  start-up file or key file, such as `~/.ssh` kept in a dotfiles directory,
  and then only to files that user could read), nothing is read through
  `/proc`, and the password files,
  their backups and anything holding a private key are never kept. The
  link itself is still recorded and reported, with a note that its content
  was not read.

What no on-machine check can rule out is a **kernel-level rootkit**: code in
the kernel can hide anything from anything that runs on top of it, telltale
included. Every report says so. Checking the disk from another, trusted
machine is the only answer, and it is planned for a later version.

## Package verification

For each installed package, telltale wants to know whether the files on disk
are the ones the distribution shipped.

1. It reads the installed packages and versions from `/var/lib/dpkg/status`.
2. It fetches the distribution's signed index (`InRelease`) from the
   official archive, checks the signature with the archive keys built into
   telltale, and follows the chain of hashes from there to the `Packages`
   index and on to each `.deb`'s SHA-256. The archives are fetched over
   plain HTTP, as apt does by default: the signatures, not the transport,
   make them trustworthy.
3. It downloads each `.deb` it needs, checks its hash, unpacks it and hashes
   every file in it, then compares those with the files on disk: content,
   and the mode bits that grant privilege (setuid, setgid, write access for
   group or others). A mode the package's own signed maintainer scripts set
   counts as shipped, and so does a mode that grants less than the package's.
4. A version the current archive no longer has comes from
   snapshot.debian.org or Ubuntu's snapshot service, which keep signed
   indexes, with Launchpad as Ubuntu's last resort (reported as a lower
   level of trust than the signed archive chain).
5. Configuration files (`conffiles`) are expected to differ from the
   package's defaults. Their changes are judged by the checklist and the
   snapshot comparison, not reported as tampering.
   Which files are configuration files comes from the signed package, never
   from the machine's own package database. A changed configuration file is
   explained by a package change only when its content equals the default in
   the signed package; anything else is ranked by where it is.

What gets verified: without a snapshot, every package file in
security-relevant places (programs, shared libraries, PAM modules, kernel
modules, `/boot`) and the packages' maintainer scripts; with a snapshot,
the package files that changed since; with `--full`, everything. telltale
plans every package `dpkg/status` lists, whatever the package's file list
says, so editing a `.list` file cannot hide a replaced program. dpkg
diversions and `statoverride` entries are followed, and the ones nothing
legitimate explains are reported.

The result for each file is one of: verified against the signed package;
**a mismatch**, which is tampering; or unverifiable (the version is in no
trusted source, the package comes from a repository with no trusted key, or
the archive could not be reached). Unverifiable files are grouped into one
note, except setuid and setgid programs, kernel modules, PAM modules and
files in `/boot`, which are each a backdoor sign.

**Offline mode** (`scan --offline`) compares files with the checksums in the
machine's own package database. Root can edit those, so it only catches a
careless attacker, and the report says so in its first lines. For an
isolated machine, use a reference bundle instead (`collect`, `fetch-refs`,
`scan --refs`; see [usage.md](usage.md)): the bundle is checked against the
built-in keys when it is used, so it is as good as downloading.

The server caches packages and per-file hashes and shares them between
machines. Carry mode never leaves a cache on the machine it checks: one
there could be edited by the attacker.

What package verification does not cover:

- file owner and group are not compared with the package (the snapshot
  comparison does see them change);
- symbolic links a package ships are not compared, because the signed file
  tables do not list them (the snapshot comparison sees them change);
- a replaced program whose package entry was removed from `dpkg/status`
  belongs to no package any more: the snapshot comparison catches it, and
  without a snapshot only the setuid and listener checks may;
- Ubuntu Pro (ESM) packages, until telltale can use a Pro token.

## The regression rule

The checklist and the snapshot meet in one rule. Attackers loosen settings
to keep their way back in: they turn root login over SSH back on, add a
sudo rule without a password, switch the firewall off. So a checklist item
that **passed in the snapshot and fails now** is not reported as a weak
setting but as **tampering**: the setting was right when the machine was
known to be clean, and someone changed it.

The same holds for an item you accepted as an exception: if its value
changes from the one you accepted, that is a regression too. Items that
were already failing when the snapshot was taken stay weak settings.

## Which changes count as routine

Without some rule for routine changes, every package update would bury the
real findings, and a report people learn to ignore has failed. These are the
rules telltale follows, in plain words:

- **An upgrade to a newer version from a trusted source is explained.**
  Trusted means the version is in the signed archive (or a snapshot of it,
  or Launchpad), or in a third-party repository verified with a key bound
  to it. The files that changed with it are shown in one quiet
  "explained" group, and only when their new hashes match the new signed
  package.
- **A version nothing trusted confirms explains nothing.** If the new
  version cannot be found in any trusted source, none of its changed files
  are explained, and the upgrade is a backdoor sign. Typing a new version
  into `dpkg/status` does not make a replaced file look like an update.
- **A new kernel** of the same flavour and a newer version is explained,
  with its companion packages. Files that packages regenerate (the
  initramfs, module indexes, the boot menu, the dynamic linker's cache) are
  explained only by a confirmed change of a package that rebuilds them, and
  the linker cache only when every library it newly lists was in the
  snapshot's cache or is verified now.
- **A newly installed package is a note**, raised to a backdoor sign when it
  adds something that runs with special rights or reaches the network: a
  setuid or setgid program, a file capability, a kernel module, a PAM
  module, an enabled service or a listening program.
- **A downgrade is a backdoor sign**: going back to an old, vulnerable
  version is a known way back in.
- **Removing a security package** (a firewall, auditd, fail2ban and the
  like) is a weak setting.
- **A changed maintainer script** (the scripts dpkg runs as root when a
  package is installed, upgraded or removed) is explained only by a
  confirmed change of its package, and otherwise is a backdoor sign.
- **An archive that cannot be reached** does not turn into a flood: when the
  distribution's own signed indexes could not be fetched, the unchecked
  changes become one note and a line under "could not rule out".
- **apt's history log** is used only as supporting evidence: root can edit
  it.

Everything else that changed is unexplained, and is ranked by where it is: a
change in a persistence location (cron, systemd, SSH, sudo, PAM, shell
start-up files, `ld.so.preload`, kernel modules) or to a security-relevant
program ranks higher than a change to a data file.

On the server, changes explained by a confirmed package update roll forward
into the snapshot by themselves. Anything else rolls forward only when you
accept it, after reviewing it.

## Exceptions and accepting changes

Some findings are intended. You can accept a finding as an **exception**
(in the web UI, or `telltale accept` in carry mode): it records the exact
value it accepted, stops being reported while the value stays the same, and
becomes a finding again when it changes. Every report lists the exceptions
in force.

On the server you can also **accept changes** since the snapshot after a
change you made on purpose: the snapshot rolls forward and later visits
compare with the new one. A compromised state is never accepted by
accident: you see every change before it is accepted, and changes that
would also hide an unrelated finding cannot be accepted until that finding
is dealt with.
