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
- **Password hashes and private keys are never kept; other secrets are
  redacted by pattern.** Password hashes are reduced to a keyed digest (so
  a changed password still shows as a change), and private key files are
  recorded by hash, permissions and owner only. In the text telltale keeps
  from startup files, secrets are found by their shape and replaced by
  keyed digests before anything is stored, reported or sent in an alert.
  The shapes it knows:
  - systemd `Environment=` values and shell `export NAME=value`;
  - `key=value` and `key: value` where the key holds `password`,
    `passwd`, `secret`, `token`, `key` or `credential`, with the key bare
    or quoted as in JSON and YAML (`"password": "..."`);
  - the user and password in a URL;
  - `Authorization:` header values;
  - `curl -u user:password` and `--user user:password`;
  - `--password ...`, `--token ...` and similar options;
  - `sshpass -p ...`, and `-p<password>` for the MySQL and MariaDB
    clients.

  This is pattern matching, not understanding: a secret written in an
  unusual format (a bare positional argument, a home-made option name, a
  secret split across lines) is not recognised and is kept as text. If
  your startup files hold such secrets, treat snapshots, reports and
  alerts as holding them too.
- **A user's link cannot aim the scan at root's files.** The scan runs as
  root and reads startup files that ordinary users own (shell start-up
  files, systemd user units). Where one of those is a symbolic link, the
  text behind it is kept only when the link's owner could have read it
  anyway: root owns the link, or the link's owner owns the target, or
  everyone may read it. A user's own link on the way to that user's own
  start-up files, key file or unit directory (`~/.config` or `~/.ssh` kept
  in a dotfiles directory) is followed, and what it leads to is read only
  where that user could read it. Any other link on the way that a non-root
  account owns is not followed. A file in a directory the user can write
  is kept only if the user could read it (it may be a hard link to someone
  else's file). Nothing is read through `/proc`, and the password files,
  their backups and anything holding a private key are never kept. A link
  that is not followed is never silent: the link itself is recorded with
  its target and ranked like any link at a startup path, and a note
  (`heur.persist_link_refused`) says what is behind it was not read. That
  holds for every reason a link is not followed, a link through `/proc` and
  a chain of links too long to walk included.
- **Only regular files are ever opened.** Opening a device can do
  something by itself (opening a watchdog device arms a reboot timer), and
  a user's link may lead to one. The scan first takes a handle that opens
  nothing, checks that it refers to a regular file that is not on `/dev` or
  a kernel filesystem, and only then opens that same file.
- **A user cannot make a scan fail by filling a directory.** From one
  user's systemd unit directory telltale reads at most 2,000 entries and
  8 MiB of text, and from all users' unit directories together 64 MiB;
  text is kept only for files systemd reads as units, and anything else
  there is recorded by hash. Past a limit the directory is reported as a
  note (`heur.persist_flooded`) and listed among what could not be
  checked. A system unit directory that is itself a symbolic link is read
  only when root made the link and it leads into the system directories.

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
   indexes. Where no signed index has it, snapshot.debian.org's file API
   and, for Ubuntu, Launchpad can still give its hash, but those two are
   trusted through HTTPS alone (reported as a lower level of trust than
   the signed archive chain). They are used only by the server. A
   `telltale scan` that runs on the machine it examines never uses them:
   there HTTPS is checked with that machine's own certificate store and
   resolver, which root on it controls. A reference bundle never holds
   them either: it carries only what signed indexes confirm, so that the
   machine reading it can check everything again with telltale's keys.
   Such a version is then reported as not found, and the report's
   "Compared against" line says the scan used signed indexes only.
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
says, so editing a `.list` file cannot hide a replaced program. With a
snapshot, a changed package path that none of the signed packages it
loaded accounts for makes it check every installed package, whatever the
path is now (a program replaced by a symbolic link, a file with its
execute bits dropped). A changed package file about which verification
then still says nothing is a backdoor sign: silence is never a pass. dpkg
diversions and `statoverride` entries are followed, and the ones nothing
legitimate explains are reported; a `statoverride` that only takes
privilege away and is not applied yet leaves the file verified.

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
  or, on the server, Launchpad), or in a third-party repository verified
  with a key bound
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
  snapshot's cache or is verified now. Removing an old kernel (`apt
  autoremove`) rewrites the boot menu and re-points the `vmlinuz.old` and
  `initrd.img.old` links; with a kernel removal in the same comparison
  those changes are notes for you to accept, and they do not roll forward
  by themselves, because a removal is only the machine's own record.
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

- **The kernel command line** the machine booted with is compared with
  the snapshot's. A change is a backdoor sign (`init=` runs any program
  first, `module.sig_enforce=0` lets unsigned modules in), shown with the
  line before and after. The one exception is a note: only the kernel
  image named in `BOOT_IMAGE=` changed, and the image named now is a
  `/boot/vmlinuz-*` file of an installed kernel package, either verified
  against the signed package in this scan or unchanged since the snapshot
  together with its package (on the server, a confirmed kernel update is
  already in the baseline by the time the machine reboots into it).
- **The live firewall** is compared as a summary: the backend, the input
  policy and the number of rules. An input policy opened to accept, or
  fewer rules than at the snapshot, is a weak setting while the firewall
  is still on (a firewall switched off is the checklist's finding, raised
  to tampering); more rules or a tighter policy is a note. Chains and
  tables that services rewrite by themselves are left out of the counts
  (fail2ban's `f2b-*`, Docker's `DOCKER*` except `DOCKER-USER`, libvirt's,
  CNI's, Kubernetes' and Podman's), so their coming and going is not a
  change.
- **The CA certificate store** (`/etc/ssl/certs`) is a persistence
  location: a planted CA lets someone read or forge the machine's TLS
  connections. A certificate that a confirmed `ca-certificates` upgrade
  brought, and the bundle that upgrade rebuilt, are explained; a
  certificate linked in from anywhere else is a backdoor sign.

Everything else that changed is unexplained, and is ranked by where it is: a
change in a persistence location or to a security-relevant program ranks
higher than a change to a data file. Persistence locations are cron,
systemd, SSH, sudo (`sudoers`, `sudo.conf`), PAM, shell start-up files,
`ld.so.preload` and the library search path, kernel module lists and
options, the boot loader's and the initramfs's configuration, udev rules,
APT's sources and trusted keys (`sources.list`, `sources.list.d`,
`trusted.gpg`, `trusted.gpg.d`, `keyrings`), logrotate and tmpfiles
snippets, NetworkManager dispatcher scripts, desktop autostart entries,
polkit rules, `nftables.conf`, the name resolution files, the CA
certificate store with `/usr/local/share/ca-certificates`, and each
user's `~/.config/environment.d`. A file added or changed there that no
confirmed package change explains is a backdoor sign. That includes APT's
configuration snippets (`apt.conf`, `apt.conf.d`), which can name commands
APT and dpkg run as root, whatever the changed snippet says: a hook can
hide behind an `#include` or in nested blocks. The cost: some packages
rewrite their snippet from a maintainer script, so when
`unattended-upgrades` is upgraded after the snapshot and rewrites
`50unattended-upgrades` to something other than the package's default,
that shows as a backdoor sign for you to look at and accept.

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

## Known limits

The README lists what telltale cannot tell you at all. These are narrower:
places where v0.1 is known to say too much, too little, or to lean on
something it does not check.

- **systemd-boot and `initrd=`.** A kernel command line that changed only
  in `BOOT_IMAGE=`, to an installed kernel package's own image, is a note.
  That is what GRUB writes. systemd-boot and unified kernel images also put
  `initrd=` words on the command line, and those change with every kernel
  update too; telltale reports such a change as a backdoor sign
  (`snap.cmdline`) for you to accept after each kernel update on machines
  that boot that way.
- **APT configuration rewritten by package scripts.** Any new or changed
  file in `/etc/apt/apt.conf.d` is a backdoor sign unless it is its
  package's default from a confirmed package change. Some packages rewrite
  theirs from a maintainer script (`unattended-upgrades` and
  `50unattended-upgrades`), which then shows as a backdoor sign to accept.
- **"No signed index has it" counts as "not in the distribution's
  history".** When a scan uses signed sources only (a scan of the machine
  it runs on, and every reference bundle), a version that no signed
  snapshot index could be asked about at all is treated like one they do
  not have: a third-party repository verified with a key bound to it may
  then confirm it. A signed lookup that failed (the network, a bad answer)
  blocks that, but "there was no signed index to ask" does not.
- **The firewall comparison counts rules.** It compares the backend, the
  input policy and how many rules there are, not what the rules say. A
  rule replaced by a weaker one leaves the count unchanged and is not
  reported; chains that fail2ban, Docker, Podman, libvirt, CNI and
  Kubernetes manage are not counted at all, so a rule hidden in one of
  those is not seen either.
- **Redaction is by pattern** (see the trust model above): a secret in a
  format telltale does not know is kept as text.
- **A hostile machine can get the server restarted.** Its collection is
  bounded in size and in number of entries, but judging one built for the
  purpose can still take more memory than the service is allowed. The
  server is then killed and started again; it reports that machine after
  three such visits in a row (see [server.md](server.md#the-systemd-unit)),
  and until then the visits of other machines that were under way are made
  again at their next turn.
- **Links the scan does not follow.** A link at a user's startup path that
  belongs to another account, leads where its owner could not read, leads
  through `/proc` or another kernel filesystem, or is one of a chain longer
  than the scan walks, is not followed. The link is recorded, ranked and
  noted (`heur.persist_link_refused`), but what is behind it is not read.
- **Files on the device filesystem are never read.** The scan opens only
  regular files, and none on `/dev` itself (`/dev/shm` is read). A startup
  link to a file kept on `/dev` is reported as a link, without its content.
