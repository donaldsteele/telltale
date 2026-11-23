# telltale

telltale tells you whether someone has backdoored a Linux machine.

It compares the machine with a snapshot you took while it was clean, checks
its system files against the distribution's signed packages, runs a
hardening checklist, and looks for things that are suspicious on any
machine, such as a second account with root's user id or a cron job that
opens a shell to somewhere else. The checklist and the snapshot meet in one
rule: a setting that was right in the snapshot and is wrong now (root login
over SSH turned back on, a password-free sudo rule, the firewall off) is not
just a weak setting but a sign that someone changed it, and it is reported as
tampering.

It assumes the machine may be lying. It is one static binary that loads none
of the machine's libraries, reads `/proc`, `/sys` and the filesystem itself
instead of trusting `ps`, `ss` or `ls`, never trusts the package database's
checksums or the machine's current keyrings, and keeps the snapshot off the
machine.
It reports and never fixes: every finding comes with why it matters, the
evidence (which file, which line, before and after) and the exact command
that would fix it, for a person to read and run.

It checks Debian 12 and 13 and Ubuntu 22.04 and 24.04, on amd64 and arm64
(arm64 is tested under emulation; see [what it cannot tell
you](#what-it-cannot-tell-you)).

```
$ sudo ./telltale scan --snapshot /media/usb/web01.snap --refs web01-refs
telltale: web01 (Debian GNU/Linux 12 (bookworm), amd64)   2026-11-23 11:04
Compared against: snapshot of 2026-11-23, reference bundle, checklist (43 items)
Could not rule out: kernel-level rootkits (any on-machine check can be fooled)
                    kernel modules (this machine is a container on its host's kernel; scan the host)

TAMPERING   /usr/bin/id does not match the signed coreutils package   /usr/bin/id
            a3d987dd3f9ec0610dc13b7fdccef84895628065434f44247a65ef0d2a341b3c  ->  e33f954597c94f72d058f2296e259f96907d7d554a00b6d3f605fbbad28c51dc   changed 2026-11-23 11:04
            differs from the file in the signed package; expected value from a reference bundle,
            checked again with the keys telltale trusts (built in, or for a third-party repository
            from the snapshot or --keys)
            /usr/bin/id
            sha256 a3d987dd3f9ec0610dc13b7fdccef84895628065434f44247a65ef0d2a341b3c size 48144  ->  sha256 e33f954597c94f72d058f2296e259f96907d7d554a00b6d3f605fbbad28c51dc size 48145   changed 2026-11-23 11:04
            changed since the snapshot
            Why: This file differs from the copy in the distribution's package for the version
                 installed (coreutils 9.1-1). A routine update would match the package; replacing
                 system programs and libraries is how rootkits and backdoors hide.
            Fix: mkdir -p /root/telltale-evidence && cp -a --parents '/usr/bin/id' /root/telltale-evidence/ && apt-get install --reinstall -- 'coreutils'
            ID: pkg.mismatch:/usr/bin/id

TAMPERING   No longer met since the snapshot of 2026-11-23: SSH root login is off (key login from the telltale server only)
            ...

BACKDOOR    SSH server configuration changed since the snapshot: /etc/ssh/sshd_config.d/00-lab.conf
            ...

BACKDOOR    New scheduled job since the snapshot: /etc/cron.d/lab-update   /etc/cron.d/lab-update:1
            ...

BACKDOOR    New SSH key for root, not in the snapshot: /root/.ssh/authorized_keys line 1
            ...

BACKDOOR    /etc/cron.d/lab-update line 1 connects out or downloads and runs code
            ...

(9 weak settings and 1 note follow)
```

That is a real report, from a clean Debian 12 machine in the [test lab](#the-test-lab)
on which four breaks were then planted: a changed `/usr/bin/id`, a root SSH key, a
cron job that calls out, and root login turned back on. It is shortened here; each
finding in full has its evidence, why it matters and the fix, as the first one
shows. The machine is a container, so its kernel belongs to its host. The
header's `checklist (43 items)` counts the items that apply to this machine:
the checklist has 44, and an item that could not be judged here is listed
under the skipped checks at the end of the report instead.

## Two ways to run it

The full build does both. The carry download (the collector build) only
carries: it cannot run the server.

- **Carry it.** Copy telltale to a machine, run it, read the report. Nothing
  is installed. The snapshot is a file you keep somewhere else (encrypted
  with a passphrase), and you bring it back for the next check. This is also
  how you look at a machine telltale has never seen, for example one you
  already suspect: without a snapshot it still checks the packages, the
  checklist and the suspicious-on-any-machine list.
- **A server that visits.** A server on your network keeps the snapshots
  and the history. On a schedule it logs in to each enrolled machine over
  SSH, copies a fresh collector over, runs it, takes the results back and
  deletes it. Nothing stays on the machine between visits, the snapshot
  never touches its disk, and all the judging happens on the server. It has
  a web UI, sends alerts to [bubbles](https://github.com/donaldsteele/bubbles),
  and lets an AI assistant read the reports over MCP.

## Which download

Every release has these files, and `SHA256SUMS` for all of them:

| File | What it is |
|------|------------|
| `telltale-carry_<version>_linux_<arch>.tar.gz` | The collector build: `scan`, `snapshot`, `accept`, `fetch-refs` and `collect`. Take this one to carry telltale to machines. About 14 MB unpacked. |
| `telltale_<version>_linux_<arch>.tar.gz` | The full build: everything above plus `server` and `mcp`. Take this one to run the server without the package, or to use `telltale mcp`. About 23 MB unpacked. |
| `telltale_<version>-1_<arch>.deb` | The server package: the full build as `/usr/bin/telltale`, the collectors for both architectures in `/usr/lib/telltale/` (what the server copies to machines), a systemd unit and an example configuration. |

`<arch>` is `amd64` or `arm64`. Every binary is static and runs on any of
the supported distributions. `telltale version` says `(collector build)` for
the collector build.

## Quick start: carry it

Check the download and unpack it on a machine you trust, then copy the
binary to the machine you want to check:

```
sha256sum --check --ignore-missing SHA256SUMS
tar xzf telltale-carry_0.1.0_linux_amd64.tar.gz
scp telltale web01:
```

`SHA256SUMS` only says the file is the one the release page lists. Each
release file also has a signed build provenance attestation, which says it
was built by this repository's release workflow from the tagged commit. With
the [GitHub CLI](https://cli.github.com/) you can check that:

```
gh attestation verify telltale-carry_0.1.0_linux_amd64.tar.gz --repo donaldsteele/telltale
```

On the machine, as root (without root it still runs, and lists what it had
to skip):

```
sudo ./telltale scan                                  # no snapshot yet: packages, checklist, suspicious things
sudo ./telltale snapshot --out /media/usb/web01.snap  # once you believe the machine is clean
```

`snapshot` asks for a passphrase and encrypts the file. Keep it off the
machine: a snapshot left there could be edited by whoever you are looking
for. Next time, bring it back:

```
sudo ./telltale scan --snapshot /media/usb/web01.snap
sudo ./telltale scan --snapshot /media/usb/web01.snap --html web01.html   # also a one-file HTML report
```

The exit code says what it found: 0 nothing, 1 notes or weak settings only,
2 tampering or a backdoor sign, 3 the scan could not run. A finding you
meant to have is recorded in the snapshot file as an exception with
`telltale accept ID --snapshot FILE`, using the ID the report prints under
it; it stays accepted while its value stays exactly the same. After bigger
intended changes, take a new snapshot.

A scan downloads the packages it checks from the distribution's archive. For
a machine that has been cut off the network, collect on it, build a
reference bundle on a machine that has a connection, and carry the bundle
back:

```
sudo ./telltale collect > web01.json                     # on the isolated machine
telltale fetch-refs --for web01.json --out web01-refs    # on a machine with network access
sudo ./telltale scan --refs web01-refs                   # back on the isolated machine
```

Everything in the bundle is checked again against the archive keys built
into telltale, so it can travel any way you like. [docs/usage.md](docs/usage.md)
has every command and flag.

## Quick start: the server

Run the server on a small machine of its own ([docs/server.md](docs/server.md)
says why). With the package:

```
sudo apt install ./telltale_0.1.0-1_amd64.deb
sudo install -m 0640 -o root -g telltale /etc/telltale/telltale.toml.example /etc/telltale/telltale.toml
sudoedit /etc/telltale/telltale.toml           # set listen to this machine's LAN address and a port
sudo install -m 0600 /dev/null /etc/telltale/passphrase
sudoedit /etc/telltale/passphrase              # the passphrase that encrypts the database
sudo systemctl enable --now telltale
sudo journalctl -u telltale                    # the one-time setup code and the certificate fingerprint
```

Open `https://<listen address>/` in a browser, check that the certificate
fingerprint matches the one in the log, and set the admin password with the
setup code. Then, for each machine:

1. **Enrol it** by name and address. The server fetches its SSH host key;
   compare the fingerprint with `ssh-keygen -lf
   /etc/ssh/ssh_host_ed25519_key.pub` on the machine's own console before
   you go on.
2. **Add the two snippets** the server shows: an `authorized_keys` line for
   root that works only from the server's address, and a `Match Address`
   block that lets root log in with a key from that address only. Root login
   stays off for everyone else.
3. **Press Check now**, read the first report (made without a snapshot),
   and when you believe the machine is clean, press **This machine is
   believed clean: take the snapshot**. Every later visit is compared with
   that snapshot.

Visits happen daily by default. A change you made on purpose is accepted
from the machine page and rolls the snapshot forward; changes that a
verified package update explains roll forward by themselves.
[docs/server.md](docs/server.md) covers enrolment, the sshd block and why,
backups, alerts and MCP.

## What it checks

- **Changes since the snapshot**: accounts, SSH keys, sudo rules, cron jobs
  and systemd units and timers, shell start-up files, PAM, `ld.so.preload`,
  kernel modules and the kernel command line, firewall rules, listening
  programs, packages, and every file in the system directories (hash, mode,
  owner, setuid bits, file capabilities, immutable flags). Changes that a
  package update explains, checked against the signed package, are set apart
  quietly; everything else is ranked by where it is.
- **Package verification**: system files are compared with the files in the
  distribution's signed packages, fetched from the official archive and
  checked with archive keys built into telltale, never the machine's.
- **The hardening checklist**: 44 items, from the DISA STIG for Ubuntu where
  a rule applies, and telltale's own for the settings attackers loosen to
  keep a way in.
- **Suspicious on any machine**: a second UID 0 account, `ld.so.preload`,
  programs running from `/tmp` or `/dev/shm` or deleted while running, SSH
  keys with forced commands, setuid programs and PAM modules that belong to
  no package, immutable files, unpackaged kernel modules, startup files that
  open a shell to somewhere else, and processes, ports, files or modules that
  the machine's own `ps`, `ss`, `ls` or `lsmod` hide.

[docs/checks.md](docs/checks.md) lists every check (it is generated from the
code), and [docs/how-it-works.md](docs/how-it-works.md) explains the trust
model, package verification and which changes count as routine.

## What it cannot tell you

- **A kernel-level rootkit can fool any check that runs on the machine**,
  telltale included: code in the kernel can hide files, processes and
  connections from everything above it. Every report says so. The answer is
  to check the disk from another machine, which is planned for a later
  version.
- **Ubuntu Pro (ESM) packages cannot be verified yet.** telltale cannot use
  a Pro token, so their files are unverified: without a snapshot they go
  into one grouped note (except setuid programs, kernel and PAM modules and
  boot files, each a backdoor sign), and after a snapshot every ESM upgrade
  that changes files is a backdoor sign for you to review.
- **Third-party repositories need a key telltale trusts.** A repository is
  verified only with a key telltale has for it: one the snapshot recorded
  for that repository, a built-in key of one of ten well-known vendors (Google
  Chrome, Microsoft, Docker, GitHub CLI, PostgreSQL PGDG, Grafana, Elastic,
  Mozilla, Brave, 1Password) for that vendor's addresses, a key you add in the server's settings for the addresses you
  give it, or a key you pass with `--keys`, which is tried for every
  third-party repository rather than bound to one. Never the machine's
  current keyrings. Without one, an upgrade from that repository cannot be
  confirmed, and after a snapshot it is reported as a backdoor sign.
  Repositories that need a login are fetched without it, so they count as
  having no key. HashiCorp's repository has no built-in key: trust it by
  adding its key as an owner key in the server's settings, or with `--keys`
  in carry mode.
- **Kernel modules and the kernel command line are tested in a virtual
  machine only.** The Docker lab shares its host's kernel, so these checks
  are tested in a QEMU virtual machine, by hand rather than in CI.
- **arm64 is tested under emulation.** The arm64 builds run the lab's Debian
  12 machines under QEMU user-mode emulation. There the kernel reports the
  emulator as every process's program, so the checks that look at which
  program a process runs are tested on amd64 only, and nothing has been run
  on real arm64 hardware yet.
- **It checks one moment**: it does not watch the machine between checks.
- **Without root** it cannot read `/etc/shadow`, other users' processes or
  the firewall, and it says which checks it skipped.
- **Only the Debian family**: Debian 12 and 13, Ubuntu 22.04 and 24.04.
  Raspberry Pi OS and the Red Hat family are not supported yet.

## The test lab

`lab/` is a Docker lab that is part of the project: clean Debian and Ubuntu
machines in several variants (hardened, `/tmp` mounted noexec, third-party
repositories, locally built software), and broken ones, each with one
backdoor planted: a root SSH key, a second UID 0 account, a cron job and a
systemd timer that call out, `ld.so.preload`, an unknown PAM module, a
replaced system binary, a setuid shell, an immutable file, a process running
from `/dev/shm`, a listening backdoor, an `LD_PRELOAD` rootkit that hides
from `ps` and `ss`, hardening settings turned back, a downgraded package,
and a few whole break-in stories. Everything planted is an inert stand-in
that only leaves the footprint (the callbacks reach a sink container on a
network with no route out). Each machine has a manifest of what telltale
must and must not report, and the tests check every report against it, with
a snapshot and without one.

The [project site](https://donaldsteele.github.io/telltale/) shows the
reports telltale prints for the lab's break-in stories, made by CI with
each release's telltale; the reports page names the build.
[docs/lab.md](docs/lab.md) describes the lab and how to run it.

## Alerts and AI assistants

The server can send alerts to a [bubbles](https://github.com/donaldsteele/bubbles)
chat when a visit finds new tampering or a new backdoor sign (or any new
finding, if you choose). An alert carries the finding and at most the one
changed line, never file contents.

`telltale mcp` is an MCP server for an AI assistant. Its tools read the
server's machines and reports and can ask for a visit: `list_machines`,
`latest_report`, `explain_finding`, `compare_reports` and `check_now`. They
cannot take a snapshot, accept a change or add an exception, and telltale
never runs a fix: fix commands are text for a person. Text that comes from a
machine is marked in the results as untrusted data. See
[docs/server.md](docs/server.md#ai-assistants-mcp) to set it up.

## Build from source

You need Go 1.26 or newer.

```
go build -o telltale ./cmd/telltale                   # the full build
go build -tags collector -o telltale ./cmd/telltale   # the collector build
bash scripts/build.sh                                 # both builds for amd64 and arm64, the tarballs and the .debs
```

`scripts/build.sh` writes everything to `dist/` (the `.deb` packages need
Docker), and `scripts/check-dist.sh` checks the result. The tarballs are
reproducible: built at the same commit with the same Go toolchain they are
the same bytes, so you can compare your own build with a release
(`SOURCE_DATE_EPOCH` defaults to the commit's time).

## Development

```
go test ./...                              # unit tests (no Docker, no network)
go test -tags lab -timeout 60m ./lab/...   # the Docker lab (needs Docker)
go run ./tools/docgen                      # regenerate docs/checks.md after changing a check
bash scripts/site-reports.sh               # the project site's real reports from the lab (needs Docker)
```

| Path | What it is |
|------|------------|
| `cmd/telltale/` | The binary |
| `internal/collect/` | Collection: the part that runs on the machine |
| `internal/judge/`, `internal/checklist/`, `internal/heuristics/`, `internal/pkgverify/` | Judging: the snapshot comparison, the checklist, the suspicious-on-any-machine checks, package verification |
| `internal/server/`, `internal/visit/`, `internal/store/`, `web/` | The server, its visits, its encrypted database and its web UI |
| `internal/alerts/`, `internal/mcpserver/` | bubbles alerts and the MCP server |
| `lab/` | The Docker lab, and the kernel checks in a QEMU VM (`lab/vm/`) |
| `deploy/` | The systemd unit, the example configuration and the Debian package scripts |
| `tools/` | Generators: `docs/checks.md`, the STIG references, the vendor keys; the site's link and privacy check |
| `site/` | The project site; `site/reports/` is made by `scripts/site-reports.sh` |

CI runs the unit tests, the race detector, the build and its checks, the
lab on Debian 12 and Ubuntu 24.04, and the Debian 12 lab on arm64 under
emulation. A tag `vX.Y.Z` builds and publishes a release, and the project
site is published with fresh reports from the lab for every tag (a push to
`main` builds it as a check).

## Security

To report a vulnerability in telltale, see [SECURITY.md](SECURITY.md).

## Licence

Apache License 2.0; see `LICENSE` and `NOTICE`.
