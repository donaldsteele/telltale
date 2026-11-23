# Using telltale

This page covers the commands for carrying telltale to a machine and the
report they print. The server has its own page: [server.md](server.md).

```
telltale scan [--snapshot FILE] [--refs DIR] [--keys DIR] [--offline] [--full] [--json FILE|-] [--html FILE]
telltale snapshot --out FILE [--no-encrypt]
telltale accept ID --snapshot FILE [--note TEXT]
telltale collect [--gzip] > SCAN.json
telltale fetch-refs --for SCAN.json --out DIR [--snapshot FILE] [--keys DIR]
telltale server --config FILE          (full build only; see server.md)
telltale mcp --server URL --token-file FILE --fingerprint SHA256:...   (full build only)
telltale version
```

Run telltale as root. Without root it still runs, but it cannot read
`/etc/shadow`, other users' processes or the firewall rules, and the report
lists the checks it had to skip. It writes nothing on the machine except
its own temporary files, which it removes, and the files you name.

## scan

```
sudo ./telltale scan
sudo ./telltale scan --snapshot /media/usb/web01.snap
```

`scan` collects the machine, compares it with the snapshot when you give
one, verifies the files of the installed packages, runs the checklist and
the suspicious-on-any-machine checks, and prints a ranked report.

| Flag | What it does |
|------|--------------|
| `--snapshot FILE` | Compare with this snapshot. The passphrase comes from `TELLTALE_PASSPHRASE` or a prompt. The report is also saved next to it as `FILE.last-report.json`, which `accept` reads. |
| `--refs DIR` | Verify packages with a reference bundle from `fetch-refs` instead of downloading. |
| `--keys DIR` | Public keys of third-party APT repositories to trust, one or more per file in DIR (armored or binary). They are tried for every third-party repository, never for the distribution's own archives. |
| `--offline` | Do not download anything: compare files with the machine's own package checksums. Root can edit those, and the report says so. |
| `--full` | Verify every file of every package, not only the security-relevant ones. Slower, and downloads more. |
| `--json FILE` | Also write the report as JSON. `--json -` prints only the JSON, on standard output. |
| `--html FILE` | Also write the report as one self-contained HTML file. |
| `--no-color` | No colour in the text report (there is none anyway unless standard output is a terminal). |

The exit code is 0 when nothing was found, 1 when there are only notes or
weak settings, 2 when there is tampering or a backdoor sign, and 3 when the
scan could not run.

### Where package references come from

Without `--refs` or `--offline`, a scan downloads what it needs from the
distribution's official archive (and, for older versions, from
snapshot.debian.org, Ubuntu's snapshot service or Launchpad) into a
temporary directory, and removes it when the scan is done: carry mode never
leaves a package cache on the machine. Without a snapshot it verifies the
security-relevant files of every installed package (programs, libraries,
PAM and kernel modules, `/boot`), which on a large machine can mean a few
hundred megabytes of packages. With a snapshot it verifies only the
package files that changed since.

### Third-party repositories

A package from a third-party APT repository (Docker, Chrome, a PPA, your
own) is verified only with a key bound to that repository, from one of
three places, and never with a key the machine holds:

- the snapshot, which records the keys the machine trusted for each
  third-party repository when it was clean;
- the keys of well-known vendors built into telltale, each pinned to its
  vendor's repository addresses;
- `--keys DIR`, keys you fetched from the vendors' own sites yourself
  (compare each fingerprint with one the vendor publishes somewhere else).

Without one, the repository's packages cannot be verified, and the report
says so.

## snapshot

```
sudo ./telltale snapshot --out /media/usb/web01.snap
```

Records the machine as it is now, as the known-good state later scans are
compared with. Take it when you believe the machine is clean: after
installing it, or after you have reviewed a scan without a snapshot.

- The file is encrypted with age under a passphrase (`TELLTALE_PASSPHRASE`
  or a prompt that asks twice). `--no-encrypt` writes it in the clear.
- Keep it off the machine. Someone who can edit the snapshot can make their
  changes look like the clean state.
- It needs root: without root it would miss files and processes, and every
  later root scan would show them as changes. `--allow-non-root` takes an
  incomplete snapshot anyway.
- It never holds secrets: password hashes are reduced to a keyed digest (so a
  password change still shows), private keys are recorded by hash,
  permissions and owner only, and secrets in the text it keeps (tokens in
  shell start-up files, passwords in units and cron lines) are replaced by
  keyed digests.
- An existing file is not overwritten without `--force`.

## accept

```
sudo ./telltale accept heur.module:nvidia --snapshot /media/usb/web01.snap --note "driver built with DKMS"
```

Some findings are intended: a checklist item you deliberately leave as it
is, a kernel module you built yourself, a setuid helper in `/usr/local`.
`accept` records the finding as an exception in the snapshot file, with the
exact value the last scan saw (from `FILE.last-report.json`). It stops
being reported while that value stays the same; if it changes again, it is
a finding again, and a checklist item that held at the accepted value and
fails now counts as tampering. Every report lists the exceptions in force.

The ID is the one the report prints under each finding (`ID: ...`).

## collect and fetch-refs: an isolated machine

A machine you suspect has often been cut off the network. To verify its
packages properly anyway:

```
sudo ./telltale collect > web01.json                     # on the isolated machine
telltale fetch-refs --for web01.json --out web01-refs    # on any machine with network access
sudo ./telltale scan --refs web01-refs                   # on the isolated machine again
```

`collect` writes the machine's raw collection as JSON (`--gzip` compresses
it). `fetch-refs` downloads every package the collection lists from the
official archives into a new or empty directory. With `--snapshot FILE` it
also fetches the third-party repositories the snapshot recorded keys for;
pass the same snapshot to `scan`. Everything in the bundle is checked again
with telltale's built-in archive keys when it is used, so the bundle can
travel any way you like.

`scan --offline` is the last resort: it compares files with the machine's
own checksums (`/var/lib/dpkg/info/*.md5sums`), which root can edit, and the
report says so in its first lines.

## Reading the report

```
telltale: web01 (Debian GNU/Linux 12 (bookworm), amd64)   2026-11-23 10:43
Compared against: snapshot of 2026-11-23, reference bundle, checklist (43 items)
Could not rule out: kernel-level rootkits (any on-machine check can be fooled)
```

The header names the machine, what the scan compared against, and what it
could not rule out: always kernel rootkits, and anything else that limited
this scan (no root, no snapshot, a container sharing its host's kernel, no
usable package reference). `checklist (43 items)` counts the checklist items
that apply to this machine: the checklist has 44, and an item that could not
be judged here is listed under the skipped checks at the end of the report
instead.

Then come the findings, most serious first, newest evidence first within a
severity:

- **TAMPERING**: a checklist item that held in the snapshot and fails now,
  something the machine's own tools hide, a system file that does not
  match its signed package.
- **BACKDOOR**: a backdoor sign, something that gives someone a way in or
  hides one.
- **WEAK**: a weak setting.
- **NOTE**: worth knowing, not a problem by itself.

Each finding has a title, its evidence (the file and line, before and
after, when it changed), why it matters, the command that would fix it, and
its ID. A fix command that removes or replaces a file first copies it into
`/root/telltale-evidence/`, and it is printed exactly as built: names from
the machine are quoted, a name with control characters gets no command at
all, only a note to handle it by hand, and a command that holds an
unprintable character is marked so that you do not paste it. telltale never
runs a fix itself.

After the findings:

- **EXPLAINED**: groups of changes that a package update explains, checked
  against the signed package (for example `openssl upgraded from 3.0.14 to
  3.0.15; 2 files changed with it`).
- **Exceptions in force**: what you accepted, with the value and the date.
- **Skipped checks**: what could not be checked, and why.

The JSON report holds all of this and is the source of truth; the text and
the HTML report are renderings of it. Text from the machine (file names,
command lines, cron lines) is escaped in every output, so a crafted file
name cannot put control sequences on your terminal or markup in the HTML.

## version

`telltale version` prints the version, and `(collector build)` for the
collector build, which has no `server` or `mcp` command.
