# The test lab

telltale is developed against a lab of Docker machines that is part of the
repository (`lab/`): clean machines, and machines with backdoors planted on
them, each with a written list of what telltale must report. On every push
CI runs the whole Docker lab on Debian 12 and Ubuntu 24.04 on amd64, and the
clean machines and every break on Debian 12 on arm64 under emulation. The
other distributions are run by hand, and so is the QEMU virtual machine test
of the kernel checks, which CI does not run. This page is the overview;
`lab/README.md` is the reference.

## The machines

**Clean machines**, for Debian 12 and 13 and Ubuntu 22.04 and 24.04, each in
five variants:

| Variant | What it is |
|---------|------------|
| `clean` | The distribution as installed, with sshd and cron |
| `hardened` | Passes the whole checklist |
| `noexec` | `/tmp` and `/dev/shm` mounted noexec, so a visit has to find another place to run |
| `thirdparty` | Two third-party APT repositories with their own keys, one of them the lab's own signed repository, from which a vendor-style package is installed |
| `localsoft` | Software built by hand in `/usr/local` and a setuid helper there, the kind of thing an owner accepts as an exception |

Package versions are pinned through snapshot.debian.org and
snapshot.ubuntu.com, and the base images by digest, so the machines are the
same on every build.

**Broken machines** are the clean machine with one technique planted:

- a root SSH key, a second account with user id 0, a sudo rule without a
  password;
- a cron job, a systemd unit and timer, and a shell start-up script that call
  out;
- `/etc/ld.so.preload`, a PAM module no package installed;
- a system program replaced by another build, a setuid copy of a shell, a
  file marked immutable;
- a program running from `/dev/shm`, one whose file was deleted while it
  ran, a listening backdoor;
- an `LD_PRELOAD` rootkit that hides a process and a port from `ps` and `ss`
  (for the cross-view check);
- root login turned back on, the firewall switched off, an empty password
  (for the regression rule);
- a package downgraded to an older version, a new package that adds a
  listening service, package directories replaced by links.

**Scenarios** tell a whole story: a guessed password, then a root key, a cron
callback hidden with `ld.so.preload` and root login turned back on; a web
shell dropped under `/var/www`, then a systemd timer that calls out and a
setuid shell in `/var/tmp`; a legitimate upgrade from a third-party
repository while its program runs (which must not alarm); and a repository
whose key was swapped.

**Update noise**: a clean machine is snapshotted, then upgraded to newer
pinned packages. Every changed package file must come back explained, with
nothing above a note, except the one change the test makes itself: it
repoints the machine's APT source at a later archive snapshot, and a
changed package source is reported as a backdoor sign.

## Everything planted is inert

No real malware is used. Each technique is a stand-in written for the lab
that leaves the footprint telltale must see (the files, keys, lines, ports
and hidden processes) and nothing more: the PAM module returns
`PAM_IGNORE`, the rootkit only hides one named process and port, the
callbacks only reach a `sink` container that logs connections. The machines
sit on a Docker network with no route out, and nothing is ever planted on a
machine that has one.

## What is checked

Each broken machine and scenario has a manifest: the findings telltale must
report (by finding key and exact severity) and the highest severity anything
else may have, once with a snapshot of the clean machine and once without
one. Each clean variant has a baseline: nothing above a weak setting without
a snapshot, and against a snapshot of the same machine nothing new above a
note. A clean machine that produces a backdoor sign fails the lab just as a
missed backdoor does.

Package verification in the lab works the way it does for an isolated
machine: `telltale collect` on the machine, `telltale fetch-refs` on the
host, `telltale scan --refs` on the machine. The machines run the collector
build, the one a server copies to machines.

Other suites in the lab:

- **visits**: server mode's visit against a real machine over SSH, including
  one where `/tmp`, `/run` and `/var/tmp` are all noexec, checking that
  nothing is left behind;
- **the server end to end**: a real server, a bubbles chat server and two
  machines in Docker Compose. The test goes through the web UI's real forms
  (setup code, enrolment, the snippets, Check now, the snapshot), plants a
  root key and turns root login back on, and checks the machine page, the
  alerts that reach bubbles, and the MCP answers;
- **systemd**: one machine with systemd as PID 1, where the callback timer
  really runs.

## What Docker cannot test

The machines share their host's kernel, so kernel modules, the kernel
command line and the live firewall are tested in a small QEMU virtual
machine (`lab/vm/`, a pinned Debian 12 cloud image) that builds an inert
module and checks that telltale reports it. That test needs `/dev/kvm`, so
it runs by hand, not in CI:

```
go test -tags 'lab vm' -timeout 30m ./lab/vm/
```

## arm64

`TELLTALE_LAB_ARCH=arm64` builds and runs the machines for arm64. On an
amd64 host they run under QEMU user-mode emulation, which needs the
`binfmt_misc` handlers registered (the `qemu-user-static` and
`binfmt-support` packages, or `docker/setup-qemu-action` in CI). Under
emulation the kernel reports the emulator as the program of every process,
so the four breaks that are detected from a process's program (the
`/dev/shm` process, the deleted program, the listening backdoor and the new
listening service) are skipped there; they are checked on amd64. Only the
Debian images are built for arm64 (Ubuntu keeps arm64 in a separate
archive). CI runs the clean variants and every break on Debian 12 arm64.

## Running it

```
go test -tags lab -timeout 60m ./lab/...                                   # everything, every distro
TELLTALE_LAB_DISTROS=debian12 go test -tags lab ./lab/ -run TestEveryBreakDetected
TELLTALE_LAB_ARCH=arm64 TELLTALE_LAB_DISTROS=debian12 go test -tags lab ./lab/ \
    -run 'TestCleanMachinesAreClean|TestEveryBreakDetected'
```

It needs Docker and at least 3 GB free in Docker's root. Every container,
network and image it makes is labelled `telltale-lab=1` and named
`telltale-lab...`, and it removes only what carries that label; it never
prunes. It builds and tests one distro at a time and removes that distro's
images afterwards, unless `TELLTALE_LAB_KEEP_IMAGES=1`. The server
end-to-end test builds the bubbles server from a checkout of the version
`go.mod` requires (`TELLTALE_LAB_BUBBLES_SRC=DIR`), at the commit
`lab/bubbles.env` pins.

## Real reports on the site

The [project site](https://donaldsteele.github.io/telltale/) shows reports
from lab machines: the terminal text, the HTML report and the JSON, as
telltale wrote them, with the story of what was done to each machine. They
are the two break-in scenarios (`weak-password-to-root` and
`web-shell-persistence`), the first of them scanned again without a
snapshot, and a clean machine (the hardened variant, whose owner accepts
as exceptions the checklist items a container cannot meet). The story of a
scenario is the list of steps in the header of its `apply.sh`.

They are not mock-ups. `scripts/site-reports.sh` builds telltale the way a
release is built and runs `TestGenerateSiteReports` (build tags `lab site`)
with it, which writes `site/reports/`. The Pages workflow runs it for every
release tag and publishes the site, so the reports are made by the
release's telltale (the reports page names the build). A push to `main`
runs the same build and checks as a test and publishes nothing. Either way
the workflow fails when a report is missing:

```
bash scripts/site-reports.sh      # needs Docker; writes site/reports/, not committed
go run ./tools/linkcheck site     # every link leads somewhere, nothing private in it
```

The machines have the made-up names web01, files02 and build03. Nothing
that identifies the computer running the lab (its host name, user, home
directory, addresses) may reach the site: the test and the link check both
fail when a file holds one. They are worked out where the check runs, so
they are not written down in the repository either. The kernel version and
the kernel settings in the reports are that computer's, as the reports
say: a lab machine is a container on its kernel.

**Publishing.** GitHub's `github-pages` environment lets only the default
branch deploy, until it is given a deployment rule for `v*` tags. Add that
rule (and set the repository's Pages source to GitHub Actions) before the
first release, or the release's deploy job is refused.
