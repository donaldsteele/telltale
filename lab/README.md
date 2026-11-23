# telltale test lab

Docker machines for developing and testing telltale. Everything here is named `telltale-lab*`.

## Layout

- `images/<distro>/Dockerfile` for debian12, debian13, ubuntu2204, ubuntu2404. Base images are pinned by digest, packages by snapshot timestamps in `images/common/pins.env` (snapshot.debian.org, snapshot.ubuntu.com). `images/common/` holds the shared setup (sshd with `PermitRootLogin no`, a key-only `lab` user, `iproute2 procps kmod sudo cron`), the entrypoint (cron plus `sshd -D -e`) and `set-snapshot.sh`, which re-points apt at another timestamp (used for the update-noise scenario).
- `variants/`: `clean`, `hardened`, `noexec` (a run flag, see below), `thirdparty` (two third-party apt sources, each with its key in a `signed-by` keyring: Tailscale, and the lab's own repository, from which `lab-vendor` 1.0 is installed through apt), `localsoft` (a built program and a setuid helper in `/usr/local`).
- `sink/`: TCP accept-and-log on 4444 and 8443, the attacker's remote end.
- `repo/`: the image `telltale-lab/repo`, a signed third-party APT repository holding `lab-vendor` 1.0 and 2.0, and a static file server for it. The signing keys are generated when the image is built, so none is in git. The image holds two trees with the same packages: one signed with the vendor's key (served as `telltale-lab-repo`) and one signed with a second key (served as `telltale-lab-repo-swapped`), for the scenario in which a repository and its key are swapped.
- `labkit/`: the Go harness (`Build`, `Start`, `Exec`, `CopyIn`, `CopyOut`, `IP`, `StartSink`, `StartRepo`, `Networks`, `Subnet`).
- `compose.yml`: the internal network and the sink, for use by hand. Build the sink first: `CGO_ENABLED=0 go build -tags lab -o lab/sink/sink ./lab/sink`.
- `compose.server.yml`: the server end-to-end test's telltale server, bubbles server and two machines (see below).

## Running

```
go test -tags lab -timeout 30m ./lab/...
```

Plain `go test ./...` never builds the lab. Images are tagged `telltale-lab/<distro>-<variant>:<hash of inputs>`. Machines run on the `telltale-lab` network (`docker network create --internal`), which has no route out. Images are built on Docker's default network because apt needs the internet.

The lab is careful with the Docker disk, which it usually shares:

- It works through one distro at a time and removes that distro's images when its tests are done. Set `TELLTALE_LAB_KEEP_IMAGES=1` to keep them for the next run.
- It skips everything, with a message, when Docker's root directory has less than 3 GB free.
- Every container, network, volume and image it creates carries the label `telltale-lab=1`. A run starts by removing containers, volumes and networks with that label that a killed run left behind, and ends the same way. Nothing without the label is touched, and nothing is pruned. If a network named `telltale-lab` or `telltale-lab-egress` exists without the label, the lab fails and asks you to remove it.
- A run fails, not skips, when Docker cannot be used. It raises `-parallel` to 16 when it is lower, because the tests have to move through the distros together.
- Lab test binaries take a lock in the cache directory, so two never run side by side.

`TELLTALE_LAB_DISTROS=debian12,ubuntu2404` limits a run to some distros. `TELLTALE_LAB_REPORTS=DIR` keeps every report as JSON under `DIR/<distro>/`.

## The scan suite

`scan_test.go` runs the real static binary inside the machines and compares every report with the manifests:

- `TestCleanMachinesAreClean`: every variant of every distro, nothing planted.
- `TestEveryBreakDetected` and `TestScenarios`: each break and each scenario on each distro.
- `TestUpdateNoiseIsExplained`: a clean machine is snapshotted and upgraded from the older pinned package snapshot to the newer one; nothing above a note may come of it. This machine has nothing planted and is the only one with a route out: it runs on `telltale-lab-egress`, because it needs the package archive.
- `TestOfflineFallbackWarns`: `scan --offline` says it used the machine's own checksums.
- `TestSystemdLiveUnit`: one machine with systemd as PID 1, where the callback unit's timer really runs.

Each case follows the same steps: take a snapshot of the clean machine and carry it off the machine, plant the break, bring the snapshot back under `/run/telltale-lab/`, then scan once with the snapshot and once without and check both reports.

Packages are verified the way an isolated machine's are (`refs.go`): `telltale collect` on the machine, `telltale fetch-refs` on the host, `telltale scan --refs` on the machine. Bundles are cached in `$TELLTALE_LAB_CACHE` (default `~/.cache/telltale-lab`), one per release and set of installed packages, and mounted read-only at `/lab-refs`.

A scan with a snapshot of a `thirdparty` machine uses a second bundle, built with `fetch-refs --snapshot`: it also carries the third-party repositories whose keys the snapshot recorded (Tailscale's, fetched from the internet, and the lab's). The host cannot resolve `telltale-lab-repo`, so for that one the harness sets `HTTP_PROXY` to the address of the repository server the machine itself reaches under that name; the server answers proxy-form requests. The scan without a snapshot uses the plain bundle: nothing vouches for a third-party repository then.

Hostnames default to `<distro>-<variant>`; set `Opts.Hostname` for the made-up names later scenarios use.

## The visit suite

`visit_test.go` runs server mode's visit (`internal/visit`) from the host against a Debian 12 machine, as the server would. The host reaches each machine's sshd directly at its address on the lab network, so no port is published. Each test enrols the machine in the owner's order: fetch the host key and compare its fingerprint with the machine's own `ssh-keygen -lf`, pin it, add the server's `authorized_keys` line for root and the `Match Address` block through `docker exec` exactly as the enrolment snippets say, and reload sshd. Then it visits and checks that a collection came back, that no `telltale.*` directory is left in `/run`, `/var/tmp`, `/root` or `/tmp`, and that the visit changed no file beyond the login records any SSH session writes.

- `TestVisitCleanMachine`: the clean machine. The collector runs from `/run`.
- `TestVisitNoexecMachine`: the noexec machine with `/run` and `/var/tmp` also mounted `noexec`, as `/run` is under systemd. Only `/root` is left for the collector.

## The server end-to-end test

`TestServerEndToEnd` (`server_test.go`) runs `compose.server.yml` as Compose project `telltale-lab-e2e`: a real `telltale server`, a bubbles server, the clean Debian 12 machine and the Ubuntu 24.04 noexec machine (with `/run` and `/var/tmp` noexec too). The server runs the binaries `scripts/build.sh` writes (built into a temporary directory with `TELLTALE_DIST_DIR`), which are also its collectors. It has a fixed address on `telltale-lab`, its `server_addr`, and also joins `telltale-lab-egress` to fetch packages for verification; the machines and bubbles are on `telltale-lab` only. Its package cache is kept in `$TELLTALE_LAB_CACHE/server-pkgcache` between runs.

The owner's part goes through the web UI's real forms: the setup code the server prints, the admin password, the login, CSRF tokens and the confirmation pages. The test pairs with bubbles (the fingerprint telltale shows is compared with bubbles' Admin > Overview, and the request is approved through bubbles' admin API, signed in with the generated admin password bubbles prints), makes an MCP token, enrols both machines (the snippets the UI shows are added through `docker exec` as shown), presses Check now, takes both snapshots, plants `root-key` and `regress-root-login` on Debian 12, and checks the machine page, the critical alerts in bubbles (only the changed line of a file, and not the server's own key or Match block), `latest_report` through `telltale mcp` on the host, and that the root key's alert is resolved once the key is gone. After every visit nothing may be left on the machine, and on the noexec machine the collector must have run from `/root`.

The bubbles image is `telltale-lab/bubbles:<version>`, the version `go.mod` requires. When it is missing it is built from bubbles' own `deploy/docker/Dockerfile` in a clean checkout of that tag: `TELLTALE_LAB_BUBBLES_SRC=DIR`, or `~/code/bubbles` (`git clone --branch v0.4.0 https://github.com/donaldsteele/bubbles DIR`). The test is skipped when `TELLTALE_LAB_DISTROS` leaves out debian12 or ubuntu2404.

## Notes

- The `noexec` variant is the plain image run with `--tmpfs /tmp:noexec --tmpfs /dev/shm:noexec`; `labkit.Start` adds those flags for it.
- `Opts.Systemd` runs `/sbin/init` as PID 1 in a private cgroup namespace (the container is privileged so that systemd can manage its own cgroup tree; the host's tree is not mounted, and the image masks the getty units so that it never opens the host's virtual terminals). It needs an image with systemd: `BuildWith(..., BuildOpts{Systemd: true})`.
- `BuildOpts{Newer: true}` builds an image at the newer pinned snapshot, upgraded. The downgrade break runs on it and goes back to the older openssl .debs the build kept.
- Machines get `CAP_SYS_PTRACE`, so that root in the container can see the programs of other accounts' processes, as root on a real machine can.
- `Opts.ExecShm` (manifest `requires.exec_shm`) mounts `/dev/shm` without `noexec`. Docker's own `/dev/shm` is `noexec`; a real machine's is not.
- `Opts.Tmpfs` adds `docker run --tmpfs` mounts (`"dir:options"`), for example `/var/tmp:noexec`.
- `Opts.Egress` puts a machine on `telltale-lab-egress`, the one lab network with a route out. The harness refuses to plant anything on such a machine.
- The `thirdparty` image is built while a copy of the repository server runs on Docker's default network (builds happen there), reached as `telltale-lab-repo` through `docker build --add-host`. Its tag depends on the repository image's ID, because the image holds that build's public key. The two servers on the lab network are started once per run and removed with everything else at the end.
- The two package snapshots in `images/common/pins.env` have to differ: the base pin is old enough that openssl, among others, has an update at the newer pin on all four distros.
- `Opts.Ext4Volume` creates a 64 MiB ext4 image on the host (no sudo), bind-mounts it into a privileged container and runs `mount -o loop` inside, giving a real ext4 at `/lab-ext4` for inode flags. (Docker's local volume driver cannot do this: it passes `loop` to mount(2) as data.) If the loop mount fails, the test skips with the reason.
- Cleanup removes only the containers, volumes and files a test created; nothing is pruned.

## Stand-ins, breaks, scenarios and manifests

- `standins/`: inert stand-ins, built at lab time (no binaries in git): `docker build -f lab/standins/Dockerfile.build -t telltale-lab/standins:dev lab/standins`. The image holds `/standins/<amd64|arm64>/{hider.so,pam_lab.so,listener,callback.sh}`. `callback.sh` connects to `sink:4444` once and exits (the callback breaks inline the same `/dev/tcp/sink/4444` command in the cron line, unit or profile script, so the entry itself shows the callback); `listener PORT` accepts and closes; `pam_lab.so` returns `PAM_IGNORE` from every hook; `hider.so` only hides the process named `lab-hidden` and TCP port 31337 from `ps`, `ss` and `/proc/net/tcp*`.
- `breaks/<id>/apply.sh` plants one technique and `breaks/<id>/manifest.json` says what telltale must report. `scenarios/<id>/` does the same for a whole story. Two of them are about the vendor's repository: `upgrade-while-running`, a legitimate upgrade through apt that must not alarm (with a snapshot it is verified with the key the snapshot recorded, and explained), and `repo-key-swapped`, in which the machine is pointed at a copy of the repository signed with another key and its keyring is replaced to match (the changed key is a note and the upgrade stays unconfirmed). Scripts run as root inside the machine and expect `lab/breaks`, `lab/scenarios` and the right-architecture stand-ins copied to `/lab/breaks`, `/lab/scenarios` and `/lab/standins`.
- `variants/<variant>.manifest.json` is each variant's baseline: nothing above "weak setting", with or without a snapshot. Against a snapshot of the same machine the only things above a note may be checklist items that were not met when the snapshot was taken either; `TestCleanMachinesAreClean` checks that.
- Manifest: `{"requires":{...}, "with_snapshot":{"must":[{"key_prefix","severity"}], "must_not_severity_above"}, "without_snapshot":{...}}`. Both sections are required (an empty `{}` means nothing is expected). `lab.Check(m, report, withSnapshot)` returns the mismatches. A `must` entry is met by a finding whose key starts with the prefix and whose severity is exactly the given one.
- `downgrade-package` and `new-service-package` install offline from .debs the image build fetched into `/var/cache/telltale-lab/debs/{openssl,lighttpd}` (see `images/common/setup.sh`). `downgrade-package` needs a machine at the newer snapshot (manifest `requires.newer_snapshot`): an image built with `BuildOpts{Newer: true}`, or by hand `docker build --build-arg LAB_NEWER=1`.
- Manifest sections may carry a `comment` (ignored by the matcher) saying why they are empty or unusual.

## Kernel checks in a VM

`lab/vm/` boots a Debian 12 machine in QEMU (a pinned image, cached in `~/.cache/telltale-lab/vm/`), builds the inert `labmod` module in it and checks that telltale reports it, along with the kernel command line and the live firewall. It needs `qemu-system-x86` and `cloud-image-utils`, network access, and read and write access to `/dev/kvm` (else the test is skipped). Run it with `go test -tags 'lab vm' -timeout 30m ./lab/vm/`: the first run downloads the image and the VM installs packages. A VM left behind by a killed test ends itself after an hour.
