# telltale test lab

Docker machines for developing and testing telltale. Everything here is named `telltale-lab*`.

## Layout

- `images/<distro>/Dockerfile` for debian12, debian13, ubuntu2204, ubuntu2404. Base images are pinned by digest, packages by snapshot timestamps in `images/common/pins.env` (snapshot.debian.org, snapshot.ubuntu.com). `images/common/` holds the shared setup (sshd with `PermitRootLogin no`, a key-only `lab` user, `iproute2 procps kmod sudo cron`), the entrypoint (cron plus `sshd -D -e`) and `set-snapshot.sh`, which re-points apt at another timestamp (used for the update-noise scenario).
- `variants/`: `clean`, `hardened`, `noexec` (a run flag, see below), `thirdparty` (Tailscale apt source and key), `localsoft` (a built program and a setuid helper in `/usr/local`).
- `sink/`: TCP accept-and-log on 4444 and 8443, the attacker's remote end.
- `labkit/`: the Go harness (`Build`, `Start`, `Exec`, `CopyIn`, `CopyOut`, `IP`, `StartSink`).
- `compose.yml`: the internal network and the sink, for use by hand. Build the sink first: `CGO_ENABLED=0 go build -tags lab -o lab/sink/sink ./lab/sink`.

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

Hostnames default to `<distro>-<variant>`; set `Opts.Hostname` for the made-up names later scenarios use.

## Notes

- The `noexec` variant is the plain image run with `--tmpfs /tmp:noexec --tmpfs /dev/shm:noexec`; `labkit.Start` adds those flags for it.
- `Opts.Systemd` runs `/sbin/init` as PID 1 in a private cgroup namespace (the container is privileged so that systemd can manage its own cgroup tree; the host's tree is not mounted, and the image masks the getty units so that it never opens the host's virtual terminals). It needs an image with systemd: `BuildWith(..., BuildOpts{Systemd: true})`.
- `BuildOpts{Newer: true}` builds an image at the newer pinned snapshot, upgraded. The downgrade break runs on it and goes back to the older openssl .debs the build kept.
- Machines get `CAP_SYS_PTRACE`, so that root in the container can see the programs of other accounts' processes, as root on a real machine can.
- `Opts.ExecShm` (manifest `requires.exec_shm`) mounts `/dev/shm` without `noexec`. Docker's own `/dev/shm` is `noexec`; a real machine's is not.
- `Opts.Egress` puts a machine on `telltale-lab-egress`, the one lab network with a route out. The harness refuses to plant anything on such a machine.
- The two package snapshots in `images/common/pins.env` have to differ: the base pin is old enough that openssl, among others, has an update at the newer pin on all four distros.
- `Opts.Ext4Volume` creates a 64 MiB ext4 image on the host (no sudo), bind-mounts it into a privileged container and runs `mount -o loop` inside, giving a real ext4 at `/lab-ext4` for inode flags. (Docker's local volume driver cannot do this: it passes `loop` to mount(2) as data.) If the loop mount fails, the test skips with the reason.
- Cleanup removes only the containers, volumes and files a test created; nothing is pruned.

## Stand-ins, breaks, scenarios and manifests

- `standins/`: inert stand-ins, built at lab time (no binaries in git): `docker build -f lab/standins/Dockerfile.build -t telltale-lab/standins:dev lab/standins`. The image holds `/standins/<amd64|arm64>/{hider.so,pam_lab.so,listener,callback.sh}`. `callback.sh` connects to `sink:4444` once and exits (the callback breaks inline the same `/dev/tcp/sink/4444` command in the cron line, unit or profile script, so the entry itself shows the callback); `listener PORT` accepts and closes; `pam_lab.so` returns `PAM_IGNORE` from every hook; `hider.so` only hides the process named `lab-hidden` and TCP port 31337 from `ps`, `ss` and `/proc/net/tcp*`.
- `breaks/<id>/apply.sh` plants one technique and `breaks/<id>/manifest.json` says what telltale must report. `scenarios/<id>/` does the same for a whole story (and `upgrade-while-running`, a legitimate event that must not alarm). Scripts run as root inside the machine and expect `lab/breaks`, `lab/scenarios` and the right-architecture stand-ins copied to `/lab/breaks`, `/lab/scenarios` and `/lab/standins`.
- `variants/<variant>.manifest.json` is each variant's baseline: nothing above "weak setting", with or without a snapshot. Against a snapshot of the same machine the only things above a note may be checklist items that were not met when the snapshot was taken either; `TestCleanMachinesAreClean` checks that.
- Manifest: `{"requires":{...}, "with_snapshot":{"must":[{"key_prefix","severity"}], "must_not_severity_above"}, "without_snapshot":{...}}`. Both sections are required (an empty `{}` means nothing is expected). `lab.Check(m, report, withSnapshot)` returns the mismatches. A `must` entry is met by a finding whose key starts with the prefix and whose severity is exactly the given one.
- `downgrade-package` and `new-service-package` install offline from .debs the image build fetched into `/var/cache/telltale-lab/debs/{openssl,lighttpd}` (see `images/common/setup.sh`). `downgrade-package` needs a machine at the newer snapshot (manifest `requires.newer_snapshot`): an image built with `BuildOpts{Newer: true}`, or by hand `docker build --build-arg LAB_NEWER=1`.
- Manifest sections may carry a `comment` (ignored by the matcher) saying why they are empty or unusual.
