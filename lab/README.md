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

Plain `go test ./...` never builds the lab. The first run builds the images (a few minutes); later runs reuse them, tagged `telltale-lab/<distro>-<variant>:<hash of inputs>`. Machines run on the `telltale-lab` network (`docker network create --internal`), which has no route out. Images are built on Docker's default network because apt needs the internet.

Hostnames default to `<distro>-<variant>`; set `Opts.Hostname` for the made-up names later scenarios use.

## Notes

- The `noexec` variant is the plain image run with `--tmpfs /tmp:noexec --tmpfs /dev/shm:noexec`; `labkit.Start` adds those flags for it.
- `Opts.Systemd` runs `/sbin/init` as PID 1 and needs an image with systemd, which the images do not carry yet.
- `Opts.Ext4Volume` creates a 64 MiB ext4 image on the host (no sudo), bind-mounts it into a privileged container and runs `mount -o loop` inside, giving a real ext4 at `/lab-ext4` for inode flags. (Docker's local volume driver cannot do this: it passes `loop` to mount(2) as data.) If the loop mount fails, the test skips with the reason.
- Cleanup removes only the containers, volumes and files a test created; nothing is pruned.

## Stand-ins, breaks, scenarios and manifests

- `standins/`: inert stand-ins, built at lab time (no binaries in git): `docker build -f lab/standins/Dockerfile.build -t telltale-lab/standins:dev lab/standins`. The image holds `/standins/<amd64|arm64>/{hider.so,pam_lab.so,listener,callback.sh}`. `callback.sh` connects to `sink:4444` once and exits (the callback breaks inline the same `/dev/tcp/sink/4444` command in the cron line, unit or profile script, so the entry itself shows the callback); `listener PORT` accepts and closes; `pam_lab.so` returns `PAM_IGNORE` from every hook; `hider.so` only hides the process named `lab-hidden` and TCP port 31337 from `ps`, `ss` and `/proc/net/tcp*`.
- `breaks/<id>/apply.sh` plants one technique and `breaks/<id>/manifest.json` says what telltale must report. `scenarios/<id>/` does the same for a whole story (and `upgrade-while-running`, a legitimate event that must not alarm). Scripts run as root inside the machine and expect `lab/breaks`, `lab/scenarios` and the right-architecture stand-ins copied to `/lab/breaks`, `/lab/scenarios` and `/lab/standins`.
- `variants/<variant>.manifest.json` is each variant's baseline: nothing above "weak setting" without a snapshot, nothing above "note" with a snapshot of the same machine.
- Manifest: `{"requires":{...}, "with_snapshot":{"must":[{"key_prefix","severity"}], "must_not_severity_above"}, "without_snapshot":{...}}`. Both sections are required (an empty `{}` means nothing is expected). `lab.Check(m, report, withSnapshot)` returns the mismatches. A `must` entry is met by a finding whose key starts with the prefix and whose severity is exactly the given one.
- `downgrade-package` and `new-service-package` install offline from .debs the image build fetched into `/var/cache/telltale-lab/debs/{openssl,lighttpd}` (see `images/common/setup.sh`). `downgrade-package` needs a machine at the newer snapshot: `prepare.sh` brings it there and needs network access, so run it on a networked bridge before the clean snapshot is taken.
- Manifest sections may carry a `comment` (ignored by the matcher) saying why they are empty or unusual.
