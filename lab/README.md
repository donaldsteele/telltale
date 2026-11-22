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
- `Opts.Ext4Volume` asks the Docker daemon for a loop-backed ext4 volume at `/lab-ext4`. On hosts where the daemon cannot do that (the local volume driver cannot pass `loop`), the test skips with a message. Inode-flag tests then need a host with a real ext4 mount.
- Cleanup removes only the containers, volumes and files a test created; nothing is pruned.
