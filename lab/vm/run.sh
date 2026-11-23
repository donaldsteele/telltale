#!/bin/sh
# Boots the Debian 12 VM that the kernel checks run in.
#
#   run.sh up   WORKDIR PUBKEY_FILE SSH_PORT   boot the VM, return when it is up
#   run.sh down WORKDIR                        stop it
#
# "up" exits 77 (skipped) when /dev/kvm is missing or the current user cannot
# read and write it. The VM needs outbound network for apt (user-mode
# networking); SSH is reached through 127.0.0.1:SSH_PORT. Nothing is written
# outside WORKDIR except the cached image under ~/.cache/telltale-lab/vm.
set -eu

# A dated Debian 12 genericcloud amd64 build, pinned by URL and SHA512 (from
# that build's SHA512SUMS; the directory publishes no SHA512SUMS.sign).
IMAGE_NAME=debian-12-genericcloud-amd64-20261117-2665.qcow2
IMAGE_URL=https://cloud.debian.org/images/cloud/bookworm/20261117-2665/$IMAGE_NAME
IMAGE_SHA512=946b917a37882f16e5b3b0b2cbe5744637d0cd36190b5b53cbb21d14a54557d5b45e9e523021b8f52c1707dbe470489f3515458e0680ded76ee2574b4a8daf1b

here=$(cd "$(dirname "$0")" && pwd)
cache=${TELLTALE_LAB_CACHE:-$HOME/.cache/telltale-lab}/vm

die() { echo "run.sh: $*" >&2; exit 1; }

stop_vm() {
	[ -f "$1/qemu.pid" ] || return 0
	pid=$(cat "$1/qemu.pid" 2>/dev/null || true)
	if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
		kill "$pid" 2>/dev/null || true
		for _ in 1 2 3 4 5 6 7 8 9 10; do
			kill -0 "$pid" 2>/dev/null || break
			sleep 0.5
		done
		kill -9 "$pid" 2>/dev/null || true
	fi
	rm -f "$1/qemu.pid"
}

fetch_image() {
	mkdir -p "$cache"
	img=$cache/$IMAGE_NAME
	if [ -f "$img" ] && echo "$IMAGE_SHA512  $img" | sha512sum -c --status 2>/dev/null; then
		return 0
	fi
	echo "run.sh: downloading $IMAGE_URL" >&2
	rm -f "$img.part"
	curl -fL --retry 3 -o "$img.part" "$IMAGE_URL"
	if ! echo "$IMAGE_SHA512  $img.part" | sha512sum -c --status; then
		rm -f "$img.part"
		die "SHA512 of the downloaded image does not match the pinned value"
	fi
	mv "$img.part" "$img"
}

case ${1:-} in
down)
	[ $# -eq 2 ] || die "usage: run.sh down WORKDIR"
	stop_vm "$2"
	;;
up)
	[ $# -eq 4 ] || die "usage: run.sh up WORKDIR PUBKEY_FILE SSH_PORT"
	work=$2 pubkey=$3 port=$4
	if [ ! -e /dev/kvm ]; then
		echo "run.sh: skipping: /dev/kvm does not exist" >&2
		exit 77
	fi
	if [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
		echo "run.sh: skipping: /dev/kvm is not readable and writable by $(id -un) (add the user to the kvm group)" >&2
		exit 77
	fi
	for t in qemu-system-x86_64 qemu-img cloud-localds curl sha512sum; do
		command -v "$t" >/dev/null 2>&1 || die "$t is not installed (apt-get install qemu-system-x86 cloud-image-utils curl)"
	done
	mkdir -p "$work"
	# A failed boot must not leave QEMU behind.
	trap 'rc=$?; [ $rc -eq 0 ] || stop_vm "$work"' EXIT
	fetch_image
	qemu-img create -q -f qcow2 -b "$cache/$IMAGE_NAME" -F qcow2 "$work/disk.qcow2" 10G
	key=$(cat "$pubkey")
	b64=$(base64 -w0 "$here/labmod.c")
	sed -e "s|@SSH_PUBKEY@|$key|" -e "s|@LABMOD_C_B64@|$b64|" "$here/user-data" >"$work/user-data"
	printf 'instance-id: telltale-lab-%s\nlocal-hostname: telltale-lab\n' "$port" >"$work/meta-data"
	cloud-localds "$work/seed.img" "$work/user-data" "$work/meta-data"
	qemu-system-x86_64 -enable-kvm -cpu host -m 2048 -smp 2 \
		-display none -serial "file:$work/console.log" \
		-drive "file=$work/disk.qcow2,if=virtio,format=qcow2" \
		-drive "file=$work/seed.img,if=virtio,format=raw,readonly=on" \
		-nic "user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:$port-:22" \
		-pidfile "$work/qemu.pid" -daemonize
	;;
*)
	die "usage: run.sh up WORKDIR PUBKEY_FILE SSH_PORT | down WORKDIR"
	;;
esac
