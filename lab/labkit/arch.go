//go:build lab

package labkit

import (
	"fmt"
	"os"
	"runtime"
)

// Arch is the architecture of the lab's machines: $TELLTALE_LAB_ARCH, amd64
// or arm64, by default the host's. Images are built and machines run for
// it (docker --platform linux/<Arch>); on another architecture than the
// host's they run under QEMU emulation, which needs binfmt_misc
// registered (qemu-user-static, or docker/setup-qemu-action in CI). The
// sink stays on the host's architecture: it only accepts connections.
var Arch = labArch()

func labArch() string {
	a := os.Getenv("TELLTALE_LAB_ARCH")
	if a == "" {
		a = runtime.GOARCH
	}
	if a != "amd64" && a != "arm64" {
		fmt.Fprintf(os.Stderr, "lab: TELLTALE_LAB_ARCH=%q: the lab runs amd64 or arm64 machines\n", a)
		os.Exit(1)
	}
	return a
}

// Platform is Arch as docker's --platform takes it.
func Platform() string { return "linux/" + Arch }

// archTag is what an image tag carries for Arch: nothing for amd64, so the
// images and caches of earlier runs keep their tags, and "arm64-" before
// the hash for arm64, so the two architectures' images never share a tag.
func archTag() string {
	if Arch == "amd64" {
		return ""
	}
	return Arch + "-"
}

// Emulated reports whether the machines run under emulation.
func Emulated() bool { return Arch != runtime.GOARCH }
