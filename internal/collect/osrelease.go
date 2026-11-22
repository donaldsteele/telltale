package collect

import (
	"path/filepath"
	"runtime"
	"strings"

	"github.com/donaldsteele/telltale/internal/model"
)

func dpkgArch(goarch string) string {
	switch goarch {
	case "arm":
		return "armhf"
	case "386":
		return "i386"
	}
	return goarch
}

// Host identifies the machine from os-release and procfs.
func Host(root, procRoot string) model.Host {
	h := model.Host{Arch: dpkgArch(runtime.GOARCH)}
	b, err := readRaw(root, "/etc/os-release", 64<<10)
	if err != nil {
		b, _ = readRaw(root, "/usr/lib/os-release", 64<<10)
	}
	for _, l := range splitLines(b) {
		k, v, ok := strings.Cut(strings.TrimSpace(l), "=")
		if !ok || strings.HasPrefix(k, "#") {
			continue
		}
		v = unquote(strings.TrimSpace(v))
		switch k {
		case "ID":
			h.OSID = v
		case "VERSION_ID":
			h.OSVersionID = v
		case "PRETTY_NAME":
			h.OSPretty = v
		}
	}
	h.Hostname = readTrim(filepath.Join(procRoot, "sys/kernel/hostname"))
	h.Kernel = readTrim(filepath.Join(procRoot, "sys/kernel/osrelease"))
	return h
}

func unquote(v string) string {
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		return v[1 : len(v)-1]
	}
	return v
}

func readTrim(p string) string {
	b, err := readBounded(p, 4096)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
