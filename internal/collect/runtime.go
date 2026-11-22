package collect

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/donaldsteele/telltale/internal/model"
	"golang.org/x/sys/unix"
)

const (
	runtimeCheck  = "runtime"
	maxExeHash    = 2 << 30
	maxCmdline    = 4096
	deletedSuffix = " (deleted)"
)

// readlinkFn is os.Readlink; tests override it to present a "(deleted)" link
// target that a fixture cannot hold.
var readlinkFn = os.Readlink

// SysctlKeys are the security-relevant sysctls collected.
var SysctlKeys = []string{
	"kernel.randomize_va_space", "kernel.kptr_restrict", "kernel.dmesg_restrict",
	"fs.suid_dumpable", "fs.protected_symlinks", "fs.protected_hardlinks",
	"net.ipv4.ip_forward", "net.ipv4.conf.all.accept_redirects",
	"net.ipv4.conf.all.send_redirects", "net.ipv4.conf.all.accept_source_route",
	"net.ipv4.conf.all.rp_filter", "net.ipv4.tcp_syncookies",
	"net.ipv6.conf.all.accept_redirects", "kernel.modules_disabled",
	"kernel.yama.ptrace_scope",
}

// readBounded reads a regular file without following a final symlink, reading
// at most max bytes.
func readBounded(path string, max int64) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, fmt.Errorf("%s: not a regular file", path)
	}
	return io.ReadAll(io.LimitReader(f, max))
}

// Runtime collects the live state of the machine from procRoot (/proc) and
// sysRoot (/sys). root is the filesystem root used to locate module files.
func Runtime(procRoot, sysRoot, root string) (model.Runtime, map[string]string, []model.Skip) {
	var rt model.Runtime
	var skips []model.Skip
	skip := func(format string, a ...any) {
		skips = append(skips, model.Skip{Check: runtimeCheck, Reason: fmt.Sprintf(format, a...)})
	}

	// Processes.
	ents, err := os.ReadDir(procRoot)
	if err != nil {
		skip("%s: %v", procRoot, err)
	}
	var pids []int
	for _, e := range ents {
		if n, err := strconv.Atoi(e.Name()); err == nil && n > 0 && e.IsDir() {
			pids = append(pids, n)
		}
	}
	sort.Ints(pids)
	exeDenied, partial := 0, 0
	for _, pid := range pids {
		if pid == os.Getpid() {
			continue // telltale does not examine itself
		}
		p, ok, denied, part := readProcess(procRoot, pid, skip)
		if denied {
			exeDenied++
		}
		if part {
			partial++
		}
		if ok {
			rt.Processes = append(rt.Processes, p)
		}
	}
	if exeDenied > 0 {
		skip("process executables: %d not readable without root", exeDenied)
	}
	if partial > 0 {
		skip("processes: %d not fully readable", partial)
	}

	// Sockets.
	owners, fdDenied := socketOwners(procRoot, pids)
	if fdDenied > 0 {
		skip("socket owners: %d processes' fd tables not readable without root", fdDenied)
	}
	for _, proto := range []string{"tcp", "tcp6", "udp", "udp6"} {
		rt.Sockets = append(rt.Sockets, parseSockets(procRoot, proto, owners, &skips)...)
	}

	// Modules, command line, mounts.
	rt.Modules = readModules(procRoot, root, skip)
	if b, err := readBounded(filepath.Join(procRoot, "cmdline"), 1<<16); err == nil {
		s := strings.ReplaceAll(strings.TrimRight(string(b), "\x00\n"), "\x00", " ")
		rt.Cmdline = strings.TrimSpace(s)
	} else if !errors.Is(err, fs.ErrNotExist) {
		skip("cmdline: %v", err)
	}
	rt.Mounts = readMounts(procRoot, skip)

	// Sysctls.
	sc := make(map[string]string)
	for _, k := range SysctlKeys {
		b, err := readBounded(filepath.Join(procRoot, "sys", strings.ReplaceAll(k, ".", "/")), 4096)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				skip("sysctl %s: %v", k, err)
			}
			continue
		}
		sc[k] = strings.TrimSpace(string(b))
	}
	if b, err := readBounded(filepath.Join(sysRoot, "module/apparmor/parameters/enabled"), 4096); err == nil {
		sc["apparmor.enabled"] = strings.TrimSpace(string(b))
	} else if !errors.Is(err, fs.ErrNotExist) {
		skip("sysctl apparmor.enabled: %v", err)
	}
	return rt, sc, skips
}

func unescapeMount(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func readMounts(procRoot string, skip func(string, ...any)) []model.Mount {
	b, err := readBounded(filepath.Join(procRoot, "self/mountinfo"), 16<<20)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			skip("mountinfo: %v", err)
		}
		return nil
	}
	var out []model.Mount
	for _, ln := range strings.Split(string(b), "\n") {
		pre, post, ok := strings.Cut(ln, " - ")
		if !ok {
			continue
		}
		a, c := strings.Fields(pre), strings.Fields(post)
		if len(a) < 6 || len(c) < 2 {
			continue
		}
		opts := a[5]
		if len(c) >= 3 && c[2] != "" {
			opts += "," + c[2]
		}
		out = append(out, model.Mount{Path: unescapeMount(a[4]), FSType: c[0], Source: unescapeMount(c[1]), Options: opts})
	}
	return out
}
