package collect

import (
	"crypto/sha256"
	"encoding/hex"
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
	exeDenied := 0
	for _, pid := range pids {
		p, ok, denied := readProcess(procRoot, pid, skip)
		if denied {
			exeDenied++
		}
		if ok {
			rt.Processes = append(rt.Processes, p)
		}
	}
	if exeDenied > 0 {
		skip("process executables: %d not readable without root", exeDenied)
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

// readProcess reads one pid. ok is false when the process is not recorded
// (it vanished). denied reports that its exe was unreadable for permissions.
func readProcess(procRoot string, pid int, skip func(string, ...any)) (p model.Process, ok, denied bool) {
	dir := filepath.Join(procRoot, strconv.Itoa(pid))
	stat, err := readBounded(filepath.Join(dir, "stat"), 1<<16)
	if err != nil {
		skip("pid %d: vanished: %v", pid, err)
		return p, false, false
	}
	s := string(stat)
	l, r := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
	if l < 0 || r < l {
		skip("pid %d: unparseable stat", pid)
		return p, false, false
	}
	rest := strings.Fields(s[r+1:])
	if len(rest) < 2 {
		skip("pid %d: unparseable stat", pid)
		return p, false, false
	}
	p.PID = pid
	p.Comm = s[l+1 : r]
	p.PPID, _ = strconv.Atoi(rest[1])

	if st, err := readBounded(filepath.Join(dir, "status"), 1<<16); err == nil {
		for _, ln := range strings.Split(string(st), "\n") {
			if f := strings.Fields(ln); len(f) >= 2 && f[0] == "Uid:" {
				p.UID, _ = strconv.Atoi(f[1])
				break
			}
		}
	} else if errors.Is(err, fs.ErrNotExist) {
		skip("pid %d: vanished: %v", pid, err)
		return p, false, false
	}

	if b, err := readBounded(filepath.Join(dir, "cmdline"), maxCmdline*2); err == nil {
		b = []byte(strings.TrimRight(string(b), "\x00"))
		if len(b) > maxCmdline {
			b = b[:maxCmdline]
		}
		p.Cmdline = strings.ReplaceAll(string(b), "\x00", " ")
	}

	link, err := readlinkFn(filepath.Join(dir, "exe"))
	switch {
	case err == nil:
		if strings.HasSuffix(link, deletedSuffix) {
			p.ExeDeleted = true
			link = strings.TrimSuffix(link, deletedSuffix)
		}
		p.Exe = link
		sha, herr := hashExe(filepath.Join(dir, "exe"))
		if herr == nil {
			p.ExeSHA256 = sha
		} else if errors.Is(herr, fs.ErrPermission) {
			denied = true
		} else if errors.Is(herr, fs.ErrNotExist) {
			skip("pid %d: vanished: %v", pid, herr)
			return p, false, false
		} else {
			skip("pid %d: hashing exe: %v", pid, herr)
		}
	case errors.Is(err, fs.ErrPermission):
		denied = true
	case errors.Is(err, fs.ErrNotExist):
		// Kernel threads and zombies have no exe link.
		if p.Cmdline != "" && p.PPID != 2 && pid != 2 {
			skip("pid %d: vanished: %v", pid, err)
			return p, false, false
		}
	default:
		skip("pid %d: exe: %v", pid, err)
	}
	return p, true, denied
}

// hashExe hashes the open exe link, which works for deleted executables. It
// follows the link on purpose (the magic link is the only way to reach a
// deleted file) and refuses anything that is not a regular file.
func hashExe(path string) (string, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", &fs.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return "", err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return "", errors.New("exe is not a regular file")
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, maxExeHash)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func readModules(procRoot, root string, skip func(string, ...any)) []model.KernelModule {
	b, err := readBounded(filepath.Join(procRoot, "modules"), 16<<20)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			skip("modules: %v", err)
		}
		return nil
	}
	var idx map[string]string
	var mods []model.KernelModule
	for _, ln := range strings.Split(string(b), "\n") {
		f := strings.Fields(ln)
		if len(f) < 6 {
			continue
		}
		if idx == nil {
			idx = moduleIndex(procRoot, root)
		}
		m := model.KernelModule{Name: f[0], File: idx[normModule(f[0])]}
		m.Size, _ = strconv.Atoi(f[1])
		if len(f) >= 7 && strings.HasPrefix(f[len(f)-1], "(") {
			m.Taint = strings.Trim(f[len(f)-1], "()")
		}
		mods = append(mods, m)
	}
	return mods
}

func normModule(n string) string { return strings.ReplaceAll(n, "-", "_") }

// moduleIndex walks the module trees once and maps normalised module names to
// machine paths. The first match wins (/lib before /usr/lib).
func moduleIndex(procRoot, root string) map[string]string {
	idx := make(map[string]string)
	rel, err := readBounded(filepath.Join(procRoot, "sys/kernel/osrelease"), 256)
	kernel := strings.TrimSpace(string(rel))
	if err != nil || kernel == "" || strings.ContainsAny(kernel, "/\x00") || kernel == ".." {
		return idx
	}
	for _, base := range []string{"/lib/modules/", "/usr/lib/modules/"} {
		top := filepath.Join(root, base, kernel)
		_ = filepath.WalkDir(top, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			n := d.Name()
			for _, ext := range []string{".ko", ".ko.xz", ".ko.zst", ".ko.gz"} {
				if strings.HasSuffix(n, ext) {
					k := normModule(strings.TrimSuffix(n, ext))
					if _, ok := idx[k]; !ok {
						idx[k] = strings.TrimPrefix(p, strings.TrimRight(root, "/"))
					}
					break
				}
			}
			return nil
		})
	}
	return idx
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
