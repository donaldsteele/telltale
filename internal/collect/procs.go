package collect

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
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

// readBoundedFn and nlinkFn are indirections so tests can inject read errors
// (such as ESRCH from an exited task) and unlinked executables.
var (
	readBoundedFn = readBounded
	nlinkFn       = func(_ string, st *unix.Stat_t) uint64 { return uint64(st.Nlink) }
)

// UnknownUID is Process.UID when the real uid could not be read (for example
// under hidepid); a plain 0 would falsely claim root.
const UnknownUID = -1

// gone reports that a read failed because the task no longer exists.
func gone(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, unix.ESRCH)
}

// readProcess reads one pid. ok is false only when the process has genuinely
// vanished or is unparseable. denied: exe unreadable for permissions.
// partial: stat/status unreadable for permissions (hidepid).
func readProcess(procRoot string, pid int, skip func(string, ...any)) (p model.Process, ok, denied, partial bool) {
	dir := filepath.Join(procRoot, strconv.Itoa(pid))
	omit := func(why error) (model.Process, bool, bool, bool) {
		skip("pid %d: vanished: %v", pid, why)
		return model.Process{}, false, false, false
	}
	p.PID = pid
	p.UID = UnknownUID

	stat, err := readBoundedFn(filepath.Join(dir, "stat"), 1<<16)
	switch {
	case err == nil:
		s := string(stat)
		l, r := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
		var rest []string
		if l >= 0 && r > l {
			rest = strings.Fields(s[r+1:])
		}
		if len(rest) < 2 {
			skip("pid %d: unparseable stat", pid)
			return model.Process{}, false, false, false
		}
		p.Comm = s[l+1 : r]
		p.PPID, _ = strconv.Atoi(rest[1])
	case errors.Is(err, fs.ErrPermission):
		partial = true
	default:
		return omit(err)
	}

	st, err := readBoundedFn(filepath.Join(dir, "status"), 1<<16)
	switch {
	case err == nil:
		found := false
		for _, ln := range strings.Split(string(st), "\n") {
			if f := strings.Fields(ln); len(f) >= 2 && f[0] == "Uid:" {
				if u, err := strconv.Atoi(f[1]); err == nil {
					p.UID, found = u, true
				}
				break
			}
		}
		if !found {
			return omit(errors.New("no Uid line in status"))
		}
	case errors.Is(err, fs.ErrPermission):
		partial = true
	default:
		return omit(err)
	}

	if b, err := readBoundedFn(filepath.Join(dir, "cmdline"), maxCmdline*2); err == nil {
		b = []byte(strings.TrimRight(string(b), "\x00"))
		if len(b) > maxCmdline {
			b = b[:maxCmdline]
		}
		p.Cmdline = strings.ReplaceAll(string(b), "\x00", " ")
	} else if gone(err) {
		return omit(err)
	}

	link, err := readlinkFn(filepath.Join(dir, "exe"))
	switch {
	case err == nil:
		p.Exe = link
		res, herr := hashExe(filepath.Join(dir, "exe"))
		if res.opened {
			p.ExeDeleted = strings.HasSuffix(link, deletedSuffix) && res.nlink == 0
		} else {
			p.ExeDeleted = strings.HasSuffix(link, deletedSuffix)
		}
		if p.ExeDeleted {
			p.Exe = strings.TrimSuffix(link, deletedSuffix)
		}
		switch {
		case herr == nil:
			p.ExeSHA256 = res.sum
		case errors.Is(herr, fs.ErrPermission):
			denied = true
		case gone(herr):
			return omit(herr)
		case errors.Is(herr, errTooLarge):
			skip("pid %d: executable too large to hash", pid)
		default:
			skip("pid %d: hashing exe: %v", pid, herr)
		}
	case errors.Is(err, fs.ErrPermission):
		denied = true
	case gone(err):
		if _, serr := os.Stat(dir); serr != nil && gone(serr) {
			return omit(err)
		}
		// Kernel threads and zombies have no exe link and no cmdline.
		if p.Cmdline != "" {
			skip("pid %d: executable link missing", pid)
		}
	default:
		skip("pid %d: exe: %v", pid, err)
	}
	return p, true, denied, partial
}

var errTooLarge = errors.New("executable too large to hash")

type exeResult struct {
	sum    string
	nlink  uint64
	opened bool
}

// hashExe hashes the open exe link, which works for deleted executables. It
// follows the link on purpose (the magic link is the only way to reach a
// deleted file) and refuses anything that is not a regular file. Files over
// the cap are not hashed at all rather than partially.
func hashExe(path string) (exeResult, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return exeResult{}, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return exeResult{}, err
	}
	res := exeResult{opened: true, nlink: nlinkFn(path, &st)}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return res, errors.New("exe is not a regular file")
	}
	if st.Size > maxExeHash {
		return res, errTooLarge
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, maxExeHash+1))
	if err != nil {
		return res, err
	}
	if n > maxExeHash {
		return res, errTooLarge
	}
	res.sum = hex.EncodeToString(h.Sum(nil))
	return res, nil
}

func readModules(procRoot, root string, skip func(string, ...any)) []model.KernelModule {
	b, err := readBounded(filepath.Join(procRoot, "modules"), 16<<20)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			skip("modules: %v", err)
		}
		return nil
	}
	var idx map[string][]string
	var mods []model.KernelModule
	for _, ln := range strings.Split(string(b), "\n") {
		f := strings.Fields(ln)
		if len(f) < 6 {
			continue
		}
		if idx == nil {
			idx = moduleIndex(procRoot, root)
		}
		m := model.KernelModule{Name: f[0]}
		m.File = pickModule(idx[normModule(f[0])], f[0], skip)
		m.Size, _ = strconv.Atoi(f[1])
		if len(f) >= 7 && strings.HasPrefix(f[len(f)-1], "(") {
			m.Taint = strings.Trim(f[len(f)-1], "()")
		}
		mods = append(mods, m)
	}
	return mods
}

func normModule(n string) string { return strings.ReplaceAll(n, "-", "_") }

// pickModule follows depmod's search order: updates/, then extra/, then the
// rest. More than one candidate at the chosen level is reported as ambiguous.
func pickModule(cands []string, name string, skip func(string, ...any)) string {
	if len(cands) == 0 {
		return ""
	}
	rank := func(p string) int {
		switch {
		case strings.Contains(p, "/updates/"):
			return 0
		case strings.Contains(p, "/extra/"):
			return 1
		}
		return 2
	}
	best := rank(cands[0])
	for _, c := range cands {
		if r := rank(c); r < best {
			best = r
		}
	}
	var at []string
	for _, c := range cands {
		if rank(c) == best {
			at = append(at, c)
		}
	}
	sort.Strings(at)
	if len(at) > 1 {
		skip("module %s: ambiguous, %d candidates, using %s", name, len(at), at[0])
	}
	return at[0]
}

// moduleIndex walks the module trees once and maps normalised module names to
// machine paths. Files reachable through both /lib and /usr/lib (merged /usr)
// are the same inode and counted once.
func moduleIndex(procRoot, root string) map[string][]string {
	idx := make(map[string][]string)
	rel, err := readBounded(filepath.Join(procRoot, "sys/kernel/osrelease"), 256)
	kernel := strings.TrimSpace(string(rel))
	if err != nil || kernel == "" || strings.ContainsAny(kernel, "/\x00") || kernel == ".." {
		return idx
	}
	type key struct{ dev, ino uint64 }
	seen := make(map[key]bool)
	for _, base := range []string{"/lib/modules/", "/usr/lib/modules/"} {
		top := filepath.Join(root, base, kernel)
		_ = filepath.WalkDir(top, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			n := d.Name()
			for _, ext := range []string{".ko", ".ko.xz", ".ko.zst", ".ko.gz"} {
				if !strings.HasSuffix(n, ext) {
					continue
				}
				var st unix.Stat_t
				if unix.Lstat(p, &st) == nil {
					k := key{uint64(st.Dev), st.Ino}
					if seen[k] {
						break
					}
					seen[k] = true
				}
				k := normModule(strings.TrimSuffix(n, ext))
				idx[k] = append(idx[k], strings.TrimPrefix(p, strings.TrimRight(root, "/")))
				break
			}
			return nil
		})
	}
	return idx
}
