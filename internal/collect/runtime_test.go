package collect

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/donaldsteele/telltale/internal/model"
	"golang.org/x/sys/unix"
)

// A fixture cannot hold a real deleted executable, so the fixture's
// <pid>/exe entries are symlinks to files under testdata/proc1/exes and the
// readlink text the collector sees is substituted through readlinkFn.
func fakeReadlink(t *testing.T, m map[string]string) {
	t.Helper()
	old := readlinkFn
	readlinkFn = func(p string) (string, error) {
		if v, ok := m[filepath.Base(filepath.Dir(p))]; ok && filepath.Base(p) == "exe" {
			return v, nil
		}
		return os.Readlink(p)
	}
	t.Cleanup(func() { readlinkFn = old })
}

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func runFixture(t *testing.T) (model.Runtime, map[string]string, []model.Skip) {
	fakeReadlink(t, map[string]string{"100": "/usr/bin/sleep", "200": "/tmp/x (deleted)"})
	fakeNlink(t, "/200/")
	root := t.TempDir()
	kdir := filepath.Join(root, "lib/modules/6.1.0-test/kernel/fs/ext4")
	os.MkdirAll(kdir, 0o755)
	os.WriteFile(filepath.Join(kdir, "ext4-mod.ko.xz"), nil, 0o644)
	ndir := filepath.Join(root, "usr/lib/modules/6.1.0-test/kernel/net")
	os.MkdirAll(ndir, 0o755)
	os.WriteFile(filepath.Join(ndir, "nf_tables.ko"), nil, 0o644)
	return Runtime("testdata/proc1", t.TempDir(), root)
}

func TestRuntimeParsesProcesses(t *testing.T) {
	rt, _, _ := runFixture(t)
	by := map[int]model.Process{}
	for _, p := range rt.Processes {
		by[p.PID] = p
	}
	p := by[100]
	if p.PPID != 1 || p.UID != 1000 || p.Comm != "sleep" || p.Cmdline != "sleep 60" || p.Exe != "/usr/bin/sleep" || p.ExeDeleted || p.ExeSHA256 != sum("ELF-normal\n") {
		t.Fatalf("pid 100: %+v", p)
	}
	d := by[200]
	if d.Comm != "we ird) name" || d.PPID != 100 || !d.ExeDeleted || d.Exe != "/tmp/x" || d.ExeSHA256 != sum("ELF-deleted\n") {
		t.Fatalf("pid 200: %+v", d)
	}
	if rt.Cmdline != "BOOT_IMAGE=/vmlinuz root=/dev/sda1 ro quiet" {
		t.Fatalf("cmdline %q", rt.Cmdline)
	}
}

func TestRuntimeSocketsOwnersAndListening(t *testing.T) {
	rt, _, _ := runFixture(t)
	by := map[uint64]model.Socket{}
	for _, s := range rt.Sockets {
		by[s.Inode] = s
	}
	if s := by[12345]; s.Proto != "tcp" || s.Local != "127.0.0.1:22" || !s.Listening || s.PID != 100 || s.State != "LISTEN" {
		t.Fatalf("%+v", s)
	}
	if s := by[99999]; s.Local != "127.0.0.1:40000" || s.Remote != "127.0.0.2:80" || s.State != "ESTABLISHED" || s.Listening || s.PID != 0 {
		t.Fatalf("%+v", s)
	}
	if s := by[34567]; s.Proto != "tcp6" || s.Local != "[::1]:22" || !s.Listening {
		t.Fatalf("%+v", s)
	}
	if s := by[23456]; s.Proto != "udp" || s.Local != "0.0.0.0:68" || !s.Listening || s.PID != 200 {
		t.Fatalf("%+v", s)
	}
}

// Pid 300 has a live cmdline but no exe link: recorded with empty Exe and a
// per-pid Skip (a live process is never dropped). Genuinely vanished pids are
// covered by the StatusReadFailure and ESRCH tests.
func TestRuntimeProcessMissingExe(t *testing.T) {
	rt, _, skips := runFixture(t)
	found := false
	for _, s := range skips {
		if s.Check == "runtime" && strings.Contains(s.Reason, "300") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no skip for pid 300: %+v", skips)
	}
	for _, p := range rt.Processes {
		if p.PID == 300 && p.Exe == "" {
			return
		}
	}
	t.Fatalf("pid 300 not recorded with empty Exe")
}

func TestRuntimeModulesResolveFile(t *testing.T) {
	rt, _, _ := runFixture(t)
	by := map[string]model.KernelModule{}
	for _, m := range rt.Modules {
		by[m.Name] = m
	}
	if m := by["ext4_mod"]; m.File != "/lib/modules/6.1.0-test/kernel/fs/ext4/ext4-mod.ko.xz" || m.Size != 16384 || m.Taint != "" {
		t.Fatalf("%+v", m)
	}
	if m := by["nf_tables"]; m.File != "/usr/lib/modules/6.1.0-test/kernel/net/nf_tables.ko" || m.Taint != "OE" {
		t.Fatalf("%+v", m)
	}
	if m := by["unknown_mod"]; m.File != "" {
		t.Fatalf("%+v", m)
	}
	if len(rt.Mounts) != 2 || rt.Mounts[1].Path != "/mnt/with space" || rt.Mounts[1].FSType != "tmpfs" || rt.Mounts[0].Options != "rw,relatime,rw,errors=remount-ro" || rt.Mounts[0].Source != "/dev/sda1" {
		t.Fatalf("mounts %+v", rt.Mounts)
	}
}

func TestRuntimeSysctl(t *testing.T) {
	sysRoot := t.TempDir()
	os.MkdirAll(filepath.Join(sysRoot, "module/apparmor/parameters"), 0o755)
	os.WriteFile(filepath.Join(sysRoot, "module/apparmor/parameters/enabled"), []byte("Y\n"), 0o644)
	_, sc, _ := Runtime("testdata/proc1", sysRoot, t.TempDir())
	if sc["kernel.randomize_va_space"] != "2" || sc["net.ipv4.ip_forward"] != "0" || sc["apparmor.enabled"] != "Y" {
		t.Fatalf("%v", sc)
	}
	if _, ok := sc["kernel.kptr_restrict"]; ok {
		t.Fatalf("absent key present: %v", sc)
	}
}

func TestRuntimeLiveSmoke(t *testing.T) {
	rt, _, _ := Runtime("/proc", "/sys", "/")
	pid, ppid := os.Getpid(), os.Getppid()
	found := false
	for _, p := range rt.Processes {
		if p.PID == pid {
			t.Fatalf("own process %d is in the collection", pid)
		}
		if p.PID == ppid {
			found = true
			if p.Comm == "" {
				t.Fatalf("parent process unreadable: %+v", p)
			}
		}
	}
	if !found {
		t.Fatalf("parent pid %d not found", ppid)
	}
}

// fakeNlink makes fstat report zero links for exe paths containing substr, as
// for a real deleted executable.
func fakeNlink(t *testing.T, substr string) {
	t.Helper()
	old := nlinkFn
	nlinkFn = func(p string, st *unix.Stat_t) uint64 {
		if strings.Contains(p, substr) {
			return 0
		}
		return uint64(st.Nlink)
	}
	t.Cleanup(func() { nlinkFn = old })
}

func mkProc(t *testing.T, pid, stat, status, cmdline string) (procRoot, dir string) {
	t.Helper()
	procRoot = t.TempDir()
	dir = filepath.Join(procRoot, pid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	w := func(n, c string) {
		if c != "" {
			os.WriteFile(filepath.Join(dir, n), []byte(c), 0o644)
		}
	}
	w("stat", stat)
	w("status", status)
	w("cmdline", cmdline)
	return
}

func hasSkip(skips []model.Skip, sub string) bool {
	for _, s := range skips {
		if strings.Contains(s.Reason, sub) {
			return true
		}
	}
	return false
}

const goodStat = "500 (x) S 1 500 500 0 -1 0\n"
const goodStatus = "Name:\tx\nUid:\t1000\t1000\t1000\t1000\n"

func TestRuntimeStatusReadFailureOmitsProcess(t *testing.T) {
	proc, dir := mkProc(t, "500", goodStat, "", "x\x00")
	os.Mkdir(filepath.Join(dir, "status"), 0o755) // unreadable as a file
	rt, _, skips := Runtime(proc, t.TempDir(), t.TempDir())
	if len(rt.Processes) != 0 || !hasSkip(skips, "pid 500: vanished") {
		t.Fatalf("%+v %+v", rt.Processes, skips)
	}
}

func TestRuntimeESRCHOmitsProcess(t *testing.T) {
	proc, _ := mkProc(t, "500", goodStat, goodStatus, "x\x00")
	old := readBoundedFn
	readBoundedFn = func(p string, max int64) ([]byte, error) {
		if strings.HasSuffix(p, "/status") {
			return nil, &fs.PathError{Op: "read", Path: p, Err: unix.ESRCH}
		}
		return old(p, max)
	}
	t.Cleanup(func() { readBoundedFn = old })
	rt, _, skips := Runtime(proc, t.TempDir(), t.TempDir())
	if len(rt.Processes) != 0 || !hasSkip(skips, "pid 500: vanished") {
		t.Fatalf("%+v %+v", rt.Processes, skips)
	}
}

func TestRuntimeMissingUidOmitsProcess(t *testing.T) {
	proc, _ := mkProc(t, "500", goodStat, "Name:\tx\n", "x\x00")
	rt, _, skips := Runtime(proc, t.TempDir(), t.TempDir())
	if len(rt.Processes) != 0 || !hasSkip(skips, "pid 500: vanished") {
		t.Fatalf("%+v %+v", rt.Processes, skips)
	}
}

func TestRuntimeMissingExeWithCmdlineIsRecorded(t *testing.T) {
	proc, _ := mkProc(t, "500", goodStat, goodStatus, "x\x00")
	rt, _, skips := Runtime(proc, t.TempDir(), t.TempDir())
	if len(rt.Processes) != 1 || rt.Processes[0].Exe != "" || rt.Processes[0].UID != 1000 || !hasSkip(skips, "pid 500: executable link missing") {
		t.Fatalf("%+v %+v", rt.Processes, skips)
	}
}

func TestRuntimeUnreadableStatusIsUnknownUID(t *testing.T) {
	proc, _ := mkProc(t, "500", goodStat, goodStatus, "x\x00")
	old := readBoundedFn
	readBoundedFn = func(p string, max int64) ([]byte, error) {
		if strings.HasSuffix(p, "/status") {
			return nil, &fs.PathError{Op: "open", Path: p, Err: unix.EACCES}
		}
		return old(p, max)
	}
	t.Cleanup(func() { readBoundedFn = old })
	rt, _, skips := Runtime(proc, t.TempDir(), t.TempDir())
	if len(rt.Processes) != 1 || rt.Processes[0].UID != UnknownUID || rt.Processes[0].Comm != "x" || !hasSkip(skips, "processes: 1 not fully readable") {
		t.Fatalf("%+v %+v", rt.Processes, skips)
	}
}

func TestRuntimeDeletedTextNeedsZeroNlink(t *testing.T) {
	proc, dir := mkProc(t, "500", goodStat, goodStatus, "x\x00")
	bin := filepath.Join(t.TempDir(), "bin")
	os.WriteFile(bin, []byte("b"), 0o755)
	os.Symlink(bin, filepath.Join(dir, "exe"))
	fakeReadlink(t, map[string]string{"500": "/tmp/x (deleted)"})
	rt, _, _ := Runtime(proc, t.TempDir(), t.TempDir())
	p := rt.Processes[0]
	if p.ExeDeleted || p.Exe != "/tmp/x (deleted)" || p.ExeSHA256 == "" {
		t.Fatalf("%+v", p)
	}
}

func TestRuntimeOversizeExeNotHashed(t *testing.T) {
	proc, dir := mkProc(t, "500", goodStat, goodStatus, "x\x00")
	bin := filepath.Join(t.TempDir(), "big")
	f, _ := os.Create(bin)
	if err := f.Truncate(3 << 30); err != nil {
		t.Skip("sparse file unsupported")
	}
	f.Close()
	os.Symlink(bin, filepath.Join(dir, "exe"))
	rt, _, skips := Runtime(proc, t.TempDir(), t.TempDir())
	if rt.Processes[0].ExeSHA256 != "" || !hasSkip(skips, "executable too large to hash") {
		t.Fatalf("%+v %+v", rt.Processes, skips)
	}
}

func TestRuntimeModulePrefersUpdates(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"updates", "kernel/x"} {
		os.MkdirAll(filepath.Join(root, "lib/modules/6.1.0-test", d), 0o755)
		os.WriteFile(filepath.Join(root, "lib/modules/6.1.0-test", d, "unknown_mod.ko"), nil, 0o644)
	}
	rt, _, skips := Runtime("testdata/proc1", t.TempDir(), root)
	for _, m := range rt.Modules {
		if m.Name == "unknown_mod" && m.File != "/lib/modules/6.1.0-test/updates/unknown_mod.ko" {
			t.Fatalf("%+v", m)
		}
	}
	if hasSkip(skips, "ambiguous") {
		t.Fatalf("unexpected ambiguity: %+v", skips)
	}
	// two candidates at the same level are reported
	os.MkdirAll(filepath.Join(root, "lib/modules/6.1.0-test/kernel/y"), 0o755)
	os.WriteFile(filepath.Join(root, "lib/modules/6.1.0-test/kernel/y/ext4_mod.ko"), nil, 0o644)
	os.WriteFile(filepath.Join(root, "lib/modules/6.1.0-test/kernel/x/ext4_mod.ko"), nil, 0o644)
	_, _, skips = Runtime("testdata/proc1", t.TempDir(), root)
	if !hasSkip(skips, "module ext4_mod: ambiguous") {
		t.Fatalf("%+v", skips)
	}
}

// R51: the collector leaves its own process out, so telltale never reports
// itself (its temp-dir working files looked like a backdoor).
func TestRuntimeOmitsOwnProcess(t *testing.T) {
	proc := t.TempDir()
	if out, err := exec.Command("cp", "-a", "testdata/proc1/.", proc).CombinedOutput(); err != nil {
		t.Fatalf("cp: %v %s", err, out)
	}
	self := filepath.Join(proc, strconv.Itoa(os.Getpid()))
	if err := exec.Command("cp", "-a", filepath.Join(proc, "100"), self).Run(); err != nil {
		t.Fatal(err)
	}
	rt, _, _ := Runtime(proc, t.TempDir(), t.TempDir())
	var got []int
	for _, p := range rt.Processes {
		got = append(got, p.PID)
	}
	if !slices.Contains(got, 100) || slices.Contains(got, os.Getpid()) {
		t.Fatalf("pids %v: want 100 present and own pid %d absent", got, os.Getpid())
	}
}
