package collect

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/donaldsteele/telltale/internal/model"
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

func TestRuntimeProcessVanishes(t *testing.T) {
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
		if p.PID == 300 {
			t.Fatalf("pid 300 should not be recorded")
		}
	}
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
	pid := os.Getpid()
	for _, p := range rt.Processes {
		if p.PID == pid {
			if p.ExeSHA256 == "" || p.Exe == "" {
				t.Fatalf("own process missing exe: %+v", p)
			}
			return
		}
	}
	t.Fatalf("own pid %d not found", pid)
}
