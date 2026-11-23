package collect

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/donaldsteele/telltale/internal/model"
	"golang.org/x/sys/unix"
)

const fsAppendFL = 0x20 // FS_APPEND_FL

func byPath(es []model.FileEntry) map[string]model.FileEntry {
	m := make(map[string]model.FileEntry, len(es))
	for _, e := range es {
		m[e.Path] = e
	}
	return m
}

func TestFilesHashesModesOwners(t *testing.T) {
	root := t.TempDir()
	content := []byte("hello telltale\n")
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(root, "etc", "prog")
	if err := os.WriteFile(f, content, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f, os.ModeSetuid|0o755); err != nil {
		t.Fatal(err)
	}
	entries, skips := Files(root, []string{"/etc"}, FileOptions{})
	if len(skips) != 0 {
		t.Fatalf("skips: %v", skips)
	}
	m := byPath(entries)
	e, ok := m["/etc/prog"]
	if !ok {
		t.Fatalf("missing /etc/prog in %v", entries)
	}
	sum := sha256.Sum256(content)
	if e.SHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("sha = %s", e.SHA256)
	}
	if e.Type != "file" || e.Size != int64(len(content)) {
		t.Errorf("type/size = %s/%d", e.Type, e.Size)
	}
	if e.Mode&0o4000 == 0 || e.Mode&0o111 == 0 {
		t.Errorf("mode = %o", e.Mode)
	}
	if e.UID != uint32(os.Getuid()) || e.GID != uint32(os.Getgid()) {
		t.Errorf("owner = %d:%d", e.UID, e.GID)
	}
	if e.MTime.IsZero() || e.CTime.IsZero() {
		t.Errorf("times zero")
	}
	if d, ok := m["/etc"]; !ok || d.Type != "dir" {
		t.Errorf("dir entry: %+v", d)
	}
}

func TestFilesMaxHashBytes(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "big"), make([]byte, 100), 0o644)
	entries, _ := Files(root, []string{"/big"}, FileOptions{MaxHashBytes: 10})
	if len(entries) != 1 || entries[0].SHA256 != "" || entries[0].Err != "too large to hash" || entries[0].Size != 100 {
		t.Fatalf("%+v", entries)
	}
}

func TestFilesUnreadableHasErr(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can read everything")
	}
	root := t.TempDir()
	p := filepath.Join(root, "secret")
	os.WriteFile(p, []byte("x"), 0o000)
	entries, skips := Files(root, []string{"/secret"}, FileOptions{})
	if len(skips) != 0 || len(entries) != 1 || entries[0].Err == "" || entries[0].SHA256 != "" {
		t.Fatalf("%+v %v", entries, skips)
	}
}

func TestFilesRecordsSymlinkWithoutFollowing(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "real"), 0o755)
	os.WriteFile(filepath.Join(root, "real", "inner"), []byte("x"), 0o644)
	if err := os.Symlink("real", filepath.Join(root, "bin")); err != nil {
		t.Fatal(err)
	}
	entries, _ := Files(root, []string{"/bin", "/real"}, FileOptions{})
	m := byPath(entries)
	e, ok := m["/bin"]
	if !ok || e.Type != "symlink" || e.Target != "real" {
		t.Fatalf("bin: %+v", e)
	}
	if _, ok := m["/bin/inner"]; ok {
		t.Errorf("followed symlink")
	}
	if _, ok := m["/real/inner"]; !ok {
		t.Errorf("real not walked")
	}
}

func TestFilesVanishingEntryIsSkipped(t *testing.T) {
	root := t.TempDir()
	f := filepath.Join(root, "gone")
	os.WriteFile(f, []byte("x"), 0o644)
	testHookBeforeOpen = func(p string) { os.Remove(p) }
	defer func() { testHookBeforeOpen = nil }()
	entries, skips := Files(root, []string{"/gone"}, FileOptions{})
	if len(entries) != 0 {
		t.Errorf("entries: %+v", entries)
	}
	if len(skips) != 1 || !strings.Contains(skips[0].Reason, "/gone") {
		t.Errorf("skips: %+v", skips)
	}
}

func TestFilesHostileNamesAndLoops(t *testing.T) {
	root := t.TempDir()
	names := []string{"a\nb", "e\x1bc", "bad\xff"}
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(root, n), []byte("x"), 0o644); err != nil {
			t.Skipf("fs rejects name %q: %v", n, err)
		}
	}
	os.Symlink("loopb", filepath.Join(root, "loopa"))
	os.Symlink("loopa", filepath.Join(root, "loopb"))
	os.Symlink(".", filepath.Join(root, "self"))
	entries, _ := Files(root, []string{"/"}, FileOptions{})
	m := byPath(entries)
	for _, n := range names {
		if _, ok := m["/"+n]; !ok {
			t.Errorf("missing %q", n)
		}
	}
	if m["/loopa"].Type != "symlink" || m["/self"].Type != "symlink" {
		t.Errorf("loops not recorded as symlinks")
	}
	if len(entries) != 1+len(names)+3 {
		t.Errorf("entries = %d", len(entries))
	}
}

func TestFilesDoesNotCrossIntoNetworkMounts(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "etc", "net"), 0o755)
	os.MkdirAll(filepath.Join(root, "etc", "ext"), 0o755)
	os.WriteFile(filepath.Join(root, "etc", "net", "secret"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(root, "etc", "ext", "ok"), []byte("x"), 0o644)
	mounts := []model.Mount{
		{Path: "/etc/net", FSType: "nfs4"},
		{Path: "/etc/ext", FSType: "ext4"},
	}
	entries, skips := Files(root, []string{"/etc"}, FileOptions{Mounts: mounts})
	m := byPath(entries)
	if _, ok := m["/etc/net/secret"]; ok {
		t.Errorf("crossed into nfs4")
	}
	if _, ok := m["/etc/ext/ok"]; !ok {
		t.Errorf("ext4 not walked")
	}
	found := false
	for _, s := range skips {
		if strings.Contains(s.Reason, "/etc/net") {
			found = true
		}
	}
	if !found {
		t.Errorf("no skip naming mount: %v", skips)
	}
	// A walked path that is itself such a mount is still walked.
	entries, _ = Files(root, []string{"/etc/net"}, FileOptions{Mounts: mounts})
	if _, ok := byPath(entries)["/etc/net/secret"]; !ok {
		t.Errorf("start path mount not walked")
	}
}

func TestSkipFSTypes(t *testing.T) {
	for _, tc := range []struct {
		t string
		w bool
	}{{"fuse.sshfs", true}, {"fuse", true}, {"nfs4", true}, {"overlay", false}, {"ext4", false}, {"xfs", false}, {"btrfs", false}} {
		if skipFS(tc.t) != tc.w {
			t.Errorf("skipFS(%q) != %v", tc.t, tc.w)
		}
	}
}

func flagsDirs(t *testing.T) []string {
	dirs := []string{t.TempDir()}
	if h := os.Getenv("HOME"); h != "" {
		if d, err := os.MkdirTemp(h, "telltale-flags-*"); err == nil {
			t.Cleanup(func() { os.RemoveAll(d) })
			dirs = append(dirs, d)
		}
	}
	return dirs
}

func TestFilesInodeFlagsWhenSupported(t *testing.T) {
	var supported string
	for _, d := range flagsDirs(t) {
		p := filepath.Join(d, "plain")
		os.WriteFile(p, []byte("x"), 0o644)
		fd, err := unix.Open(p, unix.O_RDONLY, 0)
		if err != nil {
			continue
		}
		_, err = unix.IoctlGetUint32(fd, unix.FS_IOC_GETFLAGS)
		unix.Close(fd)
		if err == nil {
			supported = d
			break
		}
	}
	if supported == "" {
		t.Skip("no filesystem here supports FS_IOC_GETFLAGS")
	}
	plain := filepath.Join(supported, "plain")
	entries, _ := Files("/", []string{plain}, FileOptions{})
	if len(entries) != 1 || entries[0].Flags != 0 {
		t.Fatalf("plain: %+v", entries)
	}
	fd, err := unix.Open(plain, unix.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	err = unix.IoctlSetPointerInt(fd, unix.FS_IOC_SETFLAGS, fsAppendFL)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EACCES) {
			t.Skipf("cannot set append-only flag: %v (reading flags verified)", err)
		}
		t.Fatal(err)
	}
	defer unix.IoctlSetPointerInt(fd, unix.FS_IOC_SETFLAGS, 0)
	entries, _ = Files("/", []string{plain}, FileOptions{})
	if len(entries) != 1 || entries[0].Flags&fsAppendFL == 0 {
		t.Fatalf("flags not reported: %+v", entries)
	}
}

func TestFilesCapabilitiesXattr(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "ping")
	os.WriteFile(p, []byte("x"), 0o755)
	// VFS_CAP_REVISION_2 header with permitted+effective cap_net_raw (bit 13).
	val := []byte{0x01, 0x00, 0x00, 0x02, 0x00, 0x20, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	if err := unix.Setxattr(p, "security.capability", val, 0); err != nil {
		t.Skipf("cannot set security.capability: %v", err)
	}
	entries, _ := Files(root, []string{"/ping"}, FileOptions{})
	if len(entries) != 1 || entries[0].Caps == "" {
		t.Fatalf("%+v", entries)
	}
}

func TestFilesNoCapsOnPlainFile(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "f"), []byte("x"), 0o644)
	entries, _ := Files(root, []string{"/f"}, FileOptions{})
	if len(entries) != 1 || entries[0].Caps != "" {
		t.Fatalf("%+v", entries)
	}
}

func TestFilesUnreadableDirIsOneEntry(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can read everything")
	}
	root := t.TempDir()
	d := filepath.Join(root, "locked")
	os.Mkdir(d, 0o755)
	os.WriteFile(filepath.Join(d, "f"), []byte("x"), 0o644)
	os.Chmod(d, 0o000)
	defer os.Chmod(d, 0o755)
	entries, skips := Files(root, []string{"/"}, FileOptions{})
	n := 0
	for _, e := range entries {
		if e.Path == "/locked" {
			n++
			if e.Err == "" || e.Type != "dir" {
				t.Errorf("entry: %+v", e)
			}
		}
	}
	if n != 1 || len(skips) != 0 {
		t.Fatalf("n=%d skips=%v", n, skips)
	}
}

func TestFilesSwappedForFIFODoesNotHang(t *testing.T) {
	root := t.TempDir()
	f := filepath.Join(root, "swap")
	os.WriteFile(f, []byte("x"), 0o644)
	testHookBeforeOpen = func(p string) {
		os.Remove(p)
		if err := unix.Mkfifo(p, 0o644); err != nil {
			t.Errorf("mkfifo: %v", err)
		}
	}
	defer func() { testHookBeforeOpen = nil }()
	type res struct {
		e []model.FileEntry
		s []model.Skip
	}
	ch := make(chan res, 1)
	go func() { e, s := Files(root, []string{"/swap"}, FileOptions{}); ch <- res{e, s} }()
	select {
	case r := <-ch:
		if len(r.e) != 1 || r.e[0].Err == "" || r.e[0].SHA256 != "" {
			t.Fatalf("%+v %v", r.e, r.s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("walk hung on FIFO")
	}
}

// A start path the machine does not have is not a path that vanished.
func TestFilesMissingStartPathIsSilent(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	entries, skips := Files(root, []string{"/etc", "/lib32"}, FileOptions{})
	if len(skips) != 0 {
		t.Fatalf("skips for a start path that never existed: %+v", skips)
	}
	if len(entries) != 1 || entries[0].Path != "/etc" {
		t.Fatalf("entries %+v", entries)
	}
}
