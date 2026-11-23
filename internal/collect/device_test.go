package collect

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/donaldsteele/telltale/internal/model"
	"golang.org/x/sys/unix"
)

// recordReopens makes every open for reading report what it opens.
func recordReopens(t *testing.T) *[]unix.Stat_t {
	t.Helper()
	var got []unix.Stat_t
	old := reopenFn
	reopenFn = func(pfd int) (int, error) {
		var st unix.Stat_t
		if err := unix.Fstat(pfd, &st); err != nil {
			t.Errorf("fstat before reopen: %v", err)
		}
		got = append(got, st)
		return old(pfd)
	}
	t.Cleanup(func() { reopenFn = old })
	return &got
}

// Opening a device can do something: opening a watchdog arms a reboot timer,
// a tape drive rewinds, a FIFO blocks. A user's link at a start-up path may
// lead to one. Nothing is opened for reading before it is known to be a
// regular file: the collector first takes a handle that opens nothing
// (O_PATH), looks at it, and only then opens it.
func TestOnlyRegularFilesAreEverOpened(t *testing.T) {
	if _, err := os.Stat("/dev/null"); err != nil {
		t.Skip("no /dev/null")
	}
	opened := recordReopens(t)
	home := t.TempDir()
	if err := os.Chmod(home, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, home, ".profile", "umask 022\n")
	if err := os.Symlink("/dev/null", filepath.Join(home, ".bashrc")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/null", filepath.Join(home, "direct")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(home, ".zshrc"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := &collector{key: testKey, seen: map[string]bool{}}
	u := model.User{Name: "u", UID: int(selfUID), Home: home}
	c.user = &u
	for _, n := range []string{".bashrc", ".profile", ".zshrc"} {
		c.file(filepath.Join(home, n), model.PersistKindShellRC)
	}
	if f, ok := findPersist(c.out, filepath.Join(home, ".bashrc")); !ok || len(f.Lines) != 1 || f.Lines[0] != "/dev/null" {
		t.Errorf("the link to a device: %+v ok=%v", f, ok)
	}
	if f, ok := findPersist(c.out, filepath.Join(home, ".profile")); !ok || len(f.Lines) != 1 {
		t.Errorf("the regular file: %+v ok=%v", f, ok)
	}

	// The other ways the collector reads files that someone else names.
	if _, err := readRaw("", "/dev/null", 1<<10); err == nil {
		t.Error("readRaw read a device")
	}
	if _, _, err := openRegular("", filepath.Join(home, ".zshrc")); err == nil {
		t.Error("openRegular opened a FIFO")
	}
	if _, err := readBounded("/dev/null", 1<<10); err == nil {
		t.Error("readBounded read a device")
	}
	if _, err := hashExe(filepath.Join(home, "direct")); err == nil {
		t.Error("hashExe opened a device behind a link")
	}
	var skips []model.Skip
	Files("", []string{"/dev/null", filepath.Join(home, ".zshrc"), filepath.Join(home, ".profile")}, FileOptions{})
	_ = skips

	if len(*opened) == 0 {
		t.Fatal("nothing was opened at all")
	}
	for _, st := range *opened {
		if st.Mode&unix.S_IFMT != unix.S_IFREG {
			t.Errorf("opened for reading something that is not a regular file: mode %#o", st.Mode)
		}
	}
}

// What lies on the device filesystem (/dev) is refused like the kernel's
// other filesystems. It has no magic number of its own (it reports tmpfs,
// as /run and /dev/shm do), so it is told by its device number: that of
// /dev, when /dev is a mount of its own.
func TestDeviceFilesystemIsToldByItsDeviceNumber(t *testing.T) {
	if !onDevFS(42, devFS{dev: 42, ok: true}) {
		t.Error("the device filesystem's own device number")
	}
	if onDevFS(43, devFS{dev: 42, ok: true}) {
		t.Error("another mount (/dev/shm, /run) counted as the device filesystem")
	}
	if onDevFS(42, devFS{}) {
		t.Error("/dev that is no mount of its own: everything on the root filesystem would be refused")
	}
	// On this machine: /dev/null is on it, a temporary file is not.
	d := devFSOf("/")
	var null, tmp unix.Stat_t
	if unix.Stat("/dev/null", &null) != nil || unix.Stat(t.TempDir(), &tmp) != nil || !d.ok {
		t.Skip("/dev is not a mount of its own here")
	}
	if !onDevFS(uint64(null.Dev), d) || onDevFS(uint64(tmp.Dev), d) {
		t.Errorf("/dev/null on it: %v, a temporary directory on it: %v", onDevFS(uint64(null.Dev), d), onDevFS(uint64(tmp.Dev), d))
	}
}
