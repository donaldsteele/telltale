package collect

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// visitDir makes what a server visit leaves on the machine while the
// collector runs: <root>/root/telltale.AbCd1234, 0700, holding the binary.
// It returns the directory's host path.
func visitDir(t *testing.T, root string) string {
	t.Helper()
	dir := filepath.Join(root, "root", "telltale.AbCd1234")
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil { // whatever the umask
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "telltale"), []byte("the collector"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "root", ".bashrc"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

var me = uint32(os.Getuid())

func TestFindSelf(t *testing.T) {
	root := t.TempDir()
	dir := visitDir(t, root)
	bin := filepath.Join(dir, "telltale")
	s, ok := FindSelf(dir, bin, me)
	var st unix.Stat_t
	if err := unix.Stat(bin, &st); err != nil {
		t.Fatal(err)
	}
	if !ok || s.Dir != dir || s.Dev != uint64(st.Dev) || s.Ino != st.Ino {
		t.Fatalf("FindSelf = %+v, %v; want the binary %d:%d in %s", s, ok, st.Dev, st.Ino, dir)
	}
	// Through a link to the program, as /proc/self/exe is.
	link := filepath.Join(t.TempDir(), "exe")
	if err := os.Symlink(bin, link); err != nil {
		t.Fatal(err)
	}
	if _, ok := FindSelf(dir, link, me); !ok {
		t.Error("the running program behind a link is not recognised")
	}
}

// Any doubt leaves nothing out.
func TestFindSelfRefuses(t *testing.T) {
	for name, spoil := range map[string]func(t *testing.T, dir string) (exe string, uid uint32){
		"another entry in the directory": func(t *testing.T, dir string) (string, uint32) {
			os.WriteFile(filepath.Join(dir, "extra"), []byte("x"), 0o600)
			return filepath.Join(dir, "telltale"), me
		},
		"mode 0755": func(t *testing.T, dir string) (string, uint32) {
			os.Chmod(dir, 0o755)
			return filepath.Join(dir, "telltale"), me
		},
		"setgid directory": func(t *testing.T, dir string) (string, uint32) {
			os.Chmod(dir, os.ModeSetgid|0o700)
			return filepath.Join(dir, "telltale"), me
		},
		"another owner": func(t *testing.T, dir string) (string, uint32) {
			return filepath.Join(dir, "telltale"), me + 1
		},
		"not the running program": func(t *testing.T, dir string) (string, uint32) {
			other := filepath.Join(t.TempDir(), "telltale")
			os.WriteFile(other, []byte("the collector"), 0o700)
			return other, me
		},
		"the binary is a link": func(t *testing.T, dir string) (string, uint32) {
			real := filepath.Join(t.TempDir(), "telltale")
			os.Rename(filepath.Join(dir, "telltale"), real)
			os.Symlink(real, filepath.Join(dir, "telltale"))
			return real, me
		},
		"the binary is not named telltale": func(t *testing.T, dir string) (string, uint32) {
			os.Rename(filepath.Join(dir, "telltale"), filepath.Join(dir, "collector"))
			return filepath.Join(dir, "collector"), me
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := visitDir(t, t.TempDir())
			exe, uid := spoil(t, dir)
			if s, ok := FindSelf(dir, exe, uid); ok {
				t.Errorf("FindSelf = %+v; want nothing left out", s)
			}
		})
	}
	t.Run("the directory is a link", func(t *testing.T) {
		root := t.TempDir()
		dir := visitDir(t, root)
		link := filepath.Join(root, "root", "telltale.EfGh5678")
		if err := os.Symlink(dir, link); err != nil {
			t.Fatal(err)
		}
		if s, ok := FindSelf(link, filepath.Join(dir, "telltale"), me); ok {
			t.Errorf("FindSelf = %+v through a linked directory", s)
		}
	})
}

// selfAt is Self for the binary in a test tree, with the directory as the
// machine path Files sees.
func selfAt(t *testing.T, root, dir string) Self {
	t.Helper()
	s, ok := FindSelf(dir, filepath.Join(dir, "telltale"), me)
	if !ok {
		t.Fatal("FindSelf refused the visit directory")
	}
	s.Dir = "/" + filepath.ToSlash(must(filepath.Rel(root, dir)))
	return s
}

func must(s string, err error) string {
	if err != nil {
		panic(err)
	}
	return s
}

// The inventory leaves out the collector's binary and its directory's own
// entry, and nothing else.
func TestFilesLeavesOutOnlyTheCollector(t *testing.T) {
	root := t.TempDir()
	dir := visitDir(t, root)
	self := selfAt(t, root, dir)
	m := byPath(must2(Files(root, []string{"/root"}, FileOptions{Self: self})))
	for _, p := range []string{"/root/telltale.AbCd1234", "/root/telltale.AbCd1234/telltale"} {
		if _, ok := m[p]; ok {
			t.Errorf("%s is in the inventory", p)
		}
	}
	if _, ok := m["/root/.bashrc"]; !ok {
		t.Error("/root/.bashrc is missing")
	}
	// Without Self everything is there.
	if all := byPath(must2(Files(root, []string{"/root"}, FileOptions{}))); len(all) != 4 {
		t.Errorf("without Self: %d entries, want 4", len(all))
	}
}

// Whatever lands in the directory during the visit is walked: a setuid
// file dropped next to the binary, and another file put where the binary
// was.
func TestFilesWalksWhatElseIsInTheCollectorsDirectory(t *testing.T) {
	root := t.TempDir()
	dir := visitDir(t, root)
	self := selfAt(t, root, dir)
	if err := os.WriteFile(filepath.Join(dir, "sh"), []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "sh"), os.ModeSetuid|0o755); err != nil {
		t.Fatal(err)
	}
	m := byPath(must2(Files(root, []string{"/root"}, FileOptions{Self: self})))
	if e, ok := m["/root/telltale.AbCd1234/sh"]; !ok || e.Mode&0o4000 == 0 {
		t.Errorf("the setuid file in the collector's directory: %+v, %v", e, ok)
	}
	if _, ok := m["/root/telltale.AbCd1234/telltale"]; ok {
		t.Error("the binary is in the inventory")
	}

	// The real binary is the running program, whose inode the kernel keeps
	// while it runs, so a file put in its place never gets its inode
	// number. Holding the stand-in open does the same; without that a
	// filesystem such as ext4 hands the freed number straight to the
	// replacement.
	bin := filepath.Join(dir, "telltale")
	running, err := os.Open(bin)
	if err != nil {
		t.Fatal(err)
	}
	defer running.Close()
	if err := os.Remove(bin); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("not the collector"), 0o700); err != nil {
		t.Fatal(err)
	}
	m = byPath(must2(Files(root, []string{"/root"}, FileOptions{Self: self})))
	if _, ok := m["/root/telltale.AbCd1234/telltale"]; !ok {
		t.Error("another file in the binary's place is left out")
	}
}

func must2[T, U any](t T, _ U) T { return t }

// The collection says which directory the collector left its binary out
// of, for the server to compare with the one it made.
func TestAllRecordsOwnDir(t *testing.T) {
	self := Self{Dir: "/root/telltale.AbCd1234", Dev: 1, Ino: 2}
	c, err := All(Options{Root: "testdata/root1", ProcRoot: "testdata/proc1", SysRoot: t.TempDir(), Self: self})
	if err != nil {
		t.Fatal(err)
	}
	if c.OwnDir != self.Dir {
		t.Errorf("OwnDir = %q, want %q", c.OwnDir, self.Dir)
	}
	if c, _ := All(Options{Root: "testdata/root1", ProcRoot: "testdata/proc1", SysRoot: t.TempDir()}); c.OwnDir != "" {
		t.Errorf("OwnDir = %q without Self", c.OwnDir)
	}
}
