package collect

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/donaldsteele/telltale/internal/model"
)

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for p, c := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

const statusFixture = `Package: zsh
Status: install ok installed
Architecture: amd64
Version: 5.9-1
Description: shell
 long text

Package: gone
Status: deinstall ok config-files
Architecture: amd64
Version: 1.0

Package: libc6
Status: install ok installed
Multi-Arch: same
Architecture: amd64
Version: 2.36-9
Conffiles:
 /etc/ld.so.conf abc123
 /etc/rpc def456 obsolete
 /etc/old 0123 remove-on-upgrade

Package: held
Status: hold ok installed
Architecture: all
Version: 2

Package: half
Status: install ok half-configured
Architecture: amd64
Version: 3
`

func dpkgRoot(t *testing.T) string {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"var/lib/dpkg/status":                     statusFixture,
		"var/lib/dpkg/info/zsh.list":              "/.\n/bin\n/bin/zsh\n",
		"var/lib/dpkg/info/zsh.md5sums":           "aaaa  bin/zsh\n",
		"var/lib/dpkg/info/libc6:amd64.list":      "/.\n/lib/x86_64-linux-gnu/libc.so.6\n",
		"var/lib/dpkg/info/libc6:amd64.md5sums":   "bbbb  lib/x86_64-linux-gnu/libc.so.6\n",
		"var/lib/dpkg/info/libc6:amd64.conffiles": "ignored",
	})
	return root
}

func TestDpkgStatusInstalledOnly(t *testing.T) {
	pk, _ := Packages(dpkgRoot(t))
	var names []string
	for _, p := range pk.Installed {
		names = append(names, p.Name)
	}
	if want := []string{"held", "libc6", "zsh"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("got %v want %v", names, want)
	}
	if pk.Installed[0].Status != "hold ok installed" || pk.Installed[2].Status != "install ok installed" {
		t.Errorf("status not kept: %+v", pk.Installed)
	}
	if pk.Installed[2].Version != "5.9-1" || pk.Installed[2].Arch != "amd64" {
		t.Errorf("bad fields: %+v", pk.Installed[2])
	}
}

func TestDpkgFilesAndLocalMD5(t *testing.T) {
	pk, _ := Packages(dpkgRoot(t))
	by := map[string]model.Package{}
	for _, p := range pk.Installed {
		by[p.Name] = p
	}
	z := by["zsh"]
	if !reflect.DeepEqual(z.Files, []string{"/.", "/bin", "/bin/zsh"}) {
		t.Errorf("zsh files %v", z.Files)
	}
	if z.LocalMD5["/bin/zsh"] != "aaaa" {
		t.Errorf("zsh md5 %v", z.LocalMD5)
	}
	l := by["libc6"]
	if len(l.Files) != 2 || l.LocalMD5["/lib/x86_64-linux-gnu/libc.so.6"] != "bbbb" {
		t.Errorf("libc6 multiarch lookup failed: %+v", l)
	}
}

func TestDpkgConffiles(t *testing.T) {
	pk, _ := Packages(dpkgRoot(t))
	for _, p := range pk.Installed {
		if p.Name != "libc6" {
			continue
		}
		want := map[string]string{"/etc/ld.so.conf": "abc123", "/etc/rpc": "def456", "/etc/old": "0123"}
		if !reflect.DeepEqual(p.Conffiles, want) {
			t.Fatalf("got %v", p.Conffiles)
		}
		return
	}
	t.Fatal("libc6 missing")
}

func TestDpkgListTooLargeSkips(t *testing.T) {
	root := dpkgRoot(t)
	old := maxDpkgList
	maxDpkgList = 8
	defer func() { maxDpkgList = old }()
	_, skips := Packages(root)
	if len(skips) == 0 {
		t.Fatal("expected skip")
	}
}

func TestDpkgHostileNameNotTraversed(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"var/lib/dpkg/status": "Package: ../../etc/evil\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1\n",
		"etc/evil.list":       "/decoy\n",
		"etc/evil.md5sums":    "aaaa  decoy\n",
	})
	pk, skips := Packages(root)
	if len(pk.Installed) != 1 || len(pk.Installed[0].Files) != 0 || len(pk.Installed[0].LocalMD5) != 0 {
		t.Fatalf("traversal read: %+v", pk.Installed)
	}
	found := false
	for _, s := range skips {
		if strings.Contains(s.Reason, "../../etc/evil") {
			found = true
		}
	}
	if !found {
		t.Errorf("no skip naming package: %v", skips)
	}
}
