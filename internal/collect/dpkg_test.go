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
	// "half" is half-configured: its files are on disk, so it is listed.
	if want := []string{"half", "held", "libc6", "zsh"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("got %v want %v", names, want)
	}
	if pk.Installed[0].Status != "install ok half-configured" || pk.Installed[1].Status != "hold ok installed" || pk.Installed[3].Status != "install ok installed" {
		t.Errorf("status not kept: %+v", pk.Installed)
	}
	if pk.Installed[3].Version != "5.9-1" || pk.Installed[3].Arch != "amd64" {
		t.Errorf("bad fields: %+v", pk.Installed[3])
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

func TestDpkgObsoleteConffiles(t *testing.T) {
	pk, _ := Packages(dpkgRoot(t))
	for _, p := range pk.Installed {
		if p.Name == "libc6" {
			if !reflect.DeepEqual(p.ObsoleteConffiles, []string{"/etc/rpc"}) {
				t.Fatalf("ObsoleteConffiles = %q", p.ObsoleteConffiles)
			}
			return
		}
	}
	t.Fatal("libc6 missing")
}

func TestDpkgDiversionsAndStatOverrides(t *testing.T) {
	root := dpkgRoot(t)
	writeTree(t, root, map[string]string{
		// Stanzas of three lines: original path, diverted-to path, the
		// diverting package or ":" for a local diversion.
		"var/lib/dpkg/diversions": "/usr/bin/man\n/usr/bin/man.REAL\n:\n/bin/sh\n/bin/sh.distrib\ndash\n" +
			"relative/path\n/x\n:\n/ok\n/ok.d\n../../evil\n/truncated\n",
		"var/lib/dpkg/statoverride": "root crontab 2755 /usr/bin/crontab\nroot root 4755 /usr/lib/a path with spaces\n" +
			"root root 99999 /bad/mode\nroot root 0644\n#1000 grp 0640 /etc/x\n",
	})
	pk, skips := Packages(root)
	wantDiv := []model.Diversion{
		{Path: "/usr/bin/man", DivertTo: "/usr/bin/man.REAL", Package: ":"},
		{Path: "/bin/sh", DivertTo: "/bin/sh.distrib", Package: "dash"},
	}
	if !reflect.DeepEqual(pk.Diversions, wantDiv) {
		t.Errorf("Diversions = %+v", pk.Diversions)
	}
	wantSO := []model.StatOverride{
		{Path: "/usr/bin/crontab", Owner: "root", Group: "crontab", Mode: 0o2755},
		{Path: "/usr/lib/a path with spaces", Owner: "root", Group: "root", Mode: 0o4755},
		{Path: "/etc/x", Owner: "#1000", Group: "grp", Mode: 0o640},
	}
	if !reflect.DeepEqual(pk.StatOverrides, wantSO) {
		t.Errorf("StatOverrides = %+v", pk.StatOverrides)
	}
	var reasons []string
	for _, s := range skips {
		reasons = append(reasons, s.Reason)
	}
	if !strings.Contains(strings.Join(reasons, "\n"), "diversions") {
		t.Errorf("malformed diversions not reported: %q", reasons)
	}
}

func TestDpkgNoDiversionFiles(t *testing.T) {
	pk, skips := Packages(dpkgRoot(t))
	if pk.Diversions != nil || pk.StatOverrides != nil || len(skips) != 0 {
		t.Errorf("diversions %v, overrides %v, skips %v", pk.Diversions, pk.StatOverrides, skips)
	}
}

// A package removed but not purged keeps its postrm, which dpkg runs on
// purge, so its name and version are recorded apart from the installed ones.
func TestDpkgStatusKeepsRemovedNotPurged(t *testing.T) {
	pk, _ := Packages(dpkgRoot(t))
	want := []model.Package{{Name: "gone", Version: "1.0", Arch: "amd64", Status: "deinstall ok config-files"}}
	if !reflect.DeepEqual(pk.Residual, want) {
		t.Fatalf("residual = %+v, want %+v", pk.Residual, want)
	}
	for _, p := range pk.Installed {
		if p.Name == "gone" {
			t.Errorf("a removed package is listed as installed")
		}
	}
}

// Whether a package's files are on disk is the third word of its Status.
// The first word is only what the administrator asked for next: a selection
// of deinstall or purge (dpkg --set-selections, which root can run without
// removing anything) must not make an installed package look removed, and a
// package caught mid-configuration is still there.
func TestDpkgStatusPresentWhateverTheSelection(t *testing.T) {
	root := t.TempDir()
	var st string
	states := map[string]string{
		"sel-deinstall": "deinstall ok installed", "sel-purge": "purge ok installed", "trig-pending": "install ok triggers-pending",
		"trig-awaited": "install ok triggers-awaited", "half-conf": "install ok half-configured", "unpacked": "install ok unpacked",
		"half-inst": "install reinstreq half-installed", "plain": "install ok installed",
		"absent": "purge ok not-installed", "rc": "deinstall ok config-files",
	}
	for name, s := range states {
		st += "Package: " + name + "\nStatus: " + s + "\nArchitecture: amd64\nVersion: 1.0\n\n"
	}
	writeTree(t, root, map[string]string{"var/lib/dpkg/status": st, "var/lib/dpkg/info/sel-deinstall.list": "/boot/vmlinuz-x\n"})
	pk, _ := Packages(root)
	got := map[string]model.Package{}
	for _, p := range pk.Installed {
		got[p.Name] = p
	}
	for name, s := range states {
		p, ok := got[name]
		if want := name != "absent" && name != "rc"; ok != want {
			t.Errorf("%s (%s): listed as installed %v, want %v", name, s, ok, want)
		} else if ok && p.Status != s {
			t.Errorf("%s: status %q, want %q", name, p.Status, s)
		}
	}
	if !reflect.DeepEqual(got["sel-deinstall"].Files, []string{"/boot/vmlinuz-x"}) {
		t.Errorf("files of a package selected for removal: %v", got["sel-deinstall"].Files)
	}
	if len(pk.Residual) != 1 || pk.Residual[0].Name != "rc" {
		t.Errorf("residual = %+v", pk.Residual)
	}
}
