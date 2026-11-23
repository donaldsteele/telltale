package pkgverify

import (
	"context"
	"testing"

	"github.com/donaldsteele/telltale/internal/model"
)

// A changed package file hidden from its package's file list is found by
// checking every package, whatever the file is now: not only an executable
// regular file in a program directory.
func TestVerifyOnlyPathsFallbackForAnyChangedPath(t *testing.T) {
	// The machine's list for tool no longer names what changed.
	hidden := toolPackage()
	hidden.Files = []string{"/usr/bin/toolctl"}

	t.Run("a data file, mode 0644, outside the program directories", func(t *testing.T) {
		f, _ := onlyPathsFixture(t)
		opt := f.opts()
		opt.OnlyPaths = map[string]bool{"/usr/share/doc/tool/README": true}
		c := onlyPathsCollection(hidden)
		withFile(c, regular("/usr/share/doc/tool/README", "trojan with the exec bits dropped\n", 0o644))
		res := Verify(context.Background(), c, opt)
		wantPaths(t, "Mismatch", res.Mismatch, "/usr/share/doc/tool/README")
	})
	t.Run("a program replaced by a symbolic link", func(t *testing.T) {
		f, _ := onlyPathsFixture(t)
		opt := f.opts()
		opt.OnlyPaths = map[string]bool{"/usr/bin/tool": true}
		c := onlyPathsCollection(hidden)
		withFile(c, symlinkEntry("/usr/bin/tool", "/tmp/.x"))
		res := Verify(context.Background(), c, opt)
		wantPaths(t, "Mismatch", res.Mismatch, "/usr/bin/tool")
		if v, _ := find(res.Mismatch, "/usr/bin/tool"); v.Kind != KindTypeDiffers || v.Package != "tool" {
			t.Errorf("mismatch %+v", v)
		}
	})
	t.Run("a changed directory alone is no reason", func(t *testing.T) {
		f, otherDeb := onlyPathsFixture(t)
		opt := f.opts()
		opt.OnlyPaths = map[string]bool{"/usr/share/doc/tool": true}
		c := onlyPathsCollection(hidden)
		withFile(c, model.FileEntry{Path: "/usr/share/doc/tool", Type: "dir", Mode: 0o40755})
		Verify(context.Background(), c, opt)
		if n := f.srv.hitCount(otherDeb); n != 0 {
			t.Errorf("fell back to every package for a directory (%d fetches)", n)
		}
	})
}

// A statoverride that only takes privilege away and is not applied yet: the
// file still has the mode the signed package installs. That is the package's
// own file, not tampering.
func TestModeDiffStatOverrideNotApplied(t *testing.T) {
	s := &session{overrides: map[string]model.StatOverride{
		"/usr/bin/chfn":    {Path: "/usr/bin/chfn", Owner: "root", Group: "root", Mode: 0o755},
		"/usr/bin/crontab": {Path: "/usr/bin/crontab", Owner: "root", Group: "crontab", Mode: 0o2755},
	}}
	why, kind := s.modeDiff("/usr/bin/chfn", 0o104755, DebFile{Mode: 0o4755})
	if kind != verdictVerified || why != "mode differs: a statoverride sets 0755 and is not applied, disk 4755 as the package installs it" {
		t.Errorf("override not applied: %q, %v", why, kind)
	}
	if k := modeKind(why); k != KindModeDiffers {
		t.Errorf("kind %q", k)
	}
	// More privilege than both the package and the override: still a mismatch.
	if why, kind := s.modeDiff("/usr/bin/chfn", 0o106755, DebFile{Mode: 0o4755}); kind != verdictMismatch {
		t.Errorf("more than the package gives: %q, %v", why, kind)
	}
	// An override that grants privilege explains nothing more than before.
	if why, kind := s.modeDiff("/usr/bin/crontab", 0o106755, DebFile{Mode: 0o755}); kind != verdictMismatch {
		t.Errorf("granting override, more than it grants: %q, %v", why, kind)
	}
}
