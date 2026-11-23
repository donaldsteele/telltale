package pkgverify

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/pkgverify/vendorkeys"
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

// A trusted third-party index offers a version of a package the
// distribution names. It may confirm that version only when the
// distribution's own history answered and does not have it. When the
// history could not be asked (a garbage answer, the network, the lookup
// budget), nobody knows what that version was, and the third-party copy
// confirms nothing.
func TestThirdPartyFallbackOnlyWhenHistoryHasNoSuchVersion(t *testing.T) {
	newer := buildDeb(t, "xz", nil, []debEntry{{name: "./usr/bin/hello", body: "hello 2.12\n", mode: 0o755}})
	theirs := buildDeb(t, "xz", nil, []debEntry{{name: "./usr/bin/hello", body: "vendor build\n", mode: 0o755}})
	pkg := model.Package{Name: "hello", Version: "2.10-3", Arch: "amd64", Status: "install ok installed", Files: []string{"/usr/bin/hello"}}
	repoKey := otherKey(t)
	setup := func(t *testing.T) (*fixture, Options, *model.Collection) {
		f := newFixture(t, map[string][]fakePkg{"bookworm": {{"hello", "2.12-1", "amd64", newer}}})
		idx := stanza("hello", "2.10-3", "amd64", "pool/main/h/hello/hello_2.10-3_amd64.deb", theirs)
		repo := newArchiveServer(t, fakeSuite(t, repoKey, recordedNow, "/repo", "stable", "", map[string][]byte{"main/binary-amd64/Packages.xz": xzBytes(t, []byte(idx))}))
		repo.set("/repo/pool/main/h/hello/hello_2.10-3_amd64.deb", theirs)
		opt := f.opts()
		opt.Vendors = &vendorkeys.Table{}
		opt.RepoTrust = []model.RepoTrust{trustOf(t, repo.URL+"/repo", "stable", repoKey)}
		c := collectionOf(map[string]string{"/usr/bin/hello": "vendor build\n"}, pkg)
		c.Packages.Sources = []model.AptSource{{File: "/etc/apt/sources.list.d/v.list", Types: []string{"deb"}, URIs: []string{repo.URL + "/repo"}, Suites: []string{"stable"}, Components: []string{"main"}}}
		return f, opt, c
	}

	t.Run("the history has no such version: the vendor's own build", func(t *testing.T) {
		_, opt, c := setup(t)
		res := Verify(context.Background(), c, opt)
		if v, ok := find(res.Verified, "/usr/bin/hello"); !ok || v.Source != SourceThirdParty {
			t.Errorf("Verified %+v, Unverifiable %+v", res.Verified, res.Unverifiable)
		}
	})
	t.Run("the history answers with garbage", func(t *testing.T) {
		f, opt, c := setup(t)
		f.srv.set("/mr/binary/hello/2.10-3/binfiles", []byte("<html>gateway error</html>"))
		res := Verify(context.Background(), c, opt)
		wantPaths(t, "Verified", res.Verified)
		if v, ok := find(res.Unverifiable, "/usr/bin/hello"); !ok || v.Kind != KindNotFound {
			t.Errorf("Unverifiable %+v", res.Unverifiable)
		}
	})
	t.Run("the lookup budget is spent", func(t *testing.T) {
		_, opt, c := setup(t)
		s := newSession(c, opt, &Result{Mode: ModeArchive})
		if err := s.setup(); err != nil {
			t.Fatal(err)
		}
		plans := s.plan()
		s.loadIndexes(context.Background(), s.indexWanted(plans))
		s.oldUsed = maxOldLookups
		results := newResults(plans)
		s.run(context.Background(), results)
		for _, r := range results {
			if r.pkg.Name == "hello" && (r.table != nil || r.kind != KindBudget) {
				t.Errorf("past the budget: table %v, kind %q, reason %q", r.table != nil, r.kind, r.reason)
			}
		}
	})
}

// Which answers of the distribution's history leave room for a third-party
// copy: "no such version", and "no signed index has it" when sources trusted
// through HTTPS alone are not used and the signed lookups themselves said
// not found. A history that could not be asked leaves none.
func TestHistoryHasNone(t *testing.T) {
	key := PkgKey{"hello", "2.10-3", "amd64"}
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"not found", fmt.Errorf("x: %w", ErrNotFound), true},
		{"signed only, nothing tried", signedOnlyError(key, nil), true},
		{"signed only, index lacks it", signedOnlyError(key, []error{fmt.Errorf("dists: %w", ErrNotFound)}), true},
		{"signed only, no such index", signedOnlyError(key, []error{fmt.Errorf("u: %w", errHTTPNotFound)}), true},
		{"signed only, network", signedOnlyError(key, []error{errors.New("dial tcp: i/o timeout")}), false},
		// Every signed lookup must have ended in not found: one that failed
		// earlier leaves the history unknown, whatever the last one said.
		{"signed only, network then not found", signedOnlyError(key, []error{errors.New("dial tcp: i/o timeout"), fmt.Errorf("dists: %w", ErrNotFound)}), false},
		{"signed only, not found then network", signedOnlyError(key, []error{fmt.Errorf("dists: %w", ErrNotFound), errors.New("unexpected EOF")}), false},
		{"signed only, not found twice", signedOnlyError(key, []error{fmt.Errorf("dists: %w", ErrNotFound), fmt.Errorf("u: %w", errHTTPNotFound)}), true},
		{"network", errors.New("dial tcp: i/o timeout"), false},
		{"API answer missing", fmt.Errorf("u: %w", errHTTPNotFound), false},
		{"garbage", errors.New("invalid character '<'"), false},
		{"budget", errOldBudget, false},
		{"no error", nil, false},
	} {
		if got := historyHasNone(tc.err); got != tc.want {
			t.Errorf("%s: historyHasNone = %v, want %v", tc.name, got, tc.want)
		}
	}
}
