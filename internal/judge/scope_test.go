package judge

import (
	"testing"

	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/pkgverify"
)

func TestChangedOwnedPathsAddsMaintainerScripts(t *testing.T) {
	file := func(p, sha string) model.FileEntry { return model.FileEntry{Path: p, Type: "file", SHA256: sha} }
	old := &model.Collection{
		Packages: model.Packages{Installed: []model.Package{{Name: "ssh", Files: []string{"/usr/bin/ssh", "/usr/bin/scp"}}}},
		Files:    []model.FileEntry{file("/usr/bin/ssh", "a"), file("/usr/bin/scp", "b"), file("/usr/bin/stray", "c"), file("/var/lib/dpkg/info/ssh.postinst", "d")},
	}
	cur := &model.Collection{
		Packages: old.Packages,
		Files: []model.FileEntry{file("/usr/bin/ssh", "A"), file("/usr/bin/scp", "b"), file("/usr/bin/stray", "C"),
			file("/var/lib/dpkg/info/ssh.postinst", "D"), file("/var/lib/dpkg/info/libc6:amd64.preinst", "e"), file("/var/lib/dpkg/info/ssh.list", "f")},
	}
	got := changedOwnedPaths(&model.Snapshot{Collection: old}, cur)
	want := map[string]bool{"/usr/bin/ssh": true, "/var/lib/dpkg/info/ssh.postinst": true, "/var/lib/dpkg/info/libc6:amd64.preinst": true}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for p := range want {
		if !got[p] {
			t.Errorf("missing %s in %v", p, got)
		}
	}
}

func TestChangedOwnedPathsMergedUsr(t *testing.T) {
	file := func(p, sha string) model.FileEntry { return model.FileEntry{Path: p, Type: "file", SHA256: sha} }
	pk := model.Packages{Installed: []model.Package{{Name: "ssh", Files: []string{"/bin/ssh"}}}}
	old := &model.Collection{Packages: pk, Files: []model.FileEntry{file("/usr/bin/ssh", "a")}}
	cur := &model.Collection{Packages: pk, Files: []model.FileEntry{file("/usr/bin/ssh", "b")}}
	if got := changedOwnedPaths(&model.Snapshot{Collection: old}, cur); !got["/usr/bin/ssh"] {
		t.Fatalf("got %v", got)
	}
}

// A package file behind a directory that is a link changes under the path it
// really has; it is still handed to package verification.
func TestChangedOwnedPathsBehindADirectoryLink(t *testing.T) {
	file := func(p, sha string) model.FileEntry { return model.FileEntry{Path: p, Type: "file", SHA256: sha} }
	dir := func(p string) model.FileEntry { return model.FileEntry{Path: p, Type: "dir"} }
	pk := model.Packages{Installed: []model.Package{{Name: "chrome", Files: []string{"/opt/google/chrome"}}}}
	base := []model.FileEntry{{Path: "/opt", Type: "symlink", Target: "/data/opt"}, dir("/data"), dir("/data/opt"), dir("/data/opt/google")}
	old := &model.Collection{Packages: pk, Files: append(base[:len(base):len(base)], file("/data/opt/google/chrome", "a"))}
	cur := &model.Collection{Packages: pk, Files: append(base[:len(base):len(base)], file("/data/opt/google/chrome", "b"), file("/data/opt/google/stray", "c"))}
	got := changedOwnedPaths(&model.Snapshot{Collection: old}, cur)
	if !got["/data/opt/google/chrome"] || got["/data/opt/google/stray"] {
		t.Fatalf("got %v", got)
	}
}

// The keys third-party repositories are verified with come from the snapshot
// alone: the collection just taken is the examined machine's word.
func TestVerifyScopeRepoTrustOnlyFromSnapshot(t *testing.T) {
	theirs := []model.RepoTrust{{URL: "https://evil.example/apt", Suite: "stable"}}
	ours := []model.RepoTrust{{URL: "https://vendor.example/apt", Suite: "stable"}}
	cur := clean()
	cur.Packages.RepoTrust = theirs

	opt := pkgverify.Options{RepoTrust: theirs}
	VerifyScope(&opt, nil, cur)
	if opt.RepoTrust != nil || opt.OnlyPaths != nil {
		t.Errorf("without a snapshot: trust %v, only %v", opt.RepoTrust, opt.OnlyPaths)
	}

	old := clean()
	old.Packages.RepoTrust = ours
	opt = pkgverify.Options{}
	VerifyScope(&opt, snapOf(old), cur)
	if len(opt.RepoTrust) != 1 || opt.RepoTrust[0].URL != ours[0].URL {
		t.Errorf("with a snapshot: trust %v", opt.RepoTrust)
	}
	if opt.OnlyPaths == nil || len(opt.OnlyPaths) != 0 {
		t.Errorf("nothing changed, so nothing is verified: %v", opt.OnlyPaths)
	}
}

func TestVerifyScopeOnlyPathsAndLinkTargets(t *testing.T) {
	old := clean()
	cur := clone(old)
	setFile(cur, file("/usr/bin/openssl", "changed", 0o755))
	// A startup link into a package-owned file outside the system
	// directories: its target is verified too.
	cur.Packages.Installed = append(cur.Packages.Installed, pkg("relay", "1.0", "/opt/relay/run"))
	cur.Files = append(cur.Files, file("/opt/relay/run", "relay", 0o755))
	cur.Persist = append(cur.Persist, model.PersistFile{Path: "/etc/systemd/system/multi-user.target.wants/relay.service",
		Kind: model.PersistKindSystemdEnabled, Mode: 0o120777, Lines: []string{"/opt/relay/run"}})
	opt := pkgverify.Options{}
	VerifyScope(&opt, snapOf(old), inventoried(cur))
	if !opt.OnlyPaths["/usr/bin/openssl"] || opt.OnlyPaths["/usr/bin/ls"] {
		t.Errorf("only %v", opt.OnlyPaths)
	}
	if len(opt.ExtraPaths) != 1 || opt.ExtraPaths[0] != "/opt/relay/run" {
		t.Errorf("extra %v", opt.ExtraPaths)
	}
}
