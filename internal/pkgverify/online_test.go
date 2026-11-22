//go:build online

package pkgverify

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/donaldsteele/telltale/internal/model"
)

// These tests talk to the real Debian and Ubuntu archives:
//
//	go test -tags online ./internal/pkgverify/

func TestOnlineDebianBookwormIndex(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	archives, err := ArchiveFor(model.Host{OSID: "debian", OSVersionID: "12", Arch: "amd64"}, nil, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a := archives[0]
	idx, err := a.Index(ctx, "bookworm", "main", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if len(idx) < 30000 {
		t.Errorf("bookworm main amd64 has only %d packages", len(idx))
	}
	var found []DebRef
	for k, ref := range idx {
		if k.Name == "openssh-server" && k.Arch == "amd64" {
			found = append(found, ref)
			if !strings.HasPrefix(ref.URL, "https://deb.debian.org/debian/pool/main/o/openssh/openssh-server_") || len(ref.SHA256) != 64 || ref.Size <= 0 || ref.Source != SourceArchive {
				t.Errorf("openssh-server %s: %+v", k.Version, ref)
			}
		}
	}
	if len(found) == 0 {
		t.Fatal("openssh-server not in bookworm main amd64")
	}
	t.Logf("bookworm main amd64: %d packages; openssh-server: %+v", len(idx), found)

	sec, err := archives[1].Index(ctx, "bookworm-security", "main", "amd64")
	if err != nil {
		t.Fatalf("bookworm-security (carries Valid-Until): %v", err)
	}
	t.Logf("bookworm-security main amd64: %d packages", len(sec))
}

func TestOnlineUbuntuNobleIndex(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	archives, err := ArchiveFor(model.Host{OSID: "ubuntu", OSVersionID: "24.04", Arch: "amd64"}, nil, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	idx, err := archives[0].Index(ctx, "noble", "main", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	ref, ok := Lookup(idx, "openssh-server", "1:9.6p1-3ubuntu13", "amd64")
	if !ok || !strings.HasPrefix(ref.URL, "http://archive.ubuntu.com/ubuntu/pool/main/o/openssh/") {
		t.Fatalf("openssh-server 1:9.6p1-3ubuntu13: %+v %v", ref, ok)
	}
	t.Logf("noble main amd64: %d packages; openssh-server: %+v", len(idx), ref)
}

// The expected SHA-256 values were checked against independent sources when
// the test was written: the downloaded files and snapshot.debian.org's SHA-1,
// and Launchpad's binaryFileUrls metadata.

func TestOnlineFindOldDebian(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	f, err := NewOldFinder(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		key    PkgKey
		prefix string
		sha256 string
	}{
		// Entered unstable on 2022-12-27, signed then by the bullseye
		// archive key; the current archive has moved on.
		{PkgKey{"hello", "2.10-3", "amd64"}, "https://snapshot.debian.org/archive/debian/20221227T032939Z/", "2e6e2f1a0007dc43bc91c273fd36e91e40a4f1c2765a03eca68b70a42103878a"},
		// A superseded bookworm security update.
		{PkgKey{"openssh-server", "1:9.2p1-2+deb12u3", "amd64"}, "https://snapshot.debian.org/archive/debian-security/", "08ffb1599d05a815ce7d82e84570ab42b0b6152cba8e421a51ab1ba0709ed706"},
	} {
		ref, err := f.Find(ctx, c.key, "debian")
		if err != nil {
			t.Errorf("%+v: %v", c.key, err)
			continue
		}
		if ref.Source != SourceArchive || !strings.HasPrefix(ref.URL, c.prefix) || ref.SHA256 != c.sha256 {
			t.Errorf("%+v: %+v", c.key, ref)
		}
		t.Logf("%+v: %+v", c.key, ref)
	}
}

func TestOnlineFindOldUbuntu(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	f, err := NewOldFinder(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		key    PkgKey
		source string
		prefix string
		sha256 string
	}{
		{PkgKey{"hello", "2.10-3build1", "amd64"}, SourceArchive, "https://snapshot.ubuntu.com/ubuntu/", "e68cf4365b7aa9c4e2af4af6eee1710d6f967059b7b4af62786e8870d7366333"},
		// Published in 2022, before snapshot.ubuntu.com begins: only
		// Launchpad has it.
		{PkgKey{"openssh-server", "1:8.9p1-3ubuntu0.1", "amd64"}, SourceLaunchpad, "https://launchpad.net/", "368a8128f706630b0a059ab5bf998ee6b75f2875d01e77d37a04e1e38c145c00"},
	} {
		ref, err := f.Find(ctx, c.key, "ubuntu")
		if err != nil {
			t.Errorf("%+v: %v", c.key, err)
			continue
		}
		if ref.Source != c.source || !strings.HasPrefix(ref.URL, c.prefix) || ref.SHA256 != c.sha256 {
			t.Errorf("%+v: %+v", c.key, ref)
		}
		t.Logf("%+v: %+v", c.key, ref)
	}
}

// fetchTable downloads a .deb found by FindOld and reads its file table.
func fetchTable(t *testing.T, ctx context.Context, key PkgKey, distro string) (DebRef, map[string]DebFile) {
	t.Helper()
	f, err := NewOldFinder(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ref, err := f.Find(ctx, key, distro)
	if err != nil {
		t.Fatal(err)
	}
	tmp, err := os.CreateTemp(t.TempDir(), "deb")
	if err != nil {
		t.Fatal(err)
	}
	defer tmp.Close()
	if err := downloadDeb(ctx, defaultClient, ref, tmp); err != nil {
		t.Fatal(err)
	}
	files, err := DebFiles(tmp, ref.Size)
	if err != nil {
		t.Fatal(err)
	}
	return ref, files
}

// The expected file hashes were checked when the test was written by
// extracting the same .debs with dpkg-deb and running sha256sum.

func TestOnlineDebFileTable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	// A superseded bookworm security update: data.tar.xz.
	ref, files := fetchTable(t, ctx, PkgKey{"openssh-server", "1:9.2p1-2+deb12u3", "amd64"}, "debian")
	if ref.SHA256 != "08ffb1599d05a815ce7d82e84570ab42b0b6152cba8e421a51ab1ba0709ed706" {
		t.Errorf("ref %+v", ref)
	}
	var scripts []string
	for p := range files {
		if name, ok := strings.CutPrefix(p, ControlPrefix); ok {
			scripts = append(scripts, name)
		}
	}
	sort.Strings(scripts)
	if want := []string{"config", "postinst", "postrm", "preinst", "prerm"}; len(files) != 23+len(want) || !slices.Equal(scripts, want) {
		t.Errorf("%d entries with maintainer scripts %v, want 23 files and %v", len(files), scripts, want)
	}
	if f := files["/usr/sbin/sshd"]; f.SHA256 != "838332fe9777b307794760e1c4800b16ac17a93a2fe3f2580ceca8ca6ca2caa5" || f.Mode != 0o755 || f.Conffile {
		t.Errorf("/usr/sbin/sshd = %+v", f)
	}
	pam := files["/etc/pam.d/sshd"]
	if !pam.Conffile || pam.SHA256 != "65822d20f36db29cb50275526854b584df7a04a9efe975f3801473f81b44f521" || sha256hex(pam.Text) != pam.SHA256 {
		t.Errorf("/etc/pam.d/sshd: conffile %v, sha256 %s, %d bytes of text", pam.Conffile, pam.SHA256, len(pam.Text))
	}
}

func TestOnlineUbuntuZstdDeb(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	// Ubuntu noble builds data.tar.zst.
	_, files := fetchTable(t, ctx, PkgKey{"hello", "2.10-3build1", "amd64"}, "ubuntu")
	if len(files) != 6 {
		t.Errorf("%d files, want 6", len(files))
	}
	if f := files["/usr/bin/hello"]; f.SHA256 != "d288b98ce5f0a3981ea833f3b1d6484dfdde9ee36a00ee3b50bd3a9f7b01f75f" || f.Mode != 0o755 {
		t.Errorf("/usr/bin/hello = %+v", f)
	}
}

// TestOnlineVerifyAndBundle verifies a made-up Debian 12 machine running an
// old openssh-server against the real archives, then builds a reference
// bundle and verifies again from it alone.
func TestOnlineVerifyAndBundle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	c := &model.Collection{
		Schema: model.CollectionSchema,
		Host:   model.Host{OSID: "debian", OSVersionID: "12", Arch: "amd64"},
		Files: []model.FileEntry{
			{Path: "/usr/sbin/sshd", Type: "file", Mode: 0o100755, SHA256: "838332fe9777b307794760e1c4800b16ac17a93a2fe3f2580ceca8ca6ca2caa5"},
			{Path: "/usr/lib/openssh/ssh-session-cleanup", Type: "file", Mode: 0o100755, SHA256: sha256hex([]byte("tampered"))},
		},
		Packages: model.Packages{Installed: []model.Package{{
			Name: "openssh-server", Version: "1:9.2p1-2+deb12u3", Arch: "amd64", Status: "install ok installed",
			Files: []string{"/usr/sbin/sshd", "/usr/lib/openssh/ssh-session-cleanup"},
		}}},
	}
	check := func(res *Result, source string) {
		t.Helper()
		if len(res.Verified) != 1 || res.Verified[0].Path != "/usr/sbin/sshd" || res.Verified[0].Source != source {
			t.Errorf("Verified = %+v", res.Verified)
		}
		if len(res.Mismatch) != 1 || res.Mismatch[0].Path != "/usr/lib/openssh/ssh-session-cleanup" {
			t.Errorf("Mismatch = %+v", res.Mismatch)
		}
		if len(res.Unverifiable) != 0 || len(res.Errors) != 0 {
			t.Errorf("Unverifiable = %+v, Errors = %q", res.Unverifiable, res.Errors)
		}
		t.Logf("sources: %q", res.SourcesUsed)
	}
	check(Verify(ctx, c, Options{CacheDir: t.TempDir()}), SourceArchive)

	dir := filepath.Join(t.TempDir(), "refs")
	if err := WriteBundle(ctx, c, dir, Options{}); err != nil {
		t.Fatal(err)
	}
	check(Verify(ctx, c, Options{RefsDir: dir}), SourceRefs)
}
