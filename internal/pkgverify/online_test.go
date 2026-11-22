//go:build online

package pkgverify

import (
	"context"
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
