package pkgverify

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func sha1hex(b []byte) string {
	s := sha1.Sum(b)
	return hex.EncodeToString(s[:])
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func otherKey(t *testing.T) *openpgp.Entity {
	t.Helper()
	e, err := openpgp.NewEntity("other", "", "other@example.invalid", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, Time: fixedClock(recordedNow.Add(-time.Hour))})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// debianSnapshot builds a fake snapshot.debian.org holding hello 2.10-3 for
// amd64: the mr API answer, the file under /file/<sha1>, and the unstable
// suite at the file's first_seen timestamp signed by signer.
func debianSnapshot(t *testing.T, signer *openpgp.Entity, deb []byte) map[string][]byte {
	t.Helper()
	hash := sha1hex(deb)
	files := map[string][]byte{
		"/mr/binary/hello/2.10-3/binfiles": mustJSON(t, map[string]any{
			"binary": "hello", "binary_version": "2.10-3",
			"result": []map[string]string{
				{"architecture": "arm64", "hash": "886b91e2acb631a2e0dcdfdf21af03f55d801d22"},
				{"architecture": "amd64", "hash": hash},
			},
			"fileinfo": map[string]any{
				hash: []map[string]any{{"archive_name": "debian", "first_seen": "20221227T032939Z", "name": "hello_2.10-3_amd64.deb", "path": "/pool/main/h/hello", "size": len(deb)}},
				"886b91e2acb631a2e0dcdfdf21af03f55d801d22": []map[string]any{{"archive_name": "debian", "first_seen": "20221227T032939Z", "name": "hello_2.10-3_arm64.deb", "path": "/pool/main/h/hello", "size": 52308}},
			},
		}),
		"/file/" + hash: deb,
	}
	pk := xzBytes(t, []byte(stanza("hello", "2.10-3", "amd64", "pool/main/h/hello/hello_2.10-3_amd64.deb", deb)))
	for k, v := range fakeSuite(t, signer, recordedNow, "/archive/debian/20221227T032939Z", "unstable", "Valid-Until: Tue, 03 Jan 2023 02:26:38 UTC\n", map[string][]byte{"main/binary-amd64/Packages.xz": pk}) {
		files[k] = v
	}
	return files
}

func testFinder(srv *archiveServer, debKR, ubuKR openpgp.EntityList) *OldFinder {
	return &OldFinder{
		Client:         srv.Client(),
		Now:            fixedClock(recordedNow),
		DebianSnapshot: srv.URL,
		UbuntuSnapshot: srv.URL + "/ubuntu-snap",
		Launchpad:      srv.URL + "/lp",
		DebianKeyring:  debKR,
		UbuntuKeyring:  ubuKR,
	}
}

func TestFindOldDebianUsesSignedSnapshotIndex(t *testing.T) {
	fake := readFakeKey(t)
	deb := []byte("hello 2.10-3 amd64 package bytes")
	srv := newArchiveServer(t, debianSnapshot(t, fake, deb))
	f := testFinder(srv, fakePublicKeyring(t), nil)
	got, err := f.Find(context.Background(), PkgKey{"hello", "2.10-3", "amd64"}, "debian")
	if err != nil {
		t.Fatal(err)
	}
	want := DebRef{
		URL:    srv.URL + "/archive/debian/20221227T032939Z/pool/main/h/hello/hello_2.10-3_amd64.deb",
		SHA256: sha256hex(deb),
		Size:   int64(len(deb)),
		Source: SourceArchive,
	}
	if got != want {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
	if n := srv.hitCount("/file/" + sha1hex(deb)); n != 0 {
		t.Errorf("downloaded the file by SHA-1 %d times although the signed index had it", n)
	}
}

func TestFindOldDebianFallsBackToSnapshotFile(t *testing.T) {
	deb := []byte("hello 2.10-3 amd64 package bytes")
	// The snapshot's index is signed by a key telltale does not trust.
	srv := newArchiveServer(t, debianSnapshot(t, otherKey(t), deb))
	f := testFinder(srv, fakePublicKeyring(t), nil)
	got, err := f.Find(context.Background(), PkgKey{"hello", "2.10-3", "amd64"}, "debian")
	if err != nil {
		t.Fatal(err)
	}
	want := DebRef{
		URL:    srv.URL + "/file/" + sha1hex(deb),
		SHA256: sha256hex(deb),
		Size:   int64(len(deb)),
		Source: SourceSnapshot,
	}
	if got != want {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

func TestFindOldDebianRejectsSnapshotFileMismatch(t *testing.T) {
	deb := []byte("hello 2.10-3 amd64 package bytes")
	files := debianSnapshot(t, otherKey(t), deb)
	files["/file/"+sha1hex(deb)] = []byte("hello 2.10-3 amd64 package bytEs")
	srv := newArchiveServer(t, files)
	f := testFinder(srv, fakePublicKeyring(t), nil)
	if ref, err := f.Find(context.Background(), PkgKey{"hello", "2.10-3", "amd64"}, "debian"); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("got %+v, err = %v, want ErrHashMismatch", ref, err)
	}
}

func TestFindOldDebianDoesNotDowngradeOnTampering(t *testing.T) {
	fake := readFakeKey(t)
	deb := []byte("hello 2.10-3 amd64 package bytes")
	files := debianSnapshot(t, fake, deb)
	// The signed index's Packages.xz was replaced: a tampered chain is an
	// error, not a reason to fall back to the weaker SHA-1 path.
	p := "/archive/debian/20221227T032939Z/dists/unstable/main/binary-amd64/Packages.xz"
	files[p] = xzBytes(t, []byte(stanza("hello", "2.10-3", "amd64", "pool/main/h/hello/hello_2.10-3_amd64.deb", []byte("evil"))))
	srv := newArchiveServer(t, files)
	f := testFinder(srv, fakePublicKeyring(t), nil)
	if ref, err := f.Find(context.Background(), PkgKey{"hello", "2.10-3", "amd64"}, "debian"); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("got %+v, err = %v, want ErrHashMismatch", ref, err)
	}
	if n := srv.hitCount("/file/" + sha1hex(deb)); n != 0 {
		t.Errorf("fell back to the SHA-1 path after tampering")
	}
}

func TestFindOldDebianNotFound(t *testing.T) {
	srv := newArchiveServer(t, debianSnapshot(t, readFakeKey(t), []byte("x")))
	f := testFinder(srv, nil, nil)
	if _, err := f.Find(context.Background(), PkgKey{"hello", "9.9-9", "amd64"}, "debian"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown version: err = %v, want ErrNotFound", err)
	}
	if _, err := f.Find(context.Background(), PkgKey{"hello", "2.10-3", "riscv64"}, "debian"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown arch: err = %v, want ErrNotFound", err)
	}
	if _, err := f.Find(context.Background(), PkgKey{"hello", "2.10-3", "amd64"}, "fedora"); err == nil {
		t.Fatal("unknown distro accepted")
	}
}

// launchpadEntries is a getPublishedBinaries answer for hello 2.10-3build1.
func launchpadEntries(t *testing.T, self string) []byte {
	return mustJSON(t, map[string]any{
		"total_size": 3,
		"entries": []map[string]any{
			{"binary_package_name": "hello", "binary_package_version": "2.10-3build1", "distro_arch_series_link": "https://api.launchpad.net/devel/ubuntu/noble/arm64", "pocket": "Release", "status": "Published", "date_published": "2024-04-16T13:15:28.310244+00:00", "architecture_specific": true, "component_name": "main", "self_link": self + "/2"},
			{"binary_package_name": "hello", "binary_package_version": "2.10-3build1", "distro_arch_series_link": "https://api.launchpad.net/devel/ubuntu/noble/amd64", "pocket": "Release", "status": "Published", "date_published": "2024-04-16T13:15:28.310244+00:00", "architecture_specific": true, "component_name": "main", "self_link": self + "/1"},
			{"binary_package_name": "hello-extra", "binary_package_version": "2.10-3build1", "distro_arch_series_link": "https://api.launchpad.net/devel/ubuntu/noble/amd64", "pocket": "Release", "status": "Published", "date_published": "2024-04-16T13:15:28.310244+00:00", "architecture_specific": true, "component_name": "main", "self_link": self + "/3"},
		},
	})
}

func TestFindOldUbuntuUsesSignedSnapshotIndex(t *testing.T) {
	fake := readFakeKey(t)
	deb := []byte("hello 2.10-3build1 amd64 package bytes")
	srv := newArchiveServer(t, map[string][]byte{})
	srv.set("/lp/ubuntu/+archive/primary", launchpadEntries(t, srv.URL+"/lp/ubuntu/+archive/primary/+binarypub"))
	// One hour after date_published.
	pk := xzBytes(t, []byte(stanza("hello", "2.10-3build1", "amd64", "pool/main/h/hello/hello_2.10-3build1_amd64.deb", deb)))
	for k, v := range fakeSuite(t, fake, recordedNow, "/ubuntu-snap/ubuntu/20240416T141528Z", "noble", "", map[string][]byte{"main/binary-amd64/Packages.xz": pk}) {
		srv.set(k, v)
	}
	f := testFinder(srv, nil, fakePublicKeyring(t))
	got, err := f.Find(context.Background(), PkgKey{"hello", "2.10-3build1", "amd64"}, "ubuntu")
	if err != nil {
		t.Fatal(err)
	}
	want := DebRef{
		URL:    srv.URL + "/ubuntu-snap/ubuntu/20240416T141528Z/pool/main/h/hello/hello_2.10-3build1_amd64.deb",
		SHA256: sha256hex(deb),
		Size:   int64(len(deb)),
		Source: SourceArchive,
	}
	if got != want {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
	q, _ := url.ParseQuery(srv.lastQuery("/lp/ubuntu/+archive/primary"))
	if q.Get("ws.op") != "getPublishedBinaries" || q.Get("binary_name") != "hello" || q.Get("version") != "2.10-3build1" || q.Get("exact_match") != "true" {
		t.Errorf("Launchpad query = %v", q)
	}
}

func TestFindOldUbuntuFallsBackToLaunchpad(t *testing.T) {
	srv := newArchiveServer(t, map[string][]byte{})
	self := srv.URL + "/lp/ubuntu/+archive/primary/+binarypub"
	srv.set("/lp/ubuntu/+archive/primary", launchpadEntries(t, self))
	sha := "7bd21b40123e5c1dbf15cf47cae97b98c1c8292ae0a518b88eed6acf6354e642"
	srv.set("/lp/ubuntu/+archive/primary/+binarypub/1", mustJSON(t, []map[string]any{
		{"url": "https://launchpad.net/ubuntu/+archive/primary/+files/hello-dbgsym_2.10-3build1_amd64.ddeb", "size": 9, "sha1": "x", "sha256": "0000000000000000000000000000000000000000000000000000000000000000"},
		{"url": "https://launchpad.net/ubuntu/+archive/primary/+files/hello_2.10-3build1_amd64.deb", "size": 26660, "sha1": "fabf8f5d364b1756a6e6fde39abec2b4a3bae3ce", "sha256": sha},
	}))
	// No snapshot of the archive is served, so only Launchpad can answer.
	f := testFinder(srv, nil, fakePublicKeyring(t))
	got, err := f.Find(context.Background(), PkgKey{"hello", "2.10-3build1", "amd64"}, "ubuntu")
	if err != nil {
		t.Fatal(err)
	}
	want := DebRef{
		URL:    "https://launchpad.net/ubuntu/+archive/primary/+files/hello_2.10-3build1_amd64.deb",
		SHA256: sha,
		Size:   26660,
		Source: SourceLaunchpad,
	}
	if got != want {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
	q, _ := url.ParseQuery(srv.lastQuery("/lp/ubuntu/+archive/primary/+binarypub/1"))
	if q.Get("ws.op") != "binaryFileUrls" || q.Get("include_meta") != "true" {
		t.Errorf("binaryFileUrls query = %v", q)
	}
}

func TestFindOldUbuntuRejectsInsecureLaunchpadURL(t *testing.T) {
	srv := newArchiveServer(t, map[string][]byte{})
	srv.set("/lp/ubuntu/+archive/primary", launchpadEntries(t, srv.URL+"/lp/ubuntu/+archive/primary/+binarypub"))
	srv.set("/lp/ubuntu/+archive/primary/+binarypub/1", mustJSON(t, []map[string]any{
		{"url": "http://launchpad.net/ubuntu/+archive/primary/+files/hello_2.10-3build1_amd64.deb", "size": 26660, "sha256": "7bd21b40123e5c1dbf15cf47cae97b98c1c8292ae0a518b88eed6acf6354e642"},
	}))
	f := testFinder(srv, nil, nil)
	if ref, err := f.Find(context.Background(), PkgKey{"hello", "2.10-3build1", "amd64"}, "ubuntu"); err == nil {
		t.Fatalf("accepted %+v", ref)
	}
}

func TestFindOldUbuntuNotFound(t *testing.T) {
	srv := newArchiveServer(t, map[string][]byte{})
	srv.set("/lp/ubuntu/+archive/primary", mustJSON(t, map[string]any{"total_size": 0, "entries": []any{}}))
	f := testFinder(srv, nil, nil)
	if _, err := f.Find(context.Background(), PkgKey{"hello", "0.1", "amd64"}, "ubuntu"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}
