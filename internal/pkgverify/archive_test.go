package pkgverify

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ulikunitz/xz"

	"github.com/donaldsteele/telltale/internal/model"
)

// testdata/debian was recorded from https://deb.debian.org/debian on
// 2026-11-22: dists/{bookworm,trixie}-updates/InRelease, each suite's
// main/binary-amd64/Packages.xz, and one small .deb from the bookworm-updates
// index. The fake archive key that signs test indexes is generated at test
// time (readFakeKey).
//
// recordedNow is shortly after the recorded indexes were published
// (Date: Sun, 22 Nov 2026 08:11:14 UTC).
var recordedNow = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

func fixedClock(t time.Time) func() time.Time { return func() time.Time { return t } }

func sha256hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// loadTree reads every file below dir into a map keyed by URL path, with
// prefix prepended.
func loadTree(t *testing.T, dir, prefix string) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		files[prefix+"/"+filepath.ToSlash(rel)] = b
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// archiveServer serves a fixed set of files the way an archive mirror does,
// including by-hash paths for any file in the by-hash directory's parent.
type archiveServer struct {
	*httptest.Server
	mu    sync.Mutex
	files map[string][]byte
	hits  map[string]int
	query map[string]string
	down  bool
}

func newArchiveServer(t *testing.T, files map[string][]byte) *archiveServer {
	t.Helper()
	s := &archiveServer{files: files, hits: map[string]int{}, query: map[string]string{}}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Close)
	return s
}

func (s *archiveServer) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := r.URL.Path
	s.hits[p]++
	s.query[p] = r.URL.RawQuery
	if s.down {
		http.Error(w, "down", http.StatusServiceUnavailable)
		return
	}
	if b, ok := s.files[p]; ok {
		w.Write(b)
		return
	}
	if i := strings.Index(p, "/by-hash/SHA256/"); i >= 0 {
		dir, want := p[:i]+"/", p[i+len("/by-hash/SHA256/"):]
		for name, b := range s.files {
			if strings.HasPrefix(name, dir) && !strings.Contains(name[len(dir):], "/") && sha256hex(b) == want {
				w.Write(b)
				return
			}
		}
	}
	http.NotFound(w, r)
}

func (s *archiveServer) set(path string, b []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.files[path] = b
}

func (s *archiveServer) hitCount(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits[path]
}

func (s *archiveServer) lastQuery(path string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.query[path]
}

func (s *archiveServer) hitPaths() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for p := range s.hits {
		out = append(out, p)
	}
	return out
}

func (s *archiveServer) setDown(down bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.down = down
}

var (
	fakeKeyOnce sync.Once
	fakeEntity  *openpgp.Entity
	fakeKeyErr  error
)

// readFakeKey returns an ed25519 archive key generated once per test run and
// trusted nowhere but in these tests. It is generated rather than stored so
// that no private key block sits in the tree.
func readFakeKey(t *testing.T) *openpgp.Entity {
	t.Helper()
	fakeKeyOnce.Do(func() {
		fakeEntity, fakeKeyErr = openpgp.NewEntity("telltale fake archive key", "test only, not trusted", "fake-archive@example.invalid",
			&packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, Time: fixedClock(recordedNow.Add(-24 * time.Hour))})
	})
	if fakeKeyErr != nil {
		t.Fatal(fakeKeyErr)
	}
	return fakeEntity
}

// publicOnly serialises the public half of e and reads it back, the way the
// embedded keyrings are read.
func publicOnly(t *testing.T, e *openpgp.Entity) openpgp.EntityList {
	t.Helper()
	var buf bytes.Buffer
	if err := e.Serialize(&buf); err != nil {
		t.Fatal(err)
	}
	el, err := openpgp.ReadKeyRing(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if el[0].PrivateKey != nil {
		t.Fatal("public keyring holds a private key")
	}
	return el
}

// fakePublicKeyring is the public half of the fake key, trusted the way the
// built-in keyrings are.
func fakePublicKeyring(t *testing.T) openpgp.EntityList {
	t.Helper()
	return publicOnly(t, readFakeKey(t))
}

func clearsignWith(t *testing.T, e *openpgp.Entity, text []byte, at time.Time) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := clearsign.Encode(&buf, e.PrivateKey, &packet.Config{Time: fixedClock(at)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(text); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func xzBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := xz.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// stanza renders one Packages entry for a file with the given content.
func stanza(name, version, arch, filename string, deb []byte) string {
	return fmt.Sprintf("Package: %s\nVersion: %s\nArchitecture: %s\nMaintainer: Test <t@example.invalid>\nFilename: %s\nSize: %d\nSHA256: %s\nDescription: test package\n multi-line description\n .\n more\n\n",
		name, version, arch, filename, len(deb), sha256hex(deb))
}

// fakeSuite signs a Release for suite that lists the given index files
// (paths relative to dists/<suite>/) and returns the archive files below
// prefix.
func fakeSuite(t *testing.T, signer *openpgp.Entity, signAt time.Time, prefix, suite, extraFields string, indexes map[string][]byte) map[string][]byte {
	t.Helper()
	var rel strings.Builder
	fmt.Fprintf(&rel, "Origin: Fake\nLabel: Fake\nSuite: %s\nCodename: %s\nDate: %s\n%sAcquire-By-Hash: yes\nSHA256:\n",
		suite, suite, signAt.UTC().Format(time.RFC1123), extraFields)
	paths := make([]string, 0, len(indexes))
	for p := range indexes {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		fmt.Fprintf(&rel, " %s %8d %s\n", sha256hex(indexes[p]), len(indexes[p]), p)
	}
	files := map[string][]byte{
		prefix + "/dists/" + suite + "/InRelease": clearsignWith(t, signer, []byte(rel.String()), signAt),
	}
	for p, b := range indexes {
		files[prefix+"/dists/"+suite+"/"+p] = b
	}
	return files
}

func debianKeyring(t *testing.T) openpgp.EntityList {
	t.Helper()
	kr, err := DebianKeyring()
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

func fingerprints(el openpgp.EntityList) []string {
	var out []string
	for _, e := range el {
		out = append(out, strings.ToUpper(hex.EncodeToString(e.PrimaryKey.Fingerprint)))
	}
	sort.Strings(out)
	return out
}

func TestEmbeddedKeyringFingerprints(t *testing.T) {
	// Debian: primary keys of the embedded debian-archive-keyring.pgp
	// (debian-archive-keyring 2025.1 from this build machine's Debian 13),
	// as listed by `gpg --show-keys --with-colons` on 2026-11-22.
	debian := map[string]string{
		"1F89983E0081FDE018F3CC9673A4F27B8DD47936": "Debian Archive Automatic Signing Key (11/bullseye)",
		"AC530D520F2F3269F5E98313A48449044AAD5C5D": "Debian Security Archive Automatic Signing Key (11/bullseye)",
		"A4285295FC7B1A81600062A9605C66F00D6C9793": "Debian Stable Release Key (11/bullseye)",
		"4D64FEC119C2029067D6E791F8D2585B8783D481": "Debian Stable Release Key (12/bookworm)",
		"B8B80B5B623EAB6AD8775C45B7C5D7D6350947F8": "Debian Archive Automatic Signing Key (12/bookworm)",
		"05AB90340C0C5E797F44A8C8254CF3B5AEC0A8F0": "Debian Security Archive Automatic Signing Key (12/bookworm)",
		"04B54C3CDCA79751B16BC6B5225629DF75B188BD": "Debian Archive Automatic Signing Key (13/trixie)",
		"5E04A1E3223A19A20706E20F9904613D4CCE68C6": "Debian Security Archive Automatic Signing Key (13/trixie)",
		"41587F7DB8C774BCCF131416762F67A0B2C39DE4": "Debian Stable Release Key (13/trixie)",
	}
	// Ubuntu: ubuntu-archive-keyring.gpg of ubuntu-keyring 2023.11.28.1.
	ubuntu := map[string]string{
		"790BC7277767219C42C86F933B4FE6ACC0B21F32": "Ubuntu Archive Automatic Signing Key (2012)",
		"843938DF228D22F7B3742BC0D94AA3F0EFE21092": "Ubuntu CD Image Automatic Signing Key (2012)",
		"F6ECB3762474EDA9D21B7022871920D1991BC93C": "Ubuntu Archive Automatic Signing Key (2018)",
	}
	// The keys that sign the supported releases' indexes must be usable
	// for signing now, as go-crypto judges them.
	mustSign := []string{
		"B8B80B5B623EAB6AD8775C45B7C5D7D6350947F8", // bookworm archive
		"05AB90340C0C5E797F44A8C8254CF3B5AEC0A8F0", // bookworm security
		"04B54C3CDCA79751B16BC6B5225629DF75B188BD", // trixie archive
		"5E04A1E3223A19A20706E20F9904613D4CCE68C6", // trixie security
		"F6ECB3762474EDA9D21B7022871920D1991BC93C", // Ubuntu 2018 archive
	}

	ub, err := UbuntuKeyring()
	if err != nil {
		t.Fatal(err)
	}
	deb := debianKeyring(t)
	for _, c := range []struct {
		name string
		kr   openpgp.EntityList
		want map[string]string
	}{{"debian", deb, debian}, {"ubuntu", ub, ubuntu}} {
		var want []string
		for fp := range c.want {
			want = append(want, fp)
		}
		sort.Strings(want)
		if got := fingerprints(c.kr); !slices.Equal(got, want) {
			t.Errorf("%s keyring primary fingerprints:\n got %v\nwant %v", c.name, got, want)
		}
	}
	all := append(append(openpgp.EntityList{}, deb...), ub...)
	for _, fp := range mustSign {
		var found bool
		for _, e := range all {
			if strings.EqualFold(hex.EncodeToString(e.PrimaryKey.Fingerprint), fp) {
				found = true
				if _, ok := e.SigningKey(recordedNow); !ok {
					t.Errorf("key %s has no usable signing key at %v", fp, recordedNow)
				}
			}
		}
		if !found {
			t.Errorf("key %s missing", fp)
		}
	}
}

func TestIndexVerifiesRecordedInRelease(t *testing.T) {
	srv := newArchiveServer(t, loadTree(t, "testdata/debian", "/debian"))
	a := &Archive{
		BaseURL: srv.URL + "/debian",
		Suites:  []string{"bookworm-updates"},
		Keyring: debianKeyring(t),
		Client:  srv.Client(),
		Now:     fixedClock(recordedNow),
	}
	idx, err := a.Index(context.Background(), "bookworm-updates", "main", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if len(idx) != 38 {
		t.Errorf("index has %d packages, want 38", len(idx))
	}
	got, ok := idx[PkgKey{"openssh-server", "1:9.2p1-2+deb12u7", "amd64"}]
	want := DebRef{
		URL:    srv.URL + "/debian/pool/main/o/openssh/openssh-server_9.2p1-2+deb12u7_amd64.deb",
		SHA256: "fdac7995f69e1059650de944b569a1028beb17dfa1cba5e8eb2779339f6a4785",
		Size:   456900,
		Source: SourceArchive,
	}
	if !ok || got != want {
		t.Errorf("openssh-server: got %+v (found %v), want %+v", got, ok, want)
	}

	// The recorded .deb closes the chain: InRelease -> Packages.xz -> .deb.
	debPath := "/debian/pool/main/s/samba/samba-ad-dc_4.17.12+dfsg-0+deb12u2_all.deb"
	deb, err := os.ReadFile("testdata" + debPath)
	if err != nil {
		t.Fatal(err)
	}
	ref, ok := idx[PkgKey{"samba-ad-dc", "2:4.17.12+dfsg-0+deb12u2", "all"}]
	if !ok {
		t.Fatal("Architecture: all package samba-ad-dc missing from the amd64 index")
	}
	if ref.SHA256 != sha256hex(deb) || ref.Size != int64(len(deb)) || ref.URL != srv.URL+debPath {
		t.Errorf("samba-ad-dc: got %+v, want sha256 %s size %d", ref, sha256hex(deb), len(deb))
	}
	if r, ok := Lookup(idx, "samba-ad-dc", "2:4.17.12+dfsg-0+deb12u2", "amd64"); !ok || r != ref {
		t.Errorf("Lookup did not fall back to Architecture: all: %+v %v", r, ok)
	}

	// Packages.xz came by hash, as apt fetches it.
	byHash := "/debian/dists/bookworm-updates/main/binary-amd64/by-hash/SHA256/87e7e94047fb7fb6f4ceecc7022d4bee55b66031cc2a7666d3196f3e0aabb846"
	if n := srv.hitCount(byHash); n != 1 {
		t.Errorf("by-hash fetches = %d, want 1 (hits %v)", n, srv.hitPaths())
	}
}

func TestIndexRejectsBadSignature(t *testing.T) {
	files := loadTree(t, "testdata/debian", "/debian")
	inrel := files["/debian/dists/bookworm-updates/InRelease"]
	block, _ := clearsign.Decode(inrel)
	if block == nil {
		t.Fatal("recorded InRelease does not decode")
	}
	fake := readFakeKey(t)

	cases := []struct {
		name    string
		content []byte
		wantErr error
	}{
		{"signed by a key not built in", clearsignWith(t, fake, block.Plaintext, recordedNow), ErrNoValidSignature},
		{"signed text altered", bytes.Replace(inrel, []byte("Date: Sun, 22 Nov 2026 08:11:14 UTC"), []byte("Date: Sun, 22 Nov 2026 08:11:15 UTC"), 1), ErrBadSignature},
		{"unsigned text after the signature", append(append([]byte{}, inrel...), []byte("\nSHA256:\n 0000000000000000000000000000000000000000000000000000000000000000 32 main/binary-amd64/Packages.xz\n")...), ErrMalformedInRelease},
		{"unsigned text before the message", append([]byte("Codename: bookworm-updates\n\n"), inrel...), ErrMalformedInRelease},
		{"no signature at all", block.Plaintext, ErrMalformedInRelease},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := map[string][]byte{}
			for k, v := range files {
				f[k] = v
			}
			f["/debian/dists/bookworm-updates/InRelease"] = c.content
			srv := newArchiveServer(t, f)
			a := &Archive{BaseURL: srv.URL + "/debian", Suites: []string{"bookworm-updates"}, Keyring: debianKeyring(t), Client: srv.Client(), Now: fixedClock(recordedNow)}
			idx, err := a.Index(context.Background(), "bookworm-updates", "main", "amd64")
			if !errors.Is(err, c.wantErr) {
				t.Fatalf("err = %v, want %v (index %d entries)", err, c.wantErr, len(idx))
			}
			for _, p := range srv.hitPaths() {
				if strings.Contains(p, "Packages") {
					t.Errorf("fetched %s after a failed signature check", p)
				}
			}
		})
	}
}

func TestIndexRejectsExpiredValidUntil(t *testing.T) {
	// trixie-updates carries Valid-Until: Sun, 29 Nov 2026 08:11:14 UTC.
	srv := newArchiveServer(t, loadTree(t, "testdata/debian", "/debian"))
	archive := func(now time.Time, historical bool) *Archive {
		return &Archive{BaseURL: srv.URL + "/debian", Suites: []string{"trixie-updates"}, Keyring: debianKeyring(t), Client: srv.Client(), Now: fixedClock(now), Historical: historical}
	}
	idx, err := archive(recordedNow, false).Index(context.Background(), "trixie-updates", "main", "amd64")
	if err != nil {
		t.Fatalf("before Valid-Until: %v", err)
	}
	if _, ok := idx[PkgKey{"tzdata", "2026f-0+deb13u1", "all"}]; !ok {
		t.Errorf("tzdata missing from %v", idx)
	}

	late := time.Date(2026, 11, 30, 0, 0, 0, 0, time.UTC)
	if _, err := archive(late, false).Index(context.Background(), "trixie-updates", "main", "amd64"); !errors.Is(err, ErrExpiredIndex) {
		t.Fatalf("after Valid-Until: err = %v, want ErrExpiredIndex", err)
	}
	// A snapshot of the archive at a past moment is historical by design.
	if _, err := archive(late, true).Index(context.Background(), "trixie-updates", "main", "amd64"); err != nil {
		t.Fatalf("historical archive after Valid-Until: %v", err)
	}
}

func TestIndexRejectsUnparsableValidUntil(t *testing.T) {
	fake := readFakeKey(t)
	pk := xzBytes(t, []byte(stanza("hello", "1.0-1", "amd64", "pool/main/h/hello/hello_1.0-1_amd64.deb", []byte("deb"))))
	files := fakeSuite(t, fake, recordedNow, "/fake", "stable", "Valid-Until: next tuesday\n", map[string][]byte{"main/binary-amd64/Packages.xz": pk})
	srv := newArchiveServer(t, files)
	a := &Archive{BaseURL: srv.URL + "/fake", Suites: []string{"stable"}, Keyring: fakePublicKeyring(t), Client: srv.Client(), Now: fixedClock(recordedNow)}
	if _, err := a.Index(context.Background(), "stable", "main", "amd64"); !errors.Is(err, ErrExpiredIndex) {
		t.Fatalf("err = %v, want ErrExpiredIndex", err)
	}
}

func TestIndexRejectsPackagesHashMismatch(t *testing.T) {
	files := loadTree(t, "testdata/debian", "/debian")
	pkPath := "/debian/dists/bookworm-updates/main/binary-amd64/Packages.xz"
	flipped := append([]byte{}, files[pkPath]...)
	flipped[len(flipped)/2] ^= 0x01
	cases := []struct {
		name string
		pk   []byte
	}{
		{"same size, one bit changed", flipped},
		{"different file", files["/debian/dists/trixie-updates/main/binary-amd64/Packages.xz"]},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := map[string][]byte{}
			for k, v := range files {
				f[k] = v
			}
			f[pkPath] = c.pk
			srv := newArchiveServer(t, f)
			a := &Archive{BaseURL: srv.URL + "/debian", Suites: []string{"bookworm-updates"}, Keyring: debianKeyring(t), Client: srv.Client(), Now: fixedClock(recordedNow)}
			if _, err := a.Index(context.Background(), "bookworm-updates", "main", "amd64"); !errors.Is(err, ErrHashMismatch) {
				t.Fatalf("err = %v, want ErrHashMismatch", err)
			}
		})
	}
}

func TestIndexRejectsWrongSuite(t *testing.T) {
	// A validly signed index of another suite served in place of the one asked for.
	files := loadTree(t, "testdata/debian", "/debian")
	files["/debian/dists/bookworm-updates/InRelease"] = files["/debian/dists/trixie-updates/InRelease"]
	srv := newArchiveServer(t, files)
	a := &Archive{BaseURL: srv.URL + "/debian", Suites: []string{"bookworm-updates"}, Keyring: debianKeyring(t), Client: srv.Client(), Now: fixedClock(recordedNow)}
	if _, err := a.Index(context.Background(), "bookworm-updates", "main", "amd64"); !errors.Is(err, ErrWrongSuite) {
		t.Fatalf("err = %v, want ErrWrongSuite", err)
	}
	if _, err := a.Index(context.Background(), "trixie-updates", "main", "amd64"); !errors.Is(err, ErrWrongSuite) {
		t.Fatal("Index accepted a suite the archive does not list")
	}
}

func TestIndexRejectsExpiredKey(t *testing.T) {
	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, KeyLifetimeSecs: 86400, Time: fixedClock(created)}
	short, err := openpgp.NewEntity("short-lived", "", "short@example.invalid", cfg)
	if err != nil {
		t.Fatal(err)
	}
	pk := xzBytes(t, []byte(stanza("hello", "1.0-1", "amd64", "pool/main/h/hello/hello_1.0-1_amd64.deb", []byte("deb"))))
	signAt := created.Add(time.Hour)
	files := fakeSuite(t, short, signAt, "/fake", "stable", "", map[string][]byte{"main/binary-amd64/Packages.xz": pk})
	srv := newArchiveServer(t, files)
	archive := func(now time.Time) *Archive {
		return &Archive{BaseURL: srv.URL + "/fake", Suites: []string{"stable"}, Keyring: openpgp.EntityList{short}, Client: srv.Client(), Now: fixedClock(now)}
	}
	if _, err := archive(signAt.Add(time.Hour)).Index(context.Background(), "stable", "main", "amd64"); err != nil {
		t.Fatalf("while the key is valid: %v", err)
	}
	if _, err := archive(created.Add(48*time.Hour)).Index(context.Background(), "stable", "main", "amd64"); !errors.Is(err, ErrNoValidSignature) {
		t.Fatalf("after the key expired: err = %v, want ErrNoValidSignature", err)
	}
}

func TestIndexSkipsHostileFilenames(t *testing.T) {
	fake := readFakeKey(t)
	deb := []byte("deb")
	text := stanza("good", "1", "amd64", "pool/main/g/good/good_1_amd64.deb", deb) +
		stanza("dotdot", "1", "amd64", "pool/../../etc/passwd", deb) +
		stanza("absolute", "1", "amd64", "/etc/passwd", deb) +
		stanza("url", "1", "amd64", "https://evil.example/x.deb", deb) +
		stanza("query", "1", "amd64", "pool/x.deb?y=1", deb) +
		stanza("otherarch", "1", "arm64", "pool/main/o/o/o_1_arm64.deb", deb) +
		"Package: nohash\nVersion: 1\nArchitecture: amd64\nFilename: pool/n.deb\nSize: 3\n\n"
	files := fakeSuite(t, fake, recordedNow, "/fake", "stable", "", map[string][]byte{"main/binary-amd64/Packages.xz": xzBytes(t, []byte(text))})
	srv := newArchiveServer(t, files)
	a := &Archive{BaseURL: srv.URL + "/fake/", Suites: []string{"stable"}, Keyring: fakePublicKeyring(t), Client: srv.Client(), Now: fixedClock(recordedNow)}
	idx, err := a.Index(context.Background(), "stable", "main", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	want := DebRef{URL: srv.URL + "/fake/pool/main/g/good/good_1_amd64.deb", SHA256: sha256hex(deb), Size: 3, Source: SourceArchive}
	if len(idx) != 1 || idx[PkgKey{"good", "1", "amd64"}] != want {
		t.Errorf("index = %+v, want only %+v", idx, want)
	}
}

func TestIndexBoundsDecompressedSize(t *testing.T) {
	old := maxPackagesSize
	maxPackagesSize = 1000
	t.Cleanup(func() { maxPackagesSize = old })
	fake := readFakeKey(t)
	var text strings.Builder
	for i := 0; i < 20; i++ {
		text.WriteString(stanza(fmt.Sprintf("p%d", i), "1", "amd64", fmt.Sprintf("pool/p%d.deb", i), []byte("x")))
	}
	files := fakeSuite(t, fake, recordedNow, "/fake", "stable", "", map[string][]byte{"main/binary-amd64/Packages.xz": xzBytes(t, []byte(text.String()))})
	srv := newArchiveServer(t, files)
	a := &Archive{BaseURL: srv.URL + "/fake", Suites: []string{"stable"}, Keyring: fakePublicKeyring(t), Client: srv.Client(), Now: fixedClock(recordedNow)}
	if _, err := a.Index(context.Background(), "stable", "main", "amd64"); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("err = %v, want a size limit error", err)
	}
}

func TestIndexMissingComponent(t *testing.T) {
	srv := newArchiveServer(t, loadTree(t, "testdata/debian", "/debian"))
	a := &Archive{BaseURL: srv.URL + "/debian", Suites: []string{"bookworm-updates"}, Keyring: debianKeyring(t), Client: srv.Client(), Now: fixedClock(recordedNow)}
	if _, err := a.Index(context.Background(), "bookworm-updates", "universe", "amd64"); err == nil || !strings.Contains(err.Error(), "universe/binary-amd64/Packages.xz") {
		t.Fatalf("err = %v, want missing index error", err)
	}
}

func TestIndexCacheIsReverified(t *testing.T) {
	cache := t.TempDir()
	srv := newArchiveServer(t, loadTree(t, "testdata/debian", "/debian"))
	a := &Archive{BaseURL: srv.URL + "/debian", Suites: []string{"bookworm-updates"}, Keyring: debianKeyring(t), Client: srv.Client(), Cache: cache, Now: fixedClock(recordedNow)}
	ctx := context.Background()
	if _, err := a.Index(ctx, "bookworm-updates", "main", "amd64"); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(cache)
	if err != nil || len(entries) != 2 {
		t.Fatalf("cache holds %v (%v), want the InRelease and the Packages.xz", entries, err)
	}

	// With the network gone, verified cached copies are used.
	srv.setDown(true)
	if _, err := a.Index(ctx, "bookworm-updates", "main", "amd64"); err != nil {
		t.Fatalf("offline with a good cache: %v", err)
	}

	// A cached file that no longer verifies is never used.
	for _, e := range entries {
		p := filepath.Join(cache, e.Name())
		good, _ := os.ReadFile(p)
		bad := bytes.Replace(good, []byte("openssh-server"), []byte("openssh-sErver"), 1)
		if strings.HasPrefix(e.Name(), "packages-") {
			bad = append([]byte{}, good...)
			bad[len(bad)/2] ^= 1
		}
		if bytes.Equal(bad, good) {
			bad = bytes.Replace(good, []byte("Date: Sun"), []byte("Date: Mon"), 1)
		}
		if err := os.WriteFile(p, bad, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := a.Index(ctx, "bookworm-updates", "main", "amd64"); err == nil {
			t.Errorf("offline index accepted tampered cache file %s", e.Name())
		}
		// Back online, the bad copy is replaced by a verified download.
		srv.setDown(false)
		if _, err := a.Index(ctx, "bookworm-updates", "main", "amd64"); err != nil {
			t.Errorf("online after tampering %s: %v", e.Name(), err)
		}
		if now, _ := os.ReadFile(p); !bytes.Equal(now, good) {
			t.Errorf("cache file %s was not repaired", e.Name())
		}
		srv.setDown(true)
	}
}

func TestArchiveForUbuntuArm64UsesPorts(t *testing.T) {
	h := model.Host{OSID: "ubuntu", OSVersionID: "24.04", Arch: "arm64"}
	srcs := []model.AptSource{{
		URIs:       []string{"http://mirror.evil.example/ubuntu-ports"},
		Suites:     []string{"noble", "noble-updates", "noble-security", "noble-backports"},
		Components: []string{"main", "universe"},
	}}
	cache := t.TempDir()
	archives, err := ArchiveFor(h, srcs, cache)
	if err != nil {
		t.Fatal(err)
	}
	if len(archives) != 1 {
		t.Fatalf("got %d archives, want 1: %+v", len(archives), archives)
	}
	a := archives[0]
	if a.BaseURL != "http://ports.ubuntu.com/ubuntu-ports" {
		t.Errorf("BaseURL = %q", a.BaseURL)
	}
	if want := []string{"noble", "noble-updates", "noble-backports", "noble-security"}; !slices.Equal(a.Suites, want) {
		t.Errorf("Suites = %v, want %v", a.Suites, want)
	}
	if want := []string{"main", "restricted", "universe", "multiverse"}; !slices.Equal(a.Components, want) {
		t.Errorf("Components = %v, want %v", a.Components, want)
	}
	if a.Cache != cache || a.Client == nil {
		t.Errorf("Cache = %q, Client = %v", a.Cache, a.Client)
	}
	if got := fingerprints(a.Keyring); !slices.Contains(got, "F6ECB3762474EDA9D21B7022871920D1991BC93C") {
		t.Errorf("keyring %v lacks the Ubuntu 2018 archive key", got)
	}
}

func TestArchiveForOfficialArchivesOnly(t *testing.T) {
	type arch struct {
		base   string
		suites []string
	}
	mirror := []model.AptSource{{URIs: []string{"http://mirror.evil.example/debian"}, Suites: []string{"bookworm"}, Components: []string{"main"}}}
	cases := []struct {
		host model.Host
		srcs []model.AptSource
		want []arch
		fp   string
	}{
		{model.Host{OSID: "debian", OSVersionID: "12", Arch: "amd64"}, mirror, []arch{
			{"https://deb.debian.org/debian", []string{"bookworm", "bookworm-updates"}},
			{"https://deb.debian.org/debian-security", []string{"bookworm-security"}},
		}, "B8B80B5B623EAB6AD8775C45B7C5D7D6350947F8"},
		{model.Host{OSID: "debian", OSVersionID: "13", Arch: "arm64"}, []model.AptSource{{Suites: []string{"trixie-backports", "sid", "bookworm-backports"}}}, []arch{
			{"https://deb.debian.org/debian", []string{"trixie", "trixie-updates", "trixie-backports"}},
			{"https://deb.debian.org/debian-security", []string{"trixie-security"}},
		}, "04B54C3CDCA79751B16BC6B5225629DF75B188BD"},
		{model.Host{OSID: "ubuntu", OSVersionID: "22.04", Arch: "amd64"}, nil, []arch{
			{"http://archive.ubuntu.com/ubuntu", []string{"jammy", "jammy-updates"}},
			{"http://security.ubuntu.com/ubuntu", []string{"jammy-security"}},
		}, "F6ECB3762474EDA9D21B7022871920D1991BC93C"},
	}
	for _, c := range cases {
		archives, err := ArchiveFor(c.host, c.srcs, "")
		if err != nil {
			t.Errorf("%+v: %v", c.host, err)
			continue
		}
		var got []arch
		for _, a := range archives {
			got = append(got, arch{a.BaseURL, a.Suites})
			if !slices.Contains(fingerprints(a.Keyring), c.fp) {
				t.Errorf("%s: keyring lacks %s", a.BaseURL, c.fp)
			}
		}
		if fmt.Sprint(got) != fmt.Sprint(c.want) {
			t.Errorf("%+v:\n got %v\nwant %v", c.host, got, c.want)
		}
	}

	for _, h := range []model.Host{
		{OSID: "debian", OSVersionID: "11", Arch: "amd64"},
		{OSID: "debian", OSVersionID: "", Arch: "amd64"},
		{OSID: "ubuntu", OSVersionID: "20.04", Arch: "amd64"},
		{OSID: "fedora", OSVersionID: "41", Arch: "amd64"},
	} {
		if _, err := ArchiveFor(h, nil, ""); err == nil || !strings.Contains(err.Error(), "release not supported for package verification") {
			t.Errorf("%+v: err = %v", h, err)
		}
	}
}

// releaseText is a minimal Release file for the signature and suite checks.
func releaseText(suite, codename string) []byte {
	return []byte(fmt.Sprintf("Origin: Fake\nSuite: %s\nCodename: %s\nDate: Thu, 01 Jan 2026 00:00:00 UTC\nSHA256:\n %s 1 main/binary-amd64/Packages.xz\n", suite, codename, sha256hex([]byte("x"))))
}

func signWith(t *testing.T, pk *packet.PrivateKey, text []byte, cfg *packet.Config) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := clearsign.Encode(&buf, pk, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(text); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestVerifyReleaseSuiteAndPocket(t *testing.T) {
	// Ubuntu gives every pocket of a release the same Codename; Debian puts
	// the pocket in Codename and names stable's proposed-updates Suite
	// "proposed-updates".
	cases := []struct {
		suite, codename, asked string
		ok                     bool
	}{
		{"noble", "noble", "noble", true},
		{"noble-updates", "noble", "noble-updates", true},
		{"noble-security", "noble", "noble-security", true},
		{"noble-proposed", "noble", "noble", false},
		{"noble-proposed", "noble", "noble-updates", false},
		{"noble-backports", "noble", "noble-security", false},
		{"oldstable", "bookworm", "bookworm", true},
		{"oldstable-updates", "bookworm-updates", "bookworm-updates", true},
		{"oldstable-security", "bookworm-security", "bookworm-security", true},
		{"proposed-updates", "bookworm-proposed-updates", "bookworm-proposed-updates", true},
		{"oldstable-proposed-updates", "bookworm-proposed-updates", "bookworm-proposed-updates", true},
		{"unstable", "sid", "unstable", true},
		{"stable-updates", "trixie-updates", "trixie", false},
		{"stable", "trixie", "bookworm", false},
	}
	fake := readFakeKey(t)
	a := &Archive{Keyring: fakePublicKeyring(t), Now: fixedClock(recordedNow)}
	for _, c := range cases {
		_, err := a.verifyRelease(signWith(t, fake.PrivateKey, releaseText(c.suite, c.codename), &packet.Config{Time: fixedClock(recordedNow)}), c.asked)
		if c.ok && err != nil {
			t.Errorf("Suite %q Codename %q asked as %q: %v", c.suite, c.codename, c.asked, err)
		}
		if !c.ok && !errors.Is(err, ErrWrongSuite) {
			t.Errorf("Suite %q Codename %q asked as %q: err = %v, want ErrWrongSuite", c.suite, c.codename, c.asked, err)
		}
	}
}

func TestVerifyInReleaseRevokedPrimaryKey(t *testing.T) {
	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	e, err := openpgp.NewEntity("revoked", "", "revoked@example.invalid", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, Time: fixedClock(created)})
	if err != nil {
		t.Fatal(err)
	}
	signed := signWith(t, e.PrivateKey, releaseText("stable", "stable"), &packet.Config{Time: fixedClock(created.Add(time.Hour))})
	if _, err := verifyInRelease(signed, publicOnly(t, e), created.Add(2*time.Hour)); err != nil {
		t.Fatalf("before revocation: %v", err)
	}
	if err := e.RevokeKey(packet.KeyCompromised, "test", &packet.Config{Time: fixedClock(created.Add(3 * time.Hour))}); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyInRelease(signed, publicOnly(t, e), created.Add(4*time.Hour)); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("revoked primary key: err = %v, want ErrBadSignature", err)
	}
}

func TestVerifyInReleaseSubkeys(t *testing.T) {
	// Debian and Ubuntu sign with subkeys of the archive keys.
	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	e, err := openpgp.NewEntity("sub", "", "sub@example.invalid", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, Time: fixedClock(created)})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.AddSigningSubkey(&packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, Time: fixedClock(created), KeyLifetimeSecs: 10 * 86400}); err != nil {
		t.Fatal(err)
	}
	var sub *openpgp.Subkey
	for i := range e.Subkeys {
		if e.Subkeys[i].Sig.FlagSign {
			sub = &e.Subkeys[i]
		}
	}
	if sub == nil {
		t.Fatal("no signing subkey")
	}
	signed := signWith(t, sub.PrivateKey, releaseText("stable", "stable"), &packet.Config{Time: fixedClock(created.Add(time.Hour))})
	if _, err := verifyInRelease(signed, publicOnly(t, e), created.Add(2*time.Hour)); err != nil {
		t.Fatalf("valid subkey: %v", err)
	}
	if _, err := verifyInRelease(signed, publicOnly(t, e), created.Add(11*24*time.Hour)); !errors.Is(err, ErrNoValidSignature) {
		t.Fatalf("expired subkey: err = %v, want ErrNoValidSignature", err)
	}
	if err := e.RevokeSubkey(sub, packet.KeyCompromised, "test", &packet.Config{Time: fixedClock(created.Add(3 * time.Hour))}); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyInRelease(signed, publicOnly(t, e), created.Add(4*time.Hour)); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("revoked subkey: err = %v, want ErrBadSignature", err)
	}
}

// clearsignWithHash clearsigns text with an explicit hash algorithm, which
// clearsign.Encode will not do for hashes weaker than SHA-256.
func clearsignWithHash(t *testing.T, e *openpgp.Entity, text []byte, h crypto.Hash, at time.Time) []byte {
	t.Helper()
	names := map[crypto.Hash]string{crypto.SHA1: "SHA1", crypto.SHA224: "SHA224", crypto.SHA256: "SHA256", crypto.SHA512: "SHA512"}
	lines := strings.Split(strings.TrimSuffix(string(text), "\n"), "\n")
	noSalt := false // the salt notation only supports SHA-256 and stronger
	cfg := &packet.Config{Time: fixedClock(at), NonDeterministicSignaturesViaNotation: &noSalt}
	sig := &packet.Signature{SigType: packet.SigTypeText, PubKeyAlgo: e.PrivateKey.PubKeyAlgo, Hash: h, CreationTime: at, IssuerKeyId: &e.PrivateKey.KeyId}
	hasher, err := sig.PrepareSign(cfg)
	if err != nil {
		t.Fatal(err)
	}
	hasher.Write([]byte(strings.Join(lines, "\r\n")))
	if err := sig.Sign(hasher, e.PrivateKey, cfg); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	fmt.Fprintf(&out, "-----BEGIN PGP SIGNED MESSAGE-----\nHash: %s\n\n%s\n", names[h], strings.Join(lines, "\n"))
	w, err := armor.Encode(&out, "PGP SIGNATURE", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := sig.Serialize(w); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	out.WriteString("\n")
	return out.Bytes()
}

func TestVerifyInReleaseRejectsWeakHash(t *testing.T) {
	fake := readFakeKey(t)
	text := releaseText("stable", "stable")
	for _, c := range []struct {
		hash crypto.Hash
		ok   bool
	}{
		{crypto.SHA1, false},
		{crypto.SHA224, false},
		{crypto.SHA256, true},
		{crypto.SHA512, true},
	} {
		signed := clearsignWithHash(t, fake, text, c.hash, recordedNow)
		block, _ := clearsign.Decode(signed)
		if block == nil {
			t.Fatalf("%v: built message does not decode", c.hash)
		}
		var sigs bytes.Buffer
		if _, err := sigs.ReadFrom(block.ArmoredSignature.Body); err != nil {
			t.Fatal(err)
		}
		p, err := packet.Read(&sigs)
		if err != nil {
			t.Fatal(err)
		}
		if got := p.(*packet.Signature).Hash; got != c.hash {
			t.Fatalf("signed with %v, want %v", got, c.hash)
		}
		_, err = verifyInRelease(signed, fakePublicKeyring(t), recordedNow)
		if c.ok && err != nil {
			t.Errorf("%v signature: %v", c.hash, err)
		}
		if !c.ok && !errors.Is(err, ErrNoValidSignature) {
			t.Errorf("%v signature: err = %v, want ErrNoValidSignature", c.hash, err)
		}
	}
}
