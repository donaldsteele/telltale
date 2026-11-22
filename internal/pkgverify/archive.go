// Package pkgverify finds what Debian and Ubuntu actually shipped for an
// installed package without trusting the examined machine: it reads the
// official archives' signed indexes, checks them with archive keys built into
// telltale, and follows the hash chain to each .deb's SHA-256.
package pkgverify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"

	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/pkgverify/keys"
)

// Where a DebRef's hash came from, strongest first.
const (
	// SourceArchive: a signed InRelease verified with a built-in key, then
	// the hash chain to the .deb (the current archive or a snapshot of it).
	SourceArchive = "archive"
	// SourceSnapshot: snapshot.debian.org's file API over HTTPS, which
	// publishes only SHA-1. Lower trust than the signed chain.
	SourceSnapshot = "snapshot"
	// SourceLaunchpad: Launchpad's API over HTTPS. Lower trust than the
	// signed chain.
	SourceLaunchpad = "launchpad"
)

// PkgKey identifies one binary package build as dpkg records it.
// Arch is "all" for architecture-independent packages.
type PkgKey struct {
	Name, Version, Arch string
}

// DebRef says where to download a .deb and what it must hash to.
type DebRef struct {
	URL    string
	SHA256 string
	Size   int64
	Source string // SourceArchive, SourceSnapshot or SourceLaunchpad
}

// Archive is one official package archive and the keys that sign it.
type Archive struct {
	BaseURL    string
	Suites     []string
	Components []string
	Keyring    openpgp.EntityList
	Client     *http.Client
	// Cache is a directory for downloaded indexes; empty means no cache.
	// Cached files are verified again every time they are used.
	Cache string
	// Now is the clock for key expiry and Valid-Until; nil means time.Now.
	// Verify and WriteBundle use it only when no index they download gives
	// a signed date (see signedClock).
	Now func() time.Time
	// Historical marks a snapshot of the archive at a past moment, whose
	// Valid-Until has passed by design. Signatures are still checked.
	Historical bool

	// memo, when set, keeps each suite's InRelease and verified Release for
	// one run, so it is fetched once however many indexes are read.
	memo *releaseMemo
	// clock, when set and once it holds a time, replaces Now: see
	// signedClock.
	clock *signedClock
}

type releaseMemo struct {
	mu sync.Mutex
	m  map[string]*memoRelease
}

type memoRelease struct {
	once sync.Once
	rel  *release
	err  error

	fetch    sync.Once
	raw      []byte
	fetchErr error
}

func (m *releaseMemo) entry(suite string) *memoRelease {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.m == nil {
		m.m = map[string]*memoRelease{}
	}
	e := m.m[suite]
	if e == nil {
		e = &memoRelease{}
		m.m[suite] = e
	}
	return e
}

// signedClock is the time one run's signed indexes vouch for: the newest
// Date among the InRelease files it downloaded whose signature is by a
// built-in key. The examined machine's clock is root's to set, so it must not
// decide whether an index has expired or a signature is from the future;
// a signed Date can only be as late as the archive really signed one.
type signedClock struct {
	mu sync.Mutex
	t  time.Time
}

// observe records a signed date.
func (c *signedClock) observe(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if t.After(c.t) {
		c.t = t
	}
}

// get returns the newest signed date, if there is one.
func (c *signedClock) get() (time.Time, bool) {
	if c == nil {
		return time.Time{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t, !c.t.IsZero()
}

// signatureSlack is how much later than the newest signed Date a signature
// may be dated: a Release is signed moments after its Date is written.
const signatureSlack = 24 * time.Hour

var (
	// ErrMalformedInRelease means the InRelease file is not one clearsigned
	// message and nothing else.
	ErrMalformedInRelease = errors.New("malformed InRelease")
	// ErrNoValidSignature means no signature on the InRelease comes from a
	// built-in key that is valid now.
	ErrNoValidSignature = errors.New("InRelease is not signed by a valid built-in archive key")
	// ErrBadSignature means a signature by a built-in key does not match the
	// signed text, or the key is revoked: evidence of tampering.
	ErrBadSignature = errors.New("InRelease signature by a built-in archive key does not verify")
	// ErrExpiredIndex means the index is past its Valid-Until, or its
	// Valid-Until cannot be read.
	ErrExpiredIndex = errors.New("InRelease is past its Valid-Until")
	// ErrHashMismatch means downloaded data does not match the size or hash
	// that the trusted source gave for it.
	ErrHashMismatch = errors.New("hash mismatch")
	// ErrNotFound means the package version is not known to the source.
	ErrNotFound = errors.New("not found")
	// ErrWrongSuite means a validly signed index is for another suite or
	// pocket than the one asked for, or the archive does not carry the suite.
	ErrWrongSuite = errors.New("index is for another suite")
	// ErrNoSuchIndex means a suite's signed Release lists no Packages index
	// for the component and architecture asked for.
	ErrNoSuchIndex = errors.New("no such index")
)

var (
	keyringsOnce             sync.Once
	debianKR, ubuntuKR       openpgp.EntityList
	debianKRErr, ubuntuKRErr error
)

func loadKeyrings() {
	debianKR, debianKRErr = openpgp.ReadKeyRing(bytes.NewReader(keys.Debian))
	ubuntuKR, ubuntuKRErr = openpgp.ReadKeyRing(bytes.NewReader(keys.Ubuntu))
}

// DebianKeyring returns the built-in Debian archive keys.
func DebianKeyring() (openpgp.EntityList, error) {
	keyringsOnce.Do(loadKeyrings)
	if debianKRErr != nil {
		return nil, fmt.Errorf("built-in Debian keyring: %w", debianKRErr)
	}
	return debianKR, nil
}

// UbuntuKeyring returns the built-in Ubuntu archive keys.
func UbuntuKeyring() (openpgp.EntityList, error) {
	keyringsOnce.Do(loadKeyrings)
	if ubuntuKRErr != nil {
		return nil, fmt.Errorf("built-in Ubuntu keyring: %w", ubuntuKRErr)
	}
	return ubuntuKR, nil
}

// codenames maps OSID and VERSION_ID to the codename of each release that
// package verification supports.
var codenames = map[string]map[string]string{
	"debian": {"12": "bookworm", "13": "trixie"},
	"ubuntu": {"22.04": "jammy", "24.04": "noble"},
}

// Codename returns the release codename for a supported host.
func Codename(h model.Host) (string, error) {
	if cn, ok := codenames[h.OSID][h.OSVersionID]; ok {
		return cn, nil
	}
	return "", fmt.Errorf("release not supported for package verification: %q %q", h.OSID, h.OSVersionID)
}

// ArchiveFor returns the official archives for the host's release: the
// release, -updates and -security suites, plus -backports when the host's
// APT sources enable it. The host's configured mirrors are never used; srcs
// only says which optional suites to add.
func ArchiveFor(h model.Host, srcs []model.AptSource, cacheDir string) ([]*Archive, error) {
	cn, err := Codename(h)
	if err != nil {
		return nil, err
	}
	if h.Arch == "" {
		return nil, fmt.Errorf("host architecture unknown")
	}
	suites := []string{cn, cn + "-updates"}
	if slices.ContainsFunc(srcs, func(s model.AptSource) bool { return slices.Contains(s.Suites, cn+"-backports") }) {
		suites = append(suites, cn+"-backports")
	}
	security := cn + "-security"

	debian := h.OSID == "debian"
	var kr openpgp.EntityList
	components := []string{"main", "restricted", "universe", "multiverse"}
	if debian {
		kr, err = DebianKeyring()
		components = []string{"main", "contrib", "non-free", "non-free-firmware"}
	} else {
		kr, err = UbuntuKeyring()
	}
	if err != nil {
		return nil, err
	}
	mk := func(base string, suites []string) *Archive {
		return &Archive{BaseURL: base, Suites: suites, Components: components, Keyring: kr, Client: defaultClient, Cache: cacheDir}
	}
	switch {
	case debian:
		return []*Archive{
			mk("https://deb.debian.org/debian", suites),
			mk("https://deb.debian.org/debian-security", []string{security}),
		}, nil
	case h.Arch == "amd64" || h.Arch == "i386":
		return []*Archive{
			mk("http://archive.ubuntu.com/ubuntu", suites),
			mk("http://security.ubuntu.com/ubuntu", []string{security}),
		}, nil
	default: // every other Ubuntu architecture lives on the ports archive
		return []*Archive{mk("http://ports.ubuntu.com/ubuntu-ports", append(suites, security))}, nil
	}
}

// defaultClient bounds every request and refuses redirects from HTTPS to
// plain HTTP, so an HTTPS trust anchor cannot be downgraded.
var defaultClient = &http.Client{
	Timeout: 15 * time.Minute,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("too many redirects")
		}
		if via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
			return fmt.Errorf("refusing redirect from HTTPS to %s", req.URL.Redacted())
		}
		return nil
	},
}

// now returns the time to check indexes against: the run's signed date
// when it has one (signed is then true), else the archive's clock.
func (a *Archive) now() (t time.Time, signed bool) {
	if t, ok := a.clock.get(); ok {
		return t, true
	}
	if a.Now != nil {
		return a.Now(), false
	}
	return time.Now(), false
}

func (a *Archive) client() *http.Client {
	if a.Client != nil {
		return a.Client
	}
	return defaultClient
}

func (a *Archive) base() string { return strings.TrimRight(a.BaseURL, "/") }

var (
	// errHTTPNotFound marks a 404 or 410 answer.
	errHTTPNotFound = errors.New("HTTP not found")
	// errTooLarge marks an answer over the size limit.
	errTooLarge = errors.New("answer too large")
)

// httpOpen issues a GET and returns the body of a 200 answer.
func httpOpen(ctx context.Context, c *http.Client, url string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "telltale")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return resp.Body, nil
	case http.StatusNotFound, http.StatusGone:
		resp.Body.Close()
		return nil, fmt.Errorf("%s: %w", url, errHTTPNotFound)
	default:
		resp.Body.Close()
		return nil, fmt.Errorf("%s: HTTP %s", url, resp.Status)
	}
}

// httpGet fetches url, refusing answers larger than max bytes.
func httpGet(ctx context.Context, c *http.Client, url string, max int64) ([]byte, error) {
	body, err := httpOpen(ctx, c, url)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	b, err := io.ReadAll(io.LimitReader(body, max+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", url, err)
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s: %w: larger than %d bytes", url, errTooLarge, max)
	}
	return b, nil
}

func hashHex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// cachePath returns where name lives in the cache, or "" without a cache.
func (a *Archive) cachePath(name string) string {
	if a.Cache == "" {
		return ""
	}
	return filepath.Join(a.Cache, name)
}

// readCache returns a cached file no larger than max, or nil.
func readCache(path string, max int64) []byte {
	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(b)) > max {
		return nil
	}
	return b
}

// writeCache stores b at path atomically. Failures only cost a later
// download, so they are ignored.
func writeCache(path string, b []byte) {
	if path == "" {
		return
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return
	}
	_, werr := tmp.Write(b)
	cerr := tmp.Close()
	if werr != nil || cerr != nil || os.Rename(tmp.Name(), path) != nil {
		os.Remove(tmp.Name())
	}
}
