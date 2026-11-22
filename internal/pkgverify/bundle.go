package pkgverify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/donaldsteele/telltale/internal/model"
)

// A reference bundle lets an isolated machine be verified properly. On a
// machine with network access, WriteBundle runs the same lookups Verify would
// for the isolated machine's collection and records every answer it used: the
// signed InRelease files, the Packages indexes, the snapshot services' API
// answers and the .debs. bundle.json maps each URL to its file. Verify with
// RefsDir replays those answers instead of using the network, so every
// signature and hash is checked again with the built-in keys, and a bundle
// cannot be forged without them. bundle.json itself is not trusted: it only
// says where to find what the signed chain then has to vouch for.

const (
	bundleManifestName = "bundle.json"
	bundleFilesDir     = "files"
	bundleSchema       = 1
	maxManifestSize    = 64 << 20
	maxBundleFiles     = 200_000
)

// BundleManifest is bundle.json.
type BundleManifest struct {
	Schema      int                 `json:"schema"`
	Created     time.Time           `json:"created"`
	Host        BundleHost          `json:"host"`
	Full        bool                `json:"full"`
	Files       []BundleFile        `json:"files"`
	Packages    []BundlePackage     `json:"packages"`
	Unavailable []BundleUnavailable `json:"unavailable,omitempty"`
	Errors      []string            `json:"errors,omitempty"`
}

// BundleHost is the release the bundle was built for.
type BundleHost struct {
	OSID        string `json:"os_id"`
	OSVersionID string `json:"os_version_id"`
	Arch        string `json:"arch"`
}

// BundleFile maps one URL to a file in the bundle, or to the URL it
// redirected to.
type BundleFile struct {
	URL      string `json:"url"`
	Name     string `json:"name,omitempty"`
	Redirect string `json:"redirect,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
	Size     int64  `json:"size,omitempty"`
}

// BundlePackage is a .deb the bundle holds.
type BundlePackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
}

// BundleUnavailable is a package the bundle could not include, and why.
type BundleUnavailable struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch"`
	Reason  string `json:"reason"`
}

// WriteBundle builds a reference bundle in dir (which must be empty or not
// exist) holding what Verify needs to check the collection's packages with
// the same Options: the signed indexes and the .debs. Packages it cannot
// include are listed in bundle.json with the reason. Only signed chains go
// into a bundle; versions that only sources trusted through HTTPS alone have
// are left out. It returns an error wrapping ErrBadSignature or
// ErrHashMismatch, after writing bundle.json, when it met evidence of
// tampering.
func WriteBundle(ctx context.Context, c *model.Collection, dir string, opt Options) error {
	if c == nil {
		return errors.New("no collection to build a bundle for")
	}
	if err := checkBundleDir(dir); err != nil {
		return err
	}
	opt.RefsDir, opt.Offline = "", false
	res := &Result{Mode: ModeArchive}
	s := newSession(c, opt, res)
	s.bw = &bundleWriter{dir: dir, files: map[string]BundleFile{}}
	plans := s.plan()
	if len(plans) > 0 {
		if err := s.setup(); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, bundleFilesDir), 0o700); err != nil {
		return err
	}
	if len(plans) > 0 {
		s.loadIndexes(ctx, plans)
		s.run(ctx, plans)
	}
	s.finish()
	m := s.bw.manifest()
	m.Created = time.Now().UTC()
	m.Host = BundleHost{OSID: c.Host.OSID, OSVersionID: c.Host.OSVersionID, Arch: c.Host.Arch}
	m.Full = opt.Full
	m.Errors = res.Errors
	if err := writeManifest(dir, m); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.tamperErr != nil {
		return fmt.Errorf("evidence of tampering while building the bundle: %w", s.tamperErr)
	}
	return nil
}

// checkBundleDir accepts a directory that does not exist yet or is empty.
func checkBundleDir(dir string) error {
	entries, err := os.ReadDir(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil
	case err != nil:
		return err
	case len(entries) > 0:
		return fmt.Errorf("%s is not empty; give a new or empty directory", dir)
	}
	return nil
}

// bundleDeb downloads a package's .deb into the bundle, checking it.
func (s *session) bundleDeb(ctx context.Context, p *model.Package, ref DebRef) {
	if ref.Source != SourceArchive {
		s.unverifiable(p, "only a source trusted through HTTPS alone has this version, and a bundle carries only signed indexes")
		return
	}
	if err := downloadDeb(ctx, s.client, ref, io.Discard); err != nil {
		if tampered(err) {
			s.problem(err)
		} else {
			s.downloadFailed(err)
		}
		s.unverifiable(p, "could not download the package: "+err.Error())
		return
	}
	s.bw.mu.Lock()
	s.bw.pkgs = append(s.bw.pkgs, BundlePackage{Name: p.Name, Version: p.Version, Arch: p.Arch, URL: ref.URL, SHA256: ref.SHA256})
	s.bw.mu.Unlock()
}

// bundleWriter records HTTP answers into a bundle directory.
type bundleWriter struct {
	dir         string
	mu          sync.Mutex
	files       map[string]BundleFile // by URL key
	pkgs        []BundlePackage
	unavailable []BundleUnavailable
}

func (bw *bundleWriter) addUnavailable(p *model.Package, reason string) {
	bw.mu.Lock()
	defer bw.mu.Unlock()
	bw.unavailable = append(bw.unavailable, BundleUnavailable{Name: p.Name, Version: p.Version, Arch: p.Arch, Reason: reason})
}

func (bw *bundleWriter) lookup(key string) (BundleFile, bool) {
	bw.mu.Lock()
	defer bw.mu.Unlock()
	f, ok := bw.files[key]
	return f, ok
}

func (bw *bundleWriter) record(f BundleFile) {
	bw.mu.Lock()
	defer bw.mu.Unlock()
	if _, dup := bw.files[f.URL]; !dup {
		bw.files[f.URL] = f
	}
}

func (bw *bundleWriter) manifest() *BundleManifest {
	bw.mu.Lock()
	defer bw.mu.Unlock()
	m := &BundleManifest{Schema: bundleSchema, Files: []BundleFile{}, Packages: bw.pkgs, Unavailable: bw.unavailable}
	for _, f := range bw.files {
		m.Files = append(m.Files, f)
	}
	sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].URL < m.Files[j].URL })
	sort.Slice(m.Packages, func(i, j int) bool {
		return pkgLess(m.Packages[i].Name, m.Packages[i].Arch, m.Packages[j].Name, m.Packages[j].Arch)
	})
	sort.Slice(m.Unavailable, func(i, j int) bool {
		return pkgLess(m.Unavailable[i].Name, m.Unavailable[i].Arch, m.Unavailable[j].Name, m.Unavailable[j].Arch)
	})
	if m.Packages == nil {
		m.Packages = []BundlePackage{}
	}
	return m
}

func pkgLess(n1, a1, n2, a2 string) bool {
	if n1 != n2 {
		return n1 < n2
	}
	return a1 < a2
}

func writeManifest(dir string, m *BundleManifest) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".bundle-*.json")
	if err != nil {
		return err
	}
	_, werr := tmp.Write(append(b, '\n'))
	cerr := tmp.Close()
	if werr == nil && cerr == nil {
		werr = os.Rename(tmp.Name(), filepath.Join(dir, bundleManifestName))
	}
	if werr != nil || cerr != nil {
		os.Remove(tmp.Name())
		return errors.Join(werr, cerr)
	}
	return nil
}

// client returns a client that records into the bundle what base fetches,
// and answers repeated requests from the recording so the bundle holds one
// consistent answer per URL.
func (bw *bundleWriter) client(base *http.Client) *http.Client {
	if base == nil {
		base = defaultClient
	}
	rt := base.Transport
	if rt == nil {
		rt = http.DefaultTransport
	}
	cr := base.CheckRedirect
	if cr == nil {
		cr = defaultClient.CheckRedirect
	}
	return &http.Client{Transport: &recordingTransport{bw: bw, base: rt}, CheckRedirect: cr, Timeout: base.Timeout}
}

type recordingTransport struct {
	bw   *bundleWriter
	base http.RoundTripper
}

func (t *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	key := urlKey(req.URL)
	if f, ok := t.bw.lookup(key); ok {
		return serveBundleFile(req, f, func(name string) (*os.File, error) {
			return os.Open(filepath.Join(t.bw.dir, filepath.FromSlash(name)))
		})
	}
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	switch resp.StatusCode {
	case http.StatusOK:
		tmp, err := os.CreateTemp(filepath.Join(t.bw.dir, bundleFilesDir), ".partial-*")
		if err != nil {
			resp.Body.Close()
			return nil, err
		}
		resp.Body = &recordingBody{rc: resp.Body, tmp: tmp, h: sha256.New(), bw: t.bw, key: key, u: req.URL}
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		if loc, err := resp.Location(); err == nil && (loc.Scheme == "http" || loc.Scheme == "https") {
			t.bw.record(BundleFile{URL: key, Redirect: urlKey(loc)})
		}
	}
	return resp, nil
}

// recordingBody copies a response body into the bundle and records it once
// it has been read to the end; a body read only in part is discarded.
type recordingBody struct {
	rc     io.ReadCloser
	tmp    *os.File
	h      hash.Hash
	n      int64
	bw     *bundleWriter
	key    string
	u      *url.URL
	done   bool
	failed bool
}

func (b *recordingBody) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	if n > 0 && !b.failed && !b.done {
		if _, werr := b.tmp.Write(p[:n]); werr != nil {
			b.failed = true
		}
		b.h.Write(p[:n])
		b.n += int64(n)
	}
	if err == io.EOF && !b.done && !b.failed {
		b.done = true
		b.keep()
	}
	return n, err
}

func (b *recordingBody) keep() {
	name := bundleFilesDir + "/" + bundleFileName(b.key, b.u)
	if err := b.tmp.Close(); err != nil {
		os.Remove(b.tmp.Name())
		return
	}
	if err := os.Rename(b.tmp.Name(), filepath.Join(b.bw.dir, filepath.FromSlash(name))); err != nil {
		os.Remove(b.tmp.Name())
		return
	}
	b.bw.record(BundleFile{URL: b.key, Name: name, SHA256: hex.EncodeToString(b.h.Sum(nil)), Size: b.n})
}

func (b *recordingBody) Close() error {
	err := b.rc.Close()
	if !b.done {
		b.done = true
		b.tmp.Close()
		os.Remove(b.tmp.Name())
	}
	return err
}

// bundleFileName names a recorded URL: a hash of the URL, for uniqueness,
// and the URL's last path element, for people looking at the bundle.
func bundleFileName(key string, u *url.URL) string {
	sum := sha256.Sum256([]byte(key))
	base := []byte(path.Base(u.Path))
	for i, c := range base {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("._+~-", c) >= 0) {
			base[i] = '_'
		}
	}
	if len(base) > 100 {
		base = base[len(base)-100:]
	}
	if len(base) == 0 || base[0] == '.' {
		base = append([]byte("f"), base...)
	}
	return hex.EncodeToString(sum[:8]) + "-" + string(base)
}

// urlKey is the form of a URL used to look it up in a bundle.
func urlKey(u *url.URL) string {
	c := *u
	c.Fragment, c.RawFragment, c.User = "", "", nil
	c.Scheme, c.Host = strings.ToLower(c.Scheme), strings.ToLower(c.Host)
	return c.String()
}

// serveBundleFile answers req from a bundle entry.
func serveBundleFile(req *http.Request, f BundleFile, open func(string) (*os.File, error)) (*http.Response, error) {
	if f.Redirect != "" {
		resp := bundleResponse(req, http.StatusFound, io.NopCloser(strings.NewReader("")), 0)
		resp.Header.Set("Location", f.Redirect)
		return resp, nil
	}
	fh, err := open(f.Name)
	if err != nil {
		return nil, fmt.Errorf("reference bundle file %s: %w", f.Name, err)
	}
	st, err := fh.Stat()
	if err != nil || !st.Mode().IsRegular() {
		fh.Close()
		return nil, fmt.Errorf("reference bundle file %s is not a regular file", f.Name)
	}
	return bundleResponse(req, http.StatusOK, fh, st.Size()), nil
}

func bundleResponse(req *http.Request, code int, body io.ReadCloser, size int64) *http.Response {
	return &http.Response{
		Status: fmt.Sprintf("%d %s", code, http.StatusText(code)), StatusCode: code,
		Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{}, Body: body, ContentLength: size, Request: req,
	}
}

// bundleReader answers requests from a bundle directory, confined to it.
type bundleReader struct {
	root        *os.Root
	files       map[string]BundleFile
	manifest    *BundleManifest
	unavailable map[PkgKey]string
}

func openBundle(dir string) (*bundleReader, error) {
	m, err := ReadBundleManifest(dir)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	b := &bundleReader{root: root, files: map[string]BundleFile{}, manifest: m, unavailable: map[PkgKey]string{}}
	for _, f := range m.Files {
		b.files[f.URL] = f
	}
	for _, u := range m.Unavailable {
		b.unavailable[PkgKey{u.Name, u.Version, u.Arch}] = u.Reason
	}
	return b, nil
}

func (b *bundleReader) close() { b.root.Close() }

// client returns a client that never touches the network.
func (b *bundleReader) client() *http.Client {
	return &http.Client{Transport: replayTransport{b}, CheckRedirect: defaultClient.CheckRedirect}
}

type replayTransport struct{ b *bundleReader }

func (t replayTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		req.Body.Close()
	}
	if req.Method != http.MethodGet {
		return nil, fmt.Errorf("reference bundle: %s requests are not replayed", req.Method)
	}
	f, ok := t.b.files[urlKey(req.URL)]
	if !ok {
		return bundleResponse(req, http.StatusNotFound, io.NopCloser(strings.NewReader("not in the reference bundle")), -1), nil
	}
	// os.Root refuses names, and symlinks, that lead out of the bundle.
	return serveBundleFile(req, f, func(name string) (*os.File, error) { return openRegular(t.b.root, name) })
}

// openRegular opens a regular file below root without blocking on a FIFO
// or device planted in its place.
func openRegular(root *os.Root, name string) (*os.File, error) {
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("%s is not a regular file", name)
	}
	return f, nil
}

// ReadBundleManifest reads and checks a bundle's bundle.json: known fields
// only, http(s) URLs, and file names that stay inside the bundle.
func ReadBundleManifest(dir string) (*BundleManifest, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	f, err := openRegular(root, bundleManifestName)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxManifestSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxManifestSize {
		return nil, fmt.Errorf("%s is larger than %d bytes", bundleManifestName, maxManifestSize)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var m BundleManifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%s: %w", bundleManifestName, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%s: data after the manifest", bundleManifestName)
	}
	if m.Schema != bundleSchema {
		return nil, fmt.Errorf("%s: schema %d, this telltale reads %d", bundleManifestName, m.Schema, bundleSchema)
	}
	if len(m.Files) > maxBundleFiles {
		return nil, fmt.Errorf("%s: more than %d files", bundleManifestName, maxBundleFiles)
	}
	seen := map[string]bool{}
	for _, f := range m.Files {
		u, err := url.Parse(f.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || urlKey(u) != f.URL {
			return nil, fmt.Errorf("%s: unusable URL %q", bundleManifestName, f.URL)
		}
		if seen[f.URL] {
			return nil, fmt.Errorf("%s: %q listed twice", bundleManifestName, f.URL)
		}
		seen[f.URL] = true
		switch {
		case f.Redirect == "" && safeBundleName(f.Name):
		case f.Redirect != "" && f.Name == "":
			r, err := url.Parse(f.Redirect)
			if err != nil || (r.Scheme != "http" && r.Scheme != "https") || r.Host == "" {
				return nil, fmt.Errorf("%s: unusable redirect %q", bundleManifestName, f.Redirect)
			}
		default:
			return nil, fmt.Errorf("%s: unsafe file name %q for %s", bundleManifestName, f.Name, f.URL)
		}
	}
	return &m, nil
}

// safeBundleName accepts a clean relative path that stays inside the bundle.
func safeBundleName(n string) bool {
	if n == "" || len(n) > 512 || strings.ContainsAny(n, "\\\x00") || strings.HasPrefix(n, "/") || path.Clean(n) != n {
		return false
	}
	for _, seg := range strings.Split(n, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return filepath.IsLocal(n)
}
