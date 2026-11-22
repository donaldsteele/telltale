package pkgverify

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"

	"github.com/donaldsteele/telltale/internal/model"
)

// Modes of a Result: how the expected file contents were obtained.
const (
	ModeArchive      = "archive"       // the official archives, over the network
	ModeRefs         = "refs"          // a reference bundle built on another machine
	ModeOfflineLocal = "offline-local" // the machine's own package checksums
)

// Verdict sources beyond the DebRef ones (SourceArchive, SourceSnapshot,
// SourceLaunchpad).
const (
	// SourceRefs: a reference bundle, re-verified with the built-in keys.
	SourceRefs = "refs"
	// SourceOfflineLocal: the machine's own md5sums, which root can edit.
	SourceOfflineLocal = "offline-local"
)

const (
	// OfflineWarning heads Result.Errors in offline-local mode.
	OfflineWarning = "Compared against the machine's own package checksums, which root can edit."
	// ReasonPro marks files of Ubuntu Pro (ESM) packages. Verifying them
	// needs a Pro token, which v1 does not support.
	ReasonPro = "Ubuntu Pro package: verification with a Pro token is planned"
	// ReasonNotOfficial starts the reason for packages found in no official
	// archive or snapshot of one.
	ReasonNotOfficial = "package not found in the official archive"
)

// Options controls Verify and WriteBundle.
type Options struct {
	// Full checks every package-owned file, not only the security-relevant
	// ones InScope selects.
	Full bool
	// Offline compares against the machine's own package checksums
	// (Package.LocalMD5) instead of the archives. Ignored with RefsDir.
	Offline bool
	// RefsDir is a reference bundle written by WriteBundle. Everything in
	// it is verified again with the archive keys; nothing else is fetched.
	RefsDir string
	// CacheDir keeps downloaded indexes and per-package file tables. It
	// must not be on the machine being examined.
	CacheDir string
	// OnlyPaths, when not nil, limits the check to these collected paths
	// (with a snapshot: the package-owned files that changed), regardless
	// of Full and InScope.
	OnlyPaths map[string]bool
	// ExtraKeys are owner-supplied keys for third-party repositories. A
	// third-party source is consulted only when its signed index verifies
	// with one of them.
	ExtraKeys openpgp.EntityList
	// Root is where the examined filesystem is mounted, for offline-local
	// mode, which reads the files to compute their MD5. "" means "/".
	Root string

	// Archives replaces the official archives for the host (tests, or a
	// mirror the owner controls); their keyrings are used as given.
	Archives []*Archive
	// Old finds versions gone from the current archive. Nil means the real
	// snapshot services, unless Archives is set, in which case none is used.
	Old *OldFinder
	// Client downloads .debs; nil means the default client.
	Client *http.Client
	// Now is the clock for key expiry where an Archive or OldFinder sets
	// none; nil means time.Now.
	Now func() time.Time
}

// Result is the outcome of verifying a collection's package-owned files.
type Result struct {
	Mode         string         `json:"mode"`
	Verified     []FileVerdict  `json:"verified,omitempty"`
	Mismatch     []FileVerdict  `json:"mismatch,omitempty"`
	Unverifiable []FileVerdict  `json:"unverifiable,omitempty"`
	Conffiles    []ConffileDiff `json:"conffiles,omitempty"`
	SourcesUsed  []string       `json:"sources_used,omitempty"`
	// Errors lists problems, most serious first: the offline warning, then
	// evidence of tampering ("BAD SIGNATURE", "HASH MISMATCH"), then
	// sources that could not be read.
	Errors []string `json:"errors,omitempty"`
}

// FileVerdict is the outcome for one file. Path is the collected path.
// Expected and Actual are SHA-256 hashes ("md5:<hex>" in offline-local mode).
// Source says how the expected value was obtained: archive, snapshot,
// launchpad, refs or offline-local.
type FileVerdict struct {
	Path     string `json:"path"`
	Package  string `json:"package"`
	Version  string `json:"version"`
	Expected string `json:"expected,omitempty"`
	Actual   string `json:"actual,omitempty"`
	Reason   string `json:"reason,omitempty"`
	Source   string `json:"source,omitempty"`
}

// ConffileDiff is a configuration file that differs from its package's
// default. Conffiles are expected to differ and are never a Mismatch.
// Default is the package's default text when it is at most 256 KiB; the
// on-disk text, redacted, is in the collection's persistence files.
type ConffileDiff struct {
	Path     string `json:"path"`
	Package  string `json:"package"`
	Version  string `json:"version"`
	Expected string `json:"expected"`
	Actual   string `json:"actual"`
	Default  string `json:"default,omitempty"`
	Source   string `json:"source,omitempty"`
}

// Verify checks the collection's package-owned files against the files in
// the distribution's signed packages. It never trusts the machine's own
// package checksums except in offline-local mode, which says so. Problems
// with sources never stop it: files that cannot be checked are Unverifiable
// with the reason, and Verify always returns a Result.
func Verify(ctx context.Context, c *model.Collection, opt Options) *Result {
	res := &Result{Mode: ModeArchive}
	switch {
	case opt.RefsDir != "":
		res.Mode = ModeRefs
	case opt.Offline:
		res.Mode = ModeOfflineLocal
	}
	if c == nil {
		res.Errors = []string{"no collection to verify"}
		return res
	}
	s := newSession(c, opt, res)
	defer s.finish()
	if res.Mode == ModeOfflineLocal {
		s.offline()
		return res
	}
	plans := s.plan()
	if len(plans) == 0 {
		return res
	}
	if err := s.setup(); err != nil {
		s.problem(err)
		for _, p := range plans {
			s.unverifiable(p, err.Error())
		}
		return res
	}
	s.loadIndexes(ctx, plans)
	s.run(ctx, plans)
	return res
}

// session is one Verify or WriteBundle run.
type session struct {
	c      *model.Collection
	opt    Options
	res    *Result
	files  map[string]*model.FileEntry
	owners map[string]string
	esm    bool // the machine has an Ubuntu Pro source

	archives []*Archive
	third    []thirdSource
	old      *OldFinder
	client   *http.Client
	source   string        // replaces DebRef.Source in verdicts (refs)
	bundle   *bundleReader // refs mode
	bw       *bundleWriter // WriteBundle

	// Written by loadIndexes, read-only afterwards.
	found      map[PkgKey]DebRef
	thirdFound map[PkgKey]DebRef
	idxErr     map[string]error // by architecture
	thirdURIs  []string
	trusted    map[string]bool // third-party URIs whose index verified

	mu        sync.Mutex
	warn      []string
	alerts    []string
	errs      []string
	seenMsg   map[string]bool
	sources   map[string]bool
	tamperErr error
	dlFailed  int
	dlFirst   string
}

type thirdSource struct {
	uri string
	a   *Archive
}

func newSession(c *model.Collection, opt Options, res *Result) *session {
	s := &session{
		c: c, opt: opt, res: res,
		files:      make(map[string]*model.FileEntry, len(c.Files)),
		owners:     c.Packages.Owners(),
		found:      map[PkgKey]DebRef{},
		thirdFound: map[PkgKey]DebRef{},
		idxErr:     map[string]error{},
		trusted:    map[string]bool{},
		seenMsg:    map[string]bool{},
		sources:    map[string]bool{},
	}
	for i := range c.Files {
		s.files[c.Files[i].Path] = &c.Files[i]
	}
	for _, src := range c.Packages.Sources {
		for _, u := range src.URIs {
			if esmURI(u) {
				s.esm = true
			}
		}
	}
	return s
}

type entryKind int

const (
	absent entryKind = iota
	regularFile
	otherFile // directory, symlink or special file
)

// locate finds the collected entry for a package path, trying its merged-/usr
// alias: on a merged-/usr machine /bin/su is collected as /usr/bin/su, since
// /bin is a symlink the collector does not follow. A regular file under
// either spelling wins over anything else.
func (s *session) locate(p string) (string, *model.FileEntry, entryKind) {
	e := s.files[p]
	if e != nil && isRegular(e) {
		return p, e, regularFile
	}
	a := usrAlias(p)
	var ea *model.FileEntry
	if a != "" {
		ea = s.files[a]
	}
	if ea != nil && isRegular(ea) {
		return a, ea, regularFile
	}
	if e != nil {
		return p, e, otherFile
	}
	if ea != nil {
		return a, ea, otherFile
	}
	return "", nil, absent
}

// isRegular accepts regular files and entries the collector could not stat,
// which are then reported as not hashed.
func isRegular(e *model.FileEntry) bool {
	return e.Type == "file" || (e.Type == "" && e.Err != "")
}

func diskMode(e *model.FileEntry, kind entryKind) uint32 {
	if kind == regularFile {
		return e.Mode
	}
	return 0
}

// filesInstalled reports whether a dpkg status means the package's files are
// on disk as its Version.
func filesInstalled(status string) bool {
	f := strings.Fields(status)
	if len(f) == 0 {
		return true
	}
	switch f[len(f)-1] {
	case "not-installed", "config-files", "half-installed":
		return false
	}
	return true
}

// plan returns the packages that own at least one file to check.
func (s *session) plan() []*model.Package {
	var out []*model.Package
	for i := range s.c.Packages.Installed {
		p := &s.c.Packages.Installed[i]
		if !filesInstalled(p.Status) {
			continue
		}
		for _, f := range p.Files {
			cp, e, kind := s.locate(f)
			if kind == regularFile || (kind == otherFile && e.Type == "symlink") {
				if s.opt.candidate(cp, f, diskMode(e, kind), nil) {
					out = append(out, p)
					break
				}
			}
		}
	}
	return out
}

// setup chooses the archives, the snapshot finder and the download client
// for the run's mode.
func (s *session) setup() error {
	refs := s.res.Mode == ModeRefs && s.bw == nil
	cache := s.opt.CacheDir
	if refs || s.bw != nil {
		cache = "" // everything must come from the bundle, or go into it
	}
	archives := s.opt.Archives
	if archives == nil {
		var err error
		if archives, err = ArchiveFor(s.c.Host, s.c.Packages.Sources, cache); err != nil {
			return err
		}
	}
	old := s.opt.Old
	if old == nil && s.opt.Archives == nil {
		o, err := NewOldFinder(cache)
		if err != nil {
			return err
		}
		old = o
	}

	var wrap func(*http.Client) *http.Client
	switch {
	case s.bw != nil:
		wrap = s.bw.client
	case refs:
		b, err := openBundle(s.opt.RefsDir)
		if err != nil {
			return fmt.Errorf("reference bundle rejected: %w", err)
		}
		s.bundle = b
		rc := b.client()
		wrap = func(*http.Client) *http.Client { return rc }
		s.source = SourceRefs
		s.addSource("reference bundle " + s.opt.RefsDir)
		if h, mh := s.c.Host, b.manifest.Host; h.OSID != mh.OSID || h.OSVersionID != mh.OSVersionID || h.Arch != mh.Arch {
			s.problem(fmt.Errorf("the reference bundle was built for %s %s (%s), this machine is %s %s (%s)", mh.OSID, mh.OSVersionID, mh.Arch, h.OSID, h.OSVersionID, h.Arch))
		}
	}
	for _, a := range archives {
		c := *a
		if wrap != nil {
			c.Client, c.Cache = wrap(a.client()), ""
		}
		if refs {
			// A bundle is a record of signed indexes at one moment, like
			// a snapshot archive: signatures are checked, Valid-Until is
			// not.
			c.Historical = true
		}
		if c.Now == nil {
			c.Now = s.opt.Now
		}
		s.archives = append(s.archives, &c)
	}
	if old != nil {
		o := *old
		if wrap != nil {
			o.Client, o.Cache, o.SignedOnly = wrap(old.client()), "", true
		}
		if o.Now == nil {
			o.Now = s.opt.Now
		}
		s.old = &o
	}
	s.client = s.opt.Client
	if s.client == nil {
		s.client = defaultClient
	}
	if wrap != nil {
		s.client = wrap(s.client)
	}
	s.setupThirdParty(wrap, cache, refs)
	return nil
}

var safeSuite = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~-]*$`)

// setupThirdParty lists the machine's non-official APT sources and, when
// the owner supplied keys, prepares to read their signed indexes. Without
// keys no third-party source is ever contacted.
func (s *session) setupThirdParty(wrap func(*http.Client) *http.Client, cache string, refs bool) {
	seen := map[string]bool{}
	for _, src := range s.c.Packages.Sources {
		if len(src.Types) > 0 && !slices.Contains(src.Types, "deb") {
			continue
		}
		for _, uri := range src.URIs {
			if officialURI(uri) || esmURI(uri) {
				continue
			}
			if !seen[uri] {
				seen[uri] = true
				s.thirdURIs = append(s.thirdURIs, uri)
			}
			if len(s.opt.ExtraKeys) == 0 {
				continue
			}
			u, err := url.Parse(uri)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				continue
			}
			var suites, comps []string
			for _, su := range src.Suites {
				if safeSuite.MatchString(su) {
					suites = append(suites, su)
				}
			}
			for _, co := range src.Components {
				if componentName.MatchString(co) {
					comps = append(comps, co)
				}
			}
			if len(suites) == 0 || len(comps) == 0 {
				continue // flat repositories are not supported
			}
			client := s.opt.Client
			if client == nil {
				client = defaultClient
			}
			if wrap != nil {
				client = wrap(client)
			}
			s.third = append(s.third, thirdSource{uri: uri, a: &Archive{
				BaseURL: strings.TrimRight(uri, "/"), Suites: suites, Components: comps,
				Keyring: s.opt.ExtraKeys, Client: client, Cache: cache, Now: s.opt.Now, Historical: refs,
			}})
		}
	}
	sort.Strings(s.thirdURIs)
}

// officialURI reports whether an APT source URI is an official Debian or
// Ubuntu archive host. Mirrors elsewhere count as third-party; telltale never
// reads them anyway.
func officialURI(uri string) bool {
	u, err := url.Parse(uri)
	if err != nil {
		return false
	}
	h := strings.ToLower(u.Hostname())
	for _, d := range []string{"debian.org", "archive.ubuntu.com", "security.ubuntu.com", "ports.ubuntu.com"} {
		if h == d || strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	return false
}

func esmURI(uri string) bool {
	u, err := url.Parse(uri)
	return err == nil && strings.EqualFold(u.Hostname(), "esm.ubuntu.com")
}

func (s *session) archOf(p *model.Package) string {
	if p.Arch == "" || p.Arch == "all" {
		return s.c.Host.Arch
	}
	return p.Arch
}

// loadIndexes reads every signed index the planned packages may be in and
// keeps only their entries.
func (s *session) loadIndexes(ctx context.Context, plans []*model.Package) {
	arches := map[string]bool{}
	want := map[[2]string]bool{}
	for _, p := range plans {
		arches[s.archOf(p)] = true
		want[[2]string{p.Name, p.Version}] = true
	}
	keep := func(idx map[PkgKey]DebRef, dst map[PkgKey]DebRef) {
		for k, ref := range idx {
			if want[[2]string{k.Name, k.Version}] {
				if _, dup := dst[k]; !dup {
					dst[k] = ref
				}
			}
		}
	}
	archList := make([]string, 0, len(arches))
	for a := range arches {
		archList = append(archList, a)
	}
	sort.Strings(archList)
	for _, arch := range archList {
		for _, a := range s.archives {
			for _, suite := range a.Suites {
				for _, comp := range a.Components {
					idx, err := a.Index(ctx, suite, comp, arch)
					switch {
					case errors.Is(err, ErrNoSuchIndex):
					case err != nil:
						if s.idxErr[arch] == nil {
							s.idxErr[arch] = err
						}
						s.problem(err)
					default:
						s.addSource(a.base() + " " + suite)
						keep(idx, s.found)
					}
				}
			}
		}
		for _, t := range s.third {
			for _, suite := range t.a.Suites {
				for _, comp := range t.a.Components {
					idx, err := t.a.Index(ctx, suite, comp, arch)
					switch {
					case errors.Is(err, ErrNoSuchIndex):
					case errors.Is(err, ErrNoValidSignature):
						// Signed by a key the owner did not supply: the
						// source is simply not trusted.
					case err != nil:
						s.problem(fmt.Errorf("third-party source: %w", err))
					default:
						s.trusted[t.uri] = true
						s.addSource(t.a.base() + " " + suite + " (owner-supplied key)")
						keep(idx, s.thirdFound)
					}
				}
			}
		}
	}
}

// run checks each planned package, a few at a time.
func (s *session) run(ctx context.Context, plans []*model.Package) {
	workers := 4
	if s.bw != nil {
		workers = 1 // a bundle records each URL once, in order
	}
	ch := make(chan *model.Package)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range ch {
				s.onePackage(ctx, p)
			}
		}()
	}
	for _, p := range plans {
		ch <- p
	}
	close(ch)
	wg.Wait()
}

func (s *session) onePackage(ctx context.Context, p *model.Package) {
	defer func() {
		if r := recover(); r != nil {
			s.unverifiable(p, fmt.Sprintf("internal error while checking the package: %v", r))
		}
	}()
	if err := ctx.Err(); err != nil {
		s.unverifiable(p, "check stopped: "+err.Error())
		return
	}
	if strings.Contains(p.Version, "+esm") {
		s.unverifiable(p, ReasonPro)
		return
	}
	arch := p.Arch
	if arch == "" {
		arch = s.c.Host.Arch
	}
	ref, ok := Lookup(s.found, p.Name, p.Version, arch)
	if !ok {
		ref, ok = Lookup(s.thirdFound, p.Name, p.Version, arch)
	}
	var oldErr error
	if !ok && s.old != nil {
		ref, oldErr = s.old.Find(ctx, PkgKey{p.Name, p.Version, arch}, s.c.Host.OSID)
		switch {
		case oldErr == nil:
			ok = true
			s.addSource(oldSource(ref))
		case tampered(oldErr):
			s.problem(oldErr)
		}
	}
	if !ok {
		s.unverifiable(p, s.notFound(p, oldErr))
		return
	}
	if s.bw != nil {
		s.bundleDeb(ctx, p, ref)
		return
	}
	table, err := s.table(ctx, ref)
	if err != nil {
		if tampered(err) {
			s.problem(err)
		} else {
			s.downloadFailed(err)
		}
		s.unverifiable(p, "could not check the package: "+s.explain(err))
		return
	}
	s.compare(p, ref, table)
}

func oldSource(ref DebRef) string {
	host := ref.URL
	if u, err := url.Parse(ref.URL); err == nil {
		host = u.Host
	}
	switch ref.Source {
	case SourceArchive:
		return host + " (signed snapshot index)"
	case SourceSnapshot:
		return host + " (file API, SHA-1 over HTTPS; lower trust than a signed index)"
	default:
		return host + " (over HTTPS; lower trust than a signed index)"
	}
}

// notFound explains why no trusted source gave a package version.
func (s *session) notFound(p *model.Package, oldErr error) string {
	if err := s.idxErr[s.archOf(p)]; err != nil {
		return "could not read the official archive index: " + s.explain(err)
	}
	if s.bundle != nil {
		if r, ok := s.bundle.unavailable[PkgKey{p.Name, p.Version, p.Arch}]; ok {
			return "not in the reference bundle: " + r
		}
		return "package not in the reference bundle"
	}
	if oldErr != nil && !errors.Is(oldErr, ErrNotFound) {
		return "not in the current archive, and the snapshot archives could not be checked: " + s.explain(oldErr)
	}
	if s.esm {
		return ReasonPro
	}
	r := ReasonNotOfficial
	if len(s.trusted) > 0 {
		r += " or the third-party sources whose keys were given"
	}
	var untrusted []string
	for _, u := range s.thirdURIs {
		if !s.trusted[u] {
			untrusted = append(untrusted, u)
		}
	}
	if len(untrusted) > 0 {
		r += "; source not trusted: " + strings.Join(untrusted, ", ")
	}
	return r
}

// table returns the file table of the .deb ref names: from the cache, keyed
// by the signed hash, or by downloading and checking the .deb.
func (s *session) table(ctx context.Context, ref DebRef) (map[string]DebFile, error) {
	if t, ok := loadTable(s.opt.CacheDir, ref.SHA256); ok {
		return t, nil
	}
	dir := ""
	if s.opt.CacheDir != "" && os.MkdirAll(s.opt.CacheDir, 0o700) == nil {
		dir = s.opt.CacheDir
	}
	f, err := os.CreateTemp(dir, ".telltale-deb-*")
	if err != nil {
		return nil, err
	}
	// Unlinked at once: nothing can replace the file by name while it is
	// checked and read.
	os.Remove(f.Name())
	defer f.Close()
	if err := downloadDeb(ctx, s.client, ref, f); err != nil {
		return nil, err
	}
	files, err := DebFiles(f, ref.Size)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ref.URL, err)
	}
	storeTable(s.opt.CacheDir, ref.SHA256, files)
	return files, nil
}

// downloadDeb writes the .deb ref names to w, checking its size and SHA-256.
func downloadDeb(ctx context.Context, c *http.Client, ref DebRef, w io.Writer) error {
	if ref.Size <= 0 || ref.Size > maxDebSize {
		return fmt.Errorf("%s: size %d is outside 1..%d bytes", ref.URL, ref.Size, int64(maxDebSize))
	}
	if !isHexLen(ref.SHA256, 64) {
		return fmt.Errorf("%s: no SHA-256 to check it against", ref.URL)
	}
	body, err := httpOpen(ctx, c, ref.URL)
	if err != nil {
		return err
	}
	defer body.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(w, h), io.LimitReader(body, ref.Size+1))
	if err != nil {
		return fmt.Errorf("%s: %w", ref.URL, err)
	}
	if n != ref.Size {
		return fmt.Errorf("%w: %s is %d bytes, the trusted source gives %d", ErrHashMismatch, ref.URL, n, ref.Size)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != strings.ToLower(ref.SHA256) {
		return fmt.Errorf("%w: %s has SHA-256 %s, the trusted source gives %s", ErrHashMismatch, ref.URL, got, ref.SHA256)
	}
	return nil
}

// compare judges a package's files against its signed .deb's table. The
// paths checked are the package's file list on the machine plus every file
// in the .deb that no other package claims, so neither adding an implant to
// the list nor removing a trojaned file from it hides anything.
func (s *session) compare(p *model.Package, ref DebRef, table map[string]DebFile) {
	src := ref.Source
	if s.source != "" {
		src = s.source
	}
	listed := make(map[string]bool, len(p.Files))
	for _, f := range p.Files {
		listed[f] = true
	}
	var extra []string
	for dp := range table {
		if listed[dp] || listed[usrAlias(dp)] {
			continue
		}
		if o := s.owners[dp]; o != "" && o != p.Name {
			continue // another package took the file over
		}
		extra = append(extra, dp)
	}
	sort.Strings(extra)

	var verified, mismatch, unverifiable []FileVerdict
	var diffs []ConffileDiff
	seen := map[string]bool{}
	for _, lp := range append(slices.Clone(p.Files), extra...) {
		cp, e, kind := s.locate(lp)
		if kind == absent {
			continue
		}
		d, inDeb := table[lp]
		if a := usrAlias(lp); !inDeb && a != "" {
			d, inDeb = table[a]
		}
		var dm *DebFile
		if inDeb {
			dm = &d
		}
		if seen[cp] || !s.opt.candidate(cp, lp, diskMode(e, kind), dm) {
			continue
		}
		seen[cp] = true
		v := FileVerdict{Path: cp, Package: p.Name, Version: p.Version, Source: src}
		switch {
		case kind == otherFile && !inDeb:
			// Not a regular file on either side.
		case kind == otherFile:
			v.Expected = d.SHA256
			v.Actual = e.Type
			if e.Type == "symlink" {
				v.Actual = "symlink to " + e.Target
			}
			v.Reason = "the signed package installs a regular file here, the machine has a " + e.Type
			mismatch = append(mismatch, v)
		case !inDeb:
			// The package ships nothing here, or a symlink or directory,
			// and no merged-/usr alias resolves to one of its regular
			// files.
			v.Actual = e.SHA256
			v.Reason = "the signed package has no regular file here, though the machine lists it as part of the package"
			mismatch = append(mismatch, v)
		case d.Conffile:
			if e.SHA256 != "" && e.SHA256 != d.SHA256 {
				diffs = append(diffs, ConffileDiff{Path: cp, Package: p.Name, Version: p.Version, Expected: d.SHA256, Actual: e.SHA256, Default: string(d.Text), Source: src})
			}
		case e.SHA256 == "":
			v.Expected = d.SHA256
			v.Reason = "the file on disk was not hashed"
			if e.Err != "" {
				v.Reason += ": " + e.Err
			}
			unverifiable = append(unverifiable, v)
		case e.SHA256 == d.SHA256:
			v.Expected, v.Actual = d.SHA256, e.SHA256
			verified = append(verified, v)
		default:
			v.Expected, v.Actual = d.SHA256, e.SHA256
			v.Reason = "differs from the file in the signed package"
			mismatch = append(mismatch, v)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.res.Verified = append(s.res.Verified, verified...)
	s.res.Mismatch = append(s.res.Mismatch, mismatch...)
	s.res.Unverifiable = append(s.res.Unverifiable, unverifiable...)
	s.res.Conffiles = append(s.res.Conffiles, diffs...)
}

// unverifiable marks the package's files that would have been checked.
func (s *session) unverifiable(p *model.Package, reason string) {
	if s.bw != nil {
		s.bw.addUnavailable(p, reason)
		return
	}
	var vs []FileVerdict
	seen := map[string]bool{}
	for _, f := range p.Files {
		cp, e, kind := s.locate(f)
		if kind != regularFile || seen[cp] || !s.opt.candidate(cp, f, e.Mode, nil) {
			continue
		}
		seen[cp] = true
		vs = append(vs, FileVerdict{Path: cp, Package: p.Name, Version: p.Version, Actual: e.SHA256, Reason: reason, Source: s.source})
	}
	s.mu.Lock()
	s.res.Unverifiable = append(s.res.Unverifiable, vs...)
	s.mu.Unlock()
}

// explain words an error for a verdict, naming the bundle in refs mode.
func (s *session) explain(err error) string {
	if s.bundle != nil && errors.Is(err, errHTTPNotFound) {
		return "not in the reference bundle (" + err.Error() + ")"
	}
	return err.Error()
}

// problem records a source problem in Result.Errors; evidence of tampering
// goes first.
func (s *session) problem(err error) {
	msg := s.explain(err)
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case errors.Is(err, ErrBadSignature), errors.Is(err, ErrNoValidSignature):
		msg = "BAD SIGNATURE: " + msg + " (the index was tampered with or intercepted, or telltale's built-in keys are out of date; nothing that depends on it was verified)"
	case errors.Is(err, ErrHashMismatch):
		msg = "HASH MISMATCH: " + msg + " (the data was altered after it was signed; nothing that depends on it was verified)"
	default:
		if !s.seenMsg[msg] {
			s.seenMsg[msg] = true
			s.errs = append(s.errs, msg)
		}
		return
	}
	if s.tamperErr == nil {
		s.tamperErr = err
	}
	if !s.seenMsg[msg] {
		s.seenMsg[msg] = true
		s.alerts = append(s.alerts, msg)
	}
}

func (s *session) downloadFailed(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dlFailed++
	if s.dlFirst == "" {
		s.dlFirst = s.explain(err)
	}
}

func (s *session) addSource(src string) {
	s.mu.Lock()
	s.sources[src] = true
	s.mu.Unlock()
}

// finish orders the Result.
func (s *session) finish() {
	if s.bundle != nil {
		s.bundle.close()
	}
	r := s.res
	for _, vs := range [][]FileVerdict{r.Verified, r.Mismatch, r.Unverifiable} {
		sort.Slice(vs, func(i, j int) bool {
			if vs[i].Path != vs[j].Path {
				return vs[i].Path < vs[j].Path
			}
			return vs[i].Package < vs[j].Package
		})
	}
	sort.Slice(r.Conffiles, func(i, j int) bool { return r.Conffiles[i].Path < r.Conffiles[j].Path })
	if s.dlFailed > 0 {
		what := "download"
		if s.bundle != nil {
			what = "read from the reference bundle"
		}
		s.errs = append(s.errs, fmt.Sprintf("could not %s %d package(s); first error: %s", what, s.dlFailed, s.dlFirst))
	}
	r.Errors = append(append(append(r.Errors, s.warn...), s.alerts...), s.errs...)
	for src := range s.sources {
		r.SourcesUsed = append(r.SourcesUsed, src)
	}
	sort.Strings(r.SourcesUsed)
}

// offline compares against the machine's own md5sums and conffile
// checksums, reading the files below Root to compute their MD5.
func (s *session) offline() {
	s.warn = append(s.warn, OfflineWarning)
	s.addSource("the machine's own package checksums (/var/lib/dpkg)")
	root := s.opt.Root
	if root == "" {
		root = "/"
	}
	for i := range s.c.Packages.Installed {
		p := &s.c.Packages.Installed[i]
		if !filesInstalled(p.Status) {
			continue
		}
		listed := make(map[string]bool, len(p.Files))
		for _, f := range p.Files {
			listed[f] = true
		}
		var extra []string
		for k := range p.LocalMD5 {
			if listed[k] || listed[usrAlias(k)] {
				continue
			}
			if o := s.owners[k]; o == "" || o == p.Name {
				extra = append(extra, k)
			}
		}
		sort.Strings(extra)
		seen := map[string]bool{}
		for _, lp := range append(slices.Clone(p.Files), extra...) {
			cp, e, kind := s.locate(lp)
			if kind != regularFile || seen[cp] || !s.opt.candidate(cp, lp, e.Mode, nil) {
				continue
			}
			seen[cp] = true
			if want, ok := lookupPath(p.Conffiles, lp); ok {
				if got, _, err := hashLocal(root, cp); err == nil && isHexLen(want, 32) && got != strings.ToLower(want) {
					s.res.Conffiles = append(s.res.Conffiles, ConffileDiff{Path: cp, Package: p.Name, Version: p.Version, Expected: "md5:" + strings.ToLower(want), Actual: "md5:" + got, Source: SourceOfflineLocal})
				}
				continue
			}
			v := FileVerdict{Path: cp, Package: p.Name, Version: p.Version, Source: SourceOfflineLocal}
			want, ok := lookupPath(p.LocalMD5, lp)
			if !ok || !isHexLen(want, 32) {
				v.Reason = "the package database holds no checksum for this file"
				s.res.Unverifiable = append(s.res.Unverifiable, v)
				continue
			}
			v.Expected = "md5:" + strings.ToLower(want)
			got, sum, err := hashLocal(root, cp)
			switch {
			case err != nil:
				v.Reason = "could not read the file: " + err.Error()
				s.res.Unverifiable = append(s.res.Unverifiable, v)
			case e.SHA256 != "" && sum != e.SHA256:
				v.Reason = "the file changed after it was collected"
				s.res.Unverifiable = append(s.res.Unverifiable, v)
			case got == strings.ToLower(want):
				v.Actual = "md5:" + got
				s.res.Verified = append(s.res.Verified, v)
			default:
				v.Actual = "md5:" + got
				v.Reason = "differs from the checksum in the machine's package database"
				s.res.Mismatch = append(s.res.Mismatch, v)
			}
		}
	}
}

// lookupPath finds p or its merged-/usr alias in m.
func lookupPath(m map[string]string, p string) (string, bool) {
	if v, ok := m[p]; ok {
		return v, true
	}
	if a := usrAlias(p); a != "" {
		v, ok := m[a]
		return v, ok
	}
	return "", false
}

// hashLocal returns the MD5 and SHA-256 of the regular file p below root,
// never following a symlink in its last component.
func hashLocal(root, p string) (string, string, error) {
	f, err := os.OpenFile(filepath.Join(root, filepath.FromSlash(p)), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", "", err
	}
	if !st.Mode().IsRegular() {
		return "", "", errors.New("not a regular file")
	}
	m, h := md5.New(), sha256.New()
	if _, err := io.Copy(io.MultiWriter(m, h), f); err != nil {
		return "", "", err
	}
	return hex.EncodeToString(m.Sum(nil)), hex.EncodeToString(h.Sum(nil)), nil
}

// LoadKeys reads the OpenPGP public keys (armored or binary) in the regular
// files of dir, for Options.ExtraKeys. A file holding no key, or a private
// key, is an error.
func LoadKeys(dir string) (openpgp.EntityList, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var kr openpgp.EntityList
	n := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}
		p := filepath.Join(dir, e.Name())
		st, err := os.Stat(p)
		if err != nil || !st.Mode().IsRegular() {
			continue
		}
		if n++; n > 256 {
			return nil, fmt.Errorf("%s: more than 256 key files", dir)
		}
		b, err := readSmallFile(p, 1<<20)
		if err != nil {
			return nil, err
		}
		el, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(b))
		if err != nil {
			el, err = openpgp.ReadKeyRing(bytes.NewReader(b))
		}
		if err != nil || len(el) == 0 {
			return nil, fmt.Errorf("%s: no OpenPGP key: %v", p, err)
		}
		for _, ent := range el {
			if ent.PrivateKey != nil {
				return nil, fmt.Errorf("%s holds a private key; pass only public keys", p)
			}
		}
		kr = append(kr, el...)
	}
	if len(kr) == 0 {
		return nil, fmt.Errorf("%s: no key files", dir)
	}
	return kr, nil
}

func readSmallFile(p string, max int64) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s: larger than %d bytes", p, max)
	}
	return b, nil
}
