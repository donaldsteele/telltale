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
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"golang.org/x/sys/unix"

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
	// SourceThirdParty: a third-party repository's signed index, verified
	// with a key the owner supplied.
	SourceThirdParty = "thirdparty"
)

const (
	// OfflineWarning heads Result.Errors in offline-local mode.
	OfflineWarning = "Compared against the machine's own package checksums, which root can edit."
	// ReasonPro marks files of Ubuntu Pro (ESM) packages, whose versions
	// contain "+esm". Verifying them needs a Pro token, which v1 does not
	// support.
	ReasonPro = "Ubuntu Pro package: verification with a Pro token is planned"
	// ReasonNotOfficial starts the reason for packages found in no official
	// archive or snapshot of one.
	ReasonNotOfficial = "package not found in the official archive"
	// ReasonLocalDiversion marks the file at the original path of a local
	// dpkg diversion: no package's version of it is expected there.
	ReasonLocalDiversion = "locally diverted (dpkg-divert)"
	// NoteObsoleteConffile marks a ConffileDiff for a conffile below /etc
	// that dpkg keeps but the installed version no longer ships.
	NoteObsoleteConffile = "obsolete conffile (no longer shipped by the package)"
)

// Kinds of Unverifiable verdict (FileVerdict.Kind): why a file could not be
// verified, for callers that must not depend on the wording of Reason.
const (
	// KindNotFound: verification ran and no trusted source (the official
	// archive, its snapshots, a trusted third-party source, the reference
	// bundle) confirmed this version: it is in none of them, its version
	// string is not a valid Debian version, or looking it up failed while the
	// host's own indexes were read.
	KindNotFound = "not_found"
	// KindUntrusted: the package comes from a third-party source whose key
	// was not given.
	KindUntrusted = "untrusted_source"
	// KindUnreachable: the host's own signed indexes (or the reference
	// bundle, or telltale's keys) could not be read, so nothing could be
	// checked. Whether the archive could be reached is decided once per scan:
	// with the indexes read, a failure for one package is KindNotFound.
	KindUnreachable = "unreachable"
	// KindBadSignature: a signed index or a package failed its signature or
	// hash check, so nothing that depends on it was verified.
	KindBadSignature = "bad_signature"
	// KindNotChecked: telltale did not check it because of an internal error.
	KindNotChecked = "not_checked"
	// KindUnsupportedArch: the package's own architecture (from dpkg status,
	// which root can edit) is not one telltale reads indexes for.
	KindUnsupportedArch = "unsupported_arch"
	// KindHostArch: telltale reads no indexes for the host's architecture
	// (the running binary's), so verification did not run.
	KindHostArch = "host_arch"
	// KindRelease: /etc/os-release (which root can edit) names a
	// distribution or release telltale does not verify, so verification did
	// not run.
	KindRelease = "release"
	// KindStopped: the scan's deadline stopped verification before this
	// package was checked.
	KindStopped = "stopped"
	// KindBudget: not checked because the collection exceeded a limit (more
	// than maxPackages packages, or more than maxOldLookups versions missing
	// from the current archive).
	KindBudget = "budget"
	// KindPro: an Ubuntu Pro package; checking it needs a Pro token.
	KindPro = "pro"
	// KindLocalDiversion: the file at the original path of a local dpkg
	// diversion, which no package's version is expected at.
	KindLocalDiversion = "local_diversion"
	// KindNotHashed: the file on disk could not be hashed, or changed while
	// it was being checked.
	KindNotHashed = "not_hashed"
	// KindNoChecksum: offline mode; the machine's package database holds no
	// checksum for the file.
	KindNoChecksum = "no_checksum"
)

// Kinds of Mismatch, Suspicious and noted Verified verdicts (FileVerdict.Kind).
const (
	// KindContentDiffers: the file differs from the package's copy.
	KindContentDiffers = "content_differs"
	// KindModeAddsPrivilege: the content matches, the mode adds privilege
	// (setuid, setgid, sticky, group or other write) the package never gives.
	KindModeAddsPrivilege = "mode_adds_privilege"
	// KindTypeDiffers: the package installs a regular file, the machine has
	// something else.
	KindTypeDiffers = "type_differs"
	// KindNotShipped: the machine lists the file as part of the package, but
	// the signed package has no regular file there.
	KindNotShipped = "not_shipped"
	// KindStatOverride: Suspicious; privilege only a local statoverride grants.
	KindStatOverride = "statoverride"
	// KindDiversion: Suspicious; a diversion by a package that is not
	// installed or does not ship the file.
	KindDiversion = "diversion"
	// KindModeLessPermissive: Verified; the mode lacks bits the package sets.
	KindModeLessPermissive = "mode_less_permissive"
	// KindModeDiffers: Verified; the mode differs without adding privilege.
	KindModeDiffers = "mode_differs"
)

// modeKind is the kind of a mode reason on a verified file.
func modeKind(reason string) string {
	if strings.HasPrefix(reason, "mode differs (less permissive)") {
		return KindModeLessPermissive
	}
	return KindModeDiffers
}

// problemKind classifies an error from reading a source.
func problemKind(err error) string {
	if tampered(err) || errors.Is(err, ErrNoValidSignature) {
		return KindBadSignature
	}
	return KindUnreachable
}

// Limits on the work one collection can cause.
const (
	maxPackages         = 10_000
	maxOldLookups       = 1_000
	maxThirdPartySuites = 32
)

// knownArches are the architectures package verification reads indexes for.
var knownArches = map[string]bool{"amd64": true, "arm64": true, "i386": true, "armhf": true, "all": true}

// Options controls Verify and WriteBundle.
type Options struct {
	// Full checks every package file, not only the security-relevant ones
	// InScope selects.
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
	// (with a snapshot: the files that changed), regardless of Full and
	// InScope. Only the packages that list them, and packages whose cached
	// signed table holds them, are fetched.
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
	// Now is the clock of the machine running the check; nil means
	// time.Now. It is compared with the signed indexes' date for
	// Result.ClockSkew, and decides key expiry and Valid-Until only when no
	// downloaded index gives a signed date and an Archive or OldFinder sets
	// no clock of its own.
	Now func() time.Time
}

// Result is the outcome of verifying a collection's files.
type Result struct {
	Mode         string        `json:"mode"`
	Verified     []FileVerdict `json:"verified,omitempty"`
	Mismatch     []FileVerdict `json:"mismatch,omitempty"`
	Unverifiable []FileVerdict `json:"unverifiable,omitempty"`
	// Suspicious files are not cleanly verified because only data on the
	// examined machine explains them: a diversion by a package that is not
	// installed or does not ship the file, or a local statoverride that
	// grants privilege the package never gives.
	Suspicious  []FileVerdict  `json:"suspicious,omitempty"`
	Conffiles   []ConffileDiff `json:"conffiles,omitempty"`
	SourcesUsed []string       `json:"sources_used,omitempty"`
	// Errors lists problems, most serious first: the offline warning, then
	// evidence of tampering ("BAD SIGNATURE", "HASH MISMATCH"), then
	// sources that could not be read.
	Errors []string `json:"errors,omitempty"`
	// ClockSkew is set when the clock of the machine running the check is
	// provably wrong: more than a day before the newest signed date of the
	// indexes it fetched, or past the Valid-Until of one that is still
	// valid at that date. The clock decides nothing else: see signedClock.
	ClockSkew *ClockSkew `json:"clock_skew,omitempty"`
}

// ClockSkew is a disagreement between the machine's clock and the signed
// indexes' date.
type ClockSkew struct {
	Clock  time.Time `json:"clock"`
	Signed time.Time `json:"signed"`
}

// FileVerdict is the outcome for one file. Path is the collected path.
// Expected and Actual are SHA-256 hashes ("md5:<hex>" in offline-local mode).
// Source says how the expected value was obtained: archive, snapshot,
// launchpad, thirdparty, refs or offline-local.
type FileVerdict struct {
	Path     string `json:"path"`
	Package  string `json:"package"`
	Version  string `json:"version"`
	Expected string `json:"expected,omitempty"`
	Actual   string `json:"actual,omitempty"`
	Reason   string `json:"reason,omitempty"`
	Source   string `json:"source,omitempty"`
	// Kind says why an Unverifiable file could not be verified (Kind*).
	Kind string `json:"kind,omitempty"`
}

// ConffileDiff is a configuration file that differs from its package's
// default. Conffiles are expected to differ and are never a Mismatch.
// Default is the package's default text when it is at most 256 KiB; the
// on-disk text, redacted, is in the collection's persistence files. Note
// explains special cases, such as an obsolete conffile.
type ConffileDiff struct {
	Path     string `json:"path"`
	Package  string `json:"package"`
	Version  string `json:"version"`
	Expected string `json:"expected"`
	Actual   string `json:"actual"`
	Default  string `json:"default,omitempty"`
	Note     string `json:"note,omitempty"`
	Source   string `json:"source,omitempty"`
}

// Verify checks the collection's files against the files in the
// distribution's signed packages. Every installed package's signed file
// table is read, and every collected file a table installs is compared with
// it, so the machine's dpkg file lists, which root can edit, never decide
// what is checked. It never trusts the machine's own package checksums
// except in offline-local mode, which says so. Problems with sources never
// stop it: files that cannot be checked are Unverifiable with the reason,
// and Verify always returns a Result.
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
	if len(plans) == 0 && !s.changedFiles() {
		return res
	}
	results := newResults(plans)
	if err := s.setup(); err != nil {
		s.problem(err)
		kind := s.setupKind
		switch {
		case tampered(err) || errors.Is(err, ErrNoValidSignature):
			kind = KindBadSignature
		case kind == "":
			kind = KindUnreachable // the bundle, keys or cache could not be used
		}
		for _, r := range results {
			r.fail(err.Error(), kind)
		}
	} else {
		s.loadIndexes(ctx, s.indexWanted(plans))
		results = s.addCachedTables(results)
		s.run(ctx, results)
		// A changed file no loaded table places may belong to a package
		// whose file list was edited to hide it: check every package.
		if s.opt.OnlyPaths != nil && s.unplacedChange(results) {
			results = s.addAllInstalled(results)
			s.run(ctx, results)
		}
	}
	s.judge(results)
	return res
}

// changedFiles reports whether OnlyPaths names any collected regular file
// or symlink.
func (s *session) changedFiles() bool {
	for p := range s.opt.OnlyPaths {
		if e := s.files[p]; e != nil && (isRegular(e) || e.Type == "symlink") {
			return true
		}
	}
	return false
}

// unplacedChange reports whether a changed in-scope regular file is placed
// by none of the loaded tables.
func (s *session) unplacedChange(results []*pkgResult) bool {
	idx := s.placeTables(results)
	for p := range s.opt.OnlyPaths {
		e := s.files[p]
		if e == nil || !isRegular(e) || len(idx[p]) > 0 || strings.HasPrefix(p, dpkgInfoDir) {
			continue // dpkg's own records are no package's files
		}
		if s.opt.Full || InScope(p, e.Mode) {
			return true
		}
	}
	return false
}

// addAllInstalled adds every installed package not yet in results.
func (s *session) addAllInstalled(results []*pkgResult) []*pkgResult {
	have := map[PkgKey]bool{}
	for _, r := range results {
		have[PkgKey{r.pkg.Name, r.pkg.Version, r.pkg.Arch}] = true
	}
	for i := range s.c.Packages.Installed {
		p := &s.c.Packages.Installed[i]
		k := PkgKey{p.Name, p.Version, p.Arch}
		if filesInstalled(p.Status) && !have[k] {
			have[k] = true
			results = append(results, &pkgResult{pkg: p})
		}
	}
	return results
}

// pkgResult is what became of one installed package.
type pkgResult struct {
	pkg    *model.Package
	ref    DebRef
	source string             // verdict Source for its files
	table  map[string]DebFile // nil when the package could not be checked
	reason string             // why not
	kind   string             // Kind* of reason
}

// fail records why a package could not be checked.
func (r *pkgResult) fail(reason, kind string) {
	r.reason, r.kind = reason, kind
}

func newResults(plans []*model.Package) []*pkgResult {
	out := make([]*pkgResult, len(plans))
	for i, p := range plans {
		out[i] = &pkgResult{pkg: p}
	}
	return out
}

// session is one Verify or WriteBundle run.
type session struct {
	setupKind string // the Kind of a setup failure, if any
	c         *model.Collection
	opt       Options
	res       *Result
	files     map[string]*model.FileEntry
	owners    map[string]string
	divs      map[string]model.Diversion    // by original path
	overrides map[string]model.StatOverride // by path
	installed map[string]bool               // package names
	byName    map[string]*pkgResult         // set by judge
	// scriptPkgs lists, by name, the checked packages whose maintainer
	// scripts dpkg keeps (set by judge).
	scriptPkgs map[string][]*pkgResult

	archives []*Archive
	clock    *signedClock // shared by every archive of the run
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
	oldUsed   int
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
		divs:       map[string]model.Diversion{},
		overrides:  map[string]model.StatOverride{},
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
	for _, d := range c.Packages.Diversions {
		s.divs[d.Path] = d
	}
	for _, o := range c.Packages.StatOverrides {
		s.overrides[o.Path] = o
	}
	s.installed = map[string]bool{}
	for _, p := range c.Packages.Installed {
		if filesInstalled(p.Status) {
			s.installed[p.Name] = true
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

// plan returns the packages whose signed tables are read: every installed
// package, whatever its file list says, or with OnlyPaths those that list a
// changed path or have a changed maintainer script. Packages removed but
// not purged are read for the maintainer scripts dpkg still keeps of them
// (a postrm runs on purge).
func (s *session) plan() []*model.Package {
	seen := map[PkgKey]bool{}
	var out []*model.Package
	for i := range s.c.Packages.Installed {
		p := &s.c.Packages.Installed[i]
		k := PkgKey{p.Name, p.Version, p.Arch}
		if !filesInstalled(p.Status) || seen[k] {
			continue
		}
		if s.opt.OnlyPaths != nil && !s.listsChanged(p) && !s.hasScript(p) {
			continue
		}
		seen[k] = true
		out = append(out, p)
	}
	for i := range s.c.Packages.Residual {
		p := &s.c.Packages.Residual[i]
		k := PkgKey{p.Name, p.Version, p.Arch}
		if filesInstalled(p.Status) || seen[k] || !s.hasScript(p) {
			continue
		}
		seen[k] = true
		out = append(out, p)
	}
	return out
}

// dpkgInfoDir is where dpkg keeps its records of each package.
const dpkgInfoDir = "/var/lib/dpkg/info/"

// scriptPaths lists where dpkg keeps the maintainer script name of p: under
// the package's name, or name:arch for a Multi-Arch: same package.
func scriptPaths(p *model.Package, name string) []string {
	out := []string{dpkgInfoDir + p.Name + "." + name}
	if p.Arch != "" {
		out = append(out, dpkgInfoDir+p.Name+":"+p.Arch+"."+name)
	}
	return out
}

// scriptOf splits the path of a maintainer script in dpkg's records into
// the package, its architecture ("" when the name has none) and the script.
func scriptOf(p string) (pkg, arch, script string, ok bool) {
	rest, found := strings.CutPrefix(p, dpkgInfoDir)
	i := strings.LastIndexByte(rest, '.')
	if !found || i <= 0 || strings.Contains(rest, "/") || !slices.Contains(MaintainerScripts, rest[i+1:]) {
		return "", "", "", false
	}
	pkg, arch, _ = strings.Cut(rest[:i], ":")
	return pkg, arch, rest[i+1:], pkg != ""
}

// hasScript reports whether a maintainer script of p was collected and,
// with OnlyPaths, is one of the changed paths.
func (s *session) hasScript(p *model.Package) bool {
	for _, name := range MaintainerScripts {
		for _, sp := range scriptPaths(p, name) {
			if s.files[sp] != nil && (s.opt.OnlyPaths == nil || s.opt.OnlyPaths[sp]) {
				return true
			}
		}
	}
	return false
}

func (s *session) listsChanged(p *model.Package) bool {
	for _, f := range p.Files {
		if s.opt.OnlyPaths[f] {
			return true
		}
		if a := usrAlias(f); a != "" && s.opt.OnlyPaths[a] {
			return true
		}
	}
	return false
}

// indexWanted returns the packages to look up in the indexes: the planned
// ones, plus with OnlyPaths every installed package, whose cached table may
// hold a changed path or which the fallback to every package may need.
func (s *session) indexWanted(plans []*model.Package) []*model.Package {
	if s.opt.OnlyPaths == nil || s.bw != nil {
		return plans
	}
	var out []*model.Package
	for i := range s.c.Packages.Installed {
		if p := &s.c.Packages.Installed[i]; filesInstalled(p.Status) {
			out = append(out, p)
		}
	}
	for _, p := range plans {
		if !filesInstalled(p.Status) {
			out = append(out, p) // removed, not purged: planned for its scripts
		}
	}
	return out
}

// addCachedTables adds, with OnlyPaths, the installed packages not listing a
// changed path whose signed table is already in the cache and holds one.
func (s *session) addCachedTables(results []*pkgResult) []*pkgResult {
	if s.opt.OnlyPaths == nil || s.opt.CacheDir == "" || s.bw != nil {
		return results
	}
	planned := map[PkgKey]bool{}
	for _, r := range results {
		planned[PkgKey{r.pkg.Name, r.pkg.Version, r.pkg.Arch}] = true
	}
	for i := range s.c.Packages.Installed {
		p := &s.c.Packages.Installed[i]
		k := PkgKey{p.Name, p.Version, p.Arch}
		if !filesInstalled(p.Status) || planned[k] || !knownArches[p.Arch] {
			continue
		}
		planned[k] = true
		ref, ok := s.lookup(p)
		if !ok {
			continue
		}
		t, ok := loadTable(s.opt.CacheDir, ref.SHA256)
		if !ok {
			continue
		}
		for dp := range t {
			if s.opt.OnlyPaths[dp] || (usrAlias(dp) != "" && s.opt.OnlyPaths[usrAlias(dp)]) {
				results = append(results, &pkgResult{pkg: p, ref: ref, source: s.sourceOf(ref), table: t})
				break
			}
		}
	}
	return results
}

// setup chooses the archives, the snapshot finder and the download client
// for the run's mode.
func (s *session) setup() error {
	if h := s.c.Host.Arch; h == "all" || !knownArches[h] {
		s.setupKind = KindHostArch
		return fmt.Errorf("host architecture %q is not supported for package verification", h)
	}
	if s.opt.Archives == nil {
		if _, err := Codename(s.c.Host); err != nil {
			s.setupKind = KindRelease
			return err
		}
	}
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
	s.clock = &signedClock{}
	for _, a := range archives {
		c := *a
		c.memo = &releaseMemo{}
		c.clock = s.clock
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
		o.clock = s.clock
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
// keys no third-party source is ever contacted, nor is an Ubuntu Pro source,
// which needs a token.
func (s *session) setupThirdParty(wrap func(*http.Client) *http.Client, cache string, refs bool) {
	seen := map[string]bool{}
	suites := 0
	for _, src := range s.c.Packages.Sources {
		if len(src.Types) > 0 && !slices.Contains(src.Types, "deb") {
			continue
		}
		for _, uri := range src.URIs {
			if officialURI(uri) {
				continue
			}
			if !seen[uri] {
				seen[uri] = true
				s.thirdURIs = append(s.thirdURIs, uri)
			}
			if len(s.opt.ExtraKeys) == 0 || esmURI(uri) {
				continue
			}
			u, err := url.Parse(uri)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				continue
			}
			var sus, comps []string
			for _, su := range src.Suites {
				if safeSuite.MatchString(su) {
					sus = append(sus, su)
				}
			}
			for _, co := range src.Components {
				if componentName.MatchString(co) && len(comps) < 16 {
					comps = append(comps, co)
				}
			}
			if len(sus) == 0 || len(comps) == 0 {
				continue // flat repositories are not supported
			}
			if suites+len(sus) > maxThirdPartySuites {
				s.problem(fmt.Errorf("more than %d third-party suites; %s and later sources were not read", maxThirdPartySuites, uri))
				return
			}
			suites += len(sus)
			client := s.opt.Client
			if client == nil {
				client = defaultClient
			}
			if wrap != nil {
				client = wrap(client)
			}
			s.third = append(s.third, thirdSource{uri: uri, a: &Archive{
				BaseURL: strings.TrimRight(uri, "/"), Suites: sus, Components: comps,
				Keyring: s.opt.ExtraKeys, Client: client, Cache: cache, Now: s.opt.Now, Historical: refs,
				memo: &releaseMemo{}, clock: s.clock,
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

// loadIndexes reads every signed index the wanted packages may be in and
// keeps only their entries.
func (s *session) loadIndexes(ctx context.Context, wanted []*model.Package) {
	s.syncClock(ctx)
	arches := map[string]bool{}
	want := map[[2]string]bool{}
	for _, p := range wanted {
		if a := s.archOf(p); knownArches[a] && a != "all" {
			arches[a] = true
		}
		want[[2]string{p.Name, p.Version}] = true
	}
	keep := func(idx map[PkgKey]DebRef, dst map[PkgKey]DebRef, source string) {
		for k, ref := range idx {
			if want[[2]string{k.Name, k.Version}] {
				if _, dup := dst[k]; !dup {
					if source != "" {
						ref.Source = source
					}
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
						keep(idx, s.found, "")
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
						keep(idx, s.thirdFound, SourceThirdParty)
					}
				}
			}
		}
	}
}

// maxClockSkew is how far the machine's clock may be behind the signed
// indexes' date before the result says so.
const maxClockSkew = 24 * time.Hour

// syncClock fetches the InRelease of every suite of the host's archives and
// takes the newest Date among those signed by a built-in key as the time
// for every later check: Valid-Until, signature dates and key expiry. The
// clock of the examined machine is root's to set, and moving it must not
// decide whether the signed indexes are usable. The clock is then only
// compared with the signed dates, for ClockSkew, and reported only when it
// is provably wrong: more than a day before the newest signed Date, or
// after the earliest Valid-Until of the indexes still valid at that date. A
// correct clock is never behind what the archive has signed, and indexes
// that were simply not re-signed for a while prove nothing.
func (s *session) syncClock(ctx context.Context) {
	var untils []time.Time
	for _, a := range s.archives {
		for _, suite := range a.Suites {
			if t, until, ok := a.signedDate(ctx, suite); ok {
				s.clock.observe(t)
				if !until.IsZero() && !a.Historical {
					untils = append(untils, until)
				}
			}
		}
	}
	signed, ok := s.clock.get()
	if !ok || s.res.Mode != ModeArchive || s.bw != nil {
		return // a bundle is read long after it was signed
	}
	clock := time.Now()
	if s.opt.Now != nil {
		clock = s.opt.Now()
	}
	wrong := clock.Before(signed.Add(-maxClockSkew))
	for _, until := range untils {
		// An index already expired at the signed date is refused, and is no
		// witness against the clock.
		if !until.Before(signed) && clock.After(until) {
			wrong = true
		}
	}
	if wrong {
		s.res.ClockSkew = &ClockSkew{Clock: clock.UTC(), Signed: signed.UTC()}
	}
}

// lookup finds a package in the signed indexes read so far.
func (s *session) lookup(p *model.Package) (DebRef, bool) {
	arch := p.Arch
	if arch == "" {
		arch = s.c.Host.Arch
	}
	if ref, ok := Lookup(s.found, p.Name, p.Version, arch); ok {
		return ref, true
	}
	return Lookup(s.thirdFound, p.Name, p.Version, arch)
}

func (s *session) sourceOf(ref DebRef) string {
	if s.source != "" {
		return s.source
	}
	return ref.Source
}

// run checks the packages that still need it, a few at a time.
func (s *session) run(ctx context.Context, results []*pkgResult) {
	workers := 4
	if s.bw != nil {
		workers = 1 // a bundle records each URL once, in order
	}
	ch := make(chan *pkgResult)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for r := range ch {
				s.onePackage(ctx, r)
			}
		}()
	}
	n := 0
	for _, r := range results {
		if r.table != nil || r.reason != "" {
			continue
		}
		if n++; n > maxPackages {
			r.fail(fmt.Sprintf("not checked: the collection lists more than %d packages", maxPackages), KindBudget)
			continue
		}
		ch <- r
	}
	close(ch)
	wg.Wait()
}

var errOldBudget = fmt.Errorf("not looked up: more than %d installed packages are missing from the current archive", maxOldLookups)

func (s *session) onePackage(ctx context.Context, r *pkgResult) {
	p := r.pkg
	defer func() {
		if x := recover(); x != nil {
			r.table = nil
			r.fail(fmt.Sprintf("internal error while checking the package: %v", x), KindNotChecked)
		}
	}()
	if err := ctx.Err(); err != nil {
		r.fail("check stopped: "+err.Error(), KindStopped)
		return
	}
	if !validVersion(p.Version) {
		r.fail("the version in dpkg status is not a valid Debian version, so no source was asked", KindNotFound)
		return
	}
	if p.Arch != "" && !knownArches[p.Arch] {
		r.fail(fmt.Sprintf("unsupported architecture %q", p.Arch), KindUnsupportedArch)
		return
	}
	if strings.Contains(p.Version, "+esm") {
		r.fail(ReasonPro, KindPro)
		return
	}
	ref, ok := s.lookup(p)
	var oldErr error
	if !ok && s.old != nil {
		s.mu.Lock()
		s.oldUsed++
		budget := s.oldUsed <= maxOldLookups
		s.mu.Unlock()
		if budget {
			arch := p.Arch
			if arch == "" {
				arch = s.c.Host.Arch
			}
			ref, oldErr = s.old.Find(ctx, PkgKey{p.Name, p.Version, arch}, s.c.Host.OSID)
		} else {
			oldErr = errOldBudget
		}
		switch {
		case oldErr == nil:
			ok = true
			s.addSource(oldSource(ref))
		case tampered(oldErr):
			s.problem(oldErr)
		}
	}
	if !ok {
		r.fail(s.notFound(p, oldErr))
		return
	}
	if s.bw != nil {
		s.bundleDeb(ctx, r, ref)
		return
	}
	table, err := s.table(ctx, ref)
	if err != nil {
		if tampered(err) {
			s.problem(err)
		} else {
			s.downloadFailed(err)
		}
		r.fail("could not check the package: "+s.explain(err), KindNotFound) // its index was read: see notFound
		return
	}
	r.ref, r.table, r.source = ref, table, s.sourceOf(ref)
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
func (s *session) notFound(p *model.Package, oldErr error) (string, string) {
	if err := s.idxErr[s.archOf(p)]; err != nil {
		return "could not read the official archive index: " + s.explain(err), problemKind(err)
	}
	if s.bundle != nil {
		if u, ok := s.bundle.unavailable[PkgKey{p.Name, p.Version, p.Arch}]; ok {
			return "not in the reference bundle: " + u.Reason, KindNotFound
		}
		return "package not in the reference bundle", KindNotFound
	}
	if oldErr != nil && !errors.Is(oldErr, ErrNotFound) {
		// The host's own indexes were read (see above), so a failure for
		// this one package is not "the archive could not be reached".
		kind := KindNotFound
		if errors.Is(oldErr, errOldBudget) {
			kind = KindBudget
		}
		return "not in the current archive, and the snapshot archives could not be checked: " + s.explain(oldErr), kind
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
		return r + "; source not trusted: " + strings.Join(untrusted, ", "), KindUntrusted
	}
	return r, KindNotFound
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

// expect is one signed package's file, as installed at some path.
type expect struct {
	r    *pkgResult
	path string // in the .deb
	f    DebFile
	// control marks a maintainer script from the .deb's control member,
	// placed where dpkg keeps it; such a file is always checked.
	control bool
}

// judge compares the collected files with the signed tables. Each table
// file is placed where dpkg installs it, after diversions and under both
// merged-/usr spellings; every collected file a table places is compared
// with it. The machine's file lists only explain files no table places:
// a file a package lists but no signed package ships, or one belonging to a
// package that could not be checked.
func (s *session) judge(results []*pkgResult) {
	idx := s.placeTables(results)
	listers := map[string][]*pkgResult{}
	for _, r := range results {
		for _, f := range r.pkg.Files {
			listers[f] = append(listers[f], r)
			if a := usrAlias(f); a != "" {
				listers[a] = append(listers[a], r)
			}
		}
	}
	s.byName = map[string]*pkgResult{}
	s.scriptPkgs = map[string][]*pkgResult{}
	for _, r := range results {
		s.scriptPkgs[r.pkg.Name] = append(s.scriptPkgs[r.pkg.Name], r)
		if !filesInstalled(r.pkg.Status) {
			continue
		}
		if _, dup := s.byName[r.pkg.Name]; !dup || r.table != nil {
			s.byName[r.pkg.Name] = r
		}
	}

	var verified, mismatch, unverifiable, suspicious []FileVerdict
	var diffs []ConffileDiff
	seen := map[string]bool{}
	for i := range s.c.Files {
		e := &s.c.Files[i]
		if seen[e.Path] || (s.opt.OnlyPaths != nil && !s.opt.OnlyPaths[e.Path]) {
			continue
		}
		seen[e.Path] = true
		v, d, kind := s.judgeFile(e, idx[e.Path], listers[e.Path])
		switch kind {
		case verdictVerified:
			verified = append(verified, v)
		case verdictMismatch:
			mismatch = append(mismatch, v)
		case verdictUnverifiable:
			unverifiable = append(unverifiable, v)
		case verdictSuspicious:
			suspicious = append(suspicious, v)
		case verdictConffile:
			diffs = append(diffs, d)
		}
	}
	s.res.Verified = append(s.res.Verified, verified...)
	s.res.Mismatch = append(s.res.Mismatch, mismatch...)
	s.res.Unverifiable = append(s.res.Unverifiable, unverifiable...)
	s.res.Suspicious = append(s.res.Suspicious, suspicious...)
	s.res.Conffiles = append(s.res.Conffiles, diffs...)
}

// placeTables maps each install path to the signed files dpkg puts there:
// a package's file at a path another party diverts goes to the divert-to
// path, and both merged-/usr spellings are entered.
func (s *session) placeTables(results []*pkgResult) map[string][]expect {
	idx := map[string][]expect{}
	place := func(at string, x expect) {
		idx[at] = append(idx[at], x)
		if a := usrAlias(at); a != "" {
			idx[a] = append(idx[a], x)
		}
	}
	for _, r := range results {
		installed := filesInstalled(r.pkg.Status)
		for p, f := range r.table {
			if name, ok := strings.CutPrefix(p, ControlPrefix); ok {
				for _, at := range scriptPaths(r.pkg, name) {
					idx[at] = append(idx[at], expect{r: r, path: at, f: f, control: true})
				}
				continue
			}
			if !installed {
				continue // removed, not purged: only its scripts are left
			}
			at := p
			if d, ok := s.divs[p]; ok && d.Package != r.pkg.Name {
				at = d.DivertTo
			}
			place(at, expect{r: r, path: p, f: f})
		}
	}
	for _, xs := range idx {
		sort.Slice(xs, func(i, j int) bool {
			if xs[i].r.pkg.Name != xs[j].r.pkg.Name {
				return xs[i].r.pkg.Name < xs[j].r.pkg.Name
			}
			return xs[i].path < xs[j].path
		})
	}
	return idx
}

type verdictKind int

const (
	verdictNone verdictKind = iota
	verdictVerified
	verdictMismatch
	verdictUnverifiable
	verdictSuspicious
	verdictConffile
)

func (k verdictKind) String() string {
	return [...]string{"none", "verified", "mismatch", "unverifiable", "suspicious", "conffile"}[k]
}

// judgeFile decides one collected entry e, given the signed files placed at
// its path and the packages whose file lists name it.
func (s *session) judgeFile(e *model.FileEntry, exp []expect, lst []*pkgResult) (FileVerdict, ConffileDiff, verdictKind) {
	regular := isRegular(e)
	var mode uint32
	if regular {
		mode = e.Mode
	}
	if len(exp) == 0 {
		return s.judgeUnshipped(e, regular, lst)
	}
	inScope := false
	for i := range exp {
		if exp[i].control || s.opt.candidate(e.Path, exp[i].path, mode, &exp[i].f) {
			inScope = true
			break
		}
	}
	if !inScope {
		return FileVerdict{}, ConffileDiff{}, verdictNone
	}
	var conf *expect
	for i := range exp {
		if exp[i].f.Conffile {
			conf = &exp[i]
			break
		}
	}
	diff := func(actual string) ConffileDiff {
		return ConffileDiff{Path: e.Path, Package: conf.r.pkg.Name, Version: conf.r.pkg.Version, Expected: conf.f.SHA256, Actual: actual, Default: string(conf.f.Text), Source: conf.r.source}
	}
	verdict := func(x *expect) FileVerdict {
		return FileVerdict{Path: e.Path, Package: x.r.pkg.Name, Version: x.r.pkg.Version, Expected: x.f.SHA256, Actual: e.SHA256, Source: x.r.source}
	}
	if !regular {
		actual := e.Type
		if e.Type == "symlink" {
			actual = "symlink to " + e.Target
		}
		if conf != nil {
			return FileVerdict{}, diff(actual), verdictConffile
		}
		v := verdict(&exp[0])
		v.Actual = actual
		v.Reason, v.Kind = "the signed package installs a regular file here, the machine has a "+e.Type, KindTypeDiffers
		return v, ConffileDiff{}, verdictMismatch
	}
	if e.SHA256 == "" {
		if conf != nil {
			return FileVerdict{}, ConffileDiff{}, verdictNone
		}
		v := verdict(&exp[0])
		v.Reason, v.Kind = "the file on disk was not hashed", KindNotHashed
		if e.Err != "" {
			v.Reason += ": " + e.Err
		}
		return v, ConffileDiff{}, verdictUnverifiable
	}
	// The best verdict among the matching shippers: an exact mode, then a
	// noted mode difference, then privilege only a local statoverride
	// grants, then added privilege.
	var noted, susp, modeV FileVerdict
	matchedConf := false
	for i := range exp {
		x := &exp[i]
		if x.f.SHA256 != e.SHA256 {
			continue
		}
		if x.f.Conffile {
			matchedConf = true
			continue
		}
		why, kind := s.modeDiff(e.Path, e.Mode, x.f)
		switch {
		case kind == verdictVerified && why == "":
			return verdict(x), ConffileDiff{}, verdictVerified
		case kind == verdictVerified && noted.Reason == "":
			noted = verdict(x)
			noted.Reason, noted.Kind = why, modeKind(why)
		case kind == verdictSuspicious && susp.Reason == "":
			susp = verdict(x)
			susp.Reason, susp.Kind = why, KindStatOverride
		case kind == verdictMismatch && modeV.Reason == "":
			modeV = verdict(x)
			modeV.Reason, modeV.Kind = why, KindModeAddsPrivilege
		}
	}
	switch {
	case noted.Reason != "":
		return noted, ConffileDiff{}, verdictVerified
	case susp.Reason != "":
		return susp, ConffileDiff{}, verdictSuspicious
	case modeV.Reason != "":
		return modeV, ConffileDiff{}, verdictMismatch
	case matchedConf:
		return FileVerdict{}, ConffileDiff{}, verdictNone // an unchanged conffile
	case conf != nil:
		return FileVerdict{}, diff(e.SHA256), verdictConffile
	}
	v := verdict(&exp[0])
	v.Reason, v.Kind = "differs from the file in the signed package", KindContentDiffers
	if exp[0].control {
		v.Reason = "differs from the maintainer script in the signed package"
	}
	var names []string
	for _, x := range exp {
		if n := x.r.pkg.Name + " " + x.r.pkg.Version; !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	if len(names) > 1 {
		v.Reason += " (shipped by " + strings.Join(names, ", ") + ")"
	}
	return v, ConffileDiff{}, verdictMismatch
}

// judgeUnshipped decides a collected entry that no signed table places.
func (s *session) judgeUnshipped(e *model.FileEntry, regular bool, lst []*pkgResult) (FileVerdict, ConffileDiff, verdictKind) {
	none := func() (FileVerdict, ConffileDiff, verdictKind) { return FileVerdict{}, ConffileDiff{}, verdictNone }
	if name, arch, script, ok := scriptOf(e.Path); ok && regular {
		// A maintainer script the signed package does not have: dpkg runs
		// whatever is there, whether or not the package shipped one.
		var owners []*pkgResult
		for _, r := range s.scriptPkgs[name] {
			if arch == "" || arch == r.pkg.Arch {
				owners = append(owners, r)
			}
		}
		if len(owners) == 0 {
			return none() // no package dpkg knows: nothing runs it
		}
		v := FileVerdict{Path: e.Path, Package: owners[0].pkg.Name, Version: owners[0].pkg.Version, Actual: e.SHA256, Source: owners[0].source}
		for _, r := range owners {
			if r.table == nil {
				v.Package, v.Version, v.Reason, v.Kind, v.Source = r.pkg.Name, r.pkg.Version, r.reason, r.kind, s.source
				return v, ConffileDiff{}, verdictUnverifiable
			}
		}
		v.Reason, v.Kind = "the signed package has no "+script+" maintainer script", KindNotShipped
		return v, ConffileDiff{}, verdictMismatch
	}
	if !regular || !s.opt.candidate(e.Path, e.Path, e.Mode, nil) {
		return none()
	}
	v := FileVerdict{Path: e.Path, Actual: e.SHA256, Source: s.source}
	if len(lst) > 0 {
		v.Package, v.Version = lst[0].pkg.Name, lst[0].pkg.Version
	}
	d, diverted := s.divs[e.Path]
	if a := usrAlias(e.Path); !diverted && a != "" {
		d, diverted = s.divs[a]
	}
	if diverted {
		if d.Package == model.LocalDiversion {
			v.Reason, v.Kind = ReasonLocalDiversion, KindLocalDiversion
			return v, ConffileDiff{}, verdictUnverifiable
		}
		// A package diversion moves the other packages' files away, and
		// only the diverting package's own file belongs here. Had its
		// signed table shipped one, this path would have been placed.
		v.Package, v.Version = d.Package, ""
		r := s.byName[d.Package]
		switch {
		case !s.installed[d.Package]:
			v.Reason, v.Kind = fmt.Sprintf("diverted by %s, which is not installed", d.Package), KindDiversion
		case r == nil:
			v.Reason, v.Kind = fmt.Sprintf("diverted by %s, which was not checked", d.Package), KindNotChecked
			return v, ConffileDiff{}, verdictUnverifiable
		case r.table == nil:
			v.Version = r.pkg.Version
			v.Reason, v.Kind = fmt.Sprintf("diverted by %s, which could not be checked: %s", d.Package, r.reason), r.kind
			return v, ConffileDiff{}, verdictUnverifiable
		default:
			v.Version, v.Source = r.pkg.Version, r.source
			v.Reason, v.Kind = fmt.Sprintf("diverted by %s, which does not ship this file", d.Package), KindDiversion
		}
		return v, ConffileDiff{}, verdictSuspicious
	}
	if len(lst) == 0 {
		return none() // not a package file
	}
	for _, r := range lst {
		if r.table == nil {
			v.Package, v.Version, v.Reason, v.Kind = r.pkg.Name, r.pkg.Version, r.reason, r.kind
			return v, ConffileDiff{}, verdictUnverifiable
		}
	}
	if strings.HasPrefix(e.Path, "/etc/") {
		for _, r := range lst {
			if slices.Contains(r.pkg.ObsoleteConffiles, e.Path) || (usrAlias(e.Path) != "" && slices.Contains(r.pkg.ObsoleteConffiles, usrAlias(e.Path))) {
				return FileVerdict{}, ConffileDiff{Path: e.Path, Package: r.pkg.Name, Version: r.pkg.Version, Actual: e.SHA256, Note: NoteObsoleteConffile, Source: r.source}, verdictConffile
			}
		}
	}
	v.Source = lst[0].source
	v.Reason, v.Kind = "the signed package has no regular file here, though the machine lists it as part of the package", KindNotShipped
	return v, ConffileDiff{}, verdictMismatch
}

// privilegeBits are the mode bits whose addition grants more than the
// package intended: setuid, setgid, sticky, and write for group or others.
const privilegeBits = 0o7000 | 0o022

type expectedMode struct {
	mode  uint32
	label string
}

// modeDiff compares a file's mode on disk with what is expected, and says
// how to judge the file (verdictVerified, verdictMismatch or
// verdictSuspicious) and why.
//
// The package gives the deb mode and any mode its own postinst sets. A
// dpkg-statoverride replaces them when it grants no privilege beyond them,
// or when the package's own maintainer script adds exactly that override;
// a local statoverride that grants more is the machine's own data, so a
// mode only it explains is suspicious. Only added privilege (privilegeBits
// on disk that no expected mode has) is a mismatch. Any other difference is
// a reason on a verified file ("less permissive" when the disk only lacks
// bits); an exact match gives "".
func (s *session) modeDiff(p string, diskMode uint32, f DebFile) (string, verdictKind) {
	disk := diskMode & 0o7777
	base := []expectedMode{{f.Mode & 0o7777, "deb"}}
	for _, m := range f.ScriptModes {
		base = append(base, expectedMode{m & 0o7777, "maintainer script"})
	}
	o, ok := s.overrides[p]
	if a := usrAlias(p); !ok && a != "" {
		o, ok = s.overrides[a]
	}
	if !ok {
		return judgeMode(base, disk, f.ScriptModes)
	}
	ov := o.Mode & 0o7777
	grants := !slices.ContainsFunc(base, func(e expectedMode) bool { return ov&^e.mode&privilegeBits == 0 })
	backed := slices.ContainsFunc(f.ScriptOverrides, func(so ScriptOverride) bool {
		return so.Owner == o.Owner && so.Group == o.Group && so.Mode&0o7777 == ov
	})
	if !grants || backed {
		if disk != ov {
			return judgeMode([]expectedMode{{ov, "statoverride"}}, disk, nil)
		}
		if !slices.ContainsFunc(base, func(e expectedMode) bool { return e.mode == disk }) && disk&^base[0].mode == 0 {
			// Privilege taken away with a statoverride.
			return fmt.Sprintf("mode differs (less permissive): deb %04o, disk %04o", base[0].mode, disk), verdictVerified
		}
		return "", verdictVerified
	}
	reason, kind := judgeMode(base, disk, f.ScriptModes)
	if kind == verdictMismatch && disk&^ov&privilegeBits == 0 {
		return fmt.Sprintf("privilege granted by a local statoverride: deb %04o, disk %04o", base[0].mode, disk), verdictSuspicious
	}
	return reason, kind
}

// judgeMode judges disk against the expected modes exp.
func judgeMode(exp []expectedMode, disk uint32, scriptModes []uint32) (string, verdictKind) {
	if slices.ContainsFunc(exp, func(e expectedMode) bool { return e.mode == disk }) {
		return "", verdictVerified
	}
	other := ""
	for _, e := range exp {
		switch {
		case disk&^e.mode&privilegeBits != 0:
		case disk&^e.mode == 0:
			return fmt.Sprintf("mode differs (less permissive): %s %04o, disk %04o", e.label, e.mode, disk), verdictVerified
		case other == "":
			other = fmt.Sprintf("mode differs: %s %04o, disk %04o", e.label, e.mode, disk)
		}
	}
	if other != "" {
		return other, verdictVerified
	}
	if len(scriptModes) > 0 {
		var sm []string
		for _, m := range scriptModes {
			sm = append(sm, fmt.Sprintf("%04o", m))
		}
		return fmt.Sprintf("mode differs: deb %04o (maintainer script sets %s), disk %04o", exp[0].mode, strings.Join(sm, " or "), disk), verdictMismatch
	}
	return fmt.Sprintf("mode differs: %s %04o, disk %04o", exp[0].label, exp[0].mode, disk), verdictMismatch
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
	for _, vs := range [][]FileVerdict{r.Verified, r.Mismatch, r.Unverifiable, r.Suspicious} {
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
				v.Reason, v.Kind = "the package database holds no checksum for this file", KindNoChecksum
				s.res.Unverifiable = append(s.res.Unverifiable, v)
				continue
			}
			v.Expected = "md5:" + strings.ToLower(want)
			got, sum, err := hashLocal(root, cp)
			switch {
			case err != nil:
				v.Reason, v.Kind = "could not read the file: "+err.Error(), KindNotHashed
				s.res.Unverifiable = append(s.res.Unverifiable, v)
			case e.SHA256 != "" && sum != e.SHA256:
				v.Reason, v.Kind = "the file changed after it was collected", KindNotHashed
				s.res.Unverifiable = append(s.res.Unverifiable, v)
			case got == strings.ToLower(want):
				v.Actual = "md5:" + got
				s.res.Verified = append(s.res.Verified, v)
			default:
				v.Actual = "md5:" + got
				v.Reason, v.Kind = "differs from the checksum in the machine's package database", KindContentDiffers
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

// hashLocal returns the MD5 and SHA-256 of the regular file p below root.
func hashLocal(root, p string) (string, string, error) {
	f, err := openBeneath(root, p)
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	m, h := md5.New(), sha256.New()
	if _, err := io.Copy(io.MultiWriter(m, h), f); err != nil {
		return "", "", err
	}
	return hex.EncodeToString(m.Sum(nil)), hex.EncodeToString(h.Sum(nil)), nil
}

// openBeneath opens the regular file at absolute path p below root one
// component at a time, refusing "..", symlinks at any component and
// anything but a regular file at the end, without blocking on a FIFO.
func openBeneath(root, p string) (*os.File, error) {
	rel := strings.TrimPrefix(p, "/")
	parts := strings.Split(rel, "/")
	if !strings.HasPrefix(p, "/") || rel == "" {
		return nil, fmt.Errorf("%q: not an absolute path", p)
	}
	for _, seg := range parts {
		if seg == "" || seg == "." || seg == ".." || strings.ContainsRune(seg, 0) {
			return nil, fmt.Errorf("%q: unsafe path", p)
		}
	}
	dfd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: root, Err: err}
	}
	for _, seg := range parts[:len(parts)-1] {
		nfd, err := unix.Openat(dfd, seg, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(dfd)
		if err != nil {
			return nil, &os.PathError{Op: "open", Path: p, Err: err}
		}
		dfd = nfd
	}
	fd, err := unix.Openat(dfd, parts[len(parts)-1], unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	unix.Close(dfd)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: p, Err: err}
	}
	f := os.NewFile(uintptr(fd), p)
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("%q: not a regular file", p)
	}
	return f, nil
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

// maxVersionLen bounds a version string before any lookup; Debian versions
// are far shorter, and a long one only makes the lookups fail.
const maxVersionLen = 256

// validVersion reports whether v is a Debian version ([epoch:]upstream
// [-revision], as Debian policy allows) no longer than maxVersionLen. A
// version from dpkg status, which root can edit, that is not one is never
// looked up.
func validVersion(v string) bool {
	if v == "" || len(v) > maxVersionLen {
		return false
	}
	if i := strings.IndexByte(v, ':'); i >= 0 {
		if i == 0 || strings.Trim(v[:i], "0123456789") != "" {
			return false
		}
		v = v[i+1:]
	}
	upstream, revision := v, ""
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		upstream, revision = v[:i], v[i+1:]
		if revision == "" || strings.Trim(revision, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.+~") != "" {
			return false
		}
	}
	if upstream == "" || upstream[0] < '0' || upstream[0] > '9' {
		return false
	}
	return strings.Trim(upstream, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.+~-") == ""
}
