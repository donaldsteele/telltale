package pkgverify

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
)

const (
	maxAPIAnswer = 16 << 20
	maxDebSize   = 4 << 30
	// maxSnapshotAttempts bounds how many signed snapshot indexes one lookup
	// may download before falling back.
	maxSnapshotAttempts = 4
)

// ubuntuSnapshotStart is the earliest moment snapshot.ubuntu.com serves.
var ubuntuSnapshotStart = time.Date(2023, 3, 1, 0, 0, 0, 0, time.UTC)

// OldFinder locates package versions the current archive no longer carries.
// It prefers a snapshot of the archive's signed indexes at the time the
// package was published, verified with the built-in keys like a live archive
// (Source "archive"). Only when no signed index can be had does it fall back
// to snapshot.debian.org's SHA-1 file API (Source "snapshot") or Launchpad
// (Source "launchpad"), both trusted through HTTPS alone. A signed chain that
// fails verification is an error, never a reason to fall back.
type OldFinder struct {
	Client         *http.Client
	Cache          string           // directory for downloaded indexes; empty means none
	Now            func() time.Time // clock for key expiry; nil means time.Now
	DebianSnapshot string           // https://snapshot.debian.org
	UbuntuSnapshot string           // https://snapshot.ubuntu.com
	Launchpad      string           // https://api.launchpad.net/devel
	DebianKeyring  openpgp.EntityList
	UbuntuKeyring  openpgp.EntityList
}

// NewOldFinder returns an OldFinder for the real snapshot services with the
// built-in keys.
func NewOldFinder(cacheDir string) (*OldFinder, error) {
	deb, err := DebianKeyring()
	if err != nil {
		return nil, err
	}
	ubu, err := UbuntuKeyring()
	if err != nil {
		return nil, err
	}
	return &OldFinder{
		Client:         defaultClient,
		Cache:          cacheDir,
		DebianSnapshot: "https://snapshot.debian.org",
		UbuntuSnapshot: "https://snapshot.ubuntu.com",
		Launchpad:      "https://api.launchpad.net/devel",
		DebianKeyring:  deb,
		UbuntuKeyring:  ubu,
	}, nil
}

// FindOld locates a package version that is gone from the current archive,
// using the real snapshot services and the built-in keys without a cache
// (NewOldFinder gives one that caches). distro is "debian" or "ubuntu".
func FindOld(ctx context.Context, key PkgKey, distro string) (DebRef, error) {
	f, err := NewOldFinder("")
	if err != nil {
		return DebRef{}, err
	}
	return f.Find(ctx, key, distro)
}

// Find locates key for distro ("debian" or "ubuntu").
func (f *OldFinder) Find(ctx context.Context, key PkgKey, distro string) (DebRef, error) {
	switch distro {
	case "debian":
		return f.findDebian(ctx, key)
	case "ubuntu":
		return f.findUbuntu(ctx, key)
	}
	return DebRef{}, fmt.Errorf("package verification does not support distribution %q", distro)
}

func (f *OldFinder) client() *http.Client {
	if f.Client != nil {
		return f.Client
	}
	return defaultClient
}

// tampered reports errors that show a signed chain was altered, as opposed to
// one that could not be followed.
func tampered(err error) bool {
	return errors.Is(err, ErrBadSignature) || errors.Is(err, ErrHashMismatch)
}

// fromSignedIndex looks key up in a snapshot of an archive at base.
func (f *OldFinder) fromSignedIndex(ctx context.Context, base, suite, component string, key PkgKey, kr openpgp.EntityList) (DebRef, error) {
	a := &Archive{BaseURL: base, Suites: []string{suite}, Keyring: kr, Client: f.client(), Cache: f.Cache, Now: f.Now, Historical: true}
	arch := key.Arch
	if arch == "all" {
		arch = "amd64" // every architecture's index carries the "all" packages
	}
	idx, err := a.Index(ctx, suite, component, arch)
	if err != nil {
		return DebRef{}, err
	}
	ref, ok := idx[key]
	if !ok {
		return DebRef{}, fmt.Errorf("%s/dists/%s: %w", base, suite, ErrNotFound)
	}
	return ref, nil
}

var (
	snapshotStamp = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z$`)
	componentName = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	debianRelease = regexp.MustCompile(`(?:[+~]deb|~bpo)([0-9]+)`)
)

// debianCodenames maps Debian major versions to codenames, for reading the
// "+deb12u1" and "~bpo12+1" version suffixes.
var debianCodenames = map[string]string{"11": "bullseye", "12": "bookworm", "13": "trixie", "14": "forky"}

// debianSnapshotSuites guesses which suites held version when snapshot first
// saw it in archive: a stable update enters <codename>-proposed-updates (or
// -security), a backport <codename>-backports, anything else unstable.
func debianSnapshotSuites(archive, version string) []string {
	var cn string
	if m := debianRelease.FindStringSubmatch(version); m != nil {
		cn = debianCodenames[m[1]]
	}
	switch {
	case archive == "debian-security" && cn != "":
		return []string{cn + "-security"}
	case archive == "debian-security":
		return []string{"trixie-security", "bookworm-security", "bullseye-security"}
	case cn != "" && strings.Contains(version, "~bpo"):
		return []string{cn + "-backports"}
	case cn != "":
		return []string{cn + "-proposed-updates", cn, cn + "-updates"}
	default:
		return []string{"unstable"}
	}
}

// poolComponent returns the archive component of a pool directory such as
// /pool/main/h/hello or /pool/updates/main/o/openssl.
func poolComponent(dir string) string {
	rest, ok := strings.CutPrefix(dir, "/pool/")
	if !ok {
		return ""
	}
	rest = strings.TrimPrefix(rest, "updates/")
	c, _, _ := strings.Cut(rest, "/")
	if !componentName.MatchString(c) {
		return ""
	}
	return c
}

type snapshotFileInfo struct {
	ArchiveName string `json:"archive_name"`
	FirstSeen   string `json:"first_seen"`
	Name        string `json:"name"`
	Path        string `json:"path"`
	Size        int64  `json:"size"`
}

func (f *OldFinder) findDebian(ctx context.Context, key PkgKey) (DebRef, error) {
	u := strings.TrimRight(f.DebianSnapshot, "/") + "/mr/binary/" + url.PathEscape(key.Name) + "/" + url.PathEscape(key.Version) + "/binfiles?fileinfo=1"
	b, err := httpGet(ctx, f.client(), u, maxAPIAnswer)
	if errors.Is(err, errHTTPNotFound) {
		return DebRef{}, fmt.Errorf("%s %s: %w on snapshot.debian.org", key.Name, key.Version, ErrNotFound)
	}
	if err != nil {
		return DebRef{}, err
	}
	var ans struct {
		Result []struct {
			Architecture string `json:"architecture"`
			Hash         string `json:"hash"`
		} `json:"result"`
		FileInfo map[string][]snapshotFileInfo `json:"fileinfo"`
	}
	if err := json.Unmarshal(b, &ans); err != nil {
		return DebRef{}, fmt.Errorf("%s: %w", u, err)
	}
	var hash string
	for _, r := range ans.Result {
		if r.Architecture == key.Arch {
			hash = strings.ToLower(r.Hash)
			break
		}
	}
	if !isHexLen(hash, 40) {
		return DebRef{}, fmt.Errorf("%s %s %s: %w on snapshot.debian.org", key.Name, key.Version, key.Arch, ErrNotFound)
	}
	infos := ans.FileInfo[hash]

	attempts := 0
	var lastErr error
	for _, fi := range infos {
		if fi.ArchiveName != "debian" && fi.ArchiveName != "debian-security" {
			continue
		}
		component := poolComponent(fi.Path)
		if !snapshotStamp.MatchString(fi.FirstSeen) || component == "" {
			continue
		}
		base := strings.TrimRight(f.DebianSnapshot, "/") + "/archive/" + fi.ArchiveName + "/" + fi.FirstSeen
		for _, suite := range debianSnapshotSuites(fi.ArchiveName, key.Version) {
			if attempts == maxSnapshotAttempts {
				break
			}
			attempts++
			ref, err := f.fromSignedIndex(ctx, base, suite, component, key, f.DebianKeyring)
			if err == nil {
				return ref, nil
			}
			if tampered(err) {
				return DebRef{}, err
			}
			lastErr = err
		}
	}
	ref, err := f.snapshotFile(ctx, hash, infos)
	if err != nil && lastErr != nil {
		return DebRef{}, fmt.Errorf("%w (no signed snapshot index either: %v)", err, lastErr)
	}
	return ref, err
}

// snapshotFile downloads snapshot.debian.org's file by SHA-1, checks it, and
// returns its SHA-256 so the caller can verify its own download the same way
// as for any other source.
func (f *OldFinder) snapshotFile(ctx context.Context, hash string, infos []snapshotFileInfo) (DebRef, error) {
	u := strings.TrimRight(f.DebianSnapshot, "/") + "/file/" + hash
	body, err := httpOpen(ctx, f.client(), u)
	if err != nil {
		return DebRef{}, err
	}
	defer body.Close()
	h1, h256 := sha1.New(), sha256.New()
	n, err := io.Copy(io.MultiWriter(h1, h256), io.LimitReader(body, maxDebSize+1))
	if err != nil {
		return DebRef{}, fmt.Errorf("%s: %w", u, err)
	}
	if n > maxDebSize {
		return DebRef{}, fmt.Errorf("%s: larger than %d bytes", u, int64(maxDebSize))
	}
	if len(infos) > 0 && infos[0].Size != n {
		return DebRef{}, fmt.Errorf("%w: %s is %d bytes, snapshot's API gives %d", ErrHashMismatch, u, n, infos[0].Size)
	}
	if got := hex.EncodeToString(h1.Sum(nil)); got != hash {
		return DebRef{}, fmt.Errorf("%w: %s has SHA-1 %s", ErrHashMismatch, u, got)
	}
	return DebRef{URL: u, SHA256: hex.EncodeToString(h256.Sum(nil)), Size: n, Source: SourceSnapshot}, nil
}

// launchpadBinary is one entry of Launchpad's getPublishedBinaries answer.
type launchpadBinary struct {
	Name             string `json:"binary_package_name"`
	Version          string `json:"binary_package_version"`
	DistroArchSeries string `json:"distro_arch_series_link"`
	Pocket           string `json:"pocket"`
	DatePublished    string `json:"date_published"`
	ArchSpecific     bool   `json:"architecture_specific"`
	Component        string `json:"component_name"`
	Self             string `json:"self_link"`
}

var pocketSuffix = map[string]string{"Release": "", "Updates": "-updates", "Security": "-security", "Proposed": "-proposed", "Backports": "-backports"}

func (f *OldFinder) findUbuntu(ctx context.Context, key PkgKey) (DebRef, error) {
	lp := strings.TrimRight(f.Launchpad, "/")
	q := url.Values{"ws.op": {"getPublishedBinaries"}, "binary_name": {key.Name}, "version": {key.Version}, "exact_match": {"true"}}
	u := lp + "/ubuntu/+archive/primary?" + q.Encode()
	b, err := httpGet(ctx, f.client(), u, maxAPIAnswer)
	if err != nil {
		return DebRef{}, err
	}
	var ans struct {
		Entries []launchpadBinary `json:"entries"`
	}
	if err := json.Unmarshal(b, &ans); err != nil {
		return DebRef{}, fmt.Errorf("%s: %w", u, err)
	}
	type match struct {
		launchpadBinary
		suite     string
		published time.Time
	}
	var matches []match
	for _, e := range ans.Entries {
		if e.Name != key.Name || e.Version != key.Version {
			continue
		}
		parts := strings.Split(strings.TrimRight(e.DistroArchSeries, "/"), "/")
		if len(parts) < 2 {
			continue
		}
		series, arch := parts[len(parts)-2], parts[len(parts)-1]
		if (key.Arch == "all" && e.ArchSpecific) || (key.Arch != "all" && arch != key.Arch) {
			continue
		}
		suffix, ok := pocketSuffix[e.Pocket]
		if !ok || !componentName.MatchString(series) {
			continue
		}
		published, _ := time.Parse(time.RFC3339Nano, e.DatePublished)
		matches = append(matches, match{e, series + suffix, published})
	}
	if len(matches) == 0 {
		return DebRef{}, fmt.Errorf("%s %s %s: %w on Launchpad", key.Name, key.Version, key.Arch, ErrNotFound)
	}
	// The first publication is the original upload.
	slices.SortStableFunc(matches, func(a, b match) int { return a.published.Compare(b.published) })

	attempts := 0
	for _, m := range matches {
		if m.published.Before(ubuntuSnapshotStart) || !componentName.MatchString(m.Component) {
			continue
		}
		// The archive's InRelease is written after the publisher run that
		// set date_published, so look a little later.
		for _, delay := range []time.Duration{time.Hour, 6 * time.Hour} {
			if attempts == maxSnapshotAttempts {
				break
			}
			attempts++
			stamp := m.published.Add(delay).UTC().Format("20060102T150405Z")
			base := strings.TrimRight(f.UbuntuSnapshot, "/") + "/ubuntu/" + stamp
			ref, err := f.fromSignedIndex(ctx, base, m.suite, m.Component, key, f.UbuntuKeyring)
			if err == nil {
				return ref, nil
			}
			if tampered(err) {
				return DebRef{}, err
			}
		}
	}
	return f.launchpadFile(ctx, key, matches[0].Self)
}

// launchpadFile asks Launchpad for the .deb's HTTPS URL, size and SHA-256.
func (f *OldFinder) launchpadFile(ctx context.Context, key PkgKey, self string) (DebRef, error) {
	lp := strings.TrimRight(f.Launchpad, "/")
	if !strings.HasPrefix(self, lp+"/") {
		return DebRef{}, fmt.Errorf("Launchpad entry %q is not below %s", self, lp)
	}
	u := self + "?ws.op=binaryFileUrls&include_meta=true"
	b, err := httpGet(ctx, f.client(), u, maxAPIAnswer)
	if err != nil {
		return DebRef{}, err
	}
	var files []struct {
		URL    string `json:"url"`
		Size   int64  `json:"size"`
		SHA256 string `json:"sha256"`
	}
	if err := json.Unmarshal(b, &files); err != nil {
		return DebRef{}, fmt.Errorf("%s: %w", u, err)
	}
	version := key.Version
	if _, v, ok := strings.Cut(version, ":"); ok {
		version = v // file names carry no epoch
	}
	want := key.Name + "_" + version + "_" + key.Arch + ".deb"
	for _, fl := range files {
		name, err := url.PathUnescape(path.Base(fl.URL))
		if err != nil || name != want {
			continue
		}
		if !strings.HasPrefix(fl.URL, "https://") || !isHexLen(fl.SHA256, 64) || fl.Size <= 0 {
			return DebRef{}, fmt.Errorf("Launchpad gives no HTTPS URL with a SHA-256 for %s: %q", want, fl.URL)
		}
		return DebRef{URL: fl.URL, SHA256: strings.ToLower(fl.SHA256), Size: fl.Size, Source: SourceLaunchpad}, nil
	}
	return DebRef{}, fmt.Errorf("Launchpad lists no file %s: %w", want, ErrNotFound)
}
