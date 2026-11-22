package pkgverify

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	pgperrors "github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ulikunitz/xz"
)

const (
	maxInReleaseSize    = 16 << 20
	maxPackagesXZSize   = 256 << 20
	maxSignaturePackets = 16
	maxPackagesLine     = 16 << 20
)

// maxPackagesSize bounds a decompressed Packages index; a variable so tests
// can lower it.
var maxPackagesSize int64 = 256 << 20

// Index fetches suite's InRelease, verifies its signature with the archive's
// keys and its Valid-Until, then fetches the Packages.xz (or, for archives
// that publish no xz index, Packages.gz or Packages) for component and arch,
// checks its size and SHA-256 against the signed Release, and returns every
// package in it. Architecture "all" packages in the index are keyed with Arch
// "all". A Release without that index gives ErrNoSuchIndex.
func (a *Archive) Index(ctx context.Context, suite, component, arch string) (map[PkgKey]DebRef, error) {
	if !slices.Contains(a.Suites, suite) {
		return nil, fmt.Errorf("%w: %q is not one of %s's suites %v", ErrWrongSuite, suite, a.BaseURL, a.Suites)
	}
	rel, err := a.release(ctx, suite)
	if err != nil {
		return nil, err
	}
	dir := component + "/binary-" + arch + "/"
	var name string
	var fh fileHash
	// Official archives publish Packages.xz; many third-party repositories
	// publish only Packages.gz or an uncompressed Packages.
	for _, n := range []string{"Packages.xz", "Packages.gz", "Packages"} {
		if h, ok := rel.sha256[dir+n]; ok {
			name, fh = n, h
			break
		}
	}
	if name == "" {
		return nil, fmt.Errorf("%w: %s %s: Release lists no SHA256 for %sPackages.xz", ErrNoSuchIndex, a.BaseURL, suite, dir)
	}
	if fh.size > maxPackagesXZSize {
		return nil, fmt.Errorf("%s %s: %s%s is %d bytes, larger than %d", a.BaseURL, suite, dir, name, fh.size, maxPackagesXZSize)
	}
	data, err := a.packagesFile(ctx, suite, dir, name, fh, rel.byHash)
	if err != nil {
		return nil, err
	}
	var r io.Reader = bytes.NewReader(data)
	switch name {
	case "Packages.xz":
		r, err = xz.NewReader(r)
	case "Packages.gz":
		r, err = gzip.NewReader(r)
	}
	if err != nil {
		return nil, fmt.Errorf("%s %s %s%s: %w", a.BaseURL, suite, dir, name, err)
	}
	lr := &io.LimitedReader{R: r, N: maxPackagesSize + 1}
	idx, err := parsePackages(lr, a.base(), arch)
	if lr.N <= 0 {
		return nil, fmt.Errorf("%s %s %s%s: decompressed index larger than %d bytes", a.BaseURL, suite, dir, name, maxPackagesSize)
	}
	if err != nil {
		return nil, fmt.Errorf("%s %s %s%s: %w", a.BaseURL, suite, dir, name, err)
	}
	return idx, nil
}

// Lookup finds name and version for arch in an index, falling back to the
// architecture-independent build.
func Lookup(idx map[PkgKey]DebRef, name, version, arch string) (DebRef, bool) {
	if ref, ok := idx[PkgKey{name, version, arch}]; ok {
		return ref, true
	}
	ref, ok := idx[PkgKey{name, version, "all"}]
	return ref, ok
}

type fileHash struct {
	hash string
	size int64
}

// release is the verified content of an InRelease file.
type release struct {
	suite, codename string
	validUntil      string
	byHash          bool
	sha256          map[string]fileHash
}

// release returns suite's verified Release, once per run when the archive
// has a memo.
func (a *Archive) release(ctx context.Context, suite string) (*release, error) {
	if a.memo == nil {
		return a.fetchRelease(ctx, suite)
	}
	e := a.memo.entry(suite)
	e.once.Do(func() { e.rel, e.err = a.fetchRelease(ctx, suite) })
	return e.rel, e.err
}

func (a *Archive) inReleaseURL(suite string) string {
	return a.base() + "/dists/" + suite + "/InRelease"
}

// download fetches suite's InRelease, once per run when the archive has a
// memo. It never reads the cache.
func (a *Archive) download(ctx context.Context, suite string) ([]byte, error) {
	if a.memo == nil {
		return httpGet(ctx, a.client(), a.inReleaseURL(suite), maxInReleaseSize)
	}
	e := a.memo.entry(suite)
	e.fetch.Do(func() { e.raw, e.fetchErr = httpGet(ctx, a.client(), a.inReleaseURL(suite), maxInReleaseSize) })
	return e.raw, e.fetchErr
}

// signedDate downloads suite's InRelease and returns its Date field, when
// the file is signed by one of the archive's keys. The signature is checked
// as of its own creation time, so the answer depends on no clock; the suite,
// Valid-Until and key expiry are checked later, against the newest such date
// (see signedClock).
// until is the file's Valid-Until, zero when it has none.
func (a *Archive) signedDate(ctx context.Context, suite string) (date, until time.Time, ok bool) {
	data, err := a.download(ctx, suite)
	if err != nil {
		return date, until, false
	}
	var signedAt time.Time // of the signature that verified: the last one tried
	text, err := verifyInReleaseAt(data, a.Keyring, func(created time.Time) (time.Time, error) {
		signedAt = created
		return created, nil
	})
	if err != nil {
		return date, until, false
	}
	defer func() {
		// A Date far after the signature that covers it witnesses nothing.
		if ok && date.After(signedAt.Add(signatureSlack)) {
			date, until, ok = time.Time{}, time.Time{}, false
		}
	}()
	for _, line := range strings.Split(string(text), "\n") {
		if v, found := strings.CutPrefix(line, "Date:"); found && !ok {
			t, err := parseReleaseDate(strings.TrimSpace(v))
			date, ok = t, err == nil
		}
		if v, found := strings.CutPrefix(line, "Valid-Until:"); found && until.IsZero() {
			until, _ = parseReleaseDate(strings.TrimSpace(v))
		}
	}
	return date, until, ok
}

// fetchRelease returns suite's verified Release. A fresh download is
// preferred; the cached copy is used (verified again) when the archive cannot
// be reached, and always for historical archives, whose indexes never change.
func (a *Archive) fetchRelease(ctx context.Context, suite string) (*release, error) {
	url := a.inReleaseURL(suite)
	cache := a.cachePath("inrelease-" + hashHex([]byte(url)))
	if a.Historical {
		if data := readCache(cache, maxInReleaseSize); data != nil {
			if rel, err := a.verifyRelease(data, suite); err == nil {
				return rel, nil
			}
		}
	}
	data, fetchErr := a.download(ctx, suite)
	if fetchErr != nil {
		data = readCache(cache, maxInReleaseSize)
		if data == nil {
			return nil, fetchErr
		}
		rel, err := a.verifyRelease(data, suite)
		if err != nil {
			return nil, fmt.Errorf("%s: download failed (%v) and the cached copy does not verify: %w", url, fetchErr, err)
		}
		return rel, nil
	}
	rel, err := a.verifyRelease(data, suite)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", url, err)
	}
	writeCache(cache, data)
	return rel, nil
}

// verifyRelease checks data's signature, suite and Valid-Until.
func (a *Archive) verifyRelease(data []byte, suite string) (*release, error) {
	now, signed := a.now()
	at := func(time.Time) (time.Time, error) { return now, nil }
	if signed {
		// now is the newest signed Date of this run. A signature may be
		// dated a little after it; the keys are judged at the later time.
		at = func(created time.Time) (time.Time, error) {
			if created.After(now.Add(signatureSlack)) {
				return now, fmt.Errorf("signature dated %s, more than a day after the newest signed index date %s",
					created.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
			}
			if created.After(now) {
				return created, nil
			}
			return now, nil
		}
	}
	text, err := verifyInReleaseAt(data, a.Keyring, at)
	if err != nil {
		return nil, err
	}
	rel, err := parseRelease(text)
	if err != nil {
		return nil, err
	}
	if !suiteMatches(rel, suite) {
		return nil, fmt.Errorf("%w: signed index is for suite %q (codename %q), not %q", ErrWrongSuite, rel.suite, rel.codename, suite)
	}
	if rel.validUntil != "" && !a.Historical {
		until, err := parseReleaseDate(rel.validUntil)
		if err != nil {
			return nil, fmt.Errorf("%w: unreadable Valid-Until %q", ErrExpiredIndex, rel.validUntil)
		}
		if now.After(until) {
			what := "now"
			if signed {
				what = "the newest signed index is dated"
			}
			return nil, fmt.Errorf("%w: valid until %s, %s %s", ErrExpiredIndex, until.UTC().Format(time.RFC3339), what, now.UTC().Format(time.RFC3339))
		}
	}
	return rel, nil
}

// suiteMatches accepts a Release for suite when its Suite is suite, or when
// its Codename is suite and its Suite names the same pocket. Ubuntu gives
// every pocket of a release the same Codename ("noble"), so a Codename match
// alone would let a signed noble-proposed index stand in for noble. Debian
// puts the pocket in Codename ("bookworm-updates") and Suite carries it too
// ("oldstable-updates", or plain "proposed-updates" for stable's).
func suiteMatches(rel *release, suite string) bool {
	if rel.suite == suite {
		return true
	}
	if rel.codename != suite {
		return false
	}
	_, pocket, ok := strings.Cut(suite, "-")
	if !ok {
		return !strings.Contains(rel.suite, "-")
	}
	return rel.suite == pocket || strings.HasSuffix(rel.suite, "-"+pocket)
}

// strongHashes are the signature hash algorithms accepted on an InRelease:
// SHA-256 and stronger, as apt requires.
var strongHashes = map[crypto.Hash]bool{
	crypto.SHA256:   true,
	crypto.SHA384:   true,
	crypto.SHA512:   true,
	crypto.SHA3_256: true,
	crypto.SHA3_512: true,
}

// checkSignature verifies one signature packet over signed with the keys in
// kr, refusing hash algorithms weaker than SHA-256. at gives the time to
// judge the signature and the keys at, from when the signature was made.
func checkSignature(kr openpgp.EntityList, signed, pkt []byte, at func(created time.Time) (time.Time, error)) error {
	p, err := packet.Read(bytes.NewReader(pkt))
	if err != nil {
		return err
	}
	sig, ok := p.(*packet.Signature)
	if !ok {
		return errors.New("not a signature packet")
	}
	if !strongHashes[sig.Hash] {
		return fmt.Errorf("signature hash %v is weaker than SHA-256", sig.Hash)
	}
	now, err := at(sig.CreationTime)
	if err != nil {
		return err
	}
	cfg := &packet.Config{Time: func() time.Time { return now }}
	_, err = openpgp.CheckDetachedSignature(kr, bytes.NewReader(signed), bytes.NewReader(pkt), cfg)
	return err
}

// verifyInRelease checks that data is exactly one clearsigned message with at
// least one signature, hashed with SHA-256 or stronger, by a key in kr that is
// valid at now, and returns the signed text. Nothing outside the signed text
// is ever returned.
func verifyInRelease(data []byte, kr openpgp.EntityList, now time.Time) ([]byte, error) {
	return verifyInReleaseAt(data, kr, func(time.Time) (time.Time, error) { return now, nil })
}

// verifyInReleaseAt is verifyInRelease with the time chosen per signature:
// at receives when the signature says it was made.
func verifyInReleaseAt(data []byte, kr openpgp.EntityList, at func(created time.Time) (time.Time, error)) ([]byte, error) {
	data = bytes.TrimLeft(data, " \t\r\n")
	if !bytes.HasPrefix(data, []byte("-----BEGIN PGP SIGNED MESSAGE-----")) {
		return nil, fmt.Errorf("%w: does not start with a clearsigned message", ErrMalformedInRelease)
	}
	block, rest := clearsign.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%w: cannot decode the clearsigned message", ErrMalformedInRelease)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("%w: data after the signature", ErrMalformedInRelease)
	}
	sigs, err := io.ReadAll(io.LimitReader(block.ArmoredSignature.Body, 1<<20+1))
	if err != nil || len(sigs) > 1<<20 {
		return nil, fmt.Errorf("%w: unreadable signature block", ErrMalformedInRelease)
	}
	pkts, err := signaturePackets(sigs)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedInRelease, err)
	}
	if len(pkts) == 0 || len(pkts) > maxSignaturePackets {
		return nil, fmt.Errorf("%w: %d signatures", ErrMalformedInRelease, len(pkts))
	}
	var bad, invalid error
	// Every signature covers the same text, so the first good signature by
	// a built-in key settles it; failures only explain why none was good.
	for _, p := range pkts {
		err := checkSignature(kr, block.Bytes, p, at)
		if err == nil {
			return block.Plaintext, nil
		}
		var sigErr pgperrors.SignatureError
		switch {
		case errors.As(err, &sigErr), errors.Is(err, pgperrors.ErrKeyRevoked):
			if bad == nil {
				bad = err
			}
		case invalid == nil || errors.Is(invalid, pgperrors.ErrUnknownIssuer):
			invalid = err
		}
	}
	if bad != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadSignature, bad)
	}
	return nil, fmt.Errorf("%w: %v", ErrNoValidSignature, invalid)
}

// signaturePackets splits a binary OpenPGP signature block into its packets
// and returns the signature packets, so each signature is checked on its own.
func signaturePackets(b []byte) ([][]byte, error) {
	var out [][]byte
	for len(b) > 0 {
		tag, hlen, blen, err := packetHeader(b)
		if err != nil {
			return nil, err
		}
		if uint64(hlen)+blen > uint64(len(b)) {
			return nil, errors.New("truncated packet")
		}
		end := hlen + int(blen)
		if tag == 2 {
			out = append(out, b[:end])
		}
		b = b[end:]
	}
	return out, nil
}

// packetHeader parses an OpenPGP packet header (RFC 9580 section 4.2).
func packetHeader(b []byte) (tag byte, hlen int, blen uint64, err error) {
	short := errors.New("truncated packet header")
	if b[0]&0x80 == 0 {
		return 0, 0, 0, errors.New("not an OpenPGP packet")
	}
	if b[0]&0x40 != 0 { // new format
		tag = b[0] & 0x3f
		if len(b) < 2 {
			return 0, 0, 0, short
		}
		switch l := b[1]; {
		case l < 192:
			return tag, 2, uint64(l), nil
		case l < 224:
			if len(b) < 3 {
				return 0, 0, 0, short
			}
			return tag, 3, (uint64(l)-192)<<8 + uint64(b[2]) + 192, nil
		case l == 255:
			if len(b) < 6 {
				return 0, 0, 0, short
			}
			return tag, 6, uint64(binary.BigEndian.Uint32(b[2:6])), nil
		default:
			return 0, 0, 0, errors.New("partial-length packet in a signature block")
		}
	}
	tag = (b[0] >> 2) & 0x0f
	switch b[0] & 3 {
	case 0:
		if len(b) < 2 {
			return 0, 0, 0, short
		}
		return tag, 2, uint64(b[1]), nil
	case 1:
		if len(b) < 3 {
			return 0, 0, 0, short
		}
		return tag, 3, uint64(binary.BigEndian.Uint16(b[1:3])), nil
	case 2:
		if len(b) < 5 {
			return 0, 0, 0, short
		}
		return tag, 5, uint64(binary.BigEndian.Uint32(b[1:5])), nil
	default:
		return 0, 0, 0, errors.New("indeterminate-length packet in a signature block")
	}
}

// parseRelease reads the fields of a Release file that index lookup needs.
func parseRelease(text []byte) (*release, error) {
	rel := &release{sha256: map[string]fileHash{}}
	var field string
	for _, line := range strings.Split(string(text), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if field != "sha256" {
				continue
			}
			f := strings.Fields(line)
			if len(f) != 3 || !isHexLen(f[0], 64) {
				return nil, fmt.Errorf("malformed SHA256 entry %q", line)
			}
			size, err := strconv.ParseInt(f[1], 10, 64)
			if err != nil || size < 0 {
				return nil, fmt.Errorf("malformed SHA256 entry %q", line)
			}
			if _, dup := rel.sha256[f[2]]; !dup {
				rel.sha256[f[2]] = fileHash{hash: strings.ToLower(f[0]), size: size}
			}
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("malformed Release line %q", line)
		}
		field = strings.ToLower(strings.TrimSpace(name))
		value = strings.TrimSpace(value)
		switch field {
		case "suite":
			rel.suite = value
		case "codename":
			rel.codename = value
		case "valid-until":
			rel.validUntil = value
		case "acquire-by-hash":
			rel.byHash = strings.EqualFold(value, "yes")
		}
	}
	if len(rel.sha256) == 0 {
		return nil, errors.New("no SHA256 entries in the Release file")
	}
	return rel, nil
}

func isHexLen(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return false
		}
	}
	return true
}

// parseReleaseDate reads a Release date such as "Sun, 29 Nov 2026 08:11:14 UTC".
func parseReleaseDate(s string) (time.Time, error) {
	var err error
	for _, layout := range []string{time.RFC1123, time.RFC1123Z, "Mon, 2 Jan 2006 15:04:05 MST", "Mon, 2 Jan 2006 15:04:05 -0700"} {
		var t time.Time
		if t, err = time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, err
}

// packagesFile returns the index file name in dir (relative to the suite)
// whose size and SHA-256 the signed Release gives. The cache is keyed by that
// SHA-256, and every copy, cached or downloaded, is checked against it.
func (a *Archive) packagesFile(ctx context.Context, suite, dir, name string, fh fileHash, byHash bool) ([]byte, error) {
	cache := a.cachePath("packages-" + fh.hash + strings.TrimPrefix(name, "Packages"))
	if b := readCache(cache, fh.size); b != nil && int64(len(b)) == fh.size && hashHex(b) == fh.hash {
		return b, nil
	}
	base := a.base() + "/dists/" + suite + "/" + dir
	urls := []string{base + name}
	if byHash {
		// By-hash cannot race with an archive update between the InRelease
		// and the index download.
		urls = []string{base + "by-hash/SHA256/" + fh.hash, base + name}
	}
	var b []byte
	var err error
	for i, u := range urls {
		b, err = httpGet(ctx, a.client(), u, fh.size)
		if errors.Is(err, errTooLarge) {
			return nil, fmt.Errorf("%w: %s is larger than the %d bytes the signed Release gives", ErrHashMismatch, u, fh.size)
		}
		if errors.Is(err, errHTTPNotFound) && i < len(urls)-1 {
			continue
		}
		if err != nil {
			return nil, err
		}
		if int64(len(b)) != fh.size {
			return nil, fmt.Errorf("%w: %s is %d bytes, the signed Release gives %d", ErrHashMismatch, u, len(b), fh.size)
		}
		if got := hashHex(b); got != fh.hash {
			return nil, fmt.Errorf("%w: %s has SHA256 %s, the signed Release gives %s", ErrHashMismatch, u, got, fh.hash)
		}
		break
	}
	writeCache(cache, b)
	return b, nil
}

// parsePackages reads a Packages index and returns the packages for arch and
// "all" with absolute URLs below base. Entries without a usable Filename,
// Size or SHA256 are skipped.
func parsePackages(r io.Reader, base, arch string) (map[PkgKey]DebRef, error) {
	idx := map[PkgKey]DebRef{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), maxPackagesLine)
	var name, version, parch, filename, size, sum string
	flush := func() {
		defer func() { name, version, parch, filename, size, sum = "", "", "", "", "", "" }()
		if name == "" || version == "" || (parch != arch && parch != "all") || !isHexLen(sum, 64) || !safeFilename(filename) {
			return
		}
		n, err := strconv.ParseInt(size, 10, 64)
		if err != nil || n < 0 {
			return
		}
		key := PkgKey{name, version, parch}
		if _, dup := idx[key]; dup {
			return
		}
		idx[key] = DebRef{URL: base + "/" + filename, SHA256: strings.ToLower(sum), Size: n, Source: SourceArchive}
	}
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			continue
		}
		field, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch field {
		case "Package":
			name = value
		case "Version":
			version = value
		case "Architecture":
			parch = value
		case "Filename":
			filename = value
		case "Size":
			size = value
		case "SHA256":
			sum = value
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	flush()
	return idx, nil
}

// safeFilename accepts a relative pool path that stays below the archive
// root when appended to its URL.
func safeFilename(f string) bool {
	if f == "" || f[0] == '/' || strings.Contains(f, "://") {
		return false
	}
	for _, c := range f {
		if c <= ' ' || c == 0x7f || c == '\\' || c == '?' || c == '#' || c == '%' {
			return false
		}
	}
	for _, seg := range strings.Split(f, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}
