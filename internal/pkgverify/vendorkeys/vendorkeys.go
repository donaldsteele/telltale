// Package vendorkeys holds the signing keys of well-known third-party APT
// repositories (Google Chrome, Docker, Microsoft and so on), each pinned by
// fingerprint and bound to that vendor's repository addresses. With them a
// routine update from such a repository can be verified without the owner
// supplying a key and without trusting anything on the examined machine.
//
// A key is added only when the key fetched from the vendor's official HTTPS
// address matches a fingerprint the vendor publishes somewhere else: both
// addresses are recorded with the entry (vendors.json). tools/vendorkeys
// checks the pins against the vendors' sites.
package vendorkeys

import (
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/repokeys"
)

//go:embed vendors.json keys
var embedded embed.FS

// Vendor is one vendor's pinned keys and the repositories they vouch for.
type Vendor struct {
	Name string `json:"name"`
	// URLPatterns are repository address prefixes: scheme, host and path.
	// A pattern covers a repository whose address is the pattern itself or
	// continues it after a "/" (Match).
	URLPatterns []string `json:"url_patterns"`
	// Fingerprints are the pinned primary-key fingerprints, upper-case hex.
	Fingerprints []string `json:"fingerprints"`
	// RetiredFingerprints are keys of the vendor that telltale knows, checked
	// against two sources like the pinned ones, and does not verify with:
	// a key that has expired, or one of the vendor's other keys that
	// machines hold in the same keyring. They only keep such a key from
	// being reported as a stranger's (Known).
	RetiredFingerprints []string `json:"retired_fingerprints,omitempty"`
	// KeyFile names the embedded keyring, below keys/.
	KeyFile string `json:"key_file"`
	// KeySourceURL is the vendor's official HTTPS address the key was
	// fetched from; FingerprintSourceURL is the separate official place
	// that publishes the fingerprint it was checked against.
	KeySourceURL         string `json:"key_source_url"`
	FingerprintSourceURL string `json:"fingerprint_source_url"`
	// Retrieved is the date (YYYY-MM-DD) both were fetched and compared.
	Retrieved string `json:"retrieved"`
	// Provisional marks an entry whose second source was not read first
	// hand and must be checked again before a release; Note says why.
	Provisional bool   `json:"provisional,omitempty"`
	Note        string `json:"note,omitempty"`

	keys openpgp.EntityList
}

// Table is a set of vendors.
type Table struct {
	Vendors []*Vendor
}

// NewVendor makes a vendor from keys given directly (tests, or a table built
// by other means). Every key is pinned.
func NewVendor(name string, patterns []string, keys openpgp.EntityList) *Vendor {
	v := &Vendor{Name: name, URLPatterns: patterns, keys: keys}
	for _, e := range keys {
		v.Fingerprints = append(v.Fingerprints, repokeys.Fingerprint(e))
	}
	return v
}

// Keys returns the vendor's pinned keys.
func (v *Vendor) Keys() openpgp.EntityList { return v.keys }

// Pinned reports whether fp is one of the vendor's pinned fingerprints.
func (v *Vendor) Pinned(fp string) bool {
	return slices.Contains(v.Fingerprints, repokeys.NormalizeFingerprint(fp))
}

// Known reports whether fp is a key of the vendor telltale has checked:
// pinned or retired.
func (v *Vendor) Known(fp string) bool {
	return v.Pinned(fp) || slices.Contains(v.RetiredFingerprints, repokeys.NormalizeFingerprint(fp))
}

// load reads the vendor's keyring and keeps exactly the pinned keys. It is
// an error when a pinned fingerprint has no key in the file: a pin without
// its key vouches for nothing, and says the entry was not checked.
func (v *Vendor) load(data []byte) error {
	el, err := repokeys.ReadEntities(data)
	if err != nil {
		return fmt.Errorf("vendor %s: %s: %w", v.Name, v.KeyFile, err)
	}
	for i, fp := range v.Fingerprints {
		v.Fingerprints[i] = repokeys.NormalizeFingerprint(fp)
	}
	for i, fp := range v.RetiredFingerprints {
		v.RetiredFingerprints[i] = repokeys.NormalizeFingerprint(fp)
	}
	v.keys = nil
	for _, e := range el {
		if v.Pinned(repokeys.Fingerprint(e)) {
			v.keys = append(v.keys, e)
		}
	}
	for _, fp := range v.Fingerprints {
		if !slices.ContainsFunc(v.keys, func(e *openpgp.Entity) bool { return repokeys.Fingerprint(e) == fp }) {
			return fmt.Errorf("vendor %s: %s holds no key with the pinned fingerprint %s", v.Name, v.KeyFile, fp)
		}
	}
	if len(v.keys) == 0 {
		return fmt.Errorf("vendor %s: no pinned key", v.Name)
	}
	return nil
}

// Parse reads a vendors.json document; keyFile returns the content of a
// vendor's KeyFile.
func Parse(doc []byte, keyFile func(name string) ([]byte, error)) (*Table, error) {
	var vs []*Vendor
	if err := json.Unmarshal(doc, &vs); err != nil {
		return nil, fmt.Errorf("vendors.json: %w", err)
	}
	for _, v := range vs {
		if v.Name == "" || len(v.URLPatterns) == 0 || len(v.Fingerprints) == 0 || v.KeyFile == "" || strings.ContainsAny(v.KeyFile, "/\\") {
			return nil, fmt.Errorf("vendors.json: entry %q lacks a name, a URL pattern, a fingerprint or a key file", v.Name)
		}
		for _, p := range v.URLPatterns {
			if n, ok := model.RepoURL(p); !ok || n != p {
				return nil, fmt.Errorf("vendors.json: %s: URL pattern %q is not a normalised http(s) address", v.Name, p)
			}
		}
		data, err := keyFile(v.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("vendor %s: %w", v.Name, err)
		}
		if err := v.load(data); err != nil {
			return nil, err
		}
	}
	return &Table{Vendors: vs}, nil
}

var (
	builtinOnce sync.Once
	builtin     *Table
	builtinErr  error
)

// Builtin returns the vendors built into telltale.
func Builtin() (*Table, error) {
	builtinOnce.Do(func() {
		doc, err := embedded.ReadFile("vendors.json")
		if err != nil {
			builtinErr = err
			return
		}
		builtin, builtinErr = Parse(doc, func(name string) ([]byte, error) { return embedded.ReadFile("keys/" + name) })
	})
	return builtin, builtinErr
}

// Covers reports whether the repository address pattern covers repoURL: the
// two are equal, or repoURL continues pattern after a "/". So
// https://dl.google.com/linux/chrome/deb covers itself and
// https://dl.google.com/linux/chrome/deb/x, and not
// https://dl.google.com/linux/chrome/debX. Both are compared in normalised
// form (model.RepoURL), and http and https are the same repository: what is
// trusted is the signature on its index, not the transport.
func Covers(pattern, repoURL string) bool {
	p, ok1 := model.RepoURL(pattern)
	u, ok2 := model.RepoURL(repoURL)
	if !ok1 || !ok2 {
		return false
	}
	p, u = model.RepoAddress(p), model.RepoAddress(u)
	return u == p || strings.HasPrefix(u, p+"/")
}

// Match returns the vendors with a pattern that covers repoURL. A nil table
// has none.
func (t *Table) Match(repoURL string) []*Vendor {
	if t == nil {
		return nil
	}
	var out []*Vendor
	for _, v := range t.Vendors {
		if slices.ContainsFunc(v.URLPatterns, func(p string) bool { return Covers(p, repoURL) }) {
			out = append(out, v)
		}
	}
	return out
}

// SigningKey is one key of an OpenPGP key that can sign a repository index:
// the primary key, when it may sign, or a signing subkey that is not
// revoked.
type SigningKey struct {
	Fingerprint string // upper-case hex
	Subkey      bool
	// Expires is when it stops being valid, no later than the primary
	// key's own expiry; Never is true when that is unbounded.
	Expires time.Time
	Never   bool
}

// Expired reports whether the key is past its expiry at now.
func (k SigningKey) Expired(now time.Time) bool { return !k.Never && !k.Expires.After(now) }

// SigningKeys lists the keys of e that can sign, each with its own expiry.
// A revoked key, or one without a usable self-signature, has none.
func SigningKeys(e *openpgp.Entity) []SigningKey {
	if len(e.Revocations) > 0 {
		return nil
	}
	id := e.PrimaryIdentity()
	if id == nil || id.SelfSignature == nil {
		return nil
	}
	end := func(created time.Time, sig *packet.Signature) (time.Time, bool) {
		if sig.KeyLifetimeSecs == nil || *sig.KeyLifetimeSecs == 0 {
			return time.Time{}, true
		}
		return created.Add(time.Duration(*sig.KeyLifetimeSecs) * time.Second), false
	}
	primary, primaryNever := end(e.PrimaryKey.CreationTime, id.SelfSignature)
	var out []SigningKey
	if !id.SelfSignature.FlagsValid || id.SelfSignature.FlagSign {
		out = append(out, SigningKey{Fingerprint: repokeys.Fingerprint(e), Expires: primary, Never: primaryNever})
	}
	for _, sk := range e.Subkeys {
		if sk.Sig == nil || len(sk.Revocations) > 0 || !sk.Sig.FlagsValid || !sk.Sig.FlagSign {
			continue
		}
		t, never := end(sk.PublicKey.CreationTime, sk.Sig)
		// A subkey is no good after its primary key has expired.
		if !primaryNever && (never || t.After(primary)) {
			t, never = primary, false
		}
		out = append(out, SigningKey{Fingerprint: strings.ToUpper(hex.EncodeToString(sk.PublicKey.Fingerprint)), Subkey: true, Expires: t, Never: never})
	}
	return out
}

// Expiry returns when a key can no longer sign a repository index. A vendor
// whose key has signing subkeys signs with those (Google adds one about
// every year), so the answer is then the latest expiry among the subkeys,
// whatever the primary key could do by itself; otherwise it is the primary
// key's. never is true when that is unbounded. A key with nothing that can
// sign has expired at its creation.
func Expiry(e *openpgp.Entity) (t time.Time, never bool) {
	keys := SigningKeys(e)
	hasSub := slices.ContainsFunc(keys, func(k SigningKey) bool { return k.Subkey })
	found := false
	for _, k := range keys {
		if hasSub && !k.Subkey {
			continue
		}
		found = true
		if k.Never {
			never = true
		} else if k.Expires.After(t) {
			t = k.Expires
		}
	}
	if !found {
		return e.PrimaryKey.CreationTime, false
	}
	if never {
		return time.Time{}, true
	}
	return t, false
}

// Expires is the earliest Expiry among the vendor's pinned keys.
func (v *Vendor) Expires() (t time.Time, never bool) {
	never = true
	for _, e := range v.keys {
		kt, kn := Expiry(e)
		if kn {
			continue
		}
		if never || kt.Before(t) {
			t, never = kt, false
		}
	}
	return t, never
}
