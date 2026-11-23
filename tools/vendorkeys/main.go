// Command vendorkeys maintains the vendor keys built into telltale
// (internal/pkgverify/vendorkeys).
//
// Usage, from the repository root:
//
//	go run ./tools/vendorkeys check          # compare every pin with the vendor's site
//	go run ./tools/vendorkeys show URL|FILE...   # print the keys at each HTTPS address or in each local file
//
// check fetches each vendor's key again from its key_source_url, compares
// the fingerprints found there with the pinned ones, and prints when each
// pinned key expires. It exits 1 when a pinned key has expired. A pin that
// expires within 90 days, a key the vendor no longer serves, a key the
// vendor serves that is not pinned (a rotation), new subkeys on a pinned key
// that the embedded copy lacks, a signing subkey that expires within 90
// days, an entry marked provisional, and a key address that cannot be
// fetched are warnings. A key that signs with subkeys has expired when its
// last signing subkey has, whatever its primary key allows.
//
// show is for adding a vendor: it prints the fingerprint, user IDs and
// expiry of every key at a URL. An entry may be added to vendors.json only
// when a fingerprint printed here matches one the vendor publishes somewhere
// else (a documentation or install page, or the key shipped in the vendor's
// own package); record both addresses in the entry. Never pin a fingerprint
// that was not checked against a second source.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"

	"github.com/donaldsteele/telltale/internal/pkgverify/vendorkeys"
	"github.com/donaldsteele/telltale/internal/repokeys"
)

// warnWithin is how long before a pinned key expires the check starts to
// warn.
const warnWithin = 90 * 24 * time.Hour

type fetcher func(ctx context.Context, url string) ([]byte, error)

func httpFetch(ctx context.Context, url string) ([]byte, error) {
	if !strings.HasPrefix(url, "https://") {
		return nil, fmt.Errorf("%s: not an HTTPS address", url)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "telltale-vendorkeys")
	c := &http.Client{Timeout: 60 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, repokeys.MaxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > repokeys.MaxFileSize {
		return nil, fmt.Errorf("%s: larger than %d bytes", url, repokeys.MaxFileSize)
	}
	return b, nil
}

func expiryText(t time.Time, never bool, now time.Time) string {
	switch {
	case never:
		return "does not expire"
	case !t.After(now):
		return "EXPIRED " + t.UTC().Format("2006-01-02")
	}
	return fmt.Sprintf("expires %s (in %d days)", t.UTC().Format("2006-01-02"), int(t.Sub(now).Hours()/24))
}

// check compares the table with what the vendors serve now. It returns the
// number of expired pinned keys and of warnings.
func check(ctx context.Context, w io.Writer, t *vendorkeys.Table, fetch fetcher, now time.Time) (expired, warnings int) {
	for _, v := range t.Vendors {
		fmt.Fprintf(w, "%s\n", v.Name)
		if v.Provisional {
			warnings++
			fmt.Fprintf(w, "  WARNING: PROVISIONAL entry: %s (check %s against %s)\n", v.Note, v.KeySourceURL, v.FingerprintSourceURL)
		}
		for _, e := range v.Keys() {
			fp := repokeys.Fingerprint(e)
			exp, never := vendorkeys.Expiry(e)
			fmt.Fprintf(w, "  pinned %s  %s\n", fp, expiryText(exp, never, now))
			switch {
			case never:
			case !exp.After(now):
				expired++
				fmt.Fprintf(w, "  ERROR: the pinned key %s has expired; fetch the vendor's current key and check its fingerprint against %s\n", fp, v.FingerprintSourceURL)
			case exp.Sub(now) < warnWithin:
				warnings++
				fmt.Fprintf(w, "  WARNING: the pinned key %s expires within 90 days\n", fp)
			}
			// Each key in it that can sign, with its own expiry: a vendor
			// that signs with subkeys adds a new one from time to time,
			// and the embedded copy must have it.
			for _, k := range vendorkeys.SigningKeys(e) {
				if !k.Subkey {
					continue // the line above
				}
				fmt.Fprintf(w, "    signing subkey %s  %s\n", k.Fingerprint, expiryText(k.Expires, k.Never, now))
				if !k.Never && k.Expires.After(now) && k.Expires.Sub(now) < warnWithin {
					warnings++
					fmt.Fprintf(w, "  WARNING: the signing subkey %s of %s expires within 90 days; fetch the key again once the vendor has added a newer one\n", k.Fingerprint, fp)
				}
			}
		}
		for _, fp := range v.RetiredFingerprints {
			fmt.Fprintf(w, "  retired %s  (known, not used to verify)\n", fp)
		}
		data, err := fetch(ctx, v.KeySourceURL)
		if err != nil {
			warnings++
			fmt.Fprintf(w, "  WARNING: could not fetch %s: %v\n", v.KeySourceURL, err)
			continue
		}
		el, err := repokeys.ReadEntities(data)
		if err != nil && !errors.Is(err, repokeys.ErrTooManyKeys) {
			warnings++
			fmt.Fprintf(w, "  WARNING: %s is not an OpenPGP keyring: %v\n", v.KeySourceURL, err)
			continue
		}
		var served []string
		for _, e := range el {
			fp := repokeys.Fingerprint(e)
			served = append(served, fp)
			for _, mine := range v.Keys() {
				if repokeys.Fingerprint(mine) != fp {
					continue
				}
				if extra := subkeysNotIn(e, mine); len(extra) > 0 {
					warnings++
					fmt.Fprintf(w, "  WARNING: %s now serves %s with subkeys the embedded copy lacks (%s); replace keys/%s with the served file\n", v.KeySourceURL, fp, strings.Join(extra, ", "), v.KeyFile)
				}
			}
		}
		for _, fp := range v.Fingerprints {
			if !slices.Contains(served, fp) {
				warnings++
				fmt.Fprintf(w, "  WARNING: %s no longer serves the pinned key %s (rotation?)\n", v.KeySourceURL, fp)
			}
		}
		for _, fp := range served {
			if !v.Known(fp) {
				warnings++
				fmt.Fprintf(w, "  WARNING: %s serves a key that is not pinned: %s (rotation? check it against %s before adding it)\n", v.KeySourceURL, fp, v.FingerprintSourceURL)
			}
		}
	}
	return expired, warnings
}

// subkeysNotIn lists the subkeys of served that mine does not have.
func subkeysNotIn(served, mine *openpgp.Entity) []string {
	var out []string
	for _, s := range served.Subkeys {
		fp := fmt.Sprintf("%X", s.PublicKey.Fingerprint)
		if !slices.ContainsFunc(mine.Subkeys, func(m openpgp.Subkey) bool { return fmt.Sprintf("%X", m.PublicKey.Fingerprint) == fp }) {
			out = append(out, fp)
		}
	}
	return out
}

// show prints the keys served at each URL.
func show(ctx context.Context, w io.Writer, urls []string, fetch fetcher, now time.Time) error {
	for _, u := range urls {
		var data []byte
		var err error
		if strings.Contains(u, "://") {
			data, err = fetch(ctx, u)
		} else {
			data, err = os.ReadFile(u)
		}
		if err != nil {
			return err
		}
		el, err := repokeys.ReadEntities(data)
		if err != nil && !errors.Is(err, repokeys.ErrTooManyKeys) {
			return fmt.Errorf("%s: %w", u, err)
		}
		fmt.Fprintf(w, "%s\n", u)
		for _, e := range el {
			exp, never := vendorkeys.Expiry(e)
			var ids []string
			for name := range e.Identities {
				ids = append(ids, name)
			}
			sort.Strings(ids)
			fmt.Fprintf(w, "  %s  created %s  %s  %s\n", repokeys.Fingerprint(e), e.PrimaryKey.CreationTime.UTC().Format("2006-01-02"), expiryText(exp, never, now), strings.Join(ids, "; "))
			for _, s := range e.Subkeys {
				life := "no expiry"
				if s.Sig != nil && s.Sig.KeyLifetimeSecs != nil && *s.Sig.KeyLifetimeSecs != 0 {
					life = "expires " + s.PublicKey.CreationTime.Add(time.Duration(*s.Sig.KeyLifetimeSecs)*time.Second).UTC().Format("2006-01-02")
				}
				fmt.Fprintf(w, "    subkey %X  created %s  %s  signing=%v revoked=%v\n", s.PublicKey.Fingerprint, s.PublicKey.CreationTime.UTC().Format("2006-01-02"), life,
					s.Sig != nil && s.Sig.FlagsValid && s.Sig.FlagSign, len(s.Revocations) > 0)
			}
		}
	}
	return nil
}

func main() {
	ctx := context.Background()
	now := time.Now()
	args := os.Args[1:]
	if len(args) == 0 {
		args = []string{"check"}
	}
	switch args[0] {
	case "check":
		t, err := vendorkeys.Builtin()
		if err != nil {
			fmt.Fprintln(os.Stderr, "vendorkeys:", err)
			os.Exit(1)
		}
		expired, warnings := check(ctx, os.Stdout, t, httpFetch, now)
		fmt.Printf("%d vendors, %d expired pinned keys, %d warnings\n", len(t.Vendors), expired, warnings)
		if expired > 0 {
			os.Exit(1)
		}
	case "show":
		if err := show(ctx, os.Stdout, args[1:], httpFetch, now); err != nil {
			fmt.Fprintln(os.Stderr, "vendorkeys:", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "usage: vendorkeys check | show URL|FILE...")
		os.Exit(2)
	}
}
