package vendorkeys

import (
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"

	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/repokeys"
)

var isDate = regexp.MustCompile(`^20[0-9]{2}-[01][0-9]-[0-3][0-9]$`)

func TestVendorKeysFileValid(t *testing.T) {
	table, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	if len(table.Vendors) == 0 {
		t.Fatal("no built-in vendors")
	}
	now := time.Now()
	names := map[string]bool{}
	for _, v := range table.Vendors {
		if names[v.Name] {
			t.Errorf("vendor %q is listed twice", v.Name)
		}
		names[v.Name] = true
		// Both sources are recorded, are HTTPS, and are not the same place.
		for what, u := range map[string]string{"key_source_url": v.KeySourceURL, "fingerprint_source_url": v.FingerprintSourceURL} {
			p, err := url.Parse(u)
			if err != nil || p.Scheme != "https" || p.Host == "" {
				t.Errorf("%s: %s %q is not an HTTPS address", v.Name, what, u)
			}
		}
		ku, _ := url.Parse(v.KeySourceURL)
		fu, _ := url.Parse(v.FingerprintSourceURL)
		if ku != nil && fu != nil && strings.EqualFold(ku.Host, fu.Host) {
			t.Errorf("%s: the key and its fingerprint come from the same host %s; that is one source, not two", v.Name, ku.Host)
		}
		if !isDate.MatchString(v.Retrieved) {
			t.Errorf("%s: retrieved %q is not a date", v.Name, v.Retrieved)
		}
		for _, p := range v.URLPatterns {
			if n, ok := model.RepoURL(p); !ok || n != p || !strings.HasPrefix(p, "https://") {
				t.Errorf("%s: pattern %q is not a normalised https address", v.Name, p)
			}
		}
		// Every pinned fingerprint is a full fingerprint with its key
		// embedded, and nothing else is in the vendor's keyring.
		if len(v.Fingerprints) == 0 || len(v.Keys()) != len(v.Fingerprints) {
			t.Errorf("%s: %d fingerprints, %d keys", v.Name, len(v.Fingerprints), len(v.Keys()))
		}
		for _, fp := range v.Fingerprints {
			if len(fp) != 40 || fp != repokeys.NormalizeFingerprint(fp) {
				t.Errorf("%s: %q is not a full upper-case fingerprint", v.Name, fp)
			}
			if !slices.ContainsFunc(v.Keys(), func(e *openpgp.Entity) bool { return repokeys.Fingerprint(e) == fp }) {
				t.Errorf("%s: no embedded key has the pinned fingerprint %s", v.Name, fp)
			}
			if slices.Contains(v.RetiredFingerprints, fp) {
				t.Errorf("%s: %s is both pinned and retired", v.Name, fp)
			}
		}
		for _, e := range v.Keys() {
			fp := repokeys.Fingerprint(e)
			if !v.Pinned(fp) {
				t.Errorf("%s: embedded key %s is not pinned", v.Name, fp)
			}
			if e.PrivateKey != nil {
				t.Errorf("%s: %s is a private key", v.Name, fp)
			}
			// No pinned key is expired when telltale is built.
			if exp, never := Expiry(e); !never && !exp.After(now) {
				t.Errorf("%s: the pinned key %s expired on %s", v.Name, fp, exp.Format("2006-01-02"))
			}
		}
	}
	// The vendors every desktop and server fleet has.
	for _, want := range []string{"Google Chrome", "Microsoft", "Docker"} {
		if !names[want] {
			t.Errorf("no entry for %s", want)
		}
	}
	// Each binds to its own addresses only.
	for u, want := range map[string]string{
		"https://dl.google.com/linux/chrome/deb":              "Google Chrome",
		"http://dl.google.com/linux/chrome/deb/":              "Google Chrome",
		"https://packages.microsoft.com/repos/code":           "Microsoft",
		"https://download.docker.com/linux/ubuntu":            "Docker",
		"https://dl.google.com/linux/chrome/debX":             "",
		"https://download.docker.com.evil.test/linux/ubuntu":  "",
		"https://example.test/dl.google.com/linux/chrome/deb": "",
	} {
		got := ""
		if m := table.Match(u); len(m) > 0 {
			got = m[0].Name
		}
		if got != want {
			t.Errorf("Match(%s) = %q, want %q", u, got, want)
		}
	}
}
