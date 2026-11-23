//go:build online

package pkgverify

import (
	"context"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"

	"github.com/donaldsteele/telltale/internal/pkgverify/vendorkeys"
)

// vendorArchive is a vendor's real repository, verified with the keys the
// built-in table binds to its address and with nothing else.
func vendorArchive(t *testing.T, base, suite string, comps ...string) *Archive {
	t.Helper()
	table, err := vendorkeys.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	var kr openpgp.EntityList
	for _, v := range table.Match(base) {
		kr = append(kr, v.Keys()...)
	}
	if len(kr) == 0 {
		t.Fatalf("no built-in vendor key covers %s", base)
	}
	return &Archive{BaseURL: base, Suites: []string{suite}, Components: comps, Keyring: kr, Client: defaultClient, memo: &releaseMemo{}}
}

// Google's real InRelease verifies with the pinned key, and the signed index
// it leads to lists Chrome.
func TestOnlineGoogleChromeVerifiesWithPinnedKey(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	a := vendorArchive(t, "https://dl.google.com/linux/chrome/deb", "stable", "main")
	idx, err := a.Index(ctx, "stable", "main", "amd64")
	if err != nil {
		t.Fatalf("Google's repository does not verify with the pinned key: %v", err)
	}
	found := false
	for k, ref := range idx {
		if k.Name == "google-chrome-stable" {
			found = true
			t.Logf("google-chrome-stable %s: %s (%d bytes)", k.Version, ref.URL, ref.Size)
			if len(ref.SHA256) != 64 || ref.Source != SourceArchive {
				t.Errorf("ref %+v", ref)
			}
		}
	}
	if !found {
		t.Errorf("google-chrome-stable is not in the signed index (%d packages)", len(idx))
	}
	// A key that is not Google's does not verify it.
	a.Keyring, a.memo = fakePublicKeyring(t), &releaseMemo{}
	if _, err := a.Index(ctx, "stable", "main", "amd64"); err == nil {
		t.Errorf("Google's index verified with an unrelated key")
	}
}

// Every built-in vendor's real repository verifies with its pinned keys.
func TestOnlineVendorRepositoriesVerifyWithPinnedKeys(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	for _, tc := range []struct{ vendor, base, suite, comp string }{
		{"Microsoft", "https://packages.microsoft.com/repos/code", "stable", "main"},
		{"Microsoft", "https://packages.microsoft.com/repos/edge", "stable", "main"},
		{"Microsoft", "https://packages.microsoft.com/debian/12/prod", "bookworm", "main"},
		{"Microsoft (2025 key)", "https://packages.microsoft.com/debian/13/prod", "trixie", "main"},
		{"Docker", "https://download.docker.com/linux/debian", "bookworm", "stable"},
		{"Docker", "https://download.docker.com/linux/ubuntu", "jammy", "stable"},
		{"HashiCorp", "https://apt.releases.hashicorp.com", "bookworm", "main"},
		{"GitHub CLI", "https://cli.github.com/packages", "stable", "main"},
		{"PostgreSQL PGDG", "https://apt.postgresql.org/pub/repos/apt", "bookworm-pgdg", "main"},
		{"Grafana", "https://apt.grafana.com", "stable", "main"},
		{"Elastic", "https://artifacts.elastic.co/packages/8.x/apt", "stable", "main"},
		{"Mozilla", "https://packages.mozilla.org/apt", "mozilla", "main"},
		{"Brave", "https://brave-browser-apt-release.s3.brave.com", "stable", "main"},
		{"1Password", "https://downloads.1password.com/linux/debian/amd64", "stable", "main"},
	} {
		a := vendorArchive(t, tc.base, tc.suite, tc.comp)
		idx, err := a.Index(ctx, tc.suite, tc.comp, "amd64")
		if err != nil {
			t.Errorf("%s: %s %s does not verify with the pinned keys: %v", tc.vendor, tc.base, tc.suite, err)
			continue
		}
		t.Logf("%s: %s %s verified, %d packages", tc.vendor, tc.base, tc.suite, len(idx))
	}
}
