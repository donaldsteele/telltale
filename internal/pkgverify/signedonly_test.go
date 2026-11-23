package pkgverify

import (
	"context"
	"strings"
	"testing"

	"github.com/donaldsteele/telltale/internal/model"
)

// With SignedOnly (a carry-mode scan of the live machine, whose CA store and
// resolver the examined machine's root controls), a version only a source
// trusted through HTTPS alone could confirm is not found, never verified.
func TestVerifySignedOnlyRefusesHTTPSOnlySources(t *testing.T) {
	hello := buildDeb(t, "xz", nil, []debEntry{{name: "./usr/bin/hello", body: "hello 2.10\n", mode: 0o755}})

	t.Run("snapshot.debian.org file API", func(t *testing.T) {
		pkg := model.Package{Name: "hello", Version: "2.10-3", Arch: "amd64", Status: "install ok installed", Files: []string{"/usr/bin/hello"}}
		c := collectionOf(map[string]string{"/usr/bin/hello": "hello 2.10\n"}, pkg)
		f := newFixture(t, map[string][]fakePkg{"bookworm": nil})
		// The snapshot's index is signed by a key telltale does not have,
		// so only the file API can answer.
		for k, v := range debianSnapshot(t, otherKey(t), hello) {
			f.srv.set(k, v)
		}
		f.srv.set("/archive/debian/20221227T032939Z/pool/main/h/hello/hello_2.10-3_amd64.deb", hello)

		res := Verify(context.Background(), c, f.opts())
		wantPaths(t, "Verified", res.Verified, "/usr/bin/hello")
		if res.SignedOnly {
			t.Error("SignedOnly reported without the option")
		}

		opt := f.opts()
		opt.SignedOnly = true
		res = Verify(context.Background(), c, opt)
		wantPaths(t, "Verified", res.Verified)
		v, ok := find(res.Unverifiable, "/usr/bin/hello")
		if !ok || v.Kind != KindNotFound || !strings.Contains(v.Reason, "HTTPS alone") {
			t.Errorf("Unverifiable = %+v", res.Unverifiable)
		}
		if !res.SignedOnly {
			t.Error("the result does not say HTTPS-only sources were left out")
		}
		for _, s := range res.SourcesUsed {
			if strings.Contains(s, "file API") || strings.Contains(s, "over HTTPS") {
				t.Errorf("an HTTPS-only source was used: %q", s)
			}
		}
	})

	t.Run("Launchpad", func(t *testing.T) {
		pkg := model.Package{Name: "hello", Version: "2.10-3build1", Arch: "amd64", Status: "install ok installed", Files: []string{"/usr/bin/hello"}}
		c := collectionOf(map[string]string{"/usr/bin/hello": "hello 2.10\n"}, pkg)
		c.Host.OSID, c.Host.OSVersionID = "ubuntu", "24.04"
		f := newFixture(t, map[string][]fakePkg{"bookworm": nil})
		self := f.srv.URL + "/lp/ubuntu/+archive/primary/+binarypub"
		f.srv.set("/lp/ubuntu/+archive/primary", launchpadEntries(t, self))
		f.srv.set("/lp/ubuntu/+archive/primary/+binarypub/1", mustJSON(t, []map[string]any{
			{"url": "https://launchpad.net/ubuntu/+archive/primary/+files/hello_2.10-3build1_amd64.deb", "size": len(hello), "sha1": sha1hex(hello), "sha256": sha256hex(hello)},
		}))
		opt := f.opts()
		opt.SignedOnly = true
		res := Verify(context.Background(), c, opt)
		wantPaths(t, "Verified", res.Verified)
		v, ok := find(res.Unverifiable, "/usr/bin/hello")
		if !ok || v.Kind != KindNotFound || !strings.Contains(v.Reason, "HTTPS alone") {
			t.Errorf("Unverifiable = %+v", res.Unverifiable)
		}
		if n := f.srv.hitCount("/lp/ubuntu/+archive/primary/+binarypub/1"); n != 0 {
			t.Errorf("Launchpad's file list was asked %d times", n)
		}
	})
}
