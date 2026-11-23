package server

import (
	"testing"

	"github.com/donaldsteele/telltale/internal/repokeys"
)

// A repository key the owner added on the server reaches package
// verification on every visit, bound to the repository address it was added
// for, never as a key for any repository.
func TestOwnerKeysReachPackageVerification(t *testing.T) {
	fx := newFixture(t)
	key, fp := armoredKey(t, false)
	if _, err := AddOwnerKey(fx.st, key, "https://download.docker.com/linux/debian", t0); err != nil {
		t.Fatal(err)
	}
	for visit := 1; visit <= 2; visit++ {
		fx.visitOK(t, fx.id)
		opt := fx.lastVerify(t)
		if len(opt.ExtraKeys) != 0 {
			t.Errorf("visit %d: the owner's key went in as an unscoped extra key", visit)
		}
		if len(opt.OwnerKeys) != 1 {
			t.Fatalf("visit %d: OwnerKeys = %+v, want the one key", visit, opt.OwnerKeys)
		}
		ok := opt.OwnerKeys[0]
		if ok.URLPattern != "https://download.docker.com/linux/debian" {
			t.Errorf("visit %d: URLPattern = %q", visit, ok.URLPattern)
		}
		if len(ok.Keys) != 1 || repokeys.Fingerprint(ok.Keys[0]) != fp {
			t.Errorf("visit %d: keys %v, want %s", visit, ok.Keys, fp)
		}
		if visit == 1 {
			if err := fx.core.MarkClean(t.Context(), fx.id, fx.latestReport(t)); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Removed: gone from the next visit.
	keys, _ := OwnerKeys(fx.st)
	if err := RemoveOwnerKey(fx.st, keys[0].ID); err != nil {
		t.Fatal(err)
	}
	fx.visitOK(t, fx.id)
	if opt := fx.lastVerify(t); len(opt.OwnerKeys) != 0 {
		t.Errorf("a removed key still reaches verification: %+v", opt.OwnerKeys)
	}
}

func (fx *fixture) latestReport(t *testing.T) int64 {
	t.Helper()
	metas, err := fx.st.Reports(fx.id, 1)
	if err != nil || len(metas) == 0 {
		t.Fatalf("no report: %v", err)
	}
	return metas[0].ID
}
