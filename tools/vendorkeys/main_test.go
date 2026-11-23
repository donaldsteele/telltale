package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/donaldsteele/telltale/internal/pkgverify/vendorkeys"
)

func key(t *testing.T, created time.Time, lifetime time.Duration) *openpgp.Entity {
	t.Helper()
	e, err := openpgp.NewEntity("v", "", "v@example.test", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, Time: func() time.Time { return created }, KeyLifetimeSecs: uint32(lifetime / time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func serialized(t *testing.T, es ...*openpgp.Entity) []byte {
	t.Helper()
	var b bytes.Buffer
	for _, e := range es {
		if err := e.Serialize(&b); err != nil {
			t.Fatal(err)
		}
	}
	return b.Bytes()
}

func TestCheckReportsExpiryAndRotation(t *testing.T) {
	now := time.Date(2026, 11, 22, 0, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	good := key(t, now.Add(-100*day), 0)
	soon := key(t, now.Add(-100*day), 130*day)   // 30 days left
	expired := key(t, now.Add(-100*day), 50*day) // 50 days ago
	rotated := key(t, now.Add(-10*day), 0)
	vendor := func(name string, e *openpgp.Entity) *vendorkeys.Vendor {
		v := vendorkeys.NewVendor(name, []string{"https://" + name + ".example.test/apt"}, openpgp.EntityList{e})
		v.KeySourceURL, v.FingerprintSourceURL = "https://"+name+".example.test/key", "https://docs."+name+".example.test/"
		return v
	}
	served := map[string][]byte{
		"https://good.example.test/key":    serialized(t, good),
		"https://soon.example.test/key":    serialized(t, soon),
		"https://expired.example.test/key": serialized(t, expired),
		"https://rotated.example.test/key": serialized(t, rotated),
	}
	fetch := func(_ context.Context, url string) ([]byte, error) {
		if b, ok := served[url]; ok {
			return b, nil
		}
		return nil, errors.New("HTTP 404")
	}
	run := func(vs ...*vendorkeys.Vendor) (int, int, string) {
		var out bytes.Buffer
		e, w := check(context.Background(), &out, &vendorkeys.Table{Vendors: vs}, fetch, now)
		return e, w, out.String()
	}
	if e, w, out := run(vendor("good", good)); e != 0 || w != 0 {
		t.Errorf("a valid, served key: %d expired, %d warnings\n%s", e, w, out)
	}
	if e, w, out := run(vendor("soon", soon)); e != 0 || w != 1 || !strings.Contains(out, "expires within 90 days") {
		t.Errorf("a key with 30 days left: %d expired, %d warnings\n%s", e, w, out)
	}
	if e, _, out := run(vendor("expired", expired)); e != 1 || !strings.Contains(out, "has expired") {
		t.Errorf("an expired key: %d expired\n%s", e, out)
	}
	// The vendor serves another key now: both halves of a rotation warn.
	if e, w, out := run(vendor("rotated", good)); e != 0 || w != 2 || !strings.Contains(out, "no longer serves the pinned key") || !strings.Contains(out, "not pinned") {
		t.Errorf("a rotated key: %d expired, %d warnings\n%s", e, w, out)
	}
	// An address that cannot be fetched is a warning, not a failure.
	if e, w, _ := run(vendor("gone", good)); e != 0 || w != 1 {
		t.Errorf("an unreachable key address: %d expired, %d warnings", e, w)
	}
}
