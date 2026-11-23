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
	// An entry marked provisional is said every time.
	prov := vendor("good", good)
	prov.Provisional, prov.Note = true, "second source not read first hand"
	if e, w, out := run(prov); e != 0 || w != 1 || !strings.Contains(out, "PROVISIONAL") || !strings.Contains(out, prov.Note) {
		t.Errorf("a provisional entry: %d expired, %d warnings\n%s", e, w, out)
	}
	// A key that signs with subkeys: its primary key never expires, the one
	// signing subkey has 30 days left (a warning), then none (an error).
	withSub := func(left time.Duration) *openpgp.Entity {
		e := key(t, now.Add(-400*day), 0)
		created := now.Add(-100 * day)
		if err := e.AddSigningSubkey(&packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, Time: func() time.Time { return created }, KeyLifetimeSecs: uint32((100*day + left) / time.Second)}); err != nil {
			t.Fatal(err)
		}
		return e
	}
	subSoon, subGone := withSub(30*day), withSub(-10*day)
	served["https://subsoon.example.test/key"], served["https://subgone.example.test/key"] = serialized(t, subSoon), serialized(t, subGone)
	if e, w, out := run(vendor("subsoon", subSoon)); e != 0 || w != 2 || !strings.Contains(out, "signing subkey") {
		t.Errorf("a signing subkey with 30 days left: %d expired, %d warnings\n%s", e, w, out)
	}
	if e, _, out := run(vendor("subgone", subGone)); e != 1 {
		t.Errorf("a key whose only signing subkey expired: %d expired\n%s", e, out)
	}
	// An address that cannot be fetched is a warning, not a failure.
	if e, w, _ := run(vendor("gone", good)); e != 0 || w != 1 {
		t.Errorf("an unreachable key address: %d expired, %d warnings", e, w)
	}
}
