package repokeys

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/donaldsteele/telltale/internal/model"
)

func newKey(t *testing.T) *openpgp.Entity {
	t.Helper()
	e, err := openpgp.NewEntity("k", "", "k@example.test", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func binary(t *testing.T, private bool, es ...*openpgp.Entity) []byte {
	t.Helper()
	var b bytes.Buffer
	for _, e := range es {
		var err error
		if private {
			err = e.SerializePrivate(&b, nil)
		} else {
			err = e.Serialize(&b)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	return b.Bytes()
}

func armored(t *testing.T, typ string, data []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w, err := armor.Encode(&b, typ, nil)
	if err != nil {
		t.Fatal(err)
	}
	w.Write(data)
	w.Close()
	b.WriteByte('\n')
	return b.Bytes()
}

func TestParseReadsBinaryAndArmoredKeyrings(t *testing.T) {
	a, b := newKey(t), newKey(t)
	for name, data := range map[string][]byte{
		"binary":             binary(t, false, a, b),
		"armored, one block": armored(t, openpgp.PublicKeyType, binary(t, false, a, b)),
		"armored, two blocks": append(append([]byte("comment line\n"), armored(t, openpgp.PublicKeyType, binary(t, false, a))...),
			armored(t, openpgp.PublicKeyType, binary(t, false, b))...),
	} {
		keys, err := Parse(data)
		if err != nil || len(keys) != 2 || keys[0].Fingerprint != Fingerprint(a) || keys[1].Fingerprint != Fingerprint(b) {
			t.Errorf("%s: %d keys, err %v", name, len(keys), err)
			continue
		}
		back := Entities(keys)
		if len(back) != 2 || Fingerprint(back[0]) != Fingerprint(a) {
			t.Errorf("%s: the stored keys do not read back", name)
		}
	}
	for name, data := range map[string][]byte{
		"empty":             nil,
		"text":              []byte("not a key\n"),
		"armored signature": armored(t, "PGP SIGNATURE", []byte("x")),
		"too large":         bytes.Repeat([]byte{0}, MaxFileSize+1),
	} {
		if keys, err := Parse(data); err == nil {
			t.Errorf("%s: parsed %d keys", name, len(keys))
		}
	}
}

// Only the public part of a key is ever stored.
func TestParseDropsPrivateKeyMaterial(t *testing.T) {
	e := newKey(t)
	keys, err := Parse(binary(t, true, e))
	if err != nil || len(keys) != 1 {
		t.Fatalf("%d keys, err %v", len(keys), err)
	}
	for _, el := range Entities(keys) {
		if el.PrivateKey != nil {
			t.Errorf("the stored key holds a private key")
		}
	}
	if bytes.Equal(keys[0].Data, binary(t, true, e)) {
		t.Errorf("the private key was stored as it was")
	}
}

func TestParseKeepsAtMostMaxKeys(t *testing.T) {
	var es []*openpgp.Entity
	for i := 0; i < MaxKeys+2; i++ {
		es = append(es, newKey(t))
	}
	keys, err := Parse(binary(t, false, es...))
	if !errors.Is(err, ErrTooManyKeys) || len(keys) != MaxKeys {
		t.Errorf("%d keys, err %v; want %d and ErrTooManyKeys", len(keys), err, MaxKeys)
	}
	if got := Entities(append(keys, keys...)); len(got) != MaxKeys {
		t.Errorf("Entities returned %d keys, more than the cap", len(got))
	}
}

// A stored key is used only when it is the key its fingerprint names: the
// fingerprint is what reports show and compare.
func TestEntitiesRejectsAKeyUnderAnotherFingerprint(t *testing.T) {
	a, b := newKey(t), newKey(t)
	ka, _ := Blob(a)
	kb, _ := Blob(b)
	lie := model.KeyBlob{Fingerprint: ka.Fingerprint, Data: kb.Data}
	two := model.KeyBlob{Fingerprint: ka.Fingerprint, Data: append(append([]byte{}, ka.Data...), kb.Data...)}
	junk := model.KeyBlob{Fingerprint: ka.Fingerprint, Data: []byte("junk")}
	if got := Entities([]model.KeyBlob{lie, two, junk}); len(got) != 0 {
		t.Errorf("accepted %d mislabelled keys", len(got))
	}
	lower := model.KeyBlob{Fingerprint: "0x" + strings.ToLower(ka.Fingerprint), Data: ka.Data}
	if got := Entities([]model.KeyBlob{lower}); len(got) != 1 {
		t.Errorf("a fingerprint written in lower case with 0x was not recognised")
	}
}
