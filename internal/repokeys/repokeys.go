// Package repokeys reads OpenPGP public keyrings of APT repositories into
// the form telltale stores and compares (model.KeyBlob), and back.
package repokeys

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"

	"github.com/donaldsteele/telltale/internal/model"
)

const (
	// MaxFileSize is the largest keyring file read.
	MaxFileSize = 1 << 20
	// MaxKeys is the most keys kept from one keyring, or for one
	// repository.
	MaxKeys = 64
)

// ErrTooManyKeys means a keyring holds more than MaxKeys keys; the first
// MaxKeys are still returned.
var ErrTooManyKeys = fmt.Errorf("more than %d keys", MaxKeys)

// Fingerprint returns the primary key's fingerprint in upper-case hex.
func Fingerprint(e *openpgp.Entity) string {
	return strings.ToUpper(hex.EncodeToString(e.PrimaryKey.Fingerprint))
}

// NormalizeFingerprint returns fp in upper-case hex without spaces or a
// leading 0x, as Fingerprint writes one.
func NormalizeFingerprint(fp string) string {
	fp = strings.ToUpper(strings.Join(strings.Fields(fp), ""))
	return strings.TrimPrefix(fp, "0X")
}

// ReadEntities reads a keyring, ASCII-armored (one or more blocks) or
// binary, of at most MaxFileSize bytes. Keys go-crypto cannot use are
// skipped. With more than MaxKeys keys it returns the first MaxKeys and
// ErrTooManyKeys.
func ReadEntities(data []byte) (openpgp.EntityList, error) {
	if len(data) > MaxFileSize {
		return nil, fmt.Errorf("keyring larger than %d bytes", MaxFileSize)
	}
	var out openpgp.EntityList
	add := func(r io.Reader) error {
		el, err := openpgp.ReadKeyRing(r)
		if err != nil && len(el) == 0 {
			return err
		}
		out = append(out, el...)
		return nil
	}
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	if bytes.HasPrefix(trimmed, []byte("-----BEGIN PGP")) {
		rest := trimmed
		var first error
		for blocks := 0; blocks < MaxKeys+1; blocks++ {
			i := bytes.Index(rest, []byte("-----BEGIN PGP"))
			if i < 0 {
				break
			}
			rest = rest[i:]
			end := bytes.Index(rest, []byte("-----END PGP"))
			if end < 0 {
				break
			}
			stop := end + bytes.IndexByte(rest[end:], '\n') + 1
			if stop <= end {
				stop = len(rest)
			}
			block, err := armor.Decode(bytes.NewReader(rest[:stop]))
			if err == nil && block.Type == openpgp.PublicKeyType {
				err = add(block.Body)
			} else if err == nil {
				err = fmt.Errorf("armored block is a %s, not a public key", block.Type)
			}
			if err != nil && first == nil {
				first = err
			}
			rest = rest[stop:]
		}
		if len(out) == 0 {
			if first == nil {
				first = errors.New("no OpenPGP public key")
			}
			return nil, first
		}
	} else if err := add(bytes.NewReader(data)); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, errors.New("no OpenPGP public key")
	}
	if len(out) > MaxKeys {
		return out[:MaxKeys], ErrTooManyKeys
	}
	return out, nil
}

// Blob serializes one key's public part.
func Blob(e *openpgp.Entity) (model.KeyBlob, error) {
	var buf bytes.Buffer
	if err := e.Serialize(&buf); err != nil {
		return model.KeyBlob{}, err
	}
	return model.KeyBlob{Fingerprint: Fingerprint(e), Data: buf.Bytes()}, nil
}

// Parse reads a keyring (see ReadEntities) into one KeyBlob per key, public
// parts only. With ErrTooManyKeys the first MaxKeys are returned.
func Parse(data []byte) ([]model.KeyBlob, error) {
	el, err := ReadEntities(data)
	if err != nil && !errors.Is(err, ErrTooManyKeys) {
		return nil, err
	}
	out := make([]model.KeyBlob, 0, len(el))
	for _, e := range el {
		b, berr := Blob(e)
		if berr != nil {
			continue // a key that cannot be written back is one that cannot be used
		}
		out = append(out, b)
	}
	if len(out) == 0 {
		return nil, errors.New("no usable OpenPGP public key")
	}
	return out, err
}

// Entities turns stored keys back into a keyring. A blob that does not parse
// to exactly the key its fingerprint names is left out: the fingerprint is
// what findings and comparisons show, and must be what is verified with.
// At most MaxKeys keys are returned.
func Entities(keys []model.KeyBlob) openpgp.EntityList {
	var out openpgp.EntityList
	for _, k := range keys {
		if len(out) == MaxKeys {
			break
		}
		if len(k.Data) > MaxFileSize {
			continue
		}
		el, err := openpgp.ReadKeyRing(bytes.NewReader(k.Data))
		if err != nil || len(el) != 1 || Fingerprint(el[0]) != NormalizeFingerprint(k.Fingerprint) {
			continue
		}
		out = append(out, el[0])
	}
	return out
}
