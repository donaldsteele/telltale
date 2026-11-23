package store

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"filippo.io/age"
	"golang.org/x/crypto/chacha20poly1305"
)

// maxBlobSize bounds a decompressed blob so a corrupt row cannot exhaust memory.
const maxBlobSize = 512 << 20

// ErrWrongUnlock means the passphrase or key file does not open this store.
var ErrWrongUnlock = errors.New("wrong passphrase or key file: this store was sealed with a different one")

// ErrClosed means the store was closed: its data key is gone, so nothing can
// be sealed or opened any more.
var ErrClosed = errors.New("store: closed")

// scryptWorkFactor is the age scrypt cost; a variable so tests can lower it.
var scryptWorkFactor = 18

// newDataKey returns 32 random bytes.
func newDataKey() ([]byte, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// seal encrypts plain with XChaCha20-Poly1305 under a fresh random nonce,
// binding it to aad. The nonce is prepended to the result.
func seal(key, plain []byte, aad string) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plain)+aead.Overhead())
	if _, err := rand.Read(out); err != nil {
		return nil, err
	}
	return aead.Seal(out, out[:aead.NonceSize()], plain, []byte(aad)), nil
}

// open reverses seal. It fails when the key, the data or aad differ.
func open(key, blob []byte, aad string) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(blob) < aead.NonceSize()+aead.Overhead() {
		return nil, errors.New("store: blob too short")
	}
	n := aead.NonceSize()
	plain, err := aead.Open(nil, blob[:n], blob[n:], []byte(aad))
	if err != nil {
		return nil, fmt.Errorf("store: cannot decrypt %s: %w", aad, err)
	}
	return plain, nil
}

// seal seals plain with the store's data key, or fails with ErrClosed once
// the store is closed.
func (s *Store) seal(plain []byte, aad string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.key == nil {
		return nil, ErrClosed
	}
	return seal(s.key, plain, aad)
}

// open opens a blob with the store's data key, or fails with ErrClosed once
// the store is closed.
func (s *Store) open(blob []byte, aad string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.key == nil {
		return nil, ErrClosed
	}
	return open(s.key, blob, aad)
}

func (s *Store) sealJSON(v any, aad string) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if err := json.NewEncoder(zw).Encode(v); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return s.seal(buf.Bytes(), aad)
}

func (s *Store) openJSON(blob []byte, aad string, v any) error {
	plain, err := s.open(blob, aad)
	if err != nil {
		return err
	}
	zr, err := gzip.NewReader(bytes.NewReader(plain))
	if err != nil {
		return err
	}
	defer zr.Close()
	b, err := io.ReadAll(io.LimitReader(zr, maxBlobSize+1))
	if err != nil {
		return err
	}
	if len(b) > maxBlobSize {
		return errors.New("store: blob too large")
	}
	return json.Unmarshal(b, v)
}

// wrapKey seals the data key with age: scrypt for a passphrase, X25519 for a
// key file. A key file that does not exist is created (mode 0600) holding a
// new identity.
func wrapKey(key []byte, u Unlock) ([]byte, error) {
	var rcpt age.Recipient
	if u.Passphrase != "" {
		r, err := age.NewScryptRecipient(u.Passphrase)
		if err != nil {
			return nil, err
		}
		r.SetWorkFactor(scryptWorkFactor)
		rcpt = r
	} else {
		id, err := loadOrCreateIdentity(u.KeyFile)
		if err != nil {
			return nil, err
		}
		rcpt = id.Recipient()
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, rcpt)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(key); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func unwrapKey(wrapped []byte, u Unlock) ([]byte, error) {
	var id age.Identity
	if u.Passphrase != "" {
		i, err := age.NewScryptIdentity(u.Passphrase)
		if err != nil {
			return nil, err
		}
		id = i
	} else {
		i, err := readIdentity(u.KeyFile)
		if err != nil {
			return nil, err
		}
		id = i
	}
	r, err := age.Decrypt(bytes.NewReader(wrapped), id)
	if err != nil {
		var nm *age.NoIdentityMatchError
		if errors.As(err, &nm) || errors.Is(err, age.ErrIncorrectIdentity) {
			return nil, ErrWrongUnlock
		}
		return nil, fmt.Errorf("%w (%v)", ErrWrongUnlock, err)
	}
	key, err := io.ReadAll(io.LimitReader(r, 64))
	if err != nil {
		return nil, err
	}
	if len(key) != chacha20poly1305.KeySize {
		return nil, errors.New("store: unwrapped data key has the wrong size")
	}
	return key, nil
}

func readIdentity(path string) (*age.X25519Identity, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("store: key file: %w", err)
	}
	defer f.Close()
	// Like ssh with private keys: refuse a key file others can read.
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("store: key file %s is accessible by group or others (mode %04o); chmod 600 it", path, fi.Mode().Perm())
	}
	ids, err := age.ParseIdentities(f)
	if err != nil {
		return nil, fmt.Errorf("store: key file %s: %w", path, err)
	}
	for _, i := range ids {
		if x, ok := i.(*age.X25519Identity); ok {
			return x, nil
		}
	}
	return nil, fmt.Errorf("store: key file %s holds no X25519 identity", path)
}

func loadOrCreateIdentity(path string) (*age.X25519Identity, error) {
	if _, err := os.Stat(path); err == nil {
		return readIdentity(path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("store: create key file: %w", err)
	}
	_, werr := fmt.Fprintf(f, "# telltale server key\n# public key: %s\n%s\n", id.Recipient(), id)
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		os.Remove(path)
		return nil, werr
	}
	// Make the new name durable before the wrapped key is committed.
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		err = d.Sync()
		d.Close()
		if err != nil {
			return nil, err
		}
	}
	return id, nil
}

// checkKeyFile fails early on a key file that cannot work: unreadable, too
// open, or absent with no directory to create it in.
func checkKeyFile(path string) error {
	if path == "" {
		return nil
	}
	if _, err := os.Stat(path); err == nil {
		_, err := readIdentity(path)
		return err
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("store: key file: %w", err)
	}
	if fi, err := os.Stat(filepath.Dir(path)); err != nil || !fi.IsDir() {
		return fmt.Errorf("store: key file %s cannot be created: its directory does not exist", path)
	}
	return nil
}
