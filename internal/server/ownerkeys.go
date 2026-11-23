package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/pkgverify"
	"github.com/donaldsteele/telltale/internal/pkgverify/vendorkeys"
	"github.com/donaldsteele/telltale/internal/repokeys"
	"github.com/donaldsteele/telltale/internal/store"
)

// ownerKeysSetting is the sealed setting that holds the repository keys the
// owner added. They are public keys, but sealing them also means nobody
// with only the database file can add one.
const ownerKeysSetting = "owner_keys"

const (
	maxOwnerKeys      = 64
	maxKeysPerPaste   = 8
	maxArmoredKeySize = 256 << 10
)

// OwnerKey is a signing key the owner trusts for the third-party APT
// repositories one address covers (the address itself, or one that continues
// it after a "/"), the way a built-in vendor key is bound to its vendor's
// addresses. It is never used for any other repository.
type OwnerKey struct {
	ID         int64         `json:"id"`
	URLPattern string        `json:"url_pattern"`
	Key        model.KeyBlob `json:"key"`
	Added      time.Time     `json:"added"`
}

type ownerKeyList struct {
	Next int64      `json:"next"`
	Keys []OwnerKey `json:"keys"`
}

// ownerKeysMu serializes changes to the list within this process.
var ownerKeysMu sync.Mutex

func loadOwnerKeys(st *store.Store) (ownerKeyList, error) {
	var l ownerKeyList
	b, err := st.SecretSetting(ownerKeysSetting)
	if err != nil || len(b) == 0 {
		return l, err
	}
	if err := json.Unmarshal(b, &l); err != nil {
		return ownerKeyList{}, fmt.Errorf("server: the stored repository keys are unreadable: %w", err)
	}
	return l, nil
}

func saveOwnerKeys(st *store.Store, l ownerKeyList) error {
	b, err := json.Marshal(l)
	if err != nil {
		return err
	}
	return st.SetSecretSetting(ownerKeysSetting, b)
}

// OwnerKeys lists the repository keys the owner added, oldest first.
func OwnerKeys(st *store.Store) ([]OwnerKey, error) {
	l, err := loadOwnerKeys(st)
	return l.Keys, err
}

// AddOwnerKey adds the public keys in an ASCII-armored block as trusted for
// the repositories repoURL covers, and returns the entries it added. The
// address must be an http or https repository that is not an official
// Debian or Ubuntu archive (those are checked with telltale's built-in
// keys). A private key, a key that cannot sign, or a key already trusted
// for that address is refused.
func AddOwnerKey(st *store.Store, armored, repoURL string, now time.Time) ([]OwnerKey, error) {
	repoURL = strings.TrimSpace(repoURL)
	if repoURL == "" {
		return nil, errors.New("give the address of the repository the key signs, as it appears in the machines' APT sources")
	}
	pattern, ok := model.RepoURL(repoURL)
	if !ok {
		return nil, errors.New("the repository address must be an http or https address with a host, and no . or .. in its path")
	}
	if model.OfficialAptURI(pattern) {
		return nil, errors.New("that is an official Debian or Ubuntu archive; telltale checks those with its built-in keys only")
	}
	armored = strings.TrimSpace(armored)
	switch {
	case len(armored) > maxArmoredKeySize:
		return nil, fmt.Errorf("the key is larger than %d KiB", maxArmoredKeySize>>10)
	case strings.Contains(armored, "PRIVATE KEY BLOCK"):
		return nil, errors.New("that is a private key; paste only the repository's public key (and treat that private key as exposed)")
	case !strings.Contains(armored, "-----BEGIN PGP PUBLIC KEY BLOCK-----"):
		return nil, errors.New("paste the key as an ASCII-armored block, starting with -----BEGIN PGP PUBLIC KEY BLOCK-----")
	}
	el, err := repokeys.ReadEntities([]byte(armored))
	if err != nil {
		return nil, fmt.Errorf("no usable OpenPGP public key in that text: %v", err)
	}
	if len(el) > maxKeysPerPaste {
		return nil, fmt.Errorf("that block holds %d keys; add at most %d at a time", len(el), maxKeysPerPaste)
	}
	var blobs []model.KeyBlob
	for _, e := range el {
		if e.PrivateKey != nil {
			return nil, errors.New("that is a private key; paste only the repository's public key")
		}
		if len(vendorkeys.SigningKeys(e)) == 0 {
			return nil, fmt.Errorf("key %s cannot sign repository indexes (it is revoked or has no signing key)", repokeys.Fingerprint(e))
		}
		b, err := repokeys.Blob(e)
		if err != nil {
			return nil, fmt.Errorf("key %s cannot be stored: %v", repokeys.Fingerprint(e), err)
		}
		blobs = append(blobs, b)
	}
	ownerKeysMu.Lock()
	defer ownerKeysMu.Unlock()
	l, err := loadOwnerKeys(st)
	if err != nil {
		return nil, err
	}
	if len(l.Keys)+len(blobs) > maxOwnerKeys {
		return nil, fmt.Errorf("at most %d repository keys can be trusted; remove some first", maxOwnerKeys)
	}
	var added []OwnerKey
	for _, b := range blobs {
		if slices.ContainsFunc(l.Keys, func(k OwnerKey) bool { return k.Key.Fingerprint == b.Fingerprint && k.URLPattern == pattern }) {
			return nil, fmt.Errorf("key %s is already trusted for %s", b.Fingerprint, pattern)
		}
		l.Next++
		k := OwnerKey{ID: l.Next, URLPattern: pattern, Key: b, Added: now.UTC()}
		l.Keys = append(l.Keys, k)
		added = append(added, k)
	}
	if err := saveOwnerKeys(st, l); err != nil {
		return nil, err
	}
	return added, nil
}

// RemoveOwnerKey stops trusting one of the owner's repository keys.
func RemoveOwnerKey(st *store.Store, id int64) error {
	ownerKeysMu.Lock()
	defer ownerKeysMu.Unlock()
	l, err := loadOwnerKeys(st)
	if err != nil {
		return err
	}
	n := len(l.Keys)
	l.Keys = slices.DeleteFunc(l.Keys, func(k OwnerKey) bool { return k.ID == id })
	if len(l.Keys) == n {
		return fmt.Errorf("no repository key %d", id)
	}
	return saveOwnerKeys(st, l)
}

// verifyOwnerKeys is the owner's keys as package verification takes them,
// each bound to its address pattern. A stored key that no longer parses to
// its own fingerprint is left out (repokeys.Entities).
func verifyOwnerKeys(st *store.Store) ([]pkgverify.OwnerKey, error) {
	keys, err := OwnerKeys(st)
	if err != nil {
		return nil, err
	}
	var out []pkgverify.OwnerKey
	for _, k := range keys {
		if el := repokeys.Entities([]model.KeyBlob{k.Key}); len(el) > 0 {
			out = append(out, pkgverify.OwnerKey{URLPattern: k.URLPattern, Keys: el})
		}
	}
	return out, nil
}
