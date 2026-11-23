package visit

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"

	"github.com/donaldsteele/telltale/internal/store"
)

// serverKeySetting is the secret setting that holds the server's private
// key, sealed with the store's data key.
const serverKeySetting = "ssh_key"

// keyComment ends the server's authorized_keys line, so the owner can tell
// it apart from other keys for root.
const keyComment = "telltale-server"

// keyMu keeps two first uses in one process from making two keys.
var keyMu sync.Mutex

// ServerKey returns the server's SSH key and its authorized_keys line
// ("ssh-ed25519 AAAA... telltale-server"). On first use it generates an
// ed25519 key and stores it sealed in the secret setting ssh_key. This key
// is root on every enrolled machine: it never leaves the store unsealed
// except in memory.
func ServerKey(st *store.Store) (ssh.Signer, string, error) {
	keyMu.Lock()
	defer keyMu.Unlock()
	raw, err := st.SecretSetting(serverKeySetting)
	if err != nil {
		return nil, "", fmt.Errorf("visit: read the server key: %w", err)
	}
	if raw == nil {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, "", fmt.Errorf("visit: generate the server key: %w", err)
		}
		block, err := ssh.MarshalPrivateKey(priv, keyComment)
		if err != nil {
			return nil, "", fmt.Errorf("visit: encode the server key: %w", err)
		}
		raw = pem.EncodeToMemory(block)
		if err := st.SetSecretSetting(serverKeySetting, raw); err != nil {
			return nil, "", fmt.Errorf("visit: store the server key: %w", err)
		}
	}
	signer, err := ssh.ParsePrivateKey(raw)
	if err != nil {
		return nil, "", fmt.Errorf("visit: the stored server key is unreadable: %w", err)
	}
	return signer, authorizedLine(signer.PublicKey()) + " " + keyComment, nil
}

// authorizedLine is k as "type base64", the way authorized_keys and the
// machines table hold a key.
func authorizedLine(k ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
}
