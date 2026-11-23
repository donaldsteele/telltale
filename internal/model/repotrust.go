package model

import (
	"net/url"
	"strings"
)

// KeyBlob is one OpenPGP public key: the primary key with its user IDs and
// subkeys in binary form, and the primary key's fingerprint (upper-case
// hex).
type KeyBlob struct {
	Fingerprint string `json:"fingerprint"`
	Data        []byte `json:"data"`
}

// Where a RepoTrust's keys were found.
const (
	// KeyOriginSignedBy: the keyring file or files the source names.
	KeyOriginSignedBy = "signed-by"
	// KeyOriginInline: the key embedded in a deb822 source.
	KeyOriginInline = "signed-by (inline)"
	// KeyOriginGlobal: the source names no key, so apt accepts any key in
	// /etc/apt/trusted.gpg and /etc/apt/trusted.gpg.d for it.
	KeyOriginGlobal = "global keyring"
)

// RepoTrust records the signing keys a machine accepts for one suite of one
// third-party APT repository. In a snapshot, taken while the machine was
// clean and kept off it, it is what later upgrades from that repository are
// verified with. In the collection of a machine being examined it is only
// what that machine says, and is never used to verify anything: it is
// compared with the snapshot's to tell that the key changed.
type RepoTrust struct {
	// URL is the repository's address: scheme, host and path, no trailing
	// slash (RepoURL).
	URL        string    `json:"url"`
	Suite      string    `json:"suite"`
	Components []string  `json:"components,omitempty"`
	Keys       []KeyBlob `json:"keys"`
	KeyOrigin  string    `json:"key_origin"`
}

// Fingerprints lists the primary fingerprints of t's keys.
func (t RepoTrust) Fingerprints() []string {
	out := make([]string, 0, len(t.Keys))
	for _, k := range t.Keys {
		out = append(out, k.Fingerprint)
	}
	return out
}

// RepoURL normalises an APT source URI for comparison: lower-case scheme and
// host, the path without trailing slashes, and nothing else (no user name
// or password, query or fragment). ok is false for anything that is not an
// http or https URL with a host.
func RepoURL(uri string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(uri))
	if err != nil || u.Host == "" {
		return "", false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", false
	}
	p := strings.TrimRight(u.EscapedPath(), "/")
	return scheme + "://" + strings.ToLower(u.Host) + p, true
}

// OfficialAptURI reports whether an APT source URI is an official Debian or
// Ubuntu archive host, which telltale verifies with its built-in archive
// keys. Everything else is a third-party repository.
func OfficialAptURI(uri string) bool {
	u, err := url.Parse(uri)
	if err != nil {
		return false
	}
	h := strings.ToLower(u.Hostname())
	for _, d := range []string{"debian.org", "archive.ubuntu.com", "security.ubuntu.com", "ports.ubuntu.com"} {
		if h == d || strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	return false
}
