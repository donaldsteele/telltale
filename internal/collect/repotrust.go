package collect

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/repokeys"
)

const (
	repoTrustCheck = "apt_keys"
	// maxRepoTrust bounds how many (repository, suite) pairs are recorded.
	maxRepoTrust = 256
	// maxKeyringFiles bounds the files read from /etc/apt/trusted.gpg.d.
	maxKeyringFiles = 256
)

var hexFingerprint = regexp.MustCompile(`^(0[xX])?[0-9A-Fa-f]{16,64}!?$`)

// keyringReader reads keyring files of the examined machine, each once.
type keyringReader struct {
	root   string
	files  map[string][]model.KeyBlob
	global []model.KeyBlob
	gotAll bool
	skips  []model.Skip
	said   map[string]bool
}

func (k *keyringReader) skip(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	if !k.said[msg] {
		k.said[msg] = true
		k.skips = append(k.skips, model.Skip{Check: repoTrustCheck, Reason: msg})
	}
}

// readKeyFile reads a keyring file of at most repokeys.MaxFileSize bytes. A
// symbolic link is followed, a few times at most: keyrings in
// /etc/apt/trusted.gpg.d are often links into /usr/share/keyrings.
func (k *keyringReader) readKeyFile(mp string) ([]byte, error) {
	for hop := 0; hop < 8; hop++ {
		st, err := os.Lstat(filepath.Join(k.root, mp))
		if err != nil {
			return nil, err
		}
		if st.Mode()&os.ModeSymlink == 0 {
			return readRaw(k.root, mp, repokeys.MaxFileSize)
		}
		target, err := os.Readlink(filepath.Join(k.root, mp))
		if err != nil {
			return nil, err
		}
		if !path.IsAbs(target) {
			target = path.Join(path.Dir(mp), target)
		}
		mp = path.Clean(target)
	}
	return nil, errors.New("too many symbolic links")
}

// file returns the keys in one keyring file, nil when it cannot be used.
func (k *keyringReader) file(mp string) []model.KeyBlob {
	if keys, seen := k.files[mp]; seen {
		return keys
	}
	var keys []model.KeyBlob
	b, err := k.readKeyFile(mp)
	switch {
	case err != nil && err.Error() == "too large":
		k.skip("%s: larger than %d bytes; its keys were not recorded", mp, repokeys.MaxFileSize)
	case err != nil:
		k.skip("%s: %v; its keys were not recorded", mp, err)
	default:
		keys, err = repokeys.Parse(b)
		switch {
		case errors.Is(err, repokeys.ErrTooManyKeys):
			k.skip("%s: more than %d keys; only the first %d were recorded", mp, repokeys.MaxKeys, repokeys.MaxKeys)
		case err != nil:
			k.skip("%s: not an OpenPGP keyring (%v); its keys were not recorded", mp, err)
		}
	}
	k.files[mp] = keys
	return keys
}

// globalKeys returns every key apt accepts for a source that names none:
// /etc/apt/trusted.gpg and the .gpg and .asc files of
// /etc/apt/trusted.gpg.d.
func (k *keyringReader) globalKeys() []model.KeyBlob {
	if k.gotAll {
		return k.global
	}
	k.gotAll = true
	var files []string
	if _, err := os.Lstat(filepath.Join(k.root, "etc/apt/trusted.gpg")); err == nil {
		files = append(files, "/etc/apt/trusted.gpg")
	}
	ents, err := os.ReadDir(filepath.Join(k.root, "etc/apt/trusted.gpg.d"))
	if err != nil && !isNotExist(err) {
		k.skip("/etc/apt/trusted.gpg.d: %v", err)
	}
	var names []string
	for _, e := range ents {
		if n := e.Name(); strings.HasSuffix(n, ".gpg") || strings.HasSuffix(n, ".asc") {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	if len(names) > maxKeyringFiles {
		k.skip("/etc/apt/trusted.gpg.d: more than %d keyrings; only the first %d were read", maxKeyringFiles, maxKeyringFiles)
		names = names[:maxKeyringFiles]
	}
	for _, n := range names {
		files = append(files, "/etc/apt/trusted.gpg.d/"+n)
	}
	for _, f := range files {
		k.global = addKeys(k.global, k.file(f))
	}
	if len(k.global) > repokeys.MaxKeys {
		k.skip("the global APT keyring holds more than %d keys; only the first %d were recorded", repokeys.MaxKeys, repokeys.MaxKeys)
		k.global = k.global[:repokeys.MaxKeys]
	}
	return k.global
}

// addKeys appends the keys of more that dst does not hold yet.
func addKeys(dst, more []model.KeyBlob) []model.KeyBlob {
	for _, m := range more {
		if !slices.ContainsFunc(dst, func(d model.KeyBlob) bool { return d.Fingerprint == m.Fingerprint }) {
			dst = append(dst, m)
		}
	}
	return dst
}

// sourceKeys returns the keys apt accepts for one source and where they
// come from.
func (k *keyringReader) sourceKeys(src model.AptSource) ([]model.KeyBlob, string) {
	if src.InlineKey != "" {
		keys, err := repokeys.Parse([]byte(src.InlineKey))
		switch {
		case errors.Is(err, repokeys.ErrTooManyKeys):
			k.skip("%s: the embedded Signed-By holds more than %d keys; only the first %d were recorded", src.File, repokeys.MaxKeys, repokeys.MaxKeys)
		case err != nil:
			k.skip("%s: the embedded Signed-By key is not an OpenPGP keyring (%v)", src.File, err)
		}
		return keys, model.KeyOriginInline
	}
	if src.SignedBy == "inline" {
		k.skip("%s: the embedded Signed-By key could not be read", src.File)
		return nil, model.KeyOriginInline
	}
	if src.SignedBy == "" {
		return k.globalKeys(), model.KeyOriginGlobal
	}
	var keys []model.KeyBlob
	var paths, prints []string
	for _, v := range strings.FieldsFunc(src.SignedBy, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		switch {
		case strings.HasPrefix(v, "/"):
			p := path.Clean(v)
			paths = append(paths, p)
			keys = addKeys(keys, k.file(p))
		case hexFingerprint.MatchString(v):
			// A fingerprint: the key of the global keyring that has it.
			want := repokeys.NormalizeFingerprint(strings.TrimSuffix(v, "!"))
			prints = append(prints, want)
			for _, g := range k.globalKeys() {
				if strings.HasSuffix(g.Fingerprint, want) || keyHasSubkey(g, want) {
					keys = addKeys(keys, []model.KeyBlob{g})
				}
			}
		default:
			k.skip("%s: signed-by value %q is neither a path nor a fingerprint", src.File, v)
		}
	}
	if len(keys) > repokeys.MaxKeys {
		k.skip("%s: more than %d signing keys for one source; only the first %d were recorded", src.File, repokeys.MaxKeys, repokeys.MaxKeys)
		keys = keys[:repokeys.MaxKeys]
	}
	origin := model.KeyOriginSignedBy
	if len(paths) > 0 {
		origin += " " + strings.Join(paths, ",")
	}
	if len(prints) > 0 {
		origin += " fingerprint " + strings.Join(prints, ",") + " in the " + model.KeyOriginGlobal
	}
	return keys, origin
}

// keyHasSubkey reports whether one of the key's subkeys has the fingerprint.
func keyHasSubkey(b model.KeyBlob, fp string) bool {
	for _, e := range repokeys.Entities([]model.KeyBlob{b}) {
		for _, s := range e.Subkeys {
			if strings.HasSuffix(strings.ToUpper(fmt.Sprintf("%x", s.PublicKey.Fingerprint)), fp) {
				return true
			}
		}
	}
	return false
}

// aptRepoTrust records, for every suite of every third-party APT source
// (one that is not the distribution's own archive), the signing keys apt
// accepts for it: the keyring the source names with signed-by, as a file or
// embedded, or else every key of the global keyring. Sources are recorded
// even when no key could be read, with no keys.
//
// On a clean machine, in a snapshot, this is what later upgrades from the
// repository are verified with. Read from a machine under examination it
// proves nothing and is only compared with the snapshot's record.
func aptRepoTrust(root string, srcs []model.AptSource) ([]model.RepoTrust, []model.Skip) {
	k := &keyringReader{root: root, files: map[string][]model.KeyBlob{}, said: map[string]bool{}}
	var out []model.RepoTrust
	at := map[[2]string]int{}
	for _, src := range srcs {
		if len(src.Types) > 0 && !slices.Contains(src.Types, "deb") {
			continue
		}
		var keys []model.KeyBlob
		origin, read := "", false
		for _, uri := range src.URIs {
			u, ok := model.RepoURL(uri)
			if !ok || model.OfficialAptURI(uri) {
				continue
			}
			if !read {
				keys, origin = k.sourceKeys(src)
				read = true
			}
			for _, suite := range src.Suites {
				id := [2]string{u, suite}
				if i, dup := at[id]; dup {
					// The same repository and suite twice: apt accepts
					// the keys of either entry.
					out[i].Keys = addKeys(out[i].Keys, keys)
					for _, c := range src.Components {
						if !slices.Contains(out[i].Components, c) {
							out[i].Components = append(out[i].Components, c)
						}
					}
					if out[i].KeyOrigin != origin {
						out[i].KeyOrigin += "; " + origin
					}
					continue
				}
				if len(out) == maxRepoTrust {
					k.skip("more than %d third-party APT sources; the keys of the rest were not recorded", maxRepoTrust)
					return out, k.skips
				}
				at[id] = len(out)
				out = append(out, model.RepoTrust{URL: u, Suite: suite, Components: slices.Clone(src.Components), Keys: slices.Clone(keys), KeyOrigin: origin})
			}
		}
	}
	return out, k.skips
}
