package collect

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/repokeys"
	"github.com/donaldsteele/telltale/internal/snapshot"
)

func pgpKey(t *testing.T, name string) *openpgp.Entity {
	t.Helper()
	e, err := openpgp.NewEntity(name, "", name+"@example.test", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func binaryKeys(t *testing.T, es ...*openpgp.Entity) string {
	t.Helper()
	var b bytes.Buffer
	for _, e := range es {
		if err := e.Serialize(&b); err != nil {
			t.Fatal(err)
		}
	}
	return b.String()
}

func armoredKeys(t *testing.T, es ...*openpgp.Entity) string {
	t.Helper()
	var b bytes.Buffer
	w, err := armor.Encode(&b, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte(binaryKeys(t, es...)))
	w.Close()
	return b.String() + "\n"
}

// deb822Inline writes an armored key the way a deb822 Signed-By field embeds
// it: each line indented, an empty line as " .".
func deb822Inline(armored string) string {
	var out []string
	for _, l := range strings.Split(strings.TrimRight(armored, "\n"), "\n") {
		if l == "" {
			l = "."
		}
		out = append(out, " "+l)
	}
	return strings.Join(out, "\n") + "\n"
}

func trustFor(ts []model.RepoTrust, url, suite string) *model.RepoTrust {
	for i := range ts {
		if ts[i].URL == url && ts[i].Suite == suite {
			return &ts[i]
		}
	}
	return nil
}

func TestSnapshotRecordsRepoTrust(t *testing.T) {
	one, path822, inline, global, distro := pgpKey(t, "one"), pgpKey(t, "path822"), pgpKey(t, "inline"), pgpKey(t, "global"), pgpKey(t, "distro")
	var many []*openpgp.Entity
	for i := 0; i < repokeys.MaxKeys+3; i++ {
		many = append(many, pgpKey(t, "many"))
	}
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"etc/apt/sources.list": "deb http://deb.debian.org/debian bookworm main\n" +
			"deb [arch=amd64 signed-by=/usr/share/keyrings/one.gpg] HTTPS://DL.Example.test/linux/deb/ stable main extra\n" +
			"deb https://legacy.example.test/apt focal main\n" +
			"deb [signed-by=/usr/share/keyrings/huge.gpg] https://huge.example.test/apt stable main\n" +
			"deb [signed-by=/usr/share/keyrings/many.gpg] https://many.example.test/apt stable main\n" +
			"deb [signed-by=/usr/share/keyrings/absent.gpg] https://absent.example.test/apt stable main\n" +
			"deb [signed-by=/usr/share/keyrings/one.gpg] https://user:secret@creds.example.test/apt?x=1 stable main\n",
		"etc/apt/sources.list.d/v.sources": "Types: deb\nURIs: https://p.example.test/apt\nSuites: stable beta\nComponents: main\nSigned-By: /etc/apt/keyrings/p.asc\n\n" +
			"Types: deb\nURIs: https://i.example.test/apt\nSuites: stable\nComponents: main\nSigned-By:\n" + deb822Inline(armoredKeys(t, inline)) + "\n" +
			"Types: deb-src\nURIs: https://src.example.test/apt\nSuites: stable\nComponents: main\n",
		"usr/share/keyrings/one.gpg":        binaryKeys(t, one),
		"usr/share/keyrings/huge.gpg":       strings.Repeat("x", repokeys.MaxFileSize+1),
		"usr/share/keyrings/many.gpg":       binaryKeys(t, many...),
		"etc/apt/keyrings/p.asc":            armoredKeys(t, path822),
		"etc/apt/trusted.gpg.d/vendor.gpg":  binaryKeys(t, global),
		"etc/apt/trusted.gpg.d/debian.asc":  armoredKeys(t, distro),
		"etc/apt/trusted.gpg.d/ignored.txt": armoredKeys(t, one),
	})
	pk, skips := Packages(root)
	ts := pk.RepoTrust
	fp := repokeys.Fingerprint

	// The distribution's own archive is not a third-party repository.
	for _, tr := range ts {
		if strings.Contains(tr.URL, "debian.org") || strings.Contains(tr.URL, "src.example") {
			t.Errorf("recorded %s", tr.URL)
		}
	}
	// One-line signed-by; the URL is normalised.
	if tr := trustFor(ts, "https://dl.example.test/linux/deb", "stable"); tr == nil || tr.KeyOrigin != model.KeyOriginSignedBy+" /usr/share/keyrings/one.gpg" ||
		!slices.Equal(tr.Fingerprints(), []string{fp(one)}) || !slices.Equal(tr.Components, []string{"main", "extra"}) {
		t.Errorf("one-line signed-by: %+v", tr)
	} else if el := repokeys.Entities(tr.Keys); len(el) != 1 || fp(el[0]) != fp(one) {
		t.Errorf("the stored key does not read back")
	}
	// deb822 Signed-By as a path, for each suite.
	for _, suite := range []string{"stable", "beta"} {
		if tr := trustFor(ts, "https://p.example.test/apt", suite); tr == nil || !slices.Equal(tr.Fingerprints(), []string{fp(path822)}) || !strings.HasPrefix(tr.KeyOrigin, model.KeyOriginSignedBy) {
			t.Errorf("deb822 path, suite %s: %+v", suite, tr)
		}
	}
	// deb822 Signed-By with the key inline.
	if tr := trustFor(ts, "https://i.example.test/apt", "stable"); tr == nil || tr.KeyOrigin != model.KeyOriginInline || !slices.Equal(tr.Fingerprints(), []string{fp(inline)}) {
		t.Errorf("deb822 inline: %+v", tr)
	}
	// No signed-by: every key of the global keyring, and it says so.
	if tr := trustFor(ts, "https://legacy.example.test/apt", "focal"); tr == nil || tr.KeyOrigin != model.KeyOriginGlobal {
		t.Errorf("global keyring: %+v", tr)
	} else {
		got := tr.Fingerprints()
		slices.Sort(got)
		want := []string{fp(global), fp(distro)}
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("global keyring keys = %v, want %v", got, want)
		}
	}
	// Bounds: a keyring over 1 MiB is not read, one with too many keys is
	// cut at the cap, and both are said.
	if tr := trustFor(ts, "https://huge.example.test/apt", "stable"); tr == nil || len(tr.Keys) != 0 {
		t.Errorf("oversized keyring: %+v", tr)
	}
	if tr := trustFor(ts, "https://many.example.test/apt", "stable"); tr == nil || len(tr.Keys) != repokeys.MaxKeys {
		t.Errorf("keyring with too many keys: %+v", tr != nil)
	}
	if tr := trustFor(ts, "https://absent.example.test/apt", "stable"); tr == nil || len(tr.Keys) != 0 {
		t.Errorf("missing keyring: %+v", tr)
	}
	for _, want := range []string{"huge.gpg", "many.gpg", "absent.gpg"} {
		if !slices.ContainsFunc(skips, func(s model.Skip) bool { return strings.Contains(s.Reason, want) }) {
			t.Errorf("no skip names %s: %v", want, skips)
		}
	}
	// A password in the source line is never recorded.
	if tr := trustFor(ts, "https://creds.example.test/apt", "stable"); tr == nil {
		t.Errorf("source with credentials not recorded under its plain URL: %+v", ts)
	}
	for _, tr := range ts {
		if strings.Contains(tr.URL, "secret") {
			t.Errorf("credentials recorded: %s", tr.URL)
		}
	}

	// The snapshot keeps them.
	c := &model.Collection{Schema: model.CollectionSchema, Packages: pk}
	file := filepath.Join(t.TempDir(), "snap")
	if err := snapshot.WriteFile(file, snapshot.New(c, nil, []byte("k")), "pass"); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(file); st == nil {
		t.Fatal("no snapshot written")
	}
	back, err := snapshot.ReadFile(file, "pass")
	if err != nil {
		t.Fatal(err)
	}
	tr := trustFor(back.Collection.Packages.RepoTrust, "https://dl.example.test/linux/deb", "stable")
	if tr == nil || len(repokeys.Entities(tr.Keys)) != 1 {
		t.Errorf("the snapshot lost the repository's key: %+v", tr)
	}
}
