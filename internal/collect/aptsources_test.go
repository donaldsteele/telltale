package collect

import (
	"reflect"
	"testing"
)

func TestAptSourcesOneLineAndDeb822(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"etc/apt/sources.list": `# comment
deb http://deb.debian.org/debian bookworm main contrib
deb-src [arch=amd64 signed-by=/usr/share/keyrings/x.gpg] https://example.com/apt stable main # trailing
`,
		"etc/apt/sources.list.d/extra.list": "deb http://x.test/ y z\n",
		"etc/apt/sources.list.d/d.sources": `Types: deb deb-src
URIs: https://a.test/apt https://b.test/apt
Suites: stable
Components: main non-free
Signed-By: /usr/share/keyrings/d.gpg

Types: deb
URIs: https://off.test
Suites: s
Components: c
Enabled: no

Types: deb
URIs: https://inl.test
Suites: s
Components: c
Signed-By:
 -----BEGIN PGP PUBLIC KEY BLOCK-----
 .
 abcd
 -----END PGP PUBLIC KEY BLOCK-----
`,
	})
	pk, _ := Packages(root)
	got := pk.Sources
	if len(got) != 5 {
		t.Fatalf("got %d sources: %+v", len(got), got)
	}
	by := map[string][]int{}
	for i, s := range got {
		by[s.File] = append(by[s.File], i)
	}
	a := got[by["/etc/apt/sources.list"][0]]
	if !reflect.DeepEqual(a.Types, []string{"deb"}) || a.URIs[0] != "http://deb.debian.org/debian" ||
		!reflect.DeepEqual(a.Suites, []string{"bookworm"}) || !reflect.DeepEqual(a.Components, []string{"main", "contrib"}) {
		t.Errorf("one-line: %+v", a)
	}
	b := got[by["/etc/apt/sources.list"][1]]
	if b.Types[0] != "deb-src" || b.SignedBy != "/usr/share/keyrings/x.gpg" || !reflect.DeepEqual(b.Components, []string{"main"}) {
		t.Errorf("options: %+v", b)
	}
	d := by["/etc/apt/sources.list.d/d.sources"]
	if len(d) != 2 {
		t.Fatalf("deb822 stanzas: %d", len(d))
	}
	d0, d1 := got[d[0]], got[d[1]]
	if !reflect.DeepEqual(d0.Types, []string{"deb", "deb-src"}) || len(d0.URIs) != 2 || d0.SignedBy != "/usr/share/keyrings/d.gpg" ||
		!reflect.DeepEqual(d0.Components, []string{"main", "non-free"}) {
		t.Errorf("deb822: %+v", d0)
	}
	if d1.SignedBy != "inline" {
		t.Errorf("inline key: %+v", d1)
	}
}

func TestHostFromOSRelease(t *testing.T) {
	root, proc := t.TempDir(), t.TempDir()
	writeTree(t, root, map[string]string{"usr/lib/os-release": "ID=debian\nVERSION_ID=\"12\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n"})
	writeTree(t, proc, map[string]string{"sys/kernel/hostname": "box\n", "sys/kernel/osrelease": "6.1.0-x\n"})
	h := Host(root, proc)
	if h.OSID != "debian" || h.OSVersionID != "12" || h.OSPretty != "Debian GNU/Linux 12 (bookworm)" ||
		h.Hostname != "box" || h.Kernel != "6.1.0-x" || h.Arch == "" {
		t.Errorf("%+v", h)
	}
}
