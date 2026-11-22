package checklist

import (
	"fmt"
	"strings"
	"testing"

	"github.com/donaldsteele/telltale/internal/model"
)

func sshdFile(p string, lines ...string) model.PersistFile {
	if lines == nil {
		lines = []string{}
	}
	return model.PersistFile{Path: p, Kind: model.PersistKindSSHD, Lines: lines, Mode: 0o100644}
}

func wantSSHD(t *testing.T, got map[string]string, key, want string) {
	t.Helper()
	if got == nil {
		t.Fatalf("EffectiveSSHD returned nil, want %s=%q", key, want)
	}
	if got[key] != want {
		t.Errorf("%s = %q, want %q", key, got[key], want)
	}
}

func TestEffectiveSSHDFirstValueWins(t *testing.T) {
	files := []model.PersistFile{sshdFile("/etc/ssh/sshd_config",
		"# PermitRootLogin yes",
		"  PermitRootLogin no   # trailing comment",
		"PermitRootLogin yes",
		"permitrootlogin=yes",
		"X11Forwarding = yes",
		"X11Forwarding no",
		`AuthorizedKeysFile ".ssh/my keys" .ssh/authorized_keys`,
	)}
	got := EffectiveSSHD(files, "")
	wantSSHD(t, got, "permitrootlogin", "no")
	wantSSHD(t, got, "x11forwarding", "yes")
	wantSSHD(t, got, "authorizedkeysfile", ".ssh/my keys .ssh/authorized_keys")
	// OpenSSH defaults for keywords that are never set.
	wantSSHD(t, got, "permitemptypasswords", "no")
	wantSSHD(t, got, "passwordauthentication", "yes")
	wantSSHD(t, got, "maxauthtries", "6")
	wantSSHD(t, got, "hostbasedauthentication", "no")
	wantSSHD(t, got, "ignorerhosts", "yes")
	if _, ok := got["PermitRootLogin"]; ok {
		t.Error("keys must be lower-cased")
	}

	defaults := EffectiveSSHD([]model.PersistFile{sshdFile("/etc/ssh/sshd_config")}, "")
	wantSSHD(t, defaults, "permitrootlogin", "prohibit-password")

	if got := EffectiveSSHD(nil, ""); got != nil {
		t.Errorf("no sshd_config collected: got %v, want nil", got)
	}
	// Other kinds at the same path are not sshd configuration.
	other := sshdFile("/etc/ssh/sshd_config", "PermitRootLogin yes")
	other.Kind = model.PersistKindSSHClient
	if got := EffectiveSSHD([]model.PersistFile{other}, ""); got != nil {
		t.Errorf("non-sshd kind used: got %v", got)
	}
}

func TestEffectiveSSHDInclude(t *testing.T) {
	files := []model.PersistFile{
		sshdFile("/etc/ssh/sshd_config",
			"Include /etc/ssh/missing.conf",
			"Include sshd_config.d/*.conf",
			"PermitRootLogin no",
			"MaxAuthTries 5",
			"HostbasedAuthentication yes",
		),
		// Collected in path order; sshd reads glob matches sorted.
		sshdFile("/etc/ssh/sshd_config.d/20-b.conf", "X11Forwarding no", "MaxAuthTries 3"),
		sshdFile("/etc/ssh/sshd_config.d/10-a.conf", "PermitRootLogin yes", "X11Forwarding yes"),
		// A Match block opened in an included file ends with that file.
		sshdFile("/etc/ssh/sshd_config.d/30-c.conf", "Match Address 192.0.2.1", "HostbasedAuthentication no"),
		// glob(3) does not match dot files with *.
		sshdFile("/etc/ssh/sshd_config.d/.hidden.conf", "IgnoreRhosts no"),
		// Not matched by the pattern.
		sshdFile("/etc/ssh/sshd_config.d/40-d.bak", "PermitEmptyPasswords yes"),
	}
	got := EffectiveSSHD(files, "")
	wantSSHD(t, got, "permitrootlogin", "yes")
	wantSSHD(t, got, "x11forwarding", "yes")
	wantSSHD(t, got, "maxauthtries", "3")
	wantSSHD(t, got, "hostbasedauthentication", "yes")
	wantSSHD(t, got, "ignorerhosts", "yes")
	wantSSHD(t, got, "permitemptypasswords", "no")

	forMatch := EffectiveSSHD(files, "192.0.2.1")
	wantSSHD(t, forMatch, "hostbasedauthentication", "no")

	// An included file whose text was not kept cannot be evaluated.
	big := sshdFile("/etc/ssh/sshd_config.d/50-big.conf")
	big.Lines = nil
	if got := EffectiveSSHD(append(files, big), ""); got != nil {
		t.Errorf("unreadable include: got %v, want nil", got)
	}
	// An Include cycle makes sshd refuse to start; it is not evaluated.
	loop := []model.PersistFile{sshdFile("/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config")}
	if got := EffectiveSSHD(loop, ""); got != nil {
		t.Errorf("include loop: got %v, want nil", got)
	}
}

func TestEffectiveSSHDMatchAddress(t *testing.T) {
	files := []model.PersistFile{sshdFile("/etc/ssh/sshd_config",
		"PermitRootLogin no",
		"X11Forwarding no",
		"Match Address 10.0.0.5",
		"    PermitRootLogin prohibit-password",
		"    PermitRootLogin yes",
		"Match Address 192.168.1.0/24,10.9.*",
		"    X11Forwarding yes",
		"Match Address !10.2.0.9,10.2.0.*",
		"    MaxAuthTries 2",
		"Match User root Address 10.3.0.1",
		"    PermitRootLogin yes",
		"Match Host example.org",
		"    PermitRootLogin yes",
		"Match all",
		"    HostbasedAuthentication no",
		"    MaxAuthTries 3",
		"Match Address 2001:db8::/32",
		"    PermitRootLogin without-password",
	)}
	cases := []struct {
		addr, key, want string
	}{
		{"10.0.0.5", "permitrootlogin", "prohibit-password"},
		{"", "permitrootlogin", "no"},
		{"10.0.0.6", "permitrootlogin", "no"},
		{"192.168.1.77", "x11forwarding", "yes"},
		{"10.9.3.4", "x11forwarding", "yes"},
		{"192.168.2.1", "x11forwarding", "no"},
		{"10.2.0.8", "maxauthtries", "2"},
		{"10.2.0.9", "maxauthtries", "3"}, // negated: falls through to Match all
		{"", "maxauthtries", "3"},         // Match all applies to any address
		{"10.3.0.1", "permitrootlogin", "no"},
		{"", "hostbasedauthentication", "no"},
		{"2001:db8::7", "permitrootlogin", "without-password"},
		{"::ffff:10.0.0.5", "permitrootlogin", "prohibit-password"},
	}
	for _, c := range cases {
		got := EffectiveSSHD(files, c.addr)
		if got == nil || got[c.key] != c.want {
			t.Errorf("addr %q: %s = %q, want %q", c.addr, c.key, got[c.key], c.want)
		}
	}
}

func TestEffectiveSSHDSymlinkedConfig(t *testing.T) {
	// A symlink is collected with its target as Lines[0], then the content.
	link := model.PersistFile{Path: "/etc/ssh/sshd_config", Kind: model.PersistKindSSHD, Mode: 0o120777,
		Lines: []string{"/etc/ssh/sshd_config.real", "PermitRootLogin yes"}}
	got := EffectiveSSHD([]model.PersistFile{link}, "")
	wantSSHD(t, got, "permitrootlogin", "yes")

	c := hardened()
	c.Persist[0] = link
	it, _ := ByID("TT-SSH-001")
	if fix := it.FixFor(c, model.ScanContext{}); fix != `sed -i --follow-symlinks '1s/.*/PermitRootLogin no/' /etc/ssh/sshd_config && systemctl reload ssh` {
		t.Errorf("fix = %q", fix)
	}
}

func TestWildMatchHostilePattern(t *testing.T) {
	pat := strings.Repeat("*?", 200) + "x"
	if addrMatchList("10.0.0.5", pat) {
		t.Error("pattern should not match")
	}
	if !wildMatch("10.*.5", "10.0.0.5") || wildMatch("10.?.5", "10.0.0.5") || !wildMatch("*", "") {
		t.Error("wildMatch basics")
	}
}

func TestEffectiveSSHDIncludeFanOutIsBounded(t *testing.T) {
	// Each file includes the next one twice: 2^15 reads of the deepest file.
	filler := make([]string, 300)
	for i := range filler {
		filler[i] = "# comment"
	}
	var files []model.PersistFile
	for i := 0; i < 16; i++ {
		p := fmt.Sprintf("/etc/ssh/f%02d.conf", i)
		if i == 0 {
			p = "/etc/ssh/sshd_config"
		}
		next := fmt.Sprintf("/etc/ssh/f%02d.conf", i+1)
		files = append(files, sshdFile(p, append([]string{"Include " + next, "Include " + next}, filler...)...))
	}
	if got := EffectiveSSHD(files, ""); got != nil {
		t.Errorf("fan-out evaluated: %v", got["permitrootlogin"])
	}
}

// The expected values in the tests below were checked with sshd -T from
// OpenSSH 10.0p2.

func TestEffectiveSSHDIncludeInsideMatch(t *testing.T) {
	// Included from inside a Match block that does not apply: none of the
	// included file's Match blocks can apply, in either pass.
	files := []model.PersistFile{
		sshdFile("/etc/ssh/sshd_config", "PermitRootLogin yes", "Match User nobody", "    Include /etc/ssh/hardening.conf"),
		sshdFile("/etc/ssh/hardening.conf", "Match all", "PermitRootLogin no"),
	}
	for _, addr := range []string{"", "10.0.0.5"} {
		wantSSHD(t, EffectiveSSHD(files, addr), "permitrootlogin", "yes")
	}

	// Included from inside a block that applies: its lines and Match blocks
	// work for that client only.
	files = []model.PersistFile{
		sshdFile("/etc/ssh/sshd_config", "PermitRootLogin no", "Match Address 10.0.0.5", "  Include /etc/ssh/m.conf"),
		sshdFile("/etc/ssh/m.conf", "X11Forwarding yes", "Match all", "  PermitRootLogin yes"),
	}
	got := EffectiveSSHD(files, "10.0.0.5")
	wantSSHD(t, got, "x11forwarding", "yes")
	wantSSHD(t, got, "permitrootlogin", "yes")
	got = EffectiveSSHD(files, "10.0.0.6")
	wantSSHD(t, got, "x11forwarding", "no")
	wantSSHD(t, got, "permitrootlogin", "no")

	// An included file's first Match line ends its match-only part: an
	// Include after it, inside a block that does not apply, is inert.
	files = []model.PersistFile{
		sshdFile("/etc/ssh/sshd_config", "Include /etc/ssh/x.conf", "PermitRootLogin no"),
		sshdFile("/etc/ssh/x.conf", "Match User nobody", "  Include /etc/ssh/y.conf"),
		sshdFile("/etc/ssh/y.conf", "Match all", "  PermitRootLogin yes"),
	}
	for _, addr := range []string{"", "10.0.0.5"} {
		wantSSHD(t, EffectiveSSHD(files, addr), "permitrootlogin", "no")
	}

	// A chain of Includes before any Match keeps Match blocks working.
	files = []model.PersistFile{
		sshdFile("/etc/ssh/sshd_config", "Include /etc/ssh/z.conf", "X11Forwarding no"),
		sshdFile("/etc/ssh/z.conf", "MaxAuthTries 3", "Include /etc/ssh/w.conf"),
		sshdFile("/etc/ssh/w.conf", "Match Address 10.0.0.5", "  X11Forwarding yes"),
	}
	wantSSHD(t, EffectiveSSHD(files, "10.0.0.5"), "x11forwarding", "yes")
	wantSSHD(t, EffectiveSSHD(files, "10.0.0.6"), "x11forwarding", "no")
	wantSSHD(t, EffectiveSSHD(files, ""), "maxauthtries", "3")
}

func TestEffectiveSSHDGlobalOnlyKeywords(t *testing.T) {
	// PermitUserEnvironment and StrictModes are not allowed in Match blocks:
	// a later Match all cannot override them, but may set other keywords.
	files := []model.PersistFile{sshdFile("/etc/ssh/sshd_config",
		"PermitUserEnvironment yes", "StrictModes no",
		"Match all", "  PermitUserEnvironment no", "  StrictModes yes", "  X11Forwarding yes")}
	got := EffectiveSSHD(files, "")
	wantSSHD(t, got, "permituserenvironment", "yes")
	wantSSHD(t, got, "strictmodes", "no")
	wantSSHD(t, got, "x11forwarding", "yes")

	// A Match all read before the global value sets it in the global pass.
	files = []model.PersistFile{
		sshdFile("/etc/ssh/sshd_config", "Include /etc/ssh/i.conf", "StrictModes yes"),
		sshdFile("/etc/ssh/i.conf", "Match all", "  StrictModes no"),
	}
	wantSSHD(t, EffectiveSSHD(files, ""), "strictmodes", "no")
}

func TestEffectiveSSHDNegatedGlob(t *testing.T) {
	files := []model.PersistFile{
		sshdFile("/etc/ssh/sshd_config", "Include /etc/ssh/evil/[!a]*", "PermitRootLogin no"),
		sshdFile("/etc/ssh/evil/a.conf", "PermitRootLogin no"),
		sshdFile("/etc/ssh/evil/b.conf", "PermitRootLogin yes"),
	}
	wantSSHD(t, EffectiveSSHD(files, ""), "permitrootlogin", "yes")
}

func TestEffectiveSSHDSymlinkContentNotKept(t *testing.T) {
	// The collector keeps only the target path when the target is another
	// symlink, too large, or a secret file: the content is unknown.
	link := model.PersistFile{Path: "/etc/ssh/sshd_config.d/00-x.conf", Kind: model.PersistKindSSHD, Mode: 0o120777,
		SHA256: "5c1e4cd27bf0f4e5c4f2d2e0d4b5a0a1c7f6b8e9d0a1b2c3d4e5f60718293a4b", Lines: []string{"/etc/ssh/l"}}
	files := []model.PersistFile{
		sshdFile("/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf", "PermitRootLogin no"),
		link,
	}
	if got := EffectiveSSHD(files, ""); got != nil {
		t.Errorf("unknown symlink content evaluated: %v", got["permitrootlogin"])
	}
	// A symlink to an empty file is read: its hash is that of no content.
	files[1].SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	wantSSHD(t, EffectiveSSHD(files, ""), "permitrootlogin", "no")
}
