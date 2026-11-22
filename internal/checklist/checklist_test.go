package checklist

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/donaldsteele/telltale/internal/model"
)

func boolp(b bool) *bool { return &b }

func dirEntry(p string, mode uint32) model.FileEntry {
	return model.FileEntry{Path: p, Type: "dir", Mode: 0o040000 | mode}
}

func fileEntry(p string, mode, uid, gid uint32) model.FileEntry {
	return model.FileEntry{Path: p, Type: "file", Mode: 0o100000 | mode, UID: uid, GID: gid}
}

// hardened returns a collection on which every item passes.
func hardened() *model.Collection {
	set := model.PasswordState{Set: true, Algo: "yescrypt", LastChange: 19000, MaxDays: 99999}
	locked := model.PasswordState{Locked: true, Algo: "none", LastChange: 19000, MaxDays: 99999}
	return &model.Collection{
		AsRoot: true,
		Accounts: model.Accounts{
			Users: []model.User{
				{Name: "root", UID: 0, Shell: "/bin/bash", Password: locked},
				{Name: "daemon", UID: 1, Shell: "/usr/sbin/nologin", Password: locked},
				{Name: "sync", UID: 4, Shell: "/bin/sync", Password: locked},
				{Name: "sshd", UID: 105, Shell: "/bin/false", Password: locked},
				{Name: "alice", UID: 1000, Shell: "/bin/bash", Password: set},
				{Name: "nobody", UID: 65534, Shell: "/usr/sbin/nologin", Password: locked},
			},
			Groups: []model.Group{{Name: "root", GID: 0}, {Name: "shadow", GID: 42}},
		},
		Persist: []model.PersistFile{
			sshdFile("/etc/ssh/sshd_config",
				"Include /etc/ssh/sshd_config.d/*.conf",
				"PermitRootLogin no",
				"MaxAuthTries 4",
			),
			{Path: "/etc/sudoers", Kind: model.PersistKindSudoers, Mode: 0o100440, Lines: []string{
				"Defaults env_reset",
				"root ALL=(ALL:ALL) ALL",
				"%sudo ALL=(ALL:ALL) ALL",
				"# bob ALL=(ALL) NOPASSWD: ALL",
				"@includedir /etc/sudoers.d",
			}},
		},
		Files: []model.FileEntry{
			fileEntry("/etc/shadow", 0o640, 0, 42),
			fileEntry("/etc/gshadow", 0o640, 0, 42),
			fileEntry("/etc/passwd", 0o644, 0, 0),
			fileEntry("/etc/group", 0o644, 0, 0),
			fileEntry("/etc/ssh/sshd_config", 0o644, 0, 0),
			fileEntry("/etc/sudoers", 0o440, 0, 0),
			fileEntry("/usr/bin/ls", 0o755, 0, 0),
			dirEntry("/etc/cron.d", 0o700),
			dirEntry("/etc/cron.daily", 0o700),
			{Path: "/usr/bin/vi", Type: "symlink", Mode: 0o120777, Target: "/etc/alternatives/vi"},
		},
		Firewall: model.Firewall{Backend: "nftables", InputPolicy: "drop", InputRules: 3, UFWEnabled: boolp(false)},
		Packages: model.Packages{Installed: []model.Package{
			{Name: "openssh-server"}, {Name: "auditd"}, {Name: "unattended-upgrades"}, {Name: "apparmor"},
		}},
		Sysctl: map[string]string{
			"kernel.randomize_va_space":             "2",
			"fs.suid_dumpable":                      "0",
			"kernel.kptr_restrict":                  "1",
			"kernel.dmesg_restrict":                 "1",
			"net.ipv4.conf.all.accept_redirects":    "0",
			"net.ipv4.conf.all.send_redirects":      "0",
			"net.ipv4.conf.all.accept_source_route": "0",
			"net.ipv4.tcp_syncookies":               "1",
			"fs.protected_symlinks":                 "1",
			"fs.protected_hardlinks":                "1",
			"net.ipv6.conf.all.accept_redirects":    "0",
			"kernel.yama.ptrace_scope":              "1",
			"apparmor.enabled":                      "Y",
		},
	}
}

func result(t *testing.T, c *model.Collection, ctx model.ScanContext, id string) model.CheckResult {
	t.Helper()
	for _, r := range Evaluate(c, ctx) {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("no result for %s", id)
	return model.CheckResult{}
}

func setSSHD(c *model.Collection, lines ...string) {
	for i, pf := range c.Persist {
		if pf.Path == "/etc/ssh/sshd_config" {
			c.Persist[i].Lines = lines
		}
	}
}

func TestHardenedCollectionPassesEverything(t *testing.T) {
	results := Evaluate(hardened(), model.ScanContext{})
	if len(results) != len(Items()) {
		t.Fatalf("%d results for %d items", len(results), len(Items()))
	}
	for _, r := range results {
		if !r.Pass || r.Skipped != "" {
			t.Errorf("%s: pass=%v skipped=%q observed=%q", r.ID, r.Pass, r.Skipped, r.Observed)
		}
	}
}

func TestRootLoginItemAllowsTelltaleServer(t *testing.T) {
	c := hardened()
	setSSHD(c,
		"PermitRootLogin no",
		"Match Address 10.0.0.5",
		"    PermitRootLogin prohibit-password",
	)
	ctx := model.ScanContext{ServerAddr: "10.0.0.5"}
	r := result(t, c, ctx, "TT-SSH-001")
	if !r.Pass || r.Skipped != "" {
		t.Fatalf("root login with telltale's Match block: %+v", r)
	}
	// The server's own block is not a loosening Match block either.
	if r := result(t, c, ctx, "TT-SSH-009"); !r.Pass {
		t.Errorf("telltale's Match block flagged: %+v", r)
	}
	// The same block without the server context (carry mode) is a
	// loosening Match block, though global root login stays off.
	if r := result(t, c, model.ScanContext{}, "TT-SSH-001"); !r.Pass {
		t.Errorf("carry mode root login: %+v", r)
	}
	if r := result(t, c, model.ScanContext{}, "TT-SSH-009"); r.Pass {
		t.Errorf("carry mode Match block not flagged: %+v", r)
	}
	// A broader block than the server's own address is a finding.
	setSSHD(c,
		"PermitRootLogin no",
		"Match Address 10.0.0.0/8",
		"    PermitRootLogin prohibit-password",
	)
	if r := result(t, c, ctx, "TT-SSH-009"); r.Pass {
		t.Errorf("broader Match block not flagged: %+v", r)
	}
}

func TestRootLoginItemFailsOnYes(t *testing.T) {
	c := hardened()
	setSSHD(c, "PermitRootLogin yes")
	r := result(t, c, model.ScanContext{}, "TT-SSH-001")
	if r.Pass || r.Skipped != "" || !strings.Contains(r.Observed, "yes") {
		t.Fatalf("PermitRootLogin yes: %+v", r)
	}
	it, _ := ByID("TT-SSH-001")
	if fix := it.FixFor(c, model.ScanContext{}); fix != `sed -i '1s/.*/PermitRootLogin no/' /etc/ssh/sshd_config && systemctl reload ssh` {
		t.Errorf("fix = %q", fix)
	}

	// The OpenSSH default (prohibit-password) is not "no".
	setSSHD(c, "# PermitRootLogin prohibit-password")
	if r := result(t, c, model.ScanContext{}, "TT-SSH-001"); r.Pass {
		t.Errorf("default prohibit-password passed: %+v", r)
	}
	if fix := it.FixFor(c, model.ScanContext{}); fix != `sed -i '1i PermitRootLogin no' /etc/ssh/sshd_config && systemctl reload ssh` {
		t.Errorf("fix for unset = %q", fix)
	}

	// Root password login from the server's own address fails too.
	setSSHD(c, "PermitRootLogin no", "Match Address 10.0.0.5", "  PermitRootLogin yes")
	ctx := model.ScanContext{ServerAddr: "10.0.0.5"}
	if r := result(t, c, ctx, "TT-SSH-001"); r.Pass {
		t.Errorf("yes for server address passed: %+v", r)
	}
	if fix := it.FixFor(c, ctx); fix != `sed -i '3s/.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config && systemctl reload ssh` {
		t.Errorf("fix for server block = %q", fix)
	}
	// Both wrong, global unset: the line edit runs before the insert that
	// would shift it.
	setSSHD(c, "# PermitRootLogin prohibit-password", "Match Address 10.0.0.5", "  PermitRootLogin yes")
	want := `sed -i '3s/.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config && sed -i '1i PermitRootLogin no' /etc/ssh/sshd_config && systemctl reload ssh`
	if fix := it.FixFor(c, ctx); fix != want {
		t.Errorf("fix for unset + server block = %q", fix)
	}
}

func TestEveryItemHasIDTitleWhyFix(t *testing.T) {
	idRe := regexp.MustCompile(`^TT-[A-Z]+-[0-9]{3}$`)
	refRe := regexp.MustCompile(`^STIG V-[0-9]+ \(UBTU-22-[0-9]+\)$`)
	seen := map[string]bool{}
	items := Items()
	if len(items) < 40 {
		t.Fatalf("%d items, want at least 40", len(items))
	}
	for _, it := range items {
		if !idRe.MatchString(it.ID) {
			t.Errorf("bad ID %q", it.ID)
		}
		if seen[it.ID] {
			t.Errorf("duplicate ID %s", it.ID)
		}
		seen[it.ID] = true
		if it.Title == "" || it.Why == "" || it.Fix == "" || it.Check == nil {
			t.Errorf("%s: missing title, why, fix or check", it.ID)
		}
		for _, r := range it.Refs {
			if !refRe.MatchString(r) {
				t.Errorf("%s: bad ref %q", it.ID, r)
			}
		}
		got, ok := ByID(it.ID)
		if !ok || got.ID != it.ID {
			t.Errorf("ByID(%s) = %v, %v", it.ID, got.ID, ok)
		}
	}
	for id := range stigRefs {
		if !seen[id] {
			t.Errorf("stig_refs.go maps unknown item %s", id)
		}
	}
	if _, ok := ByID("TT-NOPE-999"); ok {
		t.Error("ByID found an unknown ID")
	}
	// Items returns copies: changing one does not change the table.
	items[0].Refs = append(items[0].Refs, "x")
	items[0].Title = "changed"
	if again := Items(); again[0].Title == "changed" || len(again[0].Refs) == len(items[0].Refs) {
		t.Error("Items shares state between calls")
	}
}

func TestEvaluateSkipsWhenDataMissing(t *testing.T) {
	// Nothing collected at all: every item is skipped, none guessed.
	results := Evaluate(&model.Collection{}, model.ScanContext{ServerAddr: "10.0.0.5"})
	if len(results) != len(Items()) {
		t.Fatalf("%d results for %d items", len(results), len(Items()))
	}
	for _, r := range results {
		if r.Skipped == "" || r.Pass {
			t.Errorf("%s on empty collection: pass=%v skipped=%q observed=%q", r.ID, r.Pass, r.Skipped, r.Observed)
		}
	}
	if got := Evaluate(nil, model.ScanContext{}); len(got) != len(results) {
		t.Errorf("nil collection: %d results", len(got))
	}

	// Not root: passwd was read, shadow was not.
	c := hardened()
	c.AsRoot = false
	c.Skipped = []model.Skip{{Check: "accounts", Reason: "/etc/shadow: open /etc/shadow: permission denied"}}
	for i := range c.Accounts.Users {
		c.Accounts.Users[i].Password = model.PasswordState{Algo: "none", LastChange: -1, MaxDays: -1}
	}
	for _, id := range []string{"TT-ACCT-002", "TT-ACCT-004"} {
		r := result(t, c, model.ScanContext{}, id)
		if r.Skipped == "" || r.Pass {
			t.Errorf("%s without shadow: %+v", id, r)
		}
	}
	// Items that only need passwd still run.
	for _, id := range []string{"TT-ACCT-001", "TT-ACCT-003"} {
		if r := result(t, c, model.ScanContext{}, id); r.Skipped != "" || !r.Pass {
			t.Errorf("%s without shadow: %+v", id, r)
		}
	}
	// Shadow absent without a Skip (no password data at all) is skipped too.
	c.Skipped = nil
	if r := result(t, c, model.ScanContext{}, "TT-ACCT-002"); r.Skipped == "" {
		t.Errorf("no password data: %+v", r)
	}

	// sshd_config too large to keep: SSH items skip.
	c = hardened()
	c.Persist[0].Lines = nil
	if r := result(t, c, model.ScanContext{}, "TT-SSH-001"); r.Skipped == "" {
		t.Errorf("unreadable sshd_config: %+v", r)
	}
}

func TestNoPasswdSudoFails(t *testing.T) {
	c := hardened()
	c.Persist = append(c.Persist, model.PersistFile{
		Path: "/etc/sudoers.d/90-cloud-init-users", Kind: model.PersistKindSudoers, Mode: 0o100440,
		// As collected: the redactor treats "NOPASSWD:" as a secret key.
		Lines: []string{"# Created by cloud-init", "ubuntu ALL=(ALL) NOPASSWD: <redacted h:0123456789abcdef01234567>"},
	})
	c.Files = append(c.Files, fileEntry("/etc/sudoers.d/90-cloud-init-users", 0o440, 0, 0))
	r := result(t, c, model.ScanContext{}, "TT-SUDO-001")
	if r.Pass || r.Skipped != "" || !strings.Contains(r.Observed, "/etc/sudoers.d/90-cloud-init-users") {
		t.Fatalf("NOPASSWD rule: %+v", r)
	}
	it, _ := ByID("TT-SUDO-001")
	if fix := it.FixFor(c, model.ScanContext{}); fix != `sed -i 's/NOPASSWD[[:space:]]*:/PASSWD:/g' /etc/sudoers.d/90-cloud-init-users && visudo -c` {
		t.Errorf("fix = %q", fix)
	}
	if r := result(t, c, model.ScanContext{}, "TT-SUDO-002"); !r.Pass {
		t.Errorf("!authenticate item failed on NOPASSWD only: %+v", r)
	}
}

func TestAuthenticateSudoFails(t *testing.T) {
	c := hardened()
	c.Persist[1].Lines = append(c.Persist[1].Lines, "Defaults:deploy env_keep+=SSH_AUTH_SOCK, !authenticate")
	if r := result(t, c, model.ScanContext{}, "TT-SUDO-002"); r.Pass {
		t.Errorf("!authenticate: %+v", r)
	}
}

func TestSudoersModeFails(t *testing.T) {
	c := hardened()
	c.Files[5] = fileEntry("/etc/sudoers", 0o640, 0, 0)
	if r := result(t, c, model.ScanContext{}, "TT-SUDO-003"); r.Pass || !strings.Contains(r.Observed, "0640") {
		t.Errorf("sudoers 0640: %+v", r)
	}
}

func TestFirewallItem(t *testing.T) {
	cases := []struct {
		name     string
		fw       model.Firewall
		pass     bool
		skipped  bool
		observed string
	}{
		{"drop policy", model.Firewall{Backend: "nftables", InputPolicy: "drop"}, true, false, ""},
		{"accept policy with reject rules", model.Firewall{Backend: "nftables", InputPolicy: "accept", InputRules: 2}, true, false, ""},
		{"ufw enabled", model.Firewall{Backend: "unknown", InputPolicy: "none", UFWEnabled: boolp(true)}, true, false, ""},
		{"nothing", model.Firewall{Backend: "nftables", InputPolicy: "none"}, false, false, "none"},
		{"ufw disabled", model.Firewall{Backend: "unknown", InputPolicy: "none", UFWEnabled: boolp(false)}, false, false, "ufw disabled"},
		{"unreadable", model.Firewall{Backend: "unknown", InputPolicy: "none"}, false, true, ""},
	}
	for _, tc := range cases {
		c := hardened()
		c.Firewall = tc.fw
		r := result(t, c, model.ScanContext{}, "TT-FW-001")
		if r.Pass != tc.pass || (r.Skipped != "") != tc.skipped || !strings.Contains(r.Observed, tc.observed) {
			t.Errorf("%s: %+v", tc.name, r)
		}
	}
}

func TestSysctlItems(t *testing.T) {
	c := hardened()
	c.Sysctl["kernel.randomize_va_space"] = "1"
	c.Sysctl["kernel.kptr_restrict"] = "2"
	delete(c.Sysctl, "kernel.yama.ptrace_scope")
	if r := result(t, c, model.ScanContext{}, "TT-KERN-001"); r.Pass || r.Observed != "kernel.randomize_va_space = 1" {
		t.Errorf("randomize_va_space 1: %+v", r)
	}
	if r := result(t, c, model.ScanContext{}, "TT-KERN-003"); !r.Pass {
		t.Errorf("kptr_restrict 2: %+v", r)
	}
	if r := result(t, c, model.ScanContext{}, "TT-KERN-012"); r.Skipped == "" {
		t.Errorf("missing ptrace_scope: %+v", r)
	}
	it, _ := ByID("TT-KERN-001")
	if it.Fix != `sysctl -w kernel.randomize_va_space=2 && echo 'kernel.randomize_va_space = 2' > /etc/sysctl.d/99-telltale-kernel.randomize_va_space.conf` {
		t.Errorf("fix = %q", it.Fix)
	}
	c.Sysctl["apparmor.enabled"] = "N"
	if r := result(t, c, model.ScanContext{}, "TT-SVC-006"); r.Pass {
		t.Errorf("apparmor N: %+v", r)
	}
}

func TestAccountItems(t *testing.T) {
	c := hardened()
	c.Accounts.Users = append(c.Accounts.Users,
		model.User{Name: "toor", UID: 0, Shell: "/bin/sh", Password: model.PasswordState{Set: true, Algo: "md5", LastChange: 19000}},
		model.User{Name: "games", UID: 5, Shell: "/bin/bash", Password: model.PasswordState{Locked: true, LastChange: 19000}},
		model.User{Name: "bob", UID: 1001, Shell: "/bin/bash", Password: model.PasswordState{Algo: "none", LastChange: 19000}},
		// A NIS compat line is not an account.
		model.User{Name: "+", UID: 0, Shell: ""},
	)
	checks := map[string]string{
		"TT-ACCT-001": "toor",
		"TT-ACCT-002": "bob",
		"TT-ACCT-003": "games",
		"TT-ACCT-004": "toor",
	}
	for id, who := range checks {
		r := result(t, c, model.ScanContext{}, id)
		if r.Pass || r.Skipped != "" || !strings.Contains(r.Observed, who) {
			t.Errorf("%s: %+v", id, r)
		}
		if strings.Contains(r.Observed, "+") {
			t.Errorf("%s counts the NIS line: %+v", id, r)
		}
	}
	it, _ := ByID("TT-ACCT-002")
	if fix := it.FixFor(c, model.ScanContext{}); fix != "passwd -l bob" {
		t.Errorf("fix = %q", fix)
	}
}

func TestFileItems(t *testing.T) {
	c := hardened()
	c.Files[0] = fileEntry("/etc/shadow", 0o644, 0, 42)
	c.Files = append(c.Files,
		fileEntry("/etc/evil it's.sh", 0o777, 0, 0),
		dirEntry("/usr/local/drop", 0o777),
		dirEntry("/usr/local/tmp", 0o1777),
		dirEntry("/etc/cron.weekly", 0o755),
	)
	if r := result(t, c, model.ScanContext{}, "TT-FILE-001"); r.Pass || !strings.Contains(r.Observed, "0644") {
		t.Errorf("shadow 0644: %+v", r)
	}
	r := result(t, c, model.ScanContext{}, "TT-FILE-005")
	if r.Pass || !strings.Contains(r.Observed, "/usr/local/drop") || strings.Contains(r.Observed, "/usr/local/tmp") {
		t.Errorf("world-writable: %+v", r)
	}
	it, _ := ByID("TT-FILE-005")
	if fix := it.FixFor(c, model.ScanContext{}); fix != `chmod o-w '/etc/evil it'\''s.sh' /usr/local/drop` {
		t.Errorf("fix = %q", fix)
	}
	if r := result(t, c, model.ScanContext{}, "TT-FILE-006"); r.Pass || !strings.Contains(r.Observed, "/etc/cron.weekly") {
		t.Errorf("cron dir 0755: %+v", r)
	}
}

func TestServiceItems(t *testing.T) {
	c := hardened()
	c.Packages.Installed = []model.Package{{Name: "inetutils-telnetd"}, {Name: "tftpd-hpa"}, {Name: "nis"}, {Name: "rsh-server"}}
	for _, id := range []string{"TT-SVC-001", "TT-SVC-002", "TT-SVC-003", "TT-SVC-004", "TT-SVC-005", "TT-SVC-007"} {
		if r := result(t, c, model.ScanContext{}, id); r.Pass || r.Skipped != "" {
			t.Errorf("%s: %+v", id, r)
		}
	}
	it, _ := ByID("TT-SVC-001")
	if fix := it.FixFor(c, model.ScanContext{}); fix != "apt-get purge inetutils-telnetd" {
		t.Errorf("fix = %q", fix)
	}
}

func TestSSHKeywordItems(t *testing.T) {
	c := hardened()
	setSSHD(c,
		"PermitRootLogin no",
		"PermitEmptyPasswords yes",
		"X11Forwarding yes",
		"MaxAuthTries 10",
		"HostbasedAuthentication yes",
		"IgnoreRhosts no",
		"PermitUserEnvironment yes",
		"StrictModes no",
		"PasswordAuthentication yes",
	)
	for _, id := range []string{"TT-SSH-002", "TT-SSH-004", "TT-SSH-005", "TT-SSH-006", "TT-SSH-007", "TT-SSH-010", "TT-SSH-011"} {
		if r := result(t, c, model.ScanContext{}, id); r.Pass || r.Skipped != "" {
			t.Errorf("%s: %+v", id, r)
		}
	}
	// Password login is noted, never failed.
	if r := result(t, c, model.ScanContext{}, "TT-SSH-003"); !r.Pass || r.Observed != "PasswordAuthentication yes" {
		t.Errorf("TT-SSH-003: %+v", r)
	}
	// A redacted value cannot be judged.
	setSSHD(c, "PermitRootLogin no", "PermitEmptyPasswords=<redacted h:0123456789abcdef01234567>")
	if r := result(t, c, model.ScanContext{}, "TT-SSH-002"); r.Skipped == "" {
		t.Errorf("redacted value: %+v", r)
	}
	// A loosening Match block for some users is caught.
	setSSHD(c, "PermitRootLogin no", "Match User deploy", "  PermitEmptyPasswords yes")
	r := result(t, c, model.ScanContext{}, "TT-SSH-009")
	if r.Pass || !strings.Contains(r.Observed, "PermitEmptyPasswords yes") {
		t.Errorf("TT-SSH-009: %+v", r)
	}
	it, _ := ByID("TT-SSH-009")
	if fix := it.FixFor(c, model.ScanContext{}); fix != `sed -i -e '3s/^/#/' /etc/ssh/sshd_config && systemctl reload ssh` {
		t.Errorf("fix = %q", fix)
	}
	// sshd_config writable by others.
	c = hardened()
	c.Files[4] = fileEntry("/etc/ssh/sshd_config", 0o666, 0, 0)
	if r := result(t, c, model.ScanContext{}, "TT-SSH-008"); r.Pass {
		t.Errorf("TT-SSH-008: %+v", r)
	}
}

func TestSSHDFileModeFallsBackToPersistMeta(t *testing.T) {
	c := hardened()
	inc := sshdFile("/etc/ssh/sshd_config.d/50-local.conf", "MaxAuthTries 3")
	c.Persist = append(c.Persist, inc)
	if r := result(t, c, model.ScanContext{}, "TT-SSH-008"); !r.Pass {
		t.Errorf("0644 include outside the inventory: %+v", r)
	}
	c.Persist[len(c.Persist)-1].Mode = 0o100666
	r := result(t, c, model.ScanContext{}, "TT-SSH-008")
	if r.Pass || !strings.Contains(r.Observed, "50-local.conf mode 0666") {
		t.Errorf("0666 include outside the inventory: %+v", r)
	}
}

func TestSSHItemsSkipWhenConfigIncomplete(t *testing.T) {
	c := hardened()
	c.Skipped = append(c.Skipped, model.Skip{Check: model.SkipCheckSSHDConfig, Reason: "/etc/ssh/d17.conf: Include nested deeper than 16 levels, not read"})
	for _, id := range []string{"TT-SSH-001", "TT-SSH-004", "TT-SSH-008", "TT-SSH-009"} {
		if r := result(t, c, model.ScanContext{}, id); r.Skipped == "" || !strings.Contains(r.Skipped, "d17.conf") {
			t.Errorf("%s with incomplete config: %+v", id, r)
		}
	}
}

func TestSudoSymlinkContentNotKeptSkips(t *testing.T) {
	c := hardened()
	c.Persist = append(c.Persist, model.PersistFile{Path: "/etc/sudoers.d/zz", Kind: model.PersistKindSudoers,
		Mode: 0o120777, SHA256: "0f0e", Lines: []string{"/var/tmp/x"}})
	if r := result(t, c, model.ScanContext{}, "TT-SUDO-001"); r.Skipped == "" {
		t.Errorf("unknown sudoers symlink content: %+v", r)
	}
	// A NOPASSWD seen elsewhere is still a certain failure.
	c.Persist[1].Lines = append(c.Persist[1].Lines, "bob ALL=(ALL) NOPASSWD: ALL")
	if r := result(t, c, model.ScanContext{}, "TT-SUDO-001"); r.Pass || r.Skipped != "" {
		t.Errorf("NOPASSWD with an unknown file: %+v", r)
	}
}

func TestRootLoginFixKeepsServerAccess(t *testing.T) {
	c := hardened()
	ctx := model.ScanContext{ServerAddr: "10.0.0.5"}
	it, _ := ByID("TT-SSH-001")
	block := `printf '\nMatch Address %s\n    PermitRootLogin prohibit-password\n' 10.0.0.5 >> /etc/ssh/sshd_config`
	setSSHD(c, "PermitRootLogin prohibit-password")
	if fix := it.FixFor(c, ctx); fix != `sed -i '1s/.*/PermitRootLogin no/' /etc/ssh/sshd_config && `+block+` && systemctl reload ssh` {
		t.Errorf("fix = %q", fix)
	}
	setSSHD(c, "# PermitRootLogin prohibit-password")
	if fix := it.FixFor(c, ctx); fix != `sed -i '1i PermitRootLogin no' /etc/ssh/sshd_config && `+block+` && systemctl reload ssh` {
		t.Errorf("fix for unset = %q", fix)
	}
	// Carry mode: no server to keep.
	if fix := it.FixFor(c, model.ScanContext{}); fix != `sed -i '1i PermitRootLogin no' /etc/ssh/sshd_config && systemctl reload ssh` {
		t.Errorf("carry-mode fix = %q", fix)
	}
}

func TestFirewallFixAllowsSSHPorts(t *testing.T) {
	c := hardened()
	c.Firewall = model.Firewall{Backend: "nftables", InputPolicy: "accept", UFWEnabled: boolp(false)}
	setSSHD(c, "Port 22", "Port 2222", "PermitRootLogin no")
	c.Runtime.Processes = []model.Process{{PID: 900, Comm: "sshd", Exe: "/usr/sbin/sshd", Cmdline: "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups"}}
	c.Runtime.Sockets = []model.Socket{
		{Proto: "tcp", Local: "0.0.0.0:2222", Listening: true, PID: 900},
		{Proto: "tcp", Local: "0.0.0.0:80", Listening: true, PID: 1},
		{Proto: "tcp", Local: "127.0.0.1:5432", Listening: true, PID: 2},
		{Proto: "tcp6", Local: "[::]:443", Listening: true, PID: 3},
		{Proto: "tcp6", Local: "[::1]:631", Listening: true, PID: 4},
		{Proto: "udp", Local: "0.0.0.0:53", Listening: true, PID: 5},
		{Proto: "tcp", Local: "10.0.0.9:8080", Remote: "10.0.0.1:5000", PID: 6},
	}
	it, _ := ByID("TT-FW-001")
	want := "# also listening on TCP: 80, 443 (allow the ones that must stay reachable before enabling)\nufw allow 22/tcp && ufw allow 2222/tcp && ufw --force enable"
	if fix := it.FixFor(c, model.ScanContext{}); fix != want {
		t.Errorf("fix = %q", fix)
	}
	// ufw not installed yet; sshd on a command-line port only.
	c.Firewall.UFWEnabled = nil
	setSSHD(c, "PermitRootLogin no")
	c.Runtime.Processes[0].Cmdline = "sshd: /usr/sbin/sshd -D -p 2200 [listener] 0 of 10-100 startups"
	c.Runtime.Sockets = nil
	if fix := it.FixFor(c, model.ScanContext{}); fix != "apt-get install -y ufw && ufw allow 2200/tcp && ufw --force enable" {
		t.Errorf("fix = %q", fix)
	}
}

func TestNoPasswdFixSetsPasswordFirst(t *testing.T) {
	c := hardened()
	c.Accounts.Users = append(c.Accounts.Users,
		model.User{Name: "ubuntu", UID: 1001, GID: 1001, Shell: "/bin/bash", Password: model.PasswordState{Locked: true, LastChange: 19000}},
		model.User{Name: "carol", UID: 1002, GID: 1002, Shell: "/bin/bash", Password: model.PasswordState{Set: true, Algo: "yescrypt", LastChange: 19000}},
	)
	c.Accounts.Groups = append(c.Accounts.Groups, model.Group{Name: "admins", GID: 2000, Members: []string{"carol"}})
	c.Persist = append(c.Persist, model.PersistFile{Path: "/etc/sudoers.d/90-cloud-init-users", Kind: model.PersistKindSudoers, Mode: 0o100440,
		Lines: []string{"ubuntu ALL=(ALL) NOPASSWD:<redacted h:0123456789abcdef01234567>", "%admins ALL=(ALL) NOPASSWD: <redacted h:0123456789abcdef01234567>"}})
	c.Files = append(c.Files, fileEntry("/etc/sudoers.d/90-cloud-init-users", 0o440, 0, 0))
	it, _ := ByID("TT-SUDO-001")
	want := "# ubuntu has no usable password: without NOPASSWD sudo asks for one, so set it first or nobody may be able to become root\n" +
		"passwd ubuntu && sed -i 's/NOPASSWD[[:space:]]*:/PASSWD:/g' /etc/sudoers.d/90-cloud-init-users && visudo -c"
	if fix := it.FixFor(c, model.ScanContext{}); fix != want {
		t.Errorf("fix = %q", fix)
	}
	if !strings.Contains(it.Why, "password") {
		t.Errorf("Why does not warn about passwords: %q", it.Why)
	}
}

func TestSSHDCommandLineOptions(t *testing.T) {
	c := hardened()
	setSSHD(c, "PermitRootLogin no", "Match Address 10.0.0.5", "  PermitRootLogin prohibit-password")
	c.Runtime.Processes = []model.Process{
		{PID: 900, Comm: "sshd", Exe: "/usr/sbin/sshd", Cmdline: "sshd: /usr/sbin/sshd -D -o PermitRootLogin=yes -oX11Forwarding=yes [listener] 0 of 10-100 startups"},
		// A per-connection child of an older sshd is not a listener.
		{PID: 901, Comm: "sshd", Exe: "/usr/sbin/sshd", Cmdline: "sshd: alice [priv]"},
	}
	ctx := model.ScanContext{ServerAddr: "10.0.0.5"}
	r := result(t, c, ctx, "TT-SSH-001")
	// -o acts as the first global value; a matching Match block still
	// overrides it (sshd -T: prohibit-password from 10.0.0.5, yes otherwise).
	if r.Pass || r.Observed != "PermitRootLogin yes (sshd command line); from the telltale server 10.0.0.5: prohibit-password" {
		t.Errorf("TT-SSH-001 with -o: %+v", r)
	}
	if r := result(t, c, ctx, "TT-SSH-004"); r.Pass {
		t.Errorf("TT-SSH-004 with -oX11Forwarding=yes: %+v", r)
	}
	// The config file alone still evaluates as written.
	wantSSHD(t, EffectiveSSHD(c.Persist, ""), "permitrootlogin", "no")

	// A second, plain listener does not hide the loose one.
	c.Runtime.Processes = append(c.Runtime.Processes, model.Process{PID: 902, Comm: "sshd", Exe: "/usr/sbin/sshd", Cmdline: "/usr/sbin/sshd -D"})
	if r := result(t, c, ctx, "TT-SSH-001"); r.Pass {
		t.Errorf("loose listener hidden by a plain one: %+v", r)
	}

	// A listener reading another config file: the collected one is not what
	// runs, so SSH items are skipped.
	c.Runtime.Processes = []model.Process{{PID: 903, Comm: "sshd", Exe: "/tmp/.x/sshd", Cmdline: "/tmp/.x/sshd -f /tmp/.x/cfg -D"}}
	for _, id := range []string{"TT-SSH-001", "TT-SSH-002", "TT-SSH-008", "TT-SSH-009"} {
		if r := result(t, c, ctx, id); r.Skipped == "" || !strings.Contains(r.Skipped, "/tmp/.x/cfg") {
			t.Errorf("%s with -f: %+v", id, r)
		}
	}
	// -f naming the usual file changes nothing.
	c.Runtime.Processes = []model.Process{{PID: 904, Comm: "sshd", Exe: "/usr/sbin/sshd", Cmdline: "/usr/sbin/sshd -D -f /etc/ssh/sshd_config"}}
	if r := result(t, c, ctx, "TT-SSH-001"); !r.Pass {
		t.Errorf("-f /etc/ssh/sshd_config: %+v", r)
	}
}

func TestDroppedStigRefs(t *testing.T) {
	for _, id := range []string{"TT-ACCT-001", "TT-ACCT-004"} {
		if it, _ := ByID(id); len(it.Refs) != 0 {
			t.Errorf("%s refs = %v", id, it.Refs)
		}
	}
}

func TestSSHDListenerWithoutExe(t *testing.T) {
	// Without root /proc/<pid>/exe cannot be read: Exe is "", and the title
	// is "sshd: /usr/sbin/sshd ... [listener] ...".
	c := hardened()
	c.Runtime.Processes = []model.Process{{PID: 992, UID: 0, Comm: "sshd",
		Cmdline: "sshd: /usr/sbin/sshd -D -o PermitRootLogin=yes [listener] 0 of 10-100 startups"}}
	if r := result(t, c, model.ScanContext{}, "TT-SSH-001"); r.Pass || r.Observed != "PermitRootLogin yes (sshd command line)" {
		t.Errorf("listener without exe: %+v", r)
	}
	c.Runtime.Processes[0].Cmdline = "sshd: /usr/sbin/sshd -D -f /tmp/.x/cfg [listener] 0 of 10-100 startups"
	if r := result(t, c, model.ScanContext{}, "TT-SSH-001"); r.Skipped == "" {
		t.Errorf("-f on a listener without exe: %+v", r)
	}
	// Plain argv form (older sshd) works the same.
	c.Runtime.Processes[0].Cmdline = "/usr/sbin/sshd -D -o PermitRootLogin=yes"
	if r := result(t, c, model.ScanContext{}, "TT-SSH-001"); r.Pass {
		t.Errorf("plain argv listener without exe: %+v", r)
	}
}

func TestSSHDListenerMustBeRoot(t *testing.T) {
	c := hardened()
	for _, uid := range []int{1000, -1} {
		c.Runtime.Processes = []model.Process{
			{PID: 4000, UID: uid, Comm: "sshd", Exe: "/usr/sbin/sshd", Cmdline: "/usr/sbin/sshd -f /home/u/x"},
			{PID: 4001, UID: uid, Comm: "sshd", Cmdline: "sshd: /usr/sbin/sshd -o PermitRootLogin=yes [listener] 0 of 10-100 startups"},
		}
		if r := result(t, c, model.ScanContext{}, "TT-SSH-001"); !r.Pass || r.Skipped != "" {
			t.Errorf("uid %d process treated as the sshd listener: %+v", uid, r)
		}
	}
}

func TestSSHDOptionForms(t *testing.T) {
	for _, args := range []string{
		"-D -o PermitRootLogin=yes",
		"-D -oPermitRootLogin=yes",
		"-D -o PermitRootLogin = yes", // -o "PermitRootLogin = yes"
		"-D -o PermitRootLogin= yes",
		"-D -o PermitRootLogin =yes",
		"-D -o PermitRootLogin yes",
		"-De -o PermitRootLogin=yes",
	} {
		l := parseSSHDOptions(strings.Fields(args))
		if len(l.Opts) != 1 || l.Opts[0] != (sshdOption{Key: "permitrootlogin", Value: "yes"}) {
			t.Errorf("%q: opts = %+v", args, l.Opts)
		}
	}
}

func TestSSHDPortsFollowSSHD(t *testing.T) {
	// From sshd -T: -o Port adds to the file's ports; -p replaces them and
	// makes a later -o Port ignored; 22 only when nothing sets a port.
	cases := []struct {
		file []string
		args string
		want []int
	}{
		{[]string{"Port 22", "Port 2222"}, "-D -o Port=3333", []int{22, 2222, 3333}},
		{[]string{"Port 22", "Port 2222"}, "-D -p 4444", []int{4444}},
		{[]string{"Port 22", "Port 2222"}, "-D -p 4444 -o Port=3333", []int{4444}},
		{[]string{"Port 22", "Port 2222"}, "-D -o Port=3333 -p 4444", []int{3333, 4444}},
		{[]string{"PermitRootLogin no"}, "-D -o Port=3333", []int{3333}},
		{[]string{"PermitRootLogin no"}, "-D", []int{22}},
	}
	for _, tc := range cases {
		c := hardened()
		setSSHD(c, tc.file...)
		c.Runtime.Processes = []model.Process{{PID: 900, Comm: "sshd", Cmdline: "sshd: /usr/sbin/sshd " + tc.args + " [listener] 0 of 10-100 startups"}}
		if got := sshPorts(c); fmt.Sprint(got) != fmt.Sprint(tc.want) {
			t.Errorf("%v %q: ports %v, want %v", tc.file, tc.args, got, tc.want)
		}
	}
}

// applyFix runs a fix command against copies of the sshd config files in a
// temporary directory and returns them as collected files again.
func applyFix(t *testing.T, fix string, files []model.PersistFile) []model.PersistFile {
	t.Helper()
	if _, err := exec.LookPath("sed"); err != nil {
		t.Skip("no sed")
	}
	dir := t.TempDir()
	for _, f := range files {
		p := filepath.Join(dir, f.Path)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(strings.Join(f.Lines, "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cmd := strings.TrimSuffix(fix, reloadSSH)
	cmd = strings.ReplaceAll(cmd, " /etc/ssh/", " "+dir+"/etc/ssh/")
	if out, err := exec.Command("sh", "-c", cmd).CombinedOutput(); err != nil {
		t.Fatalf("%s: %v %s", cmd, err, out)
	}
	var out []model.PersistFile
	for _, f := range files {
		b, err := os.ReadFile(filepath.Join(dir, f.Path))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, sshdFile(f.Path, strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")...))
	}
	return out
}

func TestRootLoginFixPlacesServerBlockFirst(t *testing.T) {
	ctx := model.ScanContext{ServerAddr: "10.0.0.5"}
	it, _ := ByID("TT-SSH-001")
	cases := []struct {
		name  string
		lines []string
		fix   string
	}{
		{"Match all sets yes", []string{"PermitRootLogin no", "Match all", "  PermitRootLogin yes"},
			`sed -i '3s/.*/PermitRootLogin no/' /etc/ssh/sshd_config && sed -i -e '2i Match Address 10.0.0.5' -e '2i\    PermitRootLogin prohibit-password' /etc/ssh/sshd_config && systemctl reload ssh`},
		{"broader block for the server", []string{"PermitRootLogin no", "Match Address 10.0.0.0/8", "  PermitRootLogin yes"},
			`sed -i -e '2i Match Address 10.0.0.5' -e '2i\    PermitRootLogin prohibit-password' /etc/ssh/sshd_config && systemctl reload ssh`},
		{"global prohibit-password", []string{"PermitRootLogin prohibit-password", "X11Forwarding no"},
			`sed -i '1s/.*/PermitRootLogin no/' /etc/ssh/sshd_config && printf '\nMatch Address %s\n    PermitRootLogin prohibit-password\n' 10.0.0.5 >> /etc/ssh/sshd_config && systemctl reload ssh`},
		{"unset", []string{"# PermitRootLogin prohibit-password"},
			`sed -i '1i PermitRootLogin no' /etc/ssh/sshd_config && printf '\nMatch Address %s\n    PermitRootLogin prohibit-password\n' 10.0.0.5 >> /etc/ssh/sshd_config && systemctl reload ssh`},
	}
	for _, tc := range cases {
		c := hardened()
		setSSHD(c, tc.lines...)
		fix := it.FixFor(c, ctx)
		if fix != tc.fix {
			t.Errorf("%s: fix = %q", tc.name, fix)
			continue
		}
		fixed := applyFix(t, fix, []model.PersistFile{sshdFile("/etc/ssh/sshd_config", tc.lines...)})
		wantSSHD(t, EffectiveSSHD(fixed, "10.0.0.5"), "permitrootlogin", "prohibit-password")
		wantSSHD(t, EffectiveSSHD(fixed, ""), "permitrootlogin", "no")
		c.Persist[0] = fixed[0]
		if r := result(t, c, ctx, "TT-SSH-001"); !r.Pass {
			t.Errorf("%s: still failing after the fix: %+v", tc.name, r)
		}
	}
}

func TestNoPasswdUserLists(t *testing.T) {
	c := hardened()
	c.Accounts.Users = append(c.Accounts.Users,
		model.User{Name: "ubuntu", UID: 1001, GID: 1001, Shell: "/bin/bash", Password: model.PasswordState{Locked: true, LastChange: 19000}},
	)
	sudo := model.PersistFile{Path: "/etc/sudoers.d/x", Kind: model.PersistKindSudoers, Mode: 0o100440,
		Lines: []string{"alice, ubuntu ALL=(ALL) NOPASSWD: ALL"}}
	c.Persist = append(c.Persist, sudo)
	c.Files = append(c.Files, fileEntry("/etc/sudoers.d/x", 0o440, 0, 0))
	it, _ := ByID("TT-SUDO-001")
	base := `sed -i 's/NOPASSWD[[:space:]]*:/PASSWD:/g' /etc/sudoers.d/x && visudo -c`
	want := "# ubuntu has no usable password: without NOPASSWD sudo asks for one, so set it first or nobody may be able to become root\npasswd ubuntu && " + base
	if fix := it.FixFor(c, model.ScanContext{}); fix != want {
		t.Errorf("space after comma: fix = %q", fix)
	}
	c.Persist[len(c.Persist)-1].Lines = []string{"ALL ALL=(ALL) NOPASSWD: ALL"}
	want = "# a NOPASSWD rule covers ALL users: every user with a locked password must get one before this change\n" + base
	if fix := it.FixFor(c, model.ScanContext{}); fix != want {
		t.Errorf("ALL rule: fix = %q", fix)
	}
}
