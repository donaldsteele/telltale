package report

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/donaldsteele/telltale/internal/checklist"
	"github.com/donaldsteele/telltale/internal/escape"
	"github.com/donaldsteele/telltale/internal/model"
)

var update = flag.Bool("update", false, "rewrite the golden files")

func ts(s string) *time.Time {
	t, err := time.Parse("2006-01-02 15:04", s)
	if err != nil {
		panic(err)
	}
	return &t
}

func host() model.Host {
	return model.Host{Hostname: "web01", OSPretty: "Debian 12", Arch: "amd64"}
}

func tampering() *model.Report {
	return &model.Report{
		Schema: model.ReportSchema, Host: host(), Time: *ts("2026-11-22 14:05"),
		ComparedAgainst: []string{"snapshot of 2026-11-02", "Debian packages", "checklist (74 items)"},
		CouldNotRuleOut: []string{"kernel-level rootkits (any on-machine check can be fooled)"},
		Findings: []model.Finding{
			{Key: "check:sshd.permitrootlogin", ID: "TT-CHK-001", Severity: model.SevTampering, Title: "SSH root login was turned back on",
				Why:      "an attacker who has the root password can now log in directly.",
				Fix:      "sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config && systemctl reload ssh",
				Evidence: []model.Evidence{{Path: "sshd_config", Line: 32, Before: "PermitRootLogin no", After: "PermitRootLogin yes", When: ts("2026-11-21 03:12")}}},
			{Key: "snap.key_added", ID: "TT-SNAP-004", Severity: model.SevBackdoor, Title: "New SSH key for root, not in the snapshot",
				Why:      "whoever holds this key can log in as root without a password.",
				Fix:      "sed -i '3d' /root/.ssh/authorized_keys",
				Evidence: []model.Evidence{{Path: "/root/.ssh/authorized_keys", Line: 3, After: "ssh-ed25519 AAAA... mallory", When: ts("2026-11-21 03:10")}}},
			{Key: "check:umask", ID: "TT-CHK-050", Severity: model.SevWeak, Title: "Default umask is permissive",
				Why: "new files are readable by every user.", Fix: "echo 'UMASK 027' >> /etc/login.defs",
				Evidence: []model.Evidence{{Path: "/etc/login.defs", Line: 151, Before: "UMASK 022", After: "UMASK 022"}}},
			{Key: "pkg.clock_skew", ID: "TT-PKG-009", Severity: model.SevNote, Title: "The machine's clock is out of date",
				Why: "package verification took its time from the signed indexes."},
		},
		Explained: []model.Finding{
			{Key: "explained:openssl", Severity: model.SevExplained, Title: "openssl upgraded from 3.0.14 to 3.0.15; 2 files changed with it",
				Evidence: []model.Evidence{{Before: "3.0.14", After: "3.0.15", Detail: "upgraded"}, {Path: "/usr/bin/openssl"}, {Path: "/usr/lib/x86_64-linux-gnu/libssl.so.3"}}},
		},
		Exceptions: []model.Exception{{FindingKey: "check:umask", AcceptedValue: "UMASK 022", Note: "intentional", At: *ts("2026-11-10 09:00")}},
		Skipped:    []model.Skip{{Check: "firewall", Reason: "needs root"}},
		ExitCode:   2,
	}
}

func clean() *model.Report {
	return &model.Report{
		Schema: model.ReportSchema, Host: host(), Time: *ts("2026-11-22 14:05"),
		ComparedAgainst: []string{"snapshot of 2026-11-02", "Debian packages", "checklist (74 items)"},
		CouldNotRuleOut: []string{"kernel-level rootkits (any on-machine check can be fooled)"},
		Findings:        []model.Finding{}, Explained: []model.Finding{},
	}
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	p := filepath.Join("testdata", "golden", name)
	if *update {
		if err := os.WriteFile(p, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != got {
		t.Errorf("%s differs from the golden file (run with -update to rewrite it):\n--- got ---\n%s--- want ---\n%s", name, got, want)
	}
}

func text(r *model.Report, opt TextOptions) string {
	var b bytes.Buffer
	Text(&b, r, opt)
	return b.String()
}

func TestTextGoldenTampering(t *testing.T) {
	golden(t, "report-tampering.txt", text(tampering(), TextOptions{Width: 100}))
}

func TestTextGoldenClean(t *testing.T) {
	golden(t, "report-clean.txt", text(clean(), TextOptions{Width: 100}))
}

func TestTextColorOnlyWhenAsked(t *testing.T) {
	if strings.Contains(text(tampering(), TextOptions{}), "\x1b[") {
		t.Error("colour without Color")
	}
	if !strings.Contains(text(tampering(), TextOptions{Color: true}), "\x1b[1;31mTAMPERING") {
		t.Error("no colour with Color")
	}
}

func hostile() *model.Report {
	r := tampering()
	r.Host.Hostname = "evil\x1b[2Jhost<b>"
	r.Findings[0].Title = "title \x1b]0;pwned\x07 <img src=x onerror=alert(1)>"
	r.Findings[0].Fix = "rm " + escape.ShellQuote("/x'; <script>alert(2)</script>")
	r.Findings[0].Evidence = []model.Evidence{{Path: "/tmp/\x1b[2J<script>alert(1)</script>", Line: 1,
		Before: "a\x1b[2Jb", After: "<script>alert(3)</script>\x00", Detail: "x\rcarriage"}}
	r.Explained[0].Key = "explained:pk\x1b[2Jg"
	r.Skipped = []model.Skip{{Check: "c\x1b[2J", Reason: "<script>"}}
	return r
}

func TestReportEscapesHostileEvidence(t *testing.T) {
	tx := text(hostile(), TextOptions{})
	if strings.ContainsAny(tx, "\x1b\x00\x07\r") {
		t.Errorf("control byte reached the terminal: %q", tx)
	}
	if !strings.Contains(tx, `\x1b[2J`) {
		t.Errorf("the escape was not shown escaped: %q", tx)
	}
	var b bytes.Buffer
	if err := HTML(&b, hostile()); err != nil {
		t.Fatal(err)
	}
	h := b.String()
	if strings.ContainsAny(h, "\x1b\x00\x07\r") {
		t.Errorf("control byte reached the page")
	}
	for _, bad := range []string{"<script>alert", "<img src=x", "<b>"} {
		if strings.Contains(h, bad) {
			t.Errorf("%q became markup in the page", bad)
		}
	}
	if !strings.Contains(h, "&lt;script&gt;alert(1)") {
		t.Error("the script text is not shown escaped")
	}
	if strings.Contains(h, "<script") {
		t.Error("the page has a script element")
	}
}

func TestHTMLSelfContained(t *testing.T) {
	var b bytes.Buffer
	if err := HTML(&b, tampering()); err != nil {
		t.Fatal(err)
	}
	h := b.String()
	if !strings.Contains(h, "<style>") || !strings.Contains(h, "prefers-color-scheme: dark") {
		t.Error("no inline style with a dark scheme")
	}
	if m := regexp.MustCompile(`(?i)\b(src|href)\s*=\s*["']?\s*(https?:)?//`).FindString(h); m != "" {
		t.Errorf("external reference %q", m)
	}
	if regexp.MustCompile(`(?i)(url\(|@import|<link|<script|<iframe)`).MatchString(h) {
		t.Error("the page loads something")
	}
	for _, want := range []string{"TAMPERING", "SSH root login was turned back on", "sshd_config:32", "PermitRootLogin yes", "BACKDOOR", "openssl", "Skipped checks", "firewall"} {
		if !strings.Contains(h, want) {
			t.Errorf("page lacks %q", want)
		}
	}
}

func TestJSONNamesSeverity(t *testing.T) {
	var b bytes.Buffer
	if err := JSON(&b, tampering()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "\n  \"") || !strings.Contains(b.String(), `"severity": "tampering"`) {
		t.Errorf("%s", b.String())
	}
	var back model.Report
	if err := json.Unmarshal(b.Bytes(), &back); err != nil || back.ExitCode != 2 {
		t.Errorf("%v %+v", err, back.ExitCode)
	}
}

func TestFixPrintsByteForByte(t *testing.T) {
	bash, bashErr := exec.LookPath("bash")
	for _, name := range []string{"/etc/cron.d/x'; echo INJECTED; '", "a\nb", "a\x1b[2Jb", "a\u202eb", "back\\slash", "bad\xffbyte"} {
		fix := "rm " + escape.ShellQuote(name)
		r := clean()
		r.Findings = []model.Finding{{Key: "k", Severity: model.SevBackdoor, Title: "t", Fix: fix}}
		var b bytes.Buffer
		Text(&b, r, TextOptions{})
		if !strings.Contains(b.String(), "Fix: "+fix+"\n") {
			t.Errorf("%q: fix not printed as built:\n%s", name, b.String())
		}
		if bashErr == nil {
			out, err := exec.Command(bash, "-c", "printf %s "+strings.TrimPrefix(fix, "rm ")).Output()
			if err != nil || string(out) != name {
				t.Errorf("%q: bash gave %q", name, out)
			}
		}
	}
	// Defence in depth: a raw control character is shown escaped and marked.
	r := clean()
	r.Findings = []model.Finding{{Key: "k", Severity: model.SevNote, Title: "t", Fix: "rm \x1b[2J"}}
	var b bytes.Buffer
	Text(&b, r, TextOptions{})
	if strings.Contains(b.String(), "\x1b") || !strings.Contains(b.String(), "do not paste") {
		t.Errorf("%q", b.String())
	}
}

func TestIDShownAndEscaped(t *testing.T) {
	r := clean()
	r.Findings = []model.Finding{{Key: "snap.file_added:/tmp/a\x1b[2J<b>", Severity: model.SevNote, Title: "t"}}
	var b bytes.Buffer
	Text(&b, r, TextOptions{})
	if !strings.Contains(b.String(), `ID: snap.file_added:/tmp/a\x1b[2J<b>`) {
		t.Errorf("%q", b.String())
	}
	b.Reset()
	HTML(&b, r)
	if !strings.Contains(b.String(), "ID: <code>snap.file_added:/tmp/a\\x1b[2J&lt;b&gt;</code>") {
		t.Errorf("html lacks the escaped ID")
	}
}

func TestBuiltInFixesPrintExactly(t *testing.T) {
	for _, id := range []string{"TT-FILE-005", "TT-ACCT-004"} {
		it, ok := checklist.ByID(id)
		if !ok || it.Fix == "" {
			t.Fatalf("no item %s", id)
		}
		r := clean()
		r.Findings = []model.Finding{{Key: "k", Severity: model.SevWeak, Title: "t", Fix: it.Fix}}
		var b bytes.Buffer
		Text(&b, r, TextOptions{})
		if !strings.Contains(b.String(), "Fix: "+it.Fix+"\n") || strings.Contains(b.String(), "do not paste") {
			t.Errorf("%s not exact:\n%s", id, b.String())
		}
	}
}

func TestMultiLineFixPrintsUnderTheFixColumn(t *testing.T) {
	r := clean()
	r.Findings = []model.Finding{{Key: "k", Severity: model.SevWeak, Title: "t", Fix: "# note\ngrep -rn x /etc"}}
	var b bytes.Buffer
	Text(&b, r, TextOptions{})
	if !strings.Contains(b.String(), "            Fix: # note\n                 grep -rn x /etc\n") || strings.Contains(b.String(), "do not paste") {
		t.Errorf("%q", b.String())
	}
	for _, bad := range []string{"rm ‮", "rm  x", "rm \x00"} {
		r.Findings[0].Fix = bad
		b.Reset()
		Text(&b, r, TextOptions{})
		if !strings.Contains(b.String(), "do not paste") {
			t.Errorf("%q printed without the marker", bad)
		}
	}
}
