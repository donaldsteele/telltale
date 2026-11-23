package escape

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

var hostileNames = []string{"中文\\", "a\u00a0b", "a\u2028b", "/etc/cron.d/x'; echo INJECTED; '", "a\nb", "a\x1b[2Jb", "a\u202eb", "back\\slash", "bad\xffbyte", "plain name", "it's \\ \u200b", "\x7f"}

func TestShellQuoteRoundTripsThroughBash(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	for _, name := range hostileNames {
		q := ShellQuote(name)
		if HasUnsafe(q) {
			t.Errorf("%q: quoted form holds a raw control or format character: %q", name, q)
		}
		out, err := exec.Command(bash, "-c", "printf %s "+q).Output()
		if err != nil || string(out) != name {
			t.Errorf("%q: bash gave %q (%v) from %s", name, out, err, q)
		}
	}
}

func TestShellQuotePlainUsesSingleQuotes(t *testing.T) {
	if got := ShellQuote("it's"); got != `'it'\''s'` {
		t.Errorf("%s", got)
	}
}

func TestShellQuoteNULIsNotQuotable(t *testing.T) {
	if Quotable("root\x00x") || !Quotable("root") {
		t.Fatal("Quotable")
	}
}

func TestShellQuoteDollarFormIsPlainASCII(t *testing.T) {
	for _, s := range []string{"中文\\\n", "a\u00a0b", "a\u2028b", "x'y\nz", "\xe4\xb8"} {
		q := ShellQuote(s)
		for i := 0; i < len(q); i++ {
			if q[i] < 0x20 || q[i] >= 0x7f {
				t.Errorf("%q: non-ASCII byte in %q", s, q)
				break
			}
		}
	}
	if ShellQuote("中文\n") != `$'\xe4\xb8\xad\xe6\x96\x87\x0a'` {
		t.Errorf("%s", ShellQuote("中文\n"))
	}
}

func TestShellQuoteDashDoesNotInject(t *testing.T) {
	dash, err := exec.LookPath("dash")
	if err != nil {
		t.Skip("no dash")
	}
	mark := filepath.Join(t.TempDir(), "injected")
	for _, name := range []string{"'; touch " + mark + "; '", "\\'; touch " + mark + "; '", "a\nb'; touch " + mark + "; '", "中\\'; touch " + mark + "; '"} {
		exec.Command(dash, "-c", "printf %s "+ShellQuote(name)).Run()
		if _, err := os.Stat(mark); err == nil {
			t.Fatalf("%q: dash ran the injected command", name)
		}
	}
}

func TestNeedsEscapeOneRule(t *testing.T) {
	for _, r := range []rune{0, 0x1b, 0x7f, 0x85, 0x200b, 0x202e, 0xfeff, 0x2028, 0x2029, 0xe000, 0xa0, 0x3000, 0x378} {
		if !NeedsEscape(r) {
			t.Errorf("U+%04X not escaped", r)
		}
	}
	for _, r := range []rune{' ', 'a', '~', 'é', '中'} {
		if NeedsEscape(r) {
			t.Errorf("U+%04X escaped", r)
		}
	}
	if Terminal("a\u00a0b\u2028c") != `a\u{00A0}b\u{2028}c` {
		t.Errorf("%s", Terminal("a\u00a0b\u2028c"))
	}
}

func TestShellQuoteNonASCIIUsesHexForm(t *testing.T) {
	if got := ShellQuote("/srv/café"); got != `$'/srv/caf\xc3\xa9'` {
		t.Errorf("%s", got)
	}
	if got := ShellQuote("/srv/cafe"); got != `'/srv/cafe'` {
		t.Errorf("%s", got)
	}
}
