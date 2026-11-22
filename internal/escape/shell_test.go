package escape

import (
	"os/exec"
	"testing"
)

var hostileNames = []string{"/etc/cron.d/x'; echo INJECTED; '", "a\nb", "a\x1b[2Jb", "a\u202eb", "back\\slash", "bad\xffbyte", "plain name", "it's \\ \u200b", "\x7f"}

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
