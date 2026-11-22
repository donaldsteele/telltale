package escape

import "testing"

func TestTerminalEscapesANSI(t *testing.T) {
	got := Terminal("\x1b[31mred")
	want := `\x1b[31mred`
	if got != want {
		t.Errorf("Terminal = %q, want %q", got, want)
	}
}

func TestTerminalInvalidUTF8(t *testing.T) {
	got := Terminal("a\xffb")
	want := `a\xffb`
	if got != want {
		t.Errorf("Terminal = %q, want %q", got, want)
	}
}

func TestTerminalNewlineTab(t *testing.T) {
	got := Terminal("a\nb\tc")
	want := `a\nb\tc`
	if got != want {
		t.Errorf("Terminal = %q, want %q", got, want)
	}
}

func TestTerminalKeepsUnicodeLetters(t *testing.T) {
	got := Terminal("café")
	want := "café"
	if got != want {
		t.Errorf("Terminal = %q, want %q", got, want)
	}
}

func TestTerminalEscapesBackslash(t *testing.T) {
	got := Terminal(`a\b`)
	want := `a\\b`
	if got != want {
		t.Errorf("Terminal = %q, want %q", got, want)
	}
}

func TestTerminalEscapesBidiControl(t *testing.T) {
	got := Terminal("a‮b")
	want := `a\u{202E}b`
	if got != want {
		t.Errorf("Terminal = %q, want %q", got, want)
	}
}

func TestTerminalEscapesDEL(t *testing.T) {
	got := Terminal("a\x7fb")
	want := `a\x7fb`
	if got != want {
		t.Errorf("Terminal = %q, want %q", got, want)
	}
}

func TestHTMLEscapesTags(t *testing.T) {
	got := HTML("<script>alert(1)</script>")
	want := `&lt;script&gt;alert(1)&lt;/script&gt;`
	if got != want {
		t.Errorf("HTML = %q, want %q", got, want)
	}
}
