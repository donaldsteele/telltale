// Package report renders a model.Report as plain text, JSON or one
// self-contained HTML file. Every string that came from the examined machine
// is escaped for its medium first; nothing hostile reaches a terminal as a
// control sequence or a page as markup.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/donaldsteele/telltale/internal/escape"
	"github.com/donaldsteele/telltale/internal/model"
)

// TextOptions controls the plain-text rendering.
type TextOptions struct {
	// Color adds ANSI colour to the severity labels.
	Color bool
	// Width is the width the prose is wrapped to; 0 means 100.
	Width int
}

const (
	timeLayout = "2006-01-02 15:04"
	labelWidth = 12
	indent     = "            "
)

// Label is the capitalised word that heads a finding of this severity.
func Label(s model.Severity) string {
	switch s {
	case model.SevTampering:
		return "TAMPERING"
	case model.SevBackdoor:
		return "BACKDOOR"
	case model.SevWeak:
		return "WEAK"
	case model.SevNote:
		return "NOTE"
	}
	return "EXPLAINED"
}

// JSON writes the report as indented JSON.
func JSON(w io.Writer, r *model.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// Text writes the report in the layout of the design: a header, what it was
// compared against and what it could not rule out, the ranked findings, the
// explained changes, the exceptions in force and the skipped checks.
func Text(w io.Writer, r *model.Report, opt TextOptions) {
	width := opt.Width
	if width <= 0 {
		width = 100
	}
	t := &textWriter{w: w, color: opt.Color, width: width}
	h := r.Host
	t.printf("telltale: %s (%s, %s)", escape.Terminal(h.Hostname), escape.Terminal(h.OSPretty), escape.Terminal(h.Arch))
	if !r.Time.IsZero() {
		t.printf("   %s", r.Time.UTC().Format(timeLayout))
	}
	t.printf("\n")
	t.list("Compared against:", r.ComparedAgainst, ", ")
	t.list("Could not rule out:", r.CouldNotRuleOut, "")
	if len(r.Findings) == 0 {
		t.printf("\nNo findings.\n")
	}
	for i := range r.Findings {
		t.printf("\n")
		t.finding(&r.Findings[i])
	}
	if len(r.Explained) > 0 {
		t.printf("\n")
		t.explained(r.Explained)
	}
	if len(r.Exceptions) > 0 {
		t.printf("\nExceptions in force (accepted by the owner):\n")
		for _, e := range r.Exceptions {
			t.printf("  %s = %s", escape.Terminal(e.FindingKey), escape.Terminal(e.AcceptedValue))
			if e.Note != "" {
				t.printf("   (%s)", escape.Terminal(e.Note))
			}
			t.printf("   accepted %s\n", e.At.UTC().Format("2006-01-02"))
		}
	}
	if len(r.Skipped) > 0 {
		t.printf("\nSkipped checks:\n")
		for _, s := range r.Skipped {
			t.printf("  %s: %s\n", escape.Terminal(s.Check), escape.Terminal(s.Reason))
		}
	}
}

type textWriter struct {
	w     io.Writer
	color bool
	width int
}

func (t *textWriter) printf(format string, a ...any) { fmt.Fprintf(t.w, format, a...) }

// list prints "Head first" and the rest on continuation lines. With a
// separator the items share one line.
func (t *textWriter) list(head string, items []string, sep string) {
	if len(items) == 0 {
		return
	}
	pad := strings.Repeat(" ", len(head)+1)
	if sep != "" {
		esc := make([]string, len(items))
		for i, s := range items {
			esc[i] = escape.Terminal(s)
		}
		t.wrap(head+" ", pad, strings.Join(esc, sep))
		return
	}
	for i, s := range items {
		lead := pad
		if i == 0 {
			lead = head + " "
		}
		t.wrap(lead, pad, escape.Terminal(s))
	}
}

// wrap writes text after lead, continuing on lines that start with cont.
// text is already escaped.
func (t *textWriter) wrap(lead, cont, text string) {
	for _, line := range wrapLines(text, t.width-utf8.RuneCountInString(lead)) {
		t.printf("%s%s\n", lead, line)
		lead = cont
	}
}

// wrapLines breaks s at spaces into lines of at most width runes; a word
// longer than that stays whole.
func wrapLines(s string, width int) []string {
	if width < 20 {
		width = 20
	}
	var lines []string
	cur := ""
	for _, word := range strings.Fields(s) {
		switch {
		case cur == "":
			cur = word
		case utf8.RuneCountInString(cur)+1+utf8.RuneCountInString(word) <= width:
			cur += " " + word
		default:
			lines = append(lines, cur)
			cur = word
		}
	}
	if cur != "" || len(lines) == 0 {
		lines = append(lines, cur)
	}
	return lines
}

func (t *textWriter) label(s model.Severity) string {
	l := Label(s)
	if t.color {
		code := map[model.Severity]string{
			model.SevTampering: "1;31", model.SevBackdoor: "31", model.SevWeak: "33", model.SevNote: "36", model.SevExplained: "2",
		}[s]
		l = "\x1b[" + code + "m" + l + "\x1b[0m"
	}
	pad := labelWidth - len(Label(s))
	if pad < 1 {
		pad = 1
	}
	return l + strings.Repeat(" ", pad)
}

// where is "path:line" for a piece of evidence, escaped.
func where(e *model.Evidence) string {
	if e.Path == "" {
		return ""
	}
	s := escape.Terminal(e.Path)
	if e.Line > 0 {
		s += ":" + strconv.Itoa(e.Line)
	}
	return s
}

func (t *textWriter) finding(f *model.Finding) {
	title := escape.Terminal(f.Title)
	head := t.label(f.Severity) + title
	skipFirst := false
	if len(f.Evidence) > 0 {
		if p := where(&f.Evidence[0]); p != "" {
			if labelWidth+utf8.RuneCountInString(title)+3+utf8.RuneCountInString(p) <= t.width {
				head += "   " + p
				skipFirst = true
			}
		}
	}
	t.printf("%s\n", head)
	for i := range f.Evidence {
		e := &f.Evidence[i]
		if i > 0 || !skipFirst {
			if p := where(e); p != "" {
				t.printf("%s%s\n", indent, p)
			}
		}
		var line string
		switch {
		case e.Before != "" && e.After != "":
			line = escape.Terminal(e.Before) + "  ->  " + escape.Terminal(e.After)
		case e.After != "":
			line = "-> " + escape.Terminal(e.After)
		case e.Before != "":
			line = escape.Terminal(e.Before) + "  ->  (gone)"
		}
		if e.When != nil {
			if line != "" {
				line += "   "
			}
			line += "changed " + e.When.UTC().Format(timeLayout)
		}
		if line != "" {
			t.printf("%s%s\n", indent, line)
		}
		if e.Detail != "" {
			t.wrap(indent, indent, escape.Terminal(e.Detail))
		}
	}
	if f.Why != "" {
		t.wrap(indent+"Why: ", indent+"     ", escape.Terminal(f.Why))
	}
	if f.Fix != "" {
		t.printf("%sFix: %s\n", indent, FixText(f.Fix))
	}
	if f.Key != "" {
		t.printf("%sID: %s\n", indent, escape.Terminal(f.Key))
	}
}

func (t *textWriter) explained(gs []model.Finding) {
	names := make([]string, 0, len(gs))
	for _, g := range gs {
		n := strings.TrimPrefix(g.Key, "explained:")
		names = append(names, escape.Terminal(n))
	}
	n := len(gs)
	word := "groups"
	if n == 1 {
		word = "group"
	}
	t.wrap(t.label(model.SevExplained)+"", indent, fmt.Sprintf("%d %s of changes explained by their packages (%s)", n, word, strings.Join(names, ", ")))
	for i := range gs {
		g := &gs[i]
		t.wrap(indent+"- ", indent+"  ", escape.Terminal(g.Title))
		for j := range g.Evidence {
			e := &g.Evidence[j]
			if p := where(e); p != "" {
				t.printf("%s    %s\n", indent, p)
			} else if e.Detail != "" {
				t.wrap(indent+"    ", indent+"    ", escape.Terminal(e.Detail))
			}
		}
	}
}

// FixText is a fix command as it is shown: byte for byte as built, since it
// is a shell command and escaping would change what it does. A command that
// holds a control or format character anyway is shown escaped and marked.
func FixText(fix string) string {
	if escape.HasUnsafe(fix) {
		return escape.Terminal(fix) + "   (contains control characters; do not paste, edit by hand)"
	}
	return fix
}
