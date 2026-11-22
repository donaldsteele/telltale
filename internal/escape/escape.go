// Package escape renders text read from a possibly compromised machine safe
// for terminals and HTML. Nothing hostile can put control sequences on a
// terminal or markup in a page.
package escape

import (
	"fmt"
	"html"
	"strings"
	"unicode"
	"unicode/utf8"
)

const hexDigits = "0123456789abcdef"

// Terminal returns s with every byte that could alter a terminal or disguise
// text replaced by an escape. Printable ASCII and valid non-control UTF-8 are
// kept as they are; a backslash becomes a double backslash; newline and tab
// become \n and \t; every other byte becomes \xHH; and a valid rune that
// must be hidden (format or bidi controls, separators, private use) becomes
// \u{XXXX}.
func Terminal(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			writeHexByte(&b, s[i])
			i++
			continue
		}
		switch {
		case r < utf8.RuneSelf:
			writeASCII(&b, byte(r))
		case r < 0xA0:
			// C1 control: escape each UTF-8 byte of the rune.
			for j := i; j < i+size; j++ {
				writeHexByte(&b, s[j])
			}
		case mustEscape(r):
			fmt.Fprintf(&b, `\u{%04X}`, r)
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

// HTML escapes s for inclusion in HTML text or attribute values. It applies
// Terminal first so that the result is also free of control characters.
func HTML(s string) string {
	return html.EscapeString(Terminal(s))
}

func writeASCII(b *strings.Builder, c byte) {
	switch {
	case c == '\n':
		b.WriteString(`\n`)
	case c == '\t':
		b.WriteString(`\t`)
	case c == '\\':
		b.WriteString(`\\`)
	case c >= 0x20 && c <= 0x7e:
		b.WriteByte(c)
	default:
		writeHexByte(b, c)
	}
}

func writeHexByte(b *strings.Builder, c byte) {
	b.WriteString(`\x`)
	b.WriteByte(hexDigits[c>>4])
	b.WriteByte(hexDigits[c&0x0f])
}

// NeedsEscape reports whether a valid rune must not be shown or pasted raw:
// C0, DEL and C1 controls, format characters (bidi overrides, zero-width
// marks), line and paragraph separators, private use, surrogates, unassigned
// runes and every space other than U+0020.
func NeedsEscape(r rune) bool { return !unicode.IsPrint(r) }

func mustEscape(r rune) bool { return NeedsEscape(r) }
