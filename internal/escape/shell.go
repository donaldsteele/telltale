package escape

import (
	"strings"
	"unicode/utf8"
)

// ShellQuote returns s as one word for bash. A value that is valid UTF-8 in
// which every rune is printable (NeedsEscape is false for it) is
// single-quoted, which every POSIX shell reads the same way. Any other value
// uses $'...' with every control, format, odd-space, invalid, non-ASCII byte
// and every quote or backslash written as \xNN, so the word holds only
// printable ASCII and no shell, in any locale, can read it differently.
//
// A NUL byte cannot be part of a shell word: check Quotable first and give
// the value no command when it is false.
func ShellQuote(s string) string {
	if plain(s) {
		return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
	}
	var b strings.Builder
	b.WriteString("$'")
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c >= 0x7f || c == '\'' || c == '\\' {
			b.WriteString(`\x`)
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&0x0f])
		} else {
			b.WriteByte(c)
		}
	}
	b.WriteByte('\'')
	return b.String()
}

func plain(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if NeedsEscape(r) {
			return false
		}
	}
	return true
}

// Quotable reports whether s can be one word of a shell command at all: a
// NUL byte cannot, and no quoting changes that.
func Quotable(s string) bool { return !strings.ContainsRune(s, 0) }

// HasUnsafe reports whether a command text holds something that must not be
// printed raw: invalid UTF-8, or a control, format, separator, private-use or
// odd-space character. Newline and tab are fine in a command a builder wrote
// over several lines; every machine value that held one was quoted.
func HasUnsafe(s string) bool {
	if !utf8.ValidString(s) {
		return true
	}
	for _, r := range s {
		if r != '\n' && r != '\t' && NeedsEscape(r) {
			return true
		}
	}
	return false
}
