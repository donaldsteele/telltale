package escape

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// ShellQuote returns s as one word for bash. A value that is valid UTF-8
// without control or format characters is single-quoted; any other value
// uses $'...' with \xNN for each control, format or invalid byte, so the
// result never holds a raw character that could alter a terminal or
// disguise the command.
func ShellQuote(s string) string {
	if plain(s) {
		return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
	}
	var b strings.Builder
	b.WriteString("$'")
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1, unicode.IsControl(r), unicode.Is(unicode.Cf, r):
			for j := 0; j < size; j++ {
				b.WriteString(`\x`)
				b.WriteByte(hexDigits[s[i+j]>>4])
				b.WriteByte(hexDigits[s[i+j]&0x0f])
			}
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\'':
			b.WriteString(`\'`)
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	b.WriteByte('\'')
	return b.String()
}

func plain(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

// HasUnsafe reports whether s holds a control or format character or invalid
// UTF-8, which a command printed to a terminal must not contain.
func HasUnsafe(s string) bool { return !plain(s) }
