// Package redact replaces secret values in kept config text with keyed
// digests, so a changed value still shows as changed without the secret
// being stored.
package redact

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

const redactedPrefix = "<redacted "

var (
	// systemd Environment= line; the rest is one or more NAME=value
	// assignments, each optionally wrapped in double or single quotes.
	envLine = regexp.MustCompile(`^(\s*Environment=)(.*)$`)
	envArg  = regexp.MustCompile(`"([^"]*)"|'([^']*)'|([A-Za-z_][A-Za-z0-9_]*=)("[^"]*"|'[^']*'|[^\s"']+)`)
	envIn   = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*=)(.+)$`)

	// shell export NAME=value; quoted values are replaced including quotes.
	exportRe = regexp.MustCompile(`^(\s*export\s+[A-Za-z_][A-Za-z0-9_]*=)("[^"]*"|'[^']*'|\S+)`)

	// scheme://user:pass@host; user and password are redacted together.
	urlRe = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.\-]*://)([^/\s@:]*):([^/\s@]+)@`)

	// key=value or key: value where the key contains a secret-like word.
	// The value runs to the end of the line.
	kvRe = regexp.MustCompile(`(?i)([\w.\-]*(?:pass(?:word|wd)?|secret|token|key|credential)[\w.\-]*)(\s*[=:]\s*)(\S.*?)(\s*)$`)
)

// Digest returns "h:" followed by the first 12 bytes of HMAC-SHA256(key,
// value) in hex.
func Digest(key []byte, value string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(value))
	return "h:" + hex.EncodeToString(mac.Sum(nil)[:12])
}

// Line returns line with every secret value replaced by "<redacted h:...>"
// and the number of values replaced. A line with nothing to redact is
// returned unchanged with n == 0. Running Line on its own output changes
// nothing further.
func Line(key []byte, line string) (out string, n int) {
	out = line
	total := 0

	if sub := envLine.FindStringSubmatch(out); sub != nil {
		rest, c := replaceAll(envArg, sub[2], func(m []string) (string, bool) {
			return envRepl(key, m)
		})
		out = sub[1] + rest
		total += c
	}

	out, c := replaceAll(exportRe, out, func(m []string) (string, bool) {
		return assignRepl(key, m[1], m[2])
	})
	total += c

	out, c = replaceAll(urlRe, out, func(m []string) (string, bool) {
		if isRedacted(m[2]) {
			return "", false
		}
		return m[1] + replacement(key, m[2]+":"+m[3]) + "@", true
	})
	total += c

	out, c = redactKeyValues(key, out)
	total += c

	return out, total
}

// envRepl redacts one Environment= argument: either a bare NAME=value or a
// whole quoted token such as "NAME=a b c" whose value contains spaces.
func envRepl(key []byte, m []string) (string, bool) {
	if m[3] != "" {
		return assignRepl(key, m[3], m[4])
	}
	q := m[0][:1]
	inner := m[1]
	if q == "'" {
		inner = m[2]
	}
	sub := envIn.FindStringSubmatch(inner)
	if sub == nil {
		return "", false
	}
	r, ok := assignRepl(key, sub[1], sub[2])
	if !ok {
		return "", false
	}
	return q + r + q, true
}

// assignRepl redacts val after name. The name is kept; quoted values are
// replaced whole. Empty values and values that are already redacted are
// left alone.
func assignRepl(key []byte, name, val string) (string, bool) {
	secret := unquote(val)
	if secret == "" || isRedacted(secret) {
		return "", false
	}
	return name + replacement(key, secret), true
}

// redactKeyValues redacts the value of every key=value or key: value pair
// whose key looks secret. Because a value runs to the end of the line, a
// value that is already redacted is skipped past its redacted token so any
// later pair on the same line is still checked.
func redactKeyValues(key []byte, s string) (string, int) {
	var b strings.Builder
	n, last, scan := 0, 0, 0
	for scan < len(s) {
		loc := kvRe.FindStringSubmatchIndex(s[scan:])
		if loc == nil {
			break
		}
		start, end := scan+loc[0], scan+loc[1]
		valStart, valEnd := scan+loc[6], scan+loc[7]
		val := s[valStart:valEnd]
		secret := unquote(val)
		switch {
		case isRedacted(secret):
			if i := strings.IndexByte(s[valStart:], '>'); i >= 0 {
				scan = valStart + i + 1
			} else {
				scan = valStart + len(redactedPrefix)
			}
		case secret == "":
			scan = end
		default:
			b.WriteString(s[last:start])
			b.WriteString(s[scan+loc[2]:scan+loc[3]] + s[scan+loc[4]:scan+loc[5]])
			b.WriteString(replacement(key, secret))
			b.WriteString(s[scan+loc[8] : scan+loc[9]])
			last = end
			n++
			scan = end
		}
	}
	if n == 0 {
		return s, 0
	}
	b.WriteString(s[last:])
	return b.String(), n
}

func replacement(key []byte, secret string) string {
	return redactedPrefix + Digest(key, secret) + ">"
}

// isRedacted reports whether v starts with an already-redacted token. The
// bare word is checked, not the prefix with its trailing space, because a
// whitespace-delimited value captures only "<redacted".
func isRedacted(v string) bool {
	return strings.HasPrefix(v, "<redacted")
}

// unquote strips one pair of matching surrounding quotes.
func unquote(v string) string {
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		return v[1 : len(v)-1]
	}
	return v
}

// replaceAll rewrites every match of re in s for which f reports ok, and
// returns the new string and the number of replacements. f receives the
// submatches of the whole match and returns the full replacement text.
func replaceAll(re *regexp.Regexp, s string, f func(m []string) (string, bool)) (string, int) {
	locs := re.FindAllStringSubmatchIndex(s, -1)
	if locs == nil {
		return s, 0
	}
	var b strings.Builder
	last, n := 0, 0
	for _, loc := range locs {
		m := make([]string, len(loc)/2)
		for i := range m {
			if loc[2*i] >= 0 {
				m[i] = s[loc[2*i]:loc[2*i+1]]
			}
		}
		repl, ok := f(m)
		if !ok {
			continue
		}
		b.WriteString(s[last:loc[0]])
		b.WriteString(repl)
		last = loc[1]
		n++
	}
	if n == 0 {
		return s, 0
	}
	b.WriteString(s[last:])
	return b.String(), n
}
