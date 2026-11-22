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
	// systemd Environment= line; the rest is one or more NAME=value pairs.
	envLine   = regexp.MustCompile(`^(\s*Environment=)(.*)$`)
	envAssign = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*=)("[^"]*"|'[^']*'|[^\s"']+)`)

	// shell export NAME=value; quoted values are replaced including quotes.
	exportRe = regexp.MustCompile(`^(\s*export\s+[A-Za-z_][A-Za-z0-9_]*=)("[^"]*"|'[^']*'|\S+)`)

	// scheme://user:pass@host; user and password are redacted together.
	urlRe = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.\-]*://)([^/\s@:]*):([^/\s@]+)@`)

	// key=value or key: value where the key contains a secret-like word.
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
// returned unchanged with n == 0.
func Line(key []byte, line string) (out string, n int) {
	out = line
	total := 0

	if sub := envLine.FindStringSubmatch(out); sub != nil {
		rest, c := replaceAll(envAssign, sub[2], func(m []string) (string, bool) {
			secret := unquote(m[2])
			if secret == "" {
				return "", false
			}
			return m[1] + replacement(key, secret), true
		})
		out = sub[1] + rest
		total += c
	}

	out, c := replaceAll(exportRe, out, func(m []string) (string, bool) {
		secret := unquote(m[2])
		if secret == "" {
			return "", false
		}
		return m[1] + replacement(key, secret), true
	})
	total += c

	out, c = replaceAll(urlRe, out, func(m []string) (string, bool) {
		return m[1] + replacement(key, m[2]+":"+m[3]) + "@", true
	})
	total += c

	out, c = replaceAll(kvRe, out, func(m []string) (string, bool) {
		if strings.HasPrefix(m[3], redactedPrefix) {
			return "", false
		}
		secret := unquote(m[3])
		if secret == "" {
			return "", false
		}
		return m[1] + m[2] + replacement(key, secret) + m[4], true
	})
	total += c

	return out, total
}

func replacement(key []byte, secret string) string {
	return redactedPrefix + Digest(key, secret) + ">"
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
