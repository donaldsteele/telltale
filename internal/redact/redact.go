// Package redact replaces secret values in kept config text with keyed
// digests, so a changed value still shows as changed without the secret
// being stored.
//
// Redaction is by pattern. It knows these shapes:
//
//   - systemd Environment= assignments and shell export NAME=value;
//   - key=value and key: value where the key holds a secret-like word
//     (password, passwd, secret, token, key, credential), the key bare or
//     in quotes as JSON, YAML and Python write it;
//   - the user and password in a URL (scheme://user:password@host);
//   - an Authorization or Proxy-Authorization header's credentials;
//   - -u user:password for curl, and --user user:password;
//   - an option named after a secret with its value as the next word
//     (--password x, --token x);
//   - sshpass -p x, and the password glued to -p for the MySQL and MariaDB
//     clients (mysql -pSECRET).
//
// A secret written some other way is not recognised and is kept as it is.
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

	// scheme://user:pass@host; user and password are redacted together. The
	// userinfo ends at the last @ before the host, so a password may hold
	// one itself.
	urlRe = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.\-]*://)([^/\s@:]*):([^/\s]*)@`)

	// key=value or key: value where the key contains a secret-like word,
	// bare or closed by a quote ("password": ...). What follows is the
	// value: one quoted string, or the rest of the line (see keyValue).
	kvRe = regexp.MustCompile(`(?i)([\w.\-]*(?:pass(?:word|wd)?|secret|token|key|credential)[\w.\-]*)(["']?\s*[=:]\s*)`)

	// One value as a command line writes it: a quoted string or a word.
	argValue = `("[^"]*"|'[^']*'|\S+)`

	// Authorization: <scheme> <credentials>, or a bare value. The header's
	// name may end a quoted key ("Authorization": "Bearer ...").
	authRe = regexp.MustCompile(`(?i)(\b(?:proxy-)?authorization["']?\s*[:=]\s*["']?(?:(?:basic|bearer|digest|negotiate|token|apikey)\s+)?)([^\s"']+)`)

	// curl -u user:password. -u means other things to other programs, so
	// the short form counts only on a line that runs curl.
	curlRe     = regexp.MustCompile(`\bcurl\b`)
	curlUserRe = regexp.MustCompile(`((?:^|\s)-u\s*)` + argValue)
	// --user user:password, for any program.
	userRe = regexp.MustCompile(`((?:^|\s)--user(?:=|\s+))` + argValue)

	// An option named after a secret, its value the next word. An option
	// that names a file, a descriptor or a prompt holds no secret itself.
	optRe      = regexp.MustCompile(`(?i)((?:^|\s)--?[\w\-]*(?:pass(?:word|wd)?|secret|token|api-?key)[\w\-]*\s+)("[^"]*"|'[^']*'|[^\s\-]\S*)`)
	optNotARef = regexp.MustCompile(`(?i)(?:file|path|fd|stdin|prompt|cmd|command|store|dir|name|url|uri|endpoint|type|ttl|length|len)\s+$`)

	// sshpass -p password, glued or not.
	sshpassRe = regexp.MustCompile(`(\bsshpass\s+-p\s*)` + argValue)
	// mysql -pPASSWORD: the password glued to -p, among the options of a
	// MySQL or MariaDB client. -p alone asks for it and holds nothing.
	mysqlRe = regexp.MustCompile(`(\b(?:mysql|mysqldump|mysqladmin|mysqlcheck|mysqlimport|mariadb|mariadb-dump|mariadb-admin|mariadb-check)\b[^|;&]*?\s-p)("[^"]*"|'[^']*'|[^\s"']\S*)`)
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

	out, c = replaceAll(authRe, out, func(m []string) (string, bool) {
		return assignRepl(key, m[1], m[2])
	})
	total += c

	if curlRe.MatchString(out) {
		out, c = replaceAll(curlUserRe, out, func(m []string) (string, bool) {
			return userPassRepl(key, m[1], m[2])
		})
		total += c
	}
	out, c = replaceAll(userRe, out, func(m []string) (string, bool) {
		return userPassRepl(key, m[1], m[2])
	})
	total += c

	out, c = replaceAll(optRe, out, func(m []string) (string, bool) {
		if optNotARef.MatchString(m[1]) || strings.HasPrefix(m[2], "-") {
			return "", false
		}
		return assignRepl(key, m[1], m[2])
	})
	total += c

	out, c = replaceAll(sshpassRe, out, func(m []string) (string, bool) {
		return assignRepl(key, m[1], m[2])
	})
	total += c

	out, c = replaceAll(mysqlRe, out, func(m []string) (string, bool) {
		return assignRepl(key, m[1], m[2])
	})
	total += c

	out, c = redactKeyValues(key, out)
	total += c

	return out, total
}

// userPassRepl redacts a user:password argument, user and password
// together as in a URL. An argument without a colon is a user name alone
// and is kept.
func userPassRepl(key []byte, name, val string) (string, bool) {
	if !strings.Contains(unquote(val), ":") {
		return "", false
	}
	return assignRepl(key, name, val)
}

// keyValue finds the value that starts at s[at:], right after a key and
// its separator: one quoted string when what follows it is the end of the
// line or a delimiter (as in JSON, YAML flow style and Python), else
// everything up to the end of the line without trailing space. A quoted
// string with more text glued to it ('it”s') is taken with that text, to
// the end of the line. end is where the value stops.
func keyValue(s string, at int) (val string, end int) {
	rest := strings.TrimRight(s[at:], " \t")
	if rest == "" {
		return "", at
	}
	if q := rest[0]; q == '"' || q == '\'' {
		for i := 1; i < len(rest); i++ {
			if rest[i] == '\\' && q == '"' {
				i++
				continue
			}
			if rest[i] != q {
				continue
			}
			if i+1 == len(rest) || strings.IndexByte(",}]); \t", rest[i+1]) >= 0 {
				return rest[:i+1], at + i + 1
			}
			break
		}
	}
	return rest, at + len(rest)
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
// whose key looks secret. A value that is already redacted is skipped past
// its redacted token, so any later pair on the same line is still checked.
func redactKeyValues(key []byte, s string) (string, int) {
	var b strings.Builder
	n, last, scan := 0, 0, 0
	for scan < len(s) {
		loc := kvRe.FindStringSubmatchIndex(s[scan:])
		if loc == nil {
			break
		}
		start, valStart := scan+loc[0], scan+loc[1]
		val, end := keyValue(s, valStart)
		if strings.HasPrefix(s[start:], "-") && val != "" && val[0] != '"' && val[0] != '\'' {
			// A command-line option (--password=x): its value is one word.
			if i := strings.IndexAny(val, " \t"); i > 0 {
				val, end = val[:i], valStart+i
			}
		}
		secret := unquote(val)
		switch {
		case isRedacted(secret):
			if i := strings.IndexByte(s[valStart:], '>'); i >= 0 {
				scan = valStart + i + 1
			} else {
				scan = valStart + len(redactedPrefix)
			}
		case secret == "":
			scan = max(end, valStart)
			if scan == start {
				scan++
			}
		default:
			b.WriteString(s[last:valStart])
			b.WriteString(replacement(key, secret))
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
