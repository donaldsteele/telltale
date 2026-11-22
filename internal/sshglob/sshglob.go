// Package sshglob matches the glob(3) patterns sshd accepts in Include with
// Go's path matching. The collector (following Include on disk) and the
// checklist (following it over collected files) share it so both read the
// files sshd reads.
package sshglob

import (
	"path"
	"strings"
)

// Pattern rewrites a glob(3) pattern into path.Match syntax: "[!...]"
// becomes "[^...]", and a "]" right after the opening bracket (a literal in
// glob(3), an error in Go) is escaped. Character classes such as [[:alpha:]]
// are not supported; a pattern using one matches nothing.
func Pattern(p string) string {
	var b strings.Builder
	inClass := false
	for i := 0; i < len(p); i++ {
		ch := p[i]
		switch {
		case ch == '\\' && i+1 < len(p):
			b.WriteByte(ch)
			i++
			b.WriteByte(p[i])
			continue
		case !inClass && ch == '[':
			inClass = true
			b.WriteByte('[')
			if i+1 < len(p) && (p[i+1] == '!' || p[i+1] == '^') {
				b.WriteByte('^')
				i++
			}
			if i+1 < len(p) && p[i+1] == ']' {
				b.WriteString(`\]`)
				i++
			}
			continue
		case inClass && ch == ']':
			inClass = false
		}
		b.WriteByte(ch)
	}
	return b.String()
}

// Match reports whether the slash-separated path name matches the glob(3)
// pattern pat the way glob(3) does, including that a wildcard never matches
// a leading dot in a path element. A malformed pattern matches nothing.
func Match(pat, name string) bool {
	ok, err := path.Match(Pattern(pat), name)
	return err == nil && ok && !dotHidden(pat, name)
}

// dotHidden reports whether a wildcard in pat matched a leading dot in name.
func dotHidden(pat, name string) bool {
	pc, nc := strings.Split(pat, "/"), strings.Split(name, "/")
	for i := range nc {
		if i < len(pc) && strings.HasPrefix(nc[i], ".") && !strings.HasPrefix(pc[i], ".") {
			return true
		}
	}
	return false
}
