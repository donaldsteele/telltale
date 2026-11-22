package collect

import (
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// defaultAuthorizedKeysFile is sshd's compiled-in default.
var defaultAuthorizedKeysFile = []string{".ssh/authorized_keys", ".ssh/authorized_keys2"}

const maxSSHDIncludeDepth = 8

// sshdConfig reads /etc/ssh/sshd_config and its Include targets. It returns
// every config file read (machine paths, in reading order) and the
// AuthorizedKeysFile patterns: the first global-section setting, or the
// default. The listed defaults are always included so planted keys in either
// default location are seen even when the config points elsewhere.
//
// This is a deliberately small reader: no Match evaluation, no quoting
// beyond double quotes.
func (c *collector) sshdConfig() (files []string, akf []string) {
	st := &sshdState{c: c}
	st.read("/etc/ssh/sshd_config", 0)
	akf = append(akf, st.akf...)
	for _, d := range defaultAuthorizedKeysFile {
		dup := false
		for _, a := range akf {
			if a == d {
				dup = true
			}
		}
		if !dup {
			akf = append(akf, d)
		}
	}
	return st.files, akf
}

type sshdState struct {
	c       *collector
	files   []string
	akf     []string
	haveAKF bool
	inMatch bool
	visited map[string]bool
}

func (s *sshdState) read(mp string, depth int) {
	if depth > maxSSHDIncludeDepth {
		return
	}
	if s.visited == nil {
		s.visited = map[string]bool{}
	}
	if s.visited[mp] {
		return
	}
	b, err := readRaw(s.c.root, mp, maxPersistBytes)
	if err != nil {
		return
	}
	s.visited[mp] = true
	s.files = append(s.files, mp)
	for _, line := range splitLines(b) {
		args := sshdFields(line)
		if len(args) == 0 {
			continue
		}
		switch strings.ToLower(args[0]) {
		case "match":
			s.inMatch = true
		case "include":
			for _, pat := range args[1:] {
				if !path.IsAbs(pat) {
					pat = path.Join("/etc/ssh", pat)
				}
				matches, _ := filepath.Glob(filepath.Join(s.c.root, pat))
				sort.Strings(matches)
				for _, m := range matches {
					s.read(path.Join("/", filepath.ToSlash(strings.TrimPrefix(m, s.c.root))), depth+1)
				}
			}
		case "authorizedkeysfile":
			if !s.inMatch && !s.haveAKF {
				s.haveAKF = true
				s.akf = args[1:]
			}
		}
	}
}

// sshdFields splits a config line into whitespace-separated words, honouring
// double quotes, dropping comments and accepting "Keyword=value".
func sshdFields(line string) []string {
	line = strings.TrimSpace(line)
	if line == "" || line[0] == '#' {
		return nil
	}
	var out []string
	var cur strings.Builder
	inQ, have := false, false
	for i := 0; i < len(line); i++ {
		ch := line[i]
		switch {
		case ch == '"':
			inQ, have = !inQ, true
		case !inQ && (ch == ' ' || ch == '\t'):
			if have {
				out = append(out, cur.String())
				cur.Reset()
				have = false
			}
		case !inQ && ch == '=' && len(out) == 0:
			if have {
				out = append(out, cur.String())
				cur.Reset()
				have = false
			}
		default:
			cur.WriteByte(ch)
			have = true
		}
	}
	if have {
		out = append(out, cur.String())
	}
	return out
}
