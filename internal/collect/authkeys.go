package collect

import (
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

// defaultAuthorizedKeysFile is sshd's compiled-in default.
var defaultAuthorizedKeysFile = []string{".ssh/authorized_keys", ".ssh/authorized_keys2"}

const (
	maxSSHDIncludeDepth = 8
	maxSSHDParseBytes   = 16 << 20
)

// sshdConfig reads /etc/ssh/sshd_config and its Include targets. It returns
// every config file found (machine paths, in reading order, whether or not
// it could be parsed) and the AuthorizedKeysFile patterns: the union of
// every AuthorizedKeysFile value anywhere in the config (global, Match
// blocks, Include files) plus the defaults. Extra reads are harmless and
// avoid evaluating Match scoping.
//
// This is a deliberately small reader: no Match evaluation, no quoting
// beyond double quotes.
func (c *collector) sshdConfig() (files []string, akf []string) {
	st := &sshdState{c: c, seenAKF: map[string]bool{}}
	st.read("/etc/ssh/sshd_config", 0)
	akf = st.akf
	for _, d := range defaultAuthorizedKeysFile {
		if !st.seenAKF[d] {
			akf = append(akf, d)
		}
	}
	return st.files, akf
}

type sshdState struct {
	c       *collector
	files   []string
	akf     []string
	seenAKF map[string]bool
	visited map[string]bool
}

// readable returns the content of mp, following one symlink level to a
// regular file under root.
func (s *sshdState) readable(mp string) ([]byte, error) {
	var lst unix.Stat_t
	if err := unix.Lstat(filepath.Join(s.c.root, mp), &lst); err == nil && lst.Mode&unix.S_IFMT == unix.S_IFLNK {
		if t, err := os.Readlink(filepath.Join(s.c.root, mp)); err == nil {
			mp = linkTarget(mp, t)
		}
	}
	return readRaw(s.c.root, mp, maxSSHDParseBytes)
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
	var lst unix.Stat_t
	if err := unix.Lstat(filepath.Join(s.c.root, mp), &lst); err != nil {
		return // absent
	}
	s.visited[mp] = true
	s.files = append(s.files, mp)
	b, err := s.readable(mp)
	if err != nil {
		s.c.skip(mp, "sshd config not parsed for AuthorizedKeysFile: "+err.Error())
		return
	}
	for _, line := range splitLines(b) {
		args := sshdFields(line)
		if len(args) == 0 {
			continue
		}
		switch strings.ToLower(args[0]) {
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
			for _, a := range args[1:] {
				if !s.seenAKF[a] {
					s.seenAKF[a] = true
					s.akf = append(s.akf, a)
				}
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
