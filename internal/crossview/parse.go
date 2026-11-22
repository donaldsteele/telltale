package crossview

import (
	"fmt"
	"strconv"
	"strings"
)

// parsePSOutput reads the output of `ps -eo pid=`.
func parsePSOutput(out string) ([]int, error) {
	var pids []int
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		n, err := strconv.Atoi(ln)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("unexpected ps output line %q", truncate(ln))
		}
		pids = append(pids, n)
	}
	return pids, nil
}

// ssListener is one listening socket from ss. Family is "" when ss printed a
// wildcard ("*") that could be either.
type ssListener struct {
	Family string // "4", "6" or ""
	Port   int
}

// parseSSOutput reads `ss -H...` output and returns the listening sockets
// (state LISTEN for tcp, UNCONN for udp).
func parseSSOutput(out string) ([]ssListener, error) {
	var ls []ssListener
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Fields(ln)
		if len(f) == 0 {
			continue
		}
		if len(f) < 5 {
			return nil, fmt.Errorf("unexpected ss output line %q", truncate(ln))
		}
		if f[0] != "LISTEN" && f[0] != "UNCONN" {
			continue
		}
		local := f[3]
		i := strings.LastIndexByte(local, ':')
		if i < 0 {
			return nil, fmt.Errorf("unexpected ss local address %q", truncate(local))
		}
		p, err := strconv.Atoi(local[i+1:])
		if err != nil || p < 0 || p > 65535 {
			return nil, fmt.Errorf("unexpected ss local port %q", truncate(local))
		}
		host := local[:i]
		fam := "4"
		switch {
		case host == "*":
			fam = ""
		case strings.Contains(host, ":"):
			fam = "6"
		}
		ls = append(ls, ssListener{Family: fam, Port: p})
	}
	return ls, nil
}

// parseLsmod reads `lsmod` output and returns module names, normalised to
// use underscores.
func parseLsmod(out string) ([]string, error) {
	lines := strings.Split(out, "\n")
	if len(lines) == 0 || !strings.HasPrefix(lines[0], "Module") {
		return nil, fmt.Errorf("unexpected lsmod output")
	}
	var names []string
	for _, ln := range lines[1:] {
		f := strings.Fields(ln)
		if len(f) == 0 {
			continue
		}
		names = append(names, normModule(f[0]))
	}
	return names, nil
}

func normModule(s string) string { return strings.ReplaceAll(s, "-", "_") }

// parseLs reads `ls -a1fb` output: one backslash-escaped name per line, "."
// and ".." dropped. Any line that cannot be decoded is an error.
func parseLs(out string) ([]string, error) {
	var names []string
	for _, ln := range strings.Split(out, "\n") {
		if ln == "" {
			continue
		}
		n, err := unescapeLs(ln)
		if err != nil {
			return nil, err
		}
		if n == "." || n == ".." {
			continue
		}
		names = append(names, n)
	}
	return names, nil
}

// unescapeLs decodes GNU ls "escape" quoting (-b) under LC_ALL=C.
func unescapeLs(s string) (string, error) {
	if !strings.Contains(s, `\`) {
		return s, nil
	}
	var b []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' {
			b = append(b, c)
			continue
		}
		i++
		if i >= len(s) {
			return "", fmt.Errorf("undecodable ls name %q", truncate(s))
		}
		switch e := s[i]; e {
		case '\\', ' ':
			b = append(b, e)
		case 'n':
			b = append(b, '\n')
		case 't':
			b = append(b, '\t')
		case 'r':
			b = append(b, '\r')
		case 'a':
			b = append(b, '\a')
		case 'b':
			b = append(b, '\b')
		case 'f':
			b = append(b, '\f')
		case 'v':
			b = append(b, '\v')
		case '0', '1', '2', '3':
			if i+2 >= len(s) {
				return "", fmt.Errorf("undecodable ls name %q", truncate(s))
			}
			v, err := strconv.ParseUint(s[i:i+3], 8, 8)
			if err != nil {
				return "", fmt.Errorf("undecodable ls name %q", truncate(s))
			}
			b = append(b, byte(v))
			i += 2
		default:
			return "", fmt.Errorf("undecodable ls name %q", truncate(s))
		}
	}
	return string(b), nil
}

func truncate(s string) string {
	if len(s) > 60 {
		return s[:60] + "..."
	}
	return s
}
