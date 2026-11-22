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

// parseSSOutput reads `ss -H...` output and returns the local ports of
// listening sockets (state LISTEN for tcp, UNCONN for udp).
func parseSSOutput(out string) ([]int, error) {
	var ports []int
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
		ports = append(ports, p)
	}
	return ports, nil
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

// parseLs reads `ls -a1f` output: one name per line, "." and ".." dropped.
func parseLs(out string) []string {
	var names []string
	for _, ln := range strings.Split(out, "\n") {
		if ln == "" || ln == "." || ln == ".." {
			continue
		}
		names = append(names, ln)
	}
	return names
}

func truncate(s string) string {
	if len(s) > 60 {
		return s[:60] + "..."
	}
	return s
}
