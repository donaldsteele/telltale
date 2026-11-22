// Package crossview compares telltale's own view of the machine (read straight
// from the kernel) with what the machine's own tools report. A userland rootkit
// hides things from ps, ss, lsmod and ls but not from telltale. This is the
// only place the collector runs the machine's programs.
package crossview

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/donaldsteele/telltale/internal/model"
)

const (
	toolTimeout = 10 * time.Second
	maxOutput   = 32 << 20
)

var (
	// toolDirs is where the tools are looked up, under root. Never PATH.
	toolDirs = []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"}
	// procRoot is where the pid list is re-read after a tool ran.
	procRoot = "/proc"
	// toolEnv is the complete environment given to every tool.
	toolEnv = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}

	defaultDirs = []string{"/etc", "/usr/bin", "/usr/sbin", "/tmp", "/dev/shm", "/var/tmp", "/root"}
)

// Collect runs ps, ss, lsmod and ls and compares each with rt and the
// directory contents under root. dirs nil means the default directories.
func Collect(rt model.Runtime, root string, dirs []string) []model.CrossViewResult {
	if dirs == nil {
		dirs = defaultDirs
	}
	var res []model.CrossViewResult
	res = append(res, crossPS(rt, root))
	res = append(res, crossSS(rt, root, "tcp", "-Htanl"), crossSS(rt, root, "udp", "-Huanl"))
	res = append(res, crossLsmod(rt, root))
	for _, d := range dirs {
		res = append(res, crossLs(root, d))
	}
	return res
}

type capWriter struct {
	big bool
	buf bytes.Buffer
}

var errTooBig = errors.New("output larger than 32 MiB")

func (w *capWriter) Write(p []byte) (int, error) {
	if w.buf.Len()+len(p) > maxOutput {
		w.big = true
		return 0, errTooBig
	}
	return w.buf.Write(p)
}

// findTool returns the path of name in the fixed tool directories under root.
func findTool(root, name string) (string, bool) {
	for _, d := range toolDirs {
		p := filepath.Join(root, d, name)
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() && st.Mode()&0o111 != 0 {
			return p, true
		}
	}
	return "", false
}

// runTool runs one tool and returns its stdout and its own pid. A failure
// is returned as a human-readable reason.
func runTool(root, name string, args ...string) (out string, pid int, reason string) {
	path, ok := findTool(root, name)
	if !ok {
		return "", 0, name + " not installed"
	}
	ctx, cancel := context.WithTimeout(context.Background(), toolTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = append([]string(nil), toolEnv...)
	var w capWriter
	cmd.Stdout = &w
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	if cmd.Process != nil {
		pid = cmd.Process.Pid
	}
	switch {
	case ctx.Err() != nil:
		return "", pid, fmt.Sprintf("%s timed out after %s", name, toolTimeout)
	case w.big:
		return "", pid, name + " output larger than 32 MiB"
	case err != nil:
		return "", pid, fmt.Sprintf("%s failed: %v", name, err)
	}
	return w.buf.String(), pid, ""
}

func skipped(tool, reason string) model.CrossViewResult {
	return model.CrossViewResult{Tool: tool, SkipReason: reason}
}

func ran(tool string, hidden, extra []string) model.CrossViewResult {
	sort.Strings(hidden)
	sort.Strings(extra)
	return model.CrossViewResult{Tool: tool, Ran: true, HiddenFromTool: hidden, ExtraInTool: extra}
}

// readProcPIDs lists the numeric entries of procRoot.
func readProcPIDs() (map[int]bool, error) {
	ents, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, err
	}
	m := make(map[int]bool)
	for _, e := range ents {
		if n, err := strconv.Atoi(e.Name()); err == nil && n > 0 {
			m[n] = true
		}
	}
	return m, nil
}

func crossPS(rt model.Runtime, root string) model.CrossViewResult {
	const tool = "ps"
	out, self, reason := runTool(root, "ps", "-eo", "pid=")
	if reason != "" {
		return skipped(tool, reason)
	}
	toolPIDs, err := parsePSOutput(out)
	if err != nil {
		return skipped(tool, err.Error())
	}
	after, err := readProcPIDs()
	if err != nil {
		return skipped(tool, "re-read /proc: "+err.Error())
	}
	hidden, extra := comparePIDs(rt.Processes, toolPIDs, after, self)
	return ran(tool, hidden, extra)
}

// comparePIDs compares telltale's process list (before) with the tool's pids.
// A pid is hidden only if it was in before and after the tool ran and is not
// in the tool output; it is extra only if it was in neither. self is the
// tool's own pid, which is ignored.
func comparePIDs(before []model.Process, toolPIDs []int, after map[int]bool, self int) (hidden, extra []string) {
	inTool := make(map[int]bool, len(toolPIDs))
	for _, p := range toolPIDs {
		inTool[p] = true
	}
	inBefore := make(map[int]bool, len(before))
	for _, p := range before {
		inBefore[p.PID] = true
		if after[p.PID] && !inTool[p.PID] && p.PID != self {
			hidden = append(hidden, fmt.Sprintf("pid %d (%s)", p.PID, p.Comm))
		}
	}
	for _, p := range toolPIDs {
		if !inBefore[p] && !after[p] && p != self {
			extra = append(extra, fmt.Sprintf("pid %d", p))
		}
	}
	return hidden, extra
}

func crossSS(rt model.Runtime, root, proto, flags string) model.CrossViewResult {
	tool := "ss -" + proto[:1]
	out, _, reason := runTool(root, "ss", flags)
	if reason != "" {
		return skipped(tool, reason)
	}
	ports, err := parseSSOutput(out)
	if err != nil {
		return skipped(tool, err.Error())
	}
	hidden, extra := comparePorts(rt.Sockets, proto, ports)
	return ran(tool, hidden, extra)
}

func comparePorts(socks []model.Socket, proto string, toolPorts []int) (hidden, extra []string) {
	inTool := make(map[int]bool)
	for _, p := range toolPorts {
		inTool[p] = true
	}
	own := make(map[int]bool)
	for _, s := range socks {
		if !s.Listening || !strings.HasPrefix(s.Proto, proto) {
			continue
		}
		i := strings.LastIndexByte(s.Local, ':')
		p, err := strconv.Atoi(s.Local[i+1:])
		if i < 0 || err != nil {
			continue
		}
		own[p] = true
	}
	for p := range own {
		if !inTool[p] {
			hidden = append(hidden, fmt.Sprintf("%s port %d", proto, p))
		}
	}
	for p := range inTool {
		if !own[p] {
			extra = append(extra, fmt.Sprintf("%s port %d", proto, p))
		}
	}
	return hidden, extra
}

func crossLsmod(rt model.Runtime, root string) model.CrossViewResult {
	const tool = "lsmod"
	out, _, reason := runTool(root, "lsmod")
	if reason != "" {
		return skipped(tool, reason)
	}
	names, err := parseLsmod(out)
	if err != nil {
		return skipped(tool, err.Error())
	}
	own := make([]string, 0, len(rt.Modules))
	for _, m := range rt.Modules {
		own = append(own, normModule(m.Name))
	}
	hidden, extra := diffNames(own, names, nil, "module ")
	return ran(tool, hidden, extra)
}

// diffNames returns the items of own missing from tool (hidden) and the items
// of tool missing from own (extra). When after is non-nil it is the second
// read of own: an item is hidden only if also in after, extra only if also
// absent from after.
func diffNames(own, tool, after []string, prefix string) (hidden, extra []string) {
	inTool := toSet(tool)
	inOwn := toSet(own)
	var inAfter map[string]bool
	if after != nil {
		inAfter = toSet(after)
	}
	for _, n := range own {
		if !inTool[n] && (inAfter == nil || inAfter[n]) {
			hidden = append(hidden, prefix+n)
		}
	}
	for _, n := range tool {
		if !inOwn[n] && (inAfter == nil || !inAfter[n]) {
			extra = append(extra, prefix+n)
		}
	}
	return hidden, extra
}

func toSet(s []string) map[string]bool {
	m := make(map[string]bool, len(s))
	for _, v := range s {
		m[v] = true
	}
	return m
}

func readDirNames(path string) ([]string, error) {
	ents, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return names, nil
}

func crossLs(root, dir string) model.CrossViewResult {
	tool := "ls " + dir
	full := filepath.Join(root, dir)
	before, err := readDirNames(full)
	if err != nil {
		return skipped(tool, "read directory: "+err.Error())
	}
	out, _, reason := runTool(root, "ls", "-a1f", full)
	if reason != "" {
		return skipped(tool, reason)
	}
	after, err := readDirNames(full)
	if err != nil {
		return skipped(tool, "read directory: "+err.Error())
	}
	hidden, extra := diffNames(before, parseLs(out), after, strings.TrimRight(dir, "/")+"/")
	return ran(tool, hidden, extra)
}
