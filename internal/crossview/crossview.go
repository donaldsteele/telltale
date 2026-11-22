// Package crossview compares telltale's own view of the machine (read straight
// from the kernel) with what the machine's own tools report. A userland rootkit
// hides things from ps, ss, lsmod and ls but not from telltale. This is the
// only place the collector runs the machine's programs.
//
// Every comparison reads telltale's view immediately before and after the tool
// runs: a thing counts as hidden only if present in both reads and absent from
// the tool, and as extra only if absent from both reads.
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
	"syscall"
	"time"

	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/procnet"
)

const maxOutput = 32 << 20

var (
	// toolDirs is where the tools are looked up. Absolute, never under a
	// scan root and never via PATH.
	toolDirs = []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"}
	// procRoot is where telltale's own view is read.
	procRoot = "/proc"
	// toolEnv is the complete environment given to every tool.
	toolEnv = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	// toolTimeout bounds each tool run.
	toolTimeout = 10 * time.Second

	defaultDirs = []string{"/etc", "/usr/bin", "/usr/sbin", "/tmp", "/dev/shm", "/var/tmp", "/root"}
)

// Collect runs ps, lsmod, ss and ls and compares each with telltale's own
// reading of /proc and of the directories under root. dirs nil means the
// default directories. rt is only used to name processes that vanish.
func Collect(rt model.Runtime, root string, dirs []string) []model.CrossViewResult {
	if dirs == nil {
		dirs = defaultDirs
	}
	var res []model.CrossViewResult
	res = append(res, crossPS(rt))
	// lsmod before ss: ss's sock_diag requests may autoload inet_diag modules.
	res = append(res, crossLsmod())
	res = append(res, crossSS("tcp", "-Htanl"), crossSS("udp", "-Huanl"))
	for _, d := range dirs {
		res = append(res, crossLs(root, d))
	}
	return res
}

// SkipAll returns one not-run result per tool and directory, for callers that
// cannot run the comparison. dirs nil means the default directories.
func SkipAll(reason string, dirs []string) []model.CrossViewResult {
	if dirs == nil {
		dirs = defaultDirs
	}
	tools := []string{"ps", "lsmod", "ss -t", "ss -u"}
	for _, d := range dirs {
		tools = append(tools, "ls "+d)
	}
	res := make([]model.CrossViewResult, 0, len(tools))
	for _, t := range tools {
		res = append(res, skipped(t, reason))
	}
	return res
}

type capWriter struct {
	buf bytes.Buffer
	big bool
}

var errTooBig = errors.New("output larger than 32 MiB")

func (w *capWriter) Write(p []byte) (int, error) {
	if w.buf.Len()+len(p) > maxOutput {
		w.big = true
		return 0, errTooBig
	}
	return w.buf.Write(p)
}

// findTool returns the path of name in the fixed tool directories.
func findTool(name string) (string, bool) {
	for _, d := range toolDirs {
		p := filepath.Join(d, name)
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() && st.Mode()&0o111 != 0 {
			return p, true
		}
	}
	return "", false
}

// runTool runs one tool and returns its stdout and its own pid. A failure
// is returned as a human-readable reason.
func runTool(name string, args ...string) (out string, pid int, reason string) {
	path, ok := findTool(name)
	if !ok {
		return "", 0, name + " not installed"
	}
	ctx, cancel := context.WithTimeout(context.Background(), toolTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = append([]string(nil), toolEnv...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		// Kill the whole group so no child outlives the timeout.
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	var w capWriter
	cmd.Stdout = &w
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	if cmd.Process != nil {
		pid = cmd.Process.Pid
		_ = syscall.Kill(-pid, syscall.SIGKILL) // stragglers in the group
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

// diffSets returns the keys of own missing from tool (hidden, only when also
// in after) and the keys of tool missing from own and after (extra). label
// formats a key for the result.
func diffSets(own, after, tool map[string]bool, label func(string) string) (hidden, extra []string) {
	for k := range own {
		if !tool[k] && after[k] {
			hidden = append(hidden, label(k))
		}
	}
	for k := range tool {
		if !own[k] && !after[k] {
			extra = append(extra, label(k))
		}
	}
	return hidden, extra
}

func ident(s string) string { return s }

// --- ps ---

type procSnap map[int]string // pid -> comm

func readProcs(rt model.Runtime) (procSnap, error) {
	ents, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, err
	}
	known := make(map[int]string, len(rt.Processes))
	for _, p := range rt.Processes {
		known[p.PID] = p.Comm
	}
	m := make(procSnap)
	for _, e := range ents {
		n, err := strconv.Atoi(e.Name())
		if err != nil || n <= 0 {
			continue
		}
		comm := known[n]
		if b, err := os.ReadFile(filepath.Join(procRoot, e.Name(), "comm")); err == nil {
			comm = strings.TrimSpace(string(b))
		}
		m[n] = comm
	}
	return m, nil
}

func (s procSnap) set() map[string]bool {
	m := make(map[string]bool, len(s))
	for p := range s {
		m[strconv.Itoa(p)] = true
	}
	return m
}

func crossPS(rt model.Runtime) model.CrossViewResult {
	const tool = "ps"
	if _, ok := findTool("ps"); !ok {
		return skipped(tool, "ps not installed")
	}
	before, err := readProcs(rt)
	if err != nil {
		return skipped(tool, "read /proc: "+err.Error())
	}
	out, self, reason := runTool("ps", "-eo", "pid=")
	if reason != "" {
		return skipped(tool, reason)
	}
	toolPIDs, err := parsePSOutput(out)
	if err != nil {
		return skipped(tool, err.Error())
	}
	after, err := readProcs(rt)
	if err != nil {
		return skipped(tool, "read /proc: "+err.Error())
	}
	inTool := make(map[string]bool)
	for _, p := range toolPIDs {
		if p != self {
			inTool[strconv.Itoa(p)] = true
		}
	}
	bs := before.set()
	delete(bs, strconv.Itoa(self))
	label := func(k string) string {
		n, _ := strconv.Atoi(k)
		if c, ok := before[n]; ok {
			return fmt.Sprintf("pid %d (%s)", n, c)
		}
		return "pid " + k
	}
	hidden, extra := diffSets(bs, after.set(), inTool, label)
	return ran(tool, hidden, extra)
}

// --- lsmod ---

func readModules() (map[string]bool, error) {
	b, err := os.ReadFile(filepath.Join(procRoot, "modules"))
	if err != nil {
		return nil, err
	}
	m := make(map[string]bool)
	for _, ln := range strings.Split(string(b), "\n") {
		if f := strings.Fields(ln); len(f) > 0 {
			m[normModule(f[0])] = true
		}
	}
	return m, nil
}

func crossLsmod() model.CrossViewResult {
	const tool = "lsmod"
	if _, ok := findTool("lsmod"); !ok {
		return skipped(tool, "lsmod not installed")
	}
	before, err := readModules()
	if err != nil {
		return skipped(tool, "read /proc/modules: "+err.Error())
	}
	out, _, reason := runTool("lsmod")
	if reason != "" {
		return skipped(tool, reason)
	}
	names, err := parseLsmod(out)
	if err != nil {
		return skipped(tool, err.Error())
	}
	after, err := readModules()
	if err != nil {
		return skipped(tool, "read /proc/modules: "+err.Error())
	}
	hidden, extra := diffSets(before, after, toSet(names), func(k string) string { return "module " + k })
	return ran(tool, hidden, extra)
}

func toSet(s []string) map[string]bool {
	m := make(map[string]bool, len(s))
	for _, v := range s {
		m[v] = true
	}
	return m
}

// --- ss ---

// readListeners returns the listening sockets as "proto port" keys, with proto
// one of tcp, tcp6, udp, udp6, restricted to the given family prefix.
func readListeners(prefix string) (map[string]bool, error) {
	m := make(map[string]bool)
	for _, proto := range []string{prefix, prefix + "6"} {
		b, err := os.ReadFile(filepath.Join(procRoot, "net", proto))
		if err != nil {
			if os.IsNotExist(err) {
				continue // e.g. no IPv6
			}
			return nil, err
		}
		for _, r := range procnet.Parse(string(b)) {
			if r.Listening(proto) {
				m[fmt.Sprintf("%s %d", proto, r.LocalPort)] = true
			}
		}
	}
	return m, nil
}

func crossSS(proto, flags string) model.CrossViewResult {
	tool := "ss -" + proto[:1]
	if _, ok := findTool("ss"); !ok {
		return skipped(tool, "ss not installed")
	}
	before, err := readListeners(proto)
	if err != nil {
		return skipped(tool, "read /proc/net: "+err.Error())
	}
	out, _, reason := runTool("ss", flags)
	if reason != "" {
		return skipped(tool, reason)
	}
	ls, err := parseSSOutput(out)
	if err != nil {
		return skipped(tool, err.Error())
	}
	after, err := readListeners(proto)
	if err != nil {
		return skipped(tool, "read /proc/net: "+err.Error())
	}
	hidden, extra := compareListeners(proto, before, after, ls)
	return ran(tool, hidden, extra)
}

// compareListeners compares two /proc/net reads with ss's listeners. An ss
// wildcard entry ("*") satisfies either family.
func compareListeners(proto string, before, after map[string]bool, ls []ssListener) (hidden, extra []string) {
	v4, v6 := proto, proto+"6"
	inTool := make(map[string]bool)
	for _, l := range ls {
		if l.Family != "6" {
			inTool[fmt.Sprintf("%s %d", v4, l.Port)] = true
		}
		if l.Family != "4" {
			inTool[fmt.Sprintf("%s %d", v6, l.Port)] = true
		}
	}
	label := func(k string) string {
		f := strings.Fields(k)
		return f[0] + " port " + f[1]
	}
	hidden, _ = diffSets(before, after, inTool, label)
	// Extra: a tool entry matching neither read. A wildcard entry is only
	// extra if it matches no family at all.
	for _, l := range ls {
		var keys []string
		if l.Family != "6" {
			keys = append(keys, fmt.Sprintf("%s %d", v4, l.Port))
		}
		if l.Family != "4" {
			keys = append(keys, fmt.Sprintf("%s %d", v6, l.Port))
		}
		seen := false
		for _, k := range keys {
			if before[k] || after[k] {
				seen = true
			}
		}
		if !seen {
			extra = append(extra, label(keys[0]))
		}
	}
	return hidden, extra
}

// --- ls ---

type fileID struct {
	dev, ino uint64
	ctime    syscall.Timespec
}

func readDirIDs(path string) (map[string]fileID, error) {
	ents, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	m := make(map[string]fileID, len(ents))
	for _, e := range ents {
		fi, err := os.Lstat(filepath.Join(path, e.Name()))
		m[e.Name()] = fileID{} // listed, but not stat-able: kept so it is not "extra"
		if err != nil {
			continue
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			m[e.Name()] = fileID{dev: uint64(st.Dev), ino: st.Ino, ctime: st.Ctim}
		}
	}
	return m, nil
}

func crossLs(root, dir string) model.CrossViewResult {
	tool := "ls " + dir
	if _, ok := findTool("ls"); !ok {
		return skipped(tool, "ls not installed")
	}
	full := filepath.Join(root, dir)
	before, err := readDirIDs(full)
	if err != nil {
		return skipped(tool, "read directory: "+err.Error())
	}
	out, _, reason := runTool("ls", "-a1fb", "--", full)
	if reason != "" {
		return skipped(tool, reason)
	}
	names, err := parseLs(out)
	if err != nil {
		return skipped(tool, err.Error())
	}
	after, err := readDirIDs(full)
	if err != nil {
		return skipped(tool, "read directory: "+err.Error())
	}
	// A name counts as hidden only if it kept its device, inode and ctime
	// across the run (any rename, link or unlink changes ctime) and is absent
	// from ls. It counts as extra only if absent from both reads.
	inTool := toSet(names)
	prefix := strings.TrimRight(dir, "/") + "/"
	var hidden, extra []string
	for n, id := range before {
		if a, ok := after[n]; ok && a == id && id != (fileID{}) && !inTool[n] {
			hidden = append(hidden, prefix+n)
		}
	}
	for n := range inTool {
		_, b := before[n]
		_, a := after[n]
		if !b && !a {
			extra = append(extra, prefix+n)
		}
	}
	return ran(tool, hidden, extra)
}
