package checklist

import (
	"net/netip"
	"path"
	"sort"
	"strings"

	"github.com/donaldsteele/telltale/internal/model"
)

// mainSSHDConfig is the file sshd reads first.
const mainSSHDConfig = "/etc/ssh/sshd_config"

const (
	// maxSSHDDepth is sshd's own Include nesting limit (READCONF_MAX_DEPTH);
	// deeper nesting, including an Include cycle, makes sshd refuse to start.
	maxSSHDDepth = 16
	// maxSSHDWork bounds the lines read (counting every time an Include
	// reads a file again) and events kept, so an Include graph that fans out
	// (every file including every later file) cannot stall the judging side.
	maxSSHDWork = 1 << 22
)

// sshdDefaults are OpenSSH's compiled-in values for the keywords the
// checklist reads.
var sshdDefaults = map[string]string{
	"permitrootlogin":         "prohibit-password",
	"permitemptypasswords":    "no",
	"passwordauthentication":  "yes",
	"x11forwarding":           "no",
	"maxauthtries":            "6",
	"hostbasedauthentication": "no",
	"ignorerhosts":            "yes",
	"permituserenvironment":   "no",
	"strictmodes":             "yes",
}

// sshdSetting is one effective value and where it came from. Path is ""
// when the value is OpenSSH's default.
type sshdSetting struct {
	Value string
	Path  string
	Line  int
}

type sshdEventKind int

const (
	evSet sshdEventKind = iota
	evMatch
	evEnter // an Include starts reading a file
	evLeave // that file ends
)

// sshdEvent is one step of the configuration as sshd reads it, with Include
// expanded in place.
type sshdEvent struct {
	Kind sshdEventKind
	Key  string   // evSet: lower-cased keyword
	Args []string // evSet: values; evMatch: criteria
	Path string
	Line int
}

// sshdConfig is a parsed configuration: the main file with every Include
// expanded, ready to be evaluated for any client address.
type sshdConfig struct {
	events []sshdEvent
	// links marks files that are symlinks (fix commands must follow them).
	links map[string]bool
}

// EffectiveSSHD returns the sshd settings in force for a connection from
// clientAddr, keyed by lower-cased keyword, with OpenSSH's defaults filled in
// for the keywords the checklist reads. clientAddr "" means any address that
// no Match block names.
//
// It reads the sshd-kind files among files the way sshd does: starting at
// /etc/ssh/sshd_config, expanding Include in place (relative patterns are
// relative to /etc/ssh, matches in sorted order, an Include that matches no
// collected file is ignored), first value wins in the global section, and a
// Match block that applies to the client overrides the global value for the
// keywords it sets (first value wins among applying blocks).
//
// Match criteria: "all" applies to every client; "Address" takes a
// comma-separated list of addresses, CIDR ranges and */? wildcards, each
// optionally negated with "!" (a negated hit means no match). Every other
// criterion (User, Group, Host, LocalAddress, LocalPort, RDomain, ...)
// depends on more than the client address and is treated as not applying,
// so a block that needs it is never in force here; criteria in one Match
// line must all apply.
//
// It returns nil when the configuration cannot be evaluated: no
// /etc/ssh/sshd_config was collected, the text of a file it reads was not
// kept, the Include nesting is deeper than sshd allows, or the Include graph
// fans out too far to evaluate.
func EffectiveSSHD(files []model.PersistFile, clientAddr string) map[string]string {
	cfg, problem := parseSSHD(files)
	if problem != "" {
		return nil
	}
	out := map[string]string{}
	for k, s := range cfg.effective(clientAddr) {
		out[k] = s.Value
	}
	return out
}

// persistText returns the content lines of a collected file. For a symlink,
// Lines[0] is the link target and the target's content follows. ok is false
// when the text was not kept.
func persistText(pf model.PersistFile) (lines []string, ok bool) {
	if pf.Lines == nil {
		return nil, false
	}
	if isSymlinkMode(pf.Mode) {
		return pf.Lines[1:], true
	}
	return pf.Lines, true
}

func isSymlinkMode(m uint32) bool { return m&0o170000 == 0o120000 }

// parseSSHD expands the configuration into events. problem explains why it
// cannot be evaluated.
func parseSSHD(files []model.PersistFile) (*sshdConfig, string) {
	byPath := map[string]model.PersistFile{}
	var paths []string
	for _, f := range files {
		if f.Kind != model.PersistKindSSHD {
			continue
		}
		if _, dup := byPath[f.Path]; !dup {
			paths = append(paths, f.Path)
		}
		byPath[f.Path] = f
	}
	if _, ok := byPath[mainSSHDConfig]; !ok {
		return nil, "no sshd configuration collected (" + mainSSHDConfig + ")"
	}
	sort.Strings(paths)
	p := &sshdParser{files: byPath, paths: paths, cfg: &sshdConfig{links: map[string]bool{}}}
	p.read(mainSSHDConfig, 0)
	if p.problem != "" {
		return nil, p.problem
	}
	return p.cfg, ""
}

type sshdParser struct {
	files   map[string]model.PersistFile
	paths   []string
	cfg     *sshdConfig
	problem string
	work    int
}

// spend counts one unit of work and reports whether the budget allows it.
func (p *sshdParser) spend() bool {
	p.work++
	if p.work > maxSSHDWork {
		p.problem = "sshd configuration too large to evaluate (Include fan-out)"
		return false
	}
	return true
}

func (p *sshdParser) emit(e sshdEvent) bool {
	if !p.spend() {
		return false
	}
	p.cfg.events = append(p.cfg.events, e)
	return true
}

func (p *sshdParser) read(file string, depth int) {
	pf := p.files[file]
	lines, ok := persistText(pf)
	if !ok {
		p.problem = file + ": text not kept (too large or unreadable), so the sshd configuration cannot be evaluated"
		return
	}
	if isSymlinkMode(pf.Mode) {
		p.cfg.links[file] = true
	}
	for i, line := range lines {
		if p.problem != "" || !p.spend() {
			return
		}
		args := sshdArgs(line)
		if len(args) < 2 {
			continue // blank, comment, or a keyword without a value (sshd rejects it)
		}
		key := strings.ToLower(args[0])
		switch key {
		case "match":
			p.emit(sshdEvent{Kind: evMatch, Args: args[1:], Path: file, Line: i + 1})
		case "include":
			if depth+1 > maxSSHDDepth {
				p.problem = file + ": Include nested deeper than sshd allows (sshd would not start)"
				return
			}
			for _, pat := range args[1:] {
				for _, m := range p.glob(pat) {
					if !p.emit(sshdEvent{Kind: evEnter, Path: m}) {
						return
					}
					p.read(m, depth+1)
					if p.problem != "" || !p.emit(sshdEvent{Kind: evLeave, Path: m}) {
						return
					}
				}
			}
		default:
			p.emit(sshdEvent{Kind: evSet, Key: key, Args: args[1:], Path: file, Line: i + 1})
		}
	}
}

// glob returns the collected sshd files matching an Include pattern, sorted,
// with glob(3) rules: relative patterns are under /etc/ssh, and a wildcard
// does not match a leading dot.
func (p *sshdParser) glob(pat string) []string {
	if strings.HasPrefix(pat, "~") {
		return nil
	}
	if !path.IsAbs(pat) {
		pat = path.Join("/etc/ssh", pat)
	}
	var out []string
	for _, f := range p.paths {
		if ok, err := path.Match(pat, f); err == nil && ok && !dotHidden(pat, f) {
			out = append(out, f)
		}
	}
	return out
}

// dotHidden reports whether a wildcard in pat matched a leading dot in f.
func dotHidden(pat, f string) bool {
	pc, fc := strings.Split(pat, "/"), strings.Split(f, "/")
	for i := range fc {
		if i < len(pc) && strings.HasPrefix(fc[i], ".") && !strings.HasPrefix(pc[i], ".") {
			return true
		}
	}
	return false
}

// sshdArgs splits one config line the way sshd does: the keyword ends at
// whitespace or "=" (with optional whitespace around it), the arguments
// honour double quotes, and an unquoted word starting with "#" ends the
// line.
func sshdArgs(line string) []string {
	s := strings.TrimLeft(line, " \t\f\r")
	if s == "" || s[0] == '#' {
		return nil
	}
	end := strings.IndexAny(s, " \t\f\r=")
	if end < 0 {
		return []string{s}
	}
	out := []string{s[:end]}
	rest := strings.TrimLeft(s[end:], " \t\f\r")
	if strings.HasPrefix(rest, "=") {
		rest = rest[1:]
	}
	var cur strings.Builder
	inQ, have := false, false
	for i := 0; i < len(rest); i++ {
		ch := rest[i]
		switch {
		case ch == '"':
			inQ, have = !inQ, true
		case !inQ && (ch == ' ' || ch == '\t' || ch == '\f' || ch == '\r'):
			if have {
				out = append(out, cur.String())
				cur.Reset()
				have = false
			}
		case !inQ && !have && ch == '#':
			return out
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

// effective evaluates the configuration for clientAddr as sshd does: a
// global pass (Match blocks inactive except "Match all"), then a pass over
// the Match blocks that apply to the client, whose values override.
func (c *sshdConfig) effective(clientAddr string) map[string]sshdSetting {
	out := c.pass(false, "")
	for k, v := range c.pass(true, clientAddr) {
		out[k] = v
	}
	for k, v := range sshdDefaults {
		if _, ok := out[k]; !ok {
			out[k] = sshdSetting{Value: v}
		}
	}
	return out
}

// pass replays the events once. In the global pass (addr "") the global
// section and "Match all" blocks are active; in the match pass only the Match
// blocks that apply to addr are. An included file starts in its includer's
// state and never changes it.
//
// sshd also stops an Include read from inside an inactive Match block from
// activating its own Match blocks, but only in the global pass. That cannot
// change the result: such a block can only be "Match all", which is active in
// the match pass too, where its values override.
func (c *sshdConfig) pass(matchPass bool, addr string) map[string]sshdSetting {
	out := map[string]sshdSetting{}
	active := !matchPass
	var stack []bool
	for _, e := range c.events {
		switch e.Kind {
		case evEnter:
			stack = append(stack, active)
		case evLeave:
			active = stack[len(stack)-1]
			stack = stack[:len(stack)-1]
		case evMatch:
			active = matchApplies(e.Args, addr)
		case evSet:
			if _, set := out[e.Key]; active && !set {
				out[e.Key] = sshdSetting{Value: strings.Join(e.Args, " "), Path: e.Path, Line: e.Line}
			}
		}
	}
	return out
}

// matchApplies evaluates one Match line's criteria for addr ("" = no
// specific address).
func matchApplies(crit []string, addr string) bool {
	if len(crit) == 0 {
		return false
	}
	if strings.EqualFold(crit[0], "all") {
		return len(crit) == 1
	}
	if len(crit)%2 != 0 {
		return false // a criterion without its argument: sshd rejects the line
	}
	for i := 0; i < len(crit); i += 2 {
		if !strings.EqualFold(crit[i], "address") || addr == "" || !addrMatchList(addr, crit[i+1]) {
			return false
		}
	}
	return true
}

// addrMatchList follows OpenSSH's addr_match_list: a comma-separated list
// of addresses, CIDR ranges and wildcard patterns; a "!" entry that matches
// rejects the address outright. A malformed CIDR entry never matches (sshd
// rejects the whole line).
func addrMatchList(addr, list string) bool {
	a, err := netip.ParseAddr(addr)
	text := strings.ToLower(addr)
	if err == nil {
		a = a.Unmap()
		text = a.String()
	}
	matched := false
	for _, entry := range strings.Split(list, ",") {
		neg := strings.HasPrefix(entry, "!")
		entry = strings.ToLower(strings.TrimPrefix(entry, "!"))
		if entry == "" {
			continue
		}
		var hit bool
		if strings.Contains(entry, "/") {
			pfx, perr := netip.ParsePrefix(entry)
			if perr != nil {
				return false
			}
			hit = err == nil && pfx.Masked().Contains(a)
		} else {
			hit = wildMatch(entry, text)
		}
		if hit && neg {
			return false
		}
		matched = matched || hit
	}
	return matched
}

// wildMatch matches s against a pattern where * is any run of characters and
// ? is any one character. It backtracks only to the last star, so a hostile
// pattern cannot make it slow.
func wildMatch(pat, s string) bool {
	p, i, star, mark := 0, 0, -1, 0
	for i < len(s) {
		switch {
		case p < len(pat) && (pat[p] == '?' || pat[p] == s[i]):
			p++
			i++
		case p < len(pat) && pat[p] == '*':
			star, mark = p, i
			p++
		case star >= 0:
			mark++
			p, i = star+1, mark
		default:
			return false
		}
	}
	for p < len(pat) && pat[p] == '*' {
		p++
	}
	return p == len(pat)
}

// matchBlock is one Match block and the first value it sets per keyword.
type matchBlock struct {
	Criteria []string
	Path     string
	Line     int
	Settings []sshdSetting
	Keys     []string
}

// blocks lists every Match block in reading order with the settings made
// inside it (an included file's leading lines belong to the block that was
// open at the Include).
func (c *sshdConfig) blocks() []matchBlock {
	var out []matchBlock
	cur := -1
	var stack []int
	seen := map[int]map[string]bool{}
	for _, e := range c.events {
		switch e.Kind {
		case evEnter:
			stack = append(stack, cur)
		case evLeave:
			cur = stack[len(stack)-1]
			stack = stack[:len(stack)-1]
		case evMatch:
			out = append(out, matchBlock{Criteria: e.Args, Path: e.Path, Line: e.Line})
			cur = len(out) - 1
			seen[cur] = map[string]bool{}
		case evSet:
			if cur >= 0 && !seen[cur][e.Key] {
				seen[cur][e.Key] = true
				b := &out[cur]
				b.Keys = append(b.Keys, e.Key)
				b.Settings = append(b.Settings, sshdSetting{Value: strings.Join(e.Args, " "), Path: e.Path, Line: e.Line})
			}
		}
	}
	return out
}
