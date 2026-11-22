package checklist

import (
	"net/netip"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/sshglob"
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
// relative to /etc/ssh, glob(3) rules, matches in sorted order, an Include
// that matches no collected file is ignored), first value wins in the global
// section and "Match all", and a Match block that applies to the client
// overrides the global value for the keywords it sets (first value wins
// among applying blocks), except keywords not allowed in Match blocks
// (StrictModes, PermitUserEnvironment, ...), which keep their global value.
// A file included from inside a Match block that does not apply cannot
// activate any of its own Match blocks, as in sshd.
//
// Only the files are read; options on a running sshd's command line are
// applied by the checklist items, not here.
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

// emptySHA256 is the SHA-256 of no content.
const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// persistText returns the content lines of a collected file. ok is false
// when the text was not kept: Lines is nil (too large), or the file is a
// symlink whose target content was not kept. For a symlink, Lines[0] is the
// link target and the target's content follows; when only the target is
// there, the content was read only if SHA256 is that of an empty file (the
// collector otherwise hashes the target text: target is another symlink,
// too large, or a secret file).
func persistText(pf model.PersistFile) (lines []string, ok bool) {
	if pf.Lines == nil {
		return nil, false
	}
	if isSymlinkMode(pf.Mode) {
		if len(pf.Lines) == 0 || (len(pf.Lines) == 1 && pf.SHA256 != emptySHA256) {
			return nil, false
		}
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
		p.problem = file + ": content not kept (too large, or a symlink to a secret, oversized or symlinked file), so the sshd configuration cannot be evaluated"
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
			for _, pat := range args[1:] {
				for _, m := range p.glob(pat) {
					if depth+1 > maxSSHDDepth {
						p.problem = file + ": Include nested deeper than sshd allows (sshd would not start)"
						return
					}
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
// with glob(3) rules (relative patterns are under /etc/ssh).
func (p *sshdParser) glob(pat string) []string {
	if strings.HasPrefix(pat, "~") {
		return nil
	}
	if !path.IsAbs(pat) {
		pat = path.Join("/etc/ssh", pat)
	}
	var out []string
	for _, f := range p.paths {
		if sshglob.Match(pat, f) {
			out = append(out, f)
		}
	}
	return out
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

// matchAllowed lists the keywords sshd accepts after a Match line
// (sshd_config(5), OpenSSH 10.0). Every other keyword is global-only: the
// match pass never overrides it, and sshd refuses to start if one appears in
// a Match block that does not apply to every connection.
var matchAllowed = func() map[string]bool {
	m := map[string]bool{}
	for _, k := range strings.Fields(`AcceptEnv AllowAgentForwarding AllowGroups
		AllowStreamLocalForwarding AllowTcpForwarding AllowUsers AuthenticationMethods
		AuthorizedKeysCommand AuthorizedKeysCommandUser AuthorizedKeysFile
		AuthorizedPrincipalsCommand AuthorizedPrincipalsCommandUser AuthorizedPrincipalsFile
		Banner CASignatureAlgorithms ChannelTimeout ChrootDirectory ClientAliveCountMax
		ClientAliveInterval DenyGroups DenyUsers DisableForwarding ExposeAuthInfo ForceCommand
		GatewayPorts GSSAPIAuthentication HostbasedAcceptedAlgorithms HostbasedAuthentication
		HostbasedUsesNameFromPacketOnly IgnoreRhosts Include IPQoS KbdInteractiveAuthentication
		KerberosAuthentication LogLevel MaxAuthTries MaxSessions PAMServiceName
		PasswordAuthentication PermitEmptyPasswords PermitListen PermitOpen PermitRootLogin
		PermitTTY PermitTunnel PermitUserRC PubkeyAcceptedAlgorithms PubkeyAuthentication
		PubkeyAuthOptions RefuseConnection RekeyLimit RevokedKeys SetEnv StreamLocalBindMask
		StreamLocalBindUnlink TrustedUserCAKeys UnusedConnectionTimeout X11DisplayOffset
		X11Forwarding X11UseLocalhost`) {
		m[strings.ToLower(k)] = true
	}
	return m
}()

// cmdlineSource is the sshdSetting.Path of a value given with -o on a
// running sshd's command line.
const cmdlineSource = "(sshd command line)"

// sshdOption is one -o Keyword=value from a running sshd's command line.
type sshdOption struct{ Key, Value string }

// effective evaluates the configuration files alone for clientAddr.
func (c *sshdConfig) effective(clientAddr string) map[string]sshdSetting {
	return c.effectiveWith(nil, clientAddr)
}

// effectiveWith evaluates the configuration for clientAddr as sshd does:
// command-line -o values come first (first value wins, so they beat the
// files' global values), then the global pass over the files (global section
// and "Match all", first value wins), then the Match blocks that apply to the
// client override the keywords allowed in Match blocks, including -o values
// (checked with sshd -T).
func (c *sshdConfig) effectiveWith(opts []sshdOption, clientAddr string) map[string]sshdSetting {
	out := map[string]sshdSetting{}
	for _, o := range opts {
		if _, set := out[o.Key]; !set {
			out[o.Key] = sshdSetting{Value: o.Value, Path: cmdlineSource}
		}
	}
	for k, v := range c.pass(false, "") {
		if _, set := out[k]; !set {
			out[k] = v
		}
	}
	for k, v := range c.pass(true, clientAddr) {
		if matchAllowed[k] {
			out[k] = v
		}
	}
	for k, v := range sshdDefaults {
		if _, ok := out[k]; !ok {
			out[k] = sshdSetting{Value: v}
		}
	}
	return out
}

// replay walks the events for one pass and calls f with the index of every
// Match line and setting and whether it is active. The global pass
// (matchPass false, addr "") starts active and activates only "Match all";
// the match pass starts inactive and activates the Match blocks that apply
// to addr.
//
// Include follows sshd's servconf.c. An included file starts in its
// includer's active state and never changes it. Each file also has two
// flags: matchOnly (match pass, and the file is not yet past its first Match
// line) and never (none of the file's Match blocks can apply). An included
// file inherits matchOnly while its includer still has it; otherwise it gets
// never when the includer is not active at the Include.
func (c *sshdConfig) replay(matchPass bool, addr string, f func(i int, active bool)) {
	type state struct{ active, matchOnly, never bool }
	st := state{active: !matchPass, matchOnly: matchPass}
	var stack []state
	for i, e := range c.events {
		switch e.Kind {
		case evEnter:
			stack = append(stack, st)
			st = state{active: st.active, matchOnly: st.matchOnly, never: !st.matchOnly && !st.active}
		case evLeave:
			st = stack[len(stack)-1]
			stack = stack[:len(stack)-1]
		case evMatch:
			st.active = !st.never && matchApplies(e.Args, addr)
			st.matchOnly = false
			f(i, st.active)
		case evSet:
			f(i, st.active)
		}
	}
}

func eventSetting(e sshdEvent) sshdSetting {
	return sshdSetting{Value: strings.Join(e.Args, " "), Path: e.Path, Line: e.Line}
}

// pass returns the first active value of every keyword in one pass.
func (c *sshdConfig) pass(matchPass bool, addr string) map[string]sshdSetting {
	out := map[string]sshdSetting{}
	c.replay(matchPass, addr, func(i int, active bool) {
		e := c.events[i]
		if _, set := out[e.Key]; e.Kind == evSet && active && !set {
			out[e.Key] = eventSetting(e)
		}
	})
	return out
}

// ports returns every Port value in the files' global pass (Port adds up and
// is global-only; none means sshd's default 22 unless the command line sets
// a port) and separately the explicit ports of ListenAddress host:port
// lines.
func (c *sshdConfig) ports() (ports, listen []int) {
	c.replay(false, "", func(i int, active bool) {
		e := c.events[i]
		if e.Kind != evSet || !active {
			return
		}
		switch e.Key {
		case "port":
			for _, a := range e.Args {
				if n := parsePort(a); n > 0 {
					ports = append(ports, n)
				}
			}
		case "listenaddress":
			if n := listenPort(e.Args[0]); n > 0 {
				listen = append(listen, n)
			}
		}
	})
	return ports, listen
}

func parsePort(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0
	}
	return n
}

// listenPort returns the port of "host:port" or "[v6]:port", 0 when none.
func listenPort(s string) int {
	if strings.HasPrefix(s, "[") {
		if i := strings.LastIndex(s, "]:"); i >= 0 {
			return parsePort(s[i+2:])
		}
		return 0
	}
	if strings.Count(s, ":") == 1 {
		return parsePort(s[strings.IndexByte(s, ':')+1:])
	}
	return 0
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
// Everyone is set when the block applies to every connection (it is active
// when evaluated for no particular client), so its values are judged with
// the global ones.
type matchBlock struct {
	Criteria []string
	Path     string
	Line     int
	Everyone bool
	Settings []sshdSetting
	Keys     []string
}

// blocks lists every Match block in reading order with the settings made
// inside it (an included file's leading lines belong to the block that was
// open at the Include).
func (c *sshdConfig) blocks() []matchBlock {
	everyone := map[int]bool{}
	c.replay(true, "", func(i int, active bool) {
		if c.events[i].Kind == evMatch && active {
			everyone[i] = true
		}
	})
	var out []matchBlock
	cur := -1
	var stack []int
	seen := map[int]map[string]bool{}
	for i, e := range c.events {
		switch e.Kind {
		case evEnter:
			stack = append(stack, cur)
		case evLeave:
			cur = stack[len(stack)-1]
			stack = stack[:len(stack)-1]
		case evMatch:
			out = append(out, matchBlock{Criteria: e.Args, Path: e.Path, Line: e.Line, Everyone: everyone[i]})
			cur = len(out) - 1
			seen[cur] = map[string]bool{}
		case evSet:
			if cur >= 0 && !seen[cur][e.Key] {
				seen[cur][e.Key] = true
				b := &out[cur]
				b.Keys = append(b.Keys, e.Key)
				b.Settings = append(b.Settings, eventSetting(e))
			}
		}
	}
	return out
}

// blockOf returns the Match block that holds the config line of s.
func (c *sshdConfig) blockOf(s sshdSetting) (matchBlock, bool) {
	if s.Path == "" || s.Path == cmdlineSource {
		return matchBlock{}, false
	}
	for _, b := range c.blocks() {
		for _, bs := range b.Settings {
			if bs.Path == s.Path && bs.Line == s.Line {
				return b, true
			}
		}
	}
	return matchBlock{}, false
}
