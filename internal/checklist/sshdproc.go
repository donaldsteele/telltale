package checklist

import (
	"fmt"
	"net/netip"
	"path"
	"sort"
	"strings"

	"github.com/donaldsteele/telltale/internal/model"
)

// sshdListener is a running sshd that accepts connections, with the options
// on its command line.
type sshdListener struct {
	PID  int
	Opts []sshdOption // -o, in order
	// Ports are the command-line ports. With PortsOnly (-p was given) they
	// replace the files' Port lines; otherwise (-o Port) they add to them.
	Ports     []int
	PortsOnly bool
	File      string // -f, "" when not given
}

// isSSHDListener reports whether p may be an sshd listener: run by root
// (UID 0; an unknown UID is not accepted), and named sshd with an
// executable named sshd or an unreadable one (without root,
// /proc/<pid>/exe cannot be read), or with a command line starting with
// /usr/sbin/sshd.
func isSSHDListener(p model.Process) bool {
	if p.UID != 0 {
		return false
	}
	return p.Comm == "sshd" && (p.Exe == "" || strings.HasSuffix(p.Exe, "/sshd")) ||
		strings.HasPrefix(p.Cmdline, "/usr/sbin/sshd")
}

// sshdListeners finds running sshd listeners. sshd rewrites its title to
// "sshd: /usr/sbin/sshd -D [listener] ..." (older versions keep the plain
// argv); the program word must be named sshd, so per-connection children
// such as "sshd: alice [priv]" are not listeners.
func sshdListeners(c *model.Collection) []sshdListener {
	var out []sshdListener
	for _, p := range c.Runtime.Processes {
		if !isSSHDListener(p) {
			continue
		}
		args, ok := sshdArgv(p.Cmdline)
		if !ok {
			continue
		}
		l := parseSSHDOptions(args)
		l.PID = p.PID
		out = append(out, l)
	}
	return out
}

// sshdArgv returns the arguments after the program in a listener's title,
// stopping at "[listener]".
func sshdArgv(cmdline string) ([]string, bool) {
	s := strings.TrimPrefix(strings.TrimSpace(cmdline), "sshd: ")
	if i := strings.LastIndex(s, " [listener]"); i >= 0 {
		s = s[:i]
	}
	f := strings.Fields(s)
	if len(f) == 0 || path.Base(f[0]) != "sshd" {
		return nil, false
	}
	return f[1:], true
}

// sshdArgOpts are sshd's options that take an argument.
const sshdArgOpts = "CEbcfghkopu"

// parseSSHDOptions reads -o, -p and -f getopt-style ("-o X", "-oX",
// clustered flags). The collected title joins arguments with spaces, so one
// -o argument such as "PermitRootLogin = yes" arrives as several words:
// words are taken until there is a keyword and a value.
//
// Ports follow sshd -T: -p ports replace the files' Port lines and make any
// later -o Port ignored; an -o Port before -p, or without -p, is kept.
func parseSSHDOptions(args []string) sshdListener {
	var l sshdListener
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		if len(a) < 2 || a[0] != '-' {
			continue
		}
		for j := 1; j < len(a); j++ {
			ch := a[j]
			if strings.IndexByte(sshdArgOpts, ch) < 0 {
				continue
			}
			val := a[j+1:]
			if val == "" && i+1 < len(args) {
				i++
				val = args[i]
			}
			switch ch {
			case 'o':
				kv := sshdArgs(val)
				for len(kv) < 2 && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
					i++
					val += " " + args[i]
					kv = sshdArgs(val)
				}
				if len(kv) >= 2 {
					key := strings.ToLower(kv[0])
					l.Opts = append(l.Opts, sshdOption{Key: key, Value: strings.Join(kv[1:], " ")})
					if n := parsePort(kv[1]); key == "port" && n > 0 && !l.PortsOnly {
						l.Ports = append(l.Ports, n)
					}
				}
			case 'p':
				if n := parsePort(val); n > 0 {
					l.Ports = append(l.Ports, n)
					l.PortsOnly = true
				}
			case 'f':
				l.File = val
			}
			break // the rest of this word was the option's argument
		}
	}
	return l
}

// sshdView is the configuration one running sshd uses: the collected files
// plus the options on its command line. With no sshd running, there is one
// view of the files alone.
type sshdView struct {
	cfg  *sshdConfig
	opts []sshdOption
	pid  int
}

func (v sshdView) effective(addr string) map[string]sshdSetting {
	return v.cfg.effectiveWith(v.opts, addr)
}

// sshdBlocked explains why the collected sshd configuration must not be
// judged: the collector could not read all of it, or a running sshd reads
// another file.
func sshdBlocked(c *model.Collection) string {
	for _, s := range c.Skipped {
		if s.Check == model.SkipCheckSSHDConfig {
			return "sshd configuration incomplete: " + s.Reason
		}
	}
	for _, l := range sshdListeners(c) {
		if l.File != "" && path.Clean(l.File) != mainSSHDConfig {
			return "sshd runs with a different config file: " + l.File
		}
	}
	return ""
}

// sshdViews returns one view per distinct running sshd (or one for the files
// when none runs); an item passes only if it passes in every view.
func sshdViews(c *model.Collection) ([]sshdView, string) {
	if why := sshdBlocked(c); why != "" {
		return nil, why
	}
	cfg, why := parseSSHD(c.Persist)
	if why != "" {
		return nil, why
	}
	ls := sshdListeners(c)
	if len(ls) == 0 {
		return []sshdView{{cfg: cfg}}, ""
	}
	var out []sshdView
	seen := map[string]bool{}
	for _, l := range ls {
		key := fmt.Sprint(l.Opts)
		if !seen[key] {
			seen[key] = true
			out = append(out, sshdView{cfg: cfg, opts: l.Opts, pid: l.PID})
		}
	}
	return out, ""
}

// sshPorts returns the TCP ports sshd listens on, as far as can be told,
// following sshd -T: per listener, its -p ports alone, or its -o Port ports
// plus the files' Port values, or 22 when nothing sets a port (the files'
// ports count as 22 when the files cannot be read); plus ListenAddress ports
// and the ports of listening sockets owned by a listener.
func sshPorts(c *model.Collection) []int {
	cfgPorts, listen := []int{22}, []int(nil)
	if cfg, why := parseSSHD(c.Persist); why == "" {
		cfgPorts, listen = cfg.ports()
	}
	set := map[int]bool{}
	add := func(ps []int) {
		if len(ps) == 0 {
			ps = []int{22}
		}
		for _, p := range ps {
			set[p] = true
		}
	}
	for _, p := range listen {
		set[p] = true
	}
	ls := sshdListeners(c)
	if len(ls) == 0 {
		add(cfgPorts)
	}
	pids := map[int]bool{}
	for _, l := range ls {
		pids[l.PID] = true
		ports := append([]int(nil), l.Ports...)
		if !l.PortsOnly {
			ports = append(ports, cfgPorts...)
		}
		add(ports)
	}
	for _, s := range c.Runtime.Sockets {
		if port, ok := tcpListenPort(s); ok && pids[s.PID] {
			set[port] = true
		}
	}
	return sortedPorts(set)
}

// otherTCPPorts returns listening TCP ports reachable from the network
// (not loopback-only) that are not in skip.
func otherTCPPorts(c *model.Collection, skip []int) []int {
	set := map[int]bool{}
	for _, s := range c.Runtime.Sockets {
		if port, ok := tcpListenPort(s); ok {
			set[port] = true
		}
	}
	for _, p := range skip {
		delete(set, p)
	}
	return sortedPorts(set)
}

// tcpListenPort returns the port of a listening TCP socket that is not bound
// to a loopback address.
func tcpListenPort(s model.Socket) (int, bool) {
	if !strings.HasPrefix(s.Proto, "tcp") || !s.Listening {
		return 0, false
	}
	i := strings.LastIndex(s.Local, ":")
	if i < 0 {
		return 0, false
	}
	if a, err := netip.ParseAddr(strings.Trim(s.Local[:i], "[]")); err == nil && a.Unmap().IsLoopback() {
		return 0, false
	}
	n := parsePort(s.Local[i+1:])
	return n, n > 0
}

func sortedPorts(set map[int]bool) []int {
	out := make([]int, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}
