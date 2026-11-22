// Package heuristics holds checks that flag backdoor signs on any Linux
// machine, with or without a known-good snapshot. It works only on model
// types.
package heuristics

import (
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/redact"
)

const source = "heuristic"

// Rule ids.
const (
	idUID0         = "TT-HEUR-001"
	idEmptyPass    = "TT-HEUR-002"
	idSystemShell  = "TT-HEUR-003"
	idLDPreload    = "TT-HEUR-004"
	idProcExe      = "TT-HEUR-005"
	idForcedCmd    = "TT-HEUR-006"
	idRootKey      = "TT-HEUR-007"
	idSetuid       = "TT-HEUR-008"
	idImmutable    = "TT-HEUR-009"
	idModule       = "TT-HEUR-010"
	idListener     = "TT-HEUR-011"
	idCrossView    = "TT-HEUR-012"
	idPersistLink  = "TT-HEUR-013"
	idDiversion    = "TT-HEUR-014"
	evidenceDir    = "/root/telltale-evidence"
	saveEvidence   = "mkdir -p " + evidenceDir
	flagImmutable  = 0x10
	flagAppendOnly = 0x20
)

// Run returns findings for a collection. owned maps path to owning package
// (c.Packages.Owners()). Findings are sorted by Key.
func Run(c *model.Collection, ctx model.ScanContext, owned map[string]string) []model.Finding {
	var out []model.Finding
	out = append(out, accounts(c)...)
	out = append(out, ldPreload(c)...)
	out = append(out, processes(c, ctx)...)
	out = append(out, authorizedKeys(c, ctx)...)
	out = append(out, files(c, owned)...)
	out = append(out, modules(c, owned)...)
	out = append(out, listeners(c, ctx, owned)...)
	out = append(out, crossView(c)...)
	out = append(out, persistLinks(c)...)
	out = append(out, localDiversions(c)...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

const ctrlNote = "the name contains control characters, so no command is given: see the evidence above and handle it by hand"

// hasCtrl reports whether s holds a control byte (newline, escape, ...).
func hasCtrl(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

// sq single-quotes s for a POSIX shell.
func sq(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// fix builds a command from attacker-controllable values. Every value is
// shell-quoted; if any contains a control byte no command is produced.
func fix(vals []string, build func(q []string) string) string {
	q := make([]string, len(vals))
	for i, v := range vals {
		if hasCtrl(v) {
			return ctrlNote
		}
		q[i] = sq(v)
	}
	return build(q)
}

// keep saves a copy of quoted path q (keeping its directory structure) to
// the evidence directory.
func keep(q ...string) string {
	return fmt.Sprintf("%s && cp -a --parents %s %s/", saveEvidence, strings.Join(q, " "), evidenceDir)
}

func accounts(c *model.Collection) []model.Finding {
	var out []model.Finding
	for _, u := range c.Accounts.Users {
		if isNIS(u.Name) {
			continue
		}
		ev := []model.Evidence{{Path: "/etc/passwd", Detail: fmt.Sprintf("%s uid=%d shell=%s", u.Name, u.UID, u.Shell)}}
		if u.UID == 0 && u.Name != "root" {
			out = append(out, model.Finding{
				Key: "heur.uid0:" + u.Name, ID: idUID0, Source: source, Severity: model.SevBackdoor,
				Title: fmt.Sprintf("Account %q has user id 0 (root powers)", u.Name),
				Why:   "Only root should have user id 0. A second account with id 0 is a classic hidden way back in: it logs in as root under another name.",
				Fix: fix([]string{u.Name}, func(q []string) string {
					return keep("/etc/passwd", "/etc/shadow") + " && userdel " + q[0] + "   # check first that you did not create this account yourself"
				}),
				Evidence: ev, Refs: []string{"T1136.001"},
			})
		}
		if u.Password.Known && !u.Password.Set && !u.Password.Locked {
			out = append(out, model.Finding{
				Key: "heur.empty_password:" + u.Name, ID: idEmptyPass, Source: source, Severity: model.SevWeak,
				Title: fmt.Sprintf("Account %q has an empty password", u.Name),
				Why:   "An empty password lets anyone who can reach a login prompt (or su) in as this user without a password.",
				Fix: fix([]string{u.Name}, func(q []string) string {
					return "passwd -l " + q[0] + "   # locks the account; set a real password with passwd if it must be used"
				}),
				Evidence: ev, Refs: []string{"T1136.001"},
			})
		}
		if u.UID > 0 && u.UID < 1000 && !noLogin(u.Shell) {
			out = append(out, model.Finding{
				Key: "heur.system_shell:" + u.Name, ID: idSystemShell, Source: source, Severity: model.SevNote,
				Title: fmt.Sprintf("System account %q has a login shell (%s)", u.Name, u.Shell),
				Why:   "System accounts normally cannot log in. A login shell on one is how attackers turn a service account into a usable foothold.",
				Fix: fix([]string{u.Name}, func(q []string) string {
					return "usermod -s /usr/sbin/nologin " + q[0]
				}),
				Evidence: ev, Refs: []string{"T1136.001"},
			})
		}
	}
	return out
}

func ldPreload(c *model.Collection) []model.Finding {
	for _, p := range c.Persist {
		if p.Path != "/etc/ld.so.preload" && p.Kind != model.PersistKindLDPreload {
			continue
		}
		var lines []string
		for _, l := range p.Lines {
			if s := strings.TrimSpace(l); s != "" && !strings.HasPrefix(s, "#") {
				lines = append(lines, s)
			}
		}
		if len(lines) == 0 {
			continue
		}
		return []model.Finding{{
			Key: "heur.ld_preload", ID: idLDPreload, Source: source, Severity: model.SevBackdoor,
			Title: p.Path + " lists libraries that load into every program",
			Why:   "Libraries named here are injected into every program that starts. Rootkits use this to hide files, processes and connections. Few legitimate systems use it.",
			Fix: fix([]string{p.Path}, func(q []string) string {
				return keep(q[0]) + " && rm " + q[0] + "   # also copy the libraries it listed (see the evidence) to " + evidenceDir
			}),
			Evidence: []model.Evidence{{Path: p.Path, Line: 1, Detail: strings.Join(lines, "; ")}},
			Refs:     []string{"T1574.006"},
		}}
	}
	return nil
}

// suspiciousExe classifies a process executable. homes maps uid to home.
func suspiciousExe(p model.Process, homes map[int]string) (string, model.Severity, bool) {
	if p.ExeDeleted {
		return "the program file was deleted after it started", model.SevBackdoor, true
	}
	for _, d := range []string{"/tmp/", "/dev/shm/", "/var/tmp/"} {
		if strings.HasPrefix(p.Exe, d) {
			return "it runs from " + strings.TrimSuffix(d, "/"), model.SevBackdoor, true
		}
	}
	for _, comp := range strings.Split(p.Exe, "/") {
		if strings.HasPrefix(comp, ".") && comp != "." && comp != ".." {
			if h := homes[p.UID]; p.UID > 0 && h != "" && h != "/" && strings.HasPrefix(p.Exe, strings.TrimSuffix(h, "/")+"/") {
				return "its path has a hidden (dot) component, inside the owner's own home", model.SevNote, true
			}
			return "its path has a hidden (dot) component", model.SevBackdoor, true
		}
	}
	return "", 0, false
}

func processes(c *model.Collection, ctx model.ScanContext) []model.Finding {
	homes := map[int]string{}
	for _, u := range c.Accounts.Users {
		if !isNIS(u.Name) {
			homes[u.UID] = u.Home
		}
	}
	var out []model.Finding
	for _, p := range c.Runtime.Processes {
		reason, sev, bad := suspiciousExe(p, homes)
		if !bad {
			continue
		}
		pid := strconv.Itoa(p.PID)
		cmdline, _ := redact.Line(ctx.DigestKey, p.Cmdline)
		out = append(out, model.Finding{
			Key: "heur.proc_exe:" + pid, ID: idProcExe, Source: source, Severity: sev,
			Title: fmt.Sprintf("Process %s (%s) looks hidden: %s", pid, nameOf(p), reason),
			Why:   "Legitimate software is installed in system directories and stays on disk. Programs run from temporary or hidden locations, or deleted while running, are typical of malware.",
			Fix: fmt.Sprintf("%s && cp /proc/%s/exe %s/%s.exe; ls -l /proc/%s/cwd /proc/%s/fd; kill -STOP %s   # suspends, does not kill: investigate before killing",
				saveEvidence, pid, evidenceDir, pid, pid, pid, pid),
			Evidence: []model.Evidence{{Path: p.Exe, Detail: fmt.Sprintf("exe=%s cmdline=%s uid=%d deleted=%t", p.Exe, cmdline, p.UID, p.ExeDeleted)}},
			Refs:     []string{"T1036"},
		})
	}
	return out
}

func nameOf(p model.Process) string {
	if p.Comm != "" {
		return p.Comm
	}
	return path.Base(p.Exe)
}

// splitFields splits an authorized_keys line on unquoted blanks. Inside
// double quotes a backslash escapes the next byte, as in sshd's option parser.
func splitFields(line string) []string {
	var toks []string
	var cur strings.Builder
	inQ := false
	for i := 0; i < len(line); i++ {
		ch := line[i]
		switch {
		case inQ && ch == '\\' && i+1 < len(line) && line[i+1] == '"':
			cur.WriteString(`\"`)
			i++
		case ch == '"':
			inQ = !inQ
			cur.WriteByte(ch)
		case (ch == ' ' || ch == '\t') && !inQ:
			if cur.Len() > 0 {
				toks = append(toks, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(ch)
		}
	}
	if cur.Len() > 0 {
		toks = append(toks, cur.String())
	}
	return toks
}

// keyBlob returns "type base64" of the first public key in an
// authorized_keys line, and the options before it.
func keyBlob(line string) (blob, opts string) {
	toks := splitFields(line)
	for i, t := range toks {
		if (strings.HasPrefix(t, "ssh-") || strings.HasPrefix(t, "ecdsa-") || strings.HasPrefix(t, "sk-")) && i+1 < len(toks) {
			return t + " " + toks[i+1], strings.Join(toks[:i], " ")
		}
	}
	return "", strings.Join(toks, " ")
}

func hasCommandOption(opts string) bool {
	inQ := false
	start := 0
	for i := 0; i <= len(opts); i++ {
		if i < len(opts) {
			if inQ && opts[i] == '\\' && i+1 < len(opts) && opts[i+1] == '"' {
				i++
				continue
			}
			if opts[i] == '"' {
				inQ = !inQ
			}
		}
		if i == len(opts) || (opts[i] == ',' && !inQ) {
			if strings.HasPrefix(strings.ToLower(opts[start:i]), "command=") {
				return true
			}
			start = i + 1
		}
	}
	return false
}

func rootHomes(c *model.Collection) []string {
	homes := []string{"/root"}
	for _, u := range c.Accounts.Users {
		if u.UID == 0 && !isNIS(u.Name) && u.Home != "" && u.Home != "/root" {
			homes = append(homes, strings.TrimSuffix(u.Home, "/"))
		}
	}
	return homes
}

func authorizedKeys(c *model.Collection, ctx model.ScanContext) []model.Finding {
	server, _ := keyBlob(ctx.ServerKeyLine)
	homes := rootHomes(c)
	var out []model.Finding
	for _, p := range c.Persist {
		if p.Kind != model.PersistKindAuthorizedKeys {
			continue
		}
		isRoot := false
		for _, h := range homes {
			if strings.HasPrefix(p.Path, h+"/") {
				isRoot = true
			}
		}
		for i, l := range p.Lines {
			s := strings.TrimSpace(l)
			if s == "" || strings.HasPrefix(s, "#") {
				continue
			}
			blob, opts := keyBlob(s)
			if server != "" && blob == server {
				continue
			}
			ev := []model.Evidence{{Path: p.Path, Line: i + 1, After: s}}
			del := func(note string) string {
				return fix([]string{p.Path}, func(q []string) string {
					return fmt.Sprintf("%s && sed -i '%dd' %s   # %s; if you remove several lines from this file, start with the highest line number",
						keep(q[0]), i+1, q[0], note)
				})
			}
			key := fmt.Sprintf(":%s:%d", p.Path, i+1)
			if hasCommandOption(opts) {
				out = append(out, model.Finding{
					Key: "heur.forced_command" + key, ID: idForcedCmd, Source: source, Severity: model.SevBackdoor,
					Title:    fmt.Sprintf("SSH key in %s line %d forces a command", p.Path, i+1),
					Why:      "A key with command= runs a fixed program when it logs in. Attackers use it to plant a hidden shell or to run code on every connection while looking like a normal key.",
					Fix:      del("first confirm the key is not yours"),
					Evidence: ev, Refs: []string{"T1098.004"},
				})
			} else if isRoot {
				// Emitted always; the judge drops these notes when a snapshot is
				// used, since new keys are then ranked from the diff.
				out = append(out, model.Finding{
					Key: "heur.root_key" + key, ID: idRootKey, Source: source, Severity: model.SevNote,
					Title:    fmt.Sprintf("Root can log in over SSH with a key in %s line %d", p.Path, i+1),
					Why:      "Any key listed in root's authorized_keys gives its holder a root login. Make sure each one is yours.",
					Fix:      del("only if you do not recognise the key"),
					Evidence: ev, Refs: []string{"T1098.004"},
				})
			}
		}
	}
	return out
}

func files(c *model.Collection, owned map[string]string) []model.Finding {
	var out []model.Finding
	for _, f := range c.Files {
		if f.Type == "file" && f.Mode&0o6000 != 0 {
			if _, ok := owned[f.Path]; !ok {
				sev := model.SevBackdoor
				if strings.HasPrefix(f.Path, "/usr/local/") {
					sev = model.SevNote
				}
				out = append(out, model.Finding{
					Key: "heur.unowned_setuid:" + f.Path, ID: idSetuid, Source: source, Severity: sev,
					Title: fmt.Sprintf("%s runs with its owner's rights but belongs to no package", f.Path),
					Why:   "A setuid/setgid program lets any user run it with the owner's (often root's) rights. One no package installed may be a planted privilege-escalation shell.",
					Fix: fix([]string{f.Path}, func(q []string) string {
						return keep(q[0]) + " && chmod u-s,g-s " + q[0] + "   # removes the privilege bit, keeps the file; delete it only after investigating"
					}),
					Evidence: []model.Evidence{{Path: f.Path, Detail: fmt.Sprintf("mode=%o uid=%d", f.Mode&0o7777, f.UID)}},
					Refs:     []string{"T1548.001"},
				})
			}
		}
		if f.Flags&(flagImmutable|flagAppendOnly) != 0 {
			kind, flag := "immutable", "i"
			if f.Flags&flagImmutable == 0 {
				kind, flag = "append-only", "a"
			}
			out = append(out, model.Finding{
				Key: "heur.immutable:" + f.Path, ID: idImmutable, Source: source, Severity: model.SevBackdoor,
				Title: fmt.Sprintf("%s is marked %s", f.Path, kind),
				Why:   "The immutable and append-only flags stop even root from changing or deleting a file. Attackers set them to protect a backdoor from removal. Ordinary systems rarely use them on system files.",
				Fix: fix([]string{f.Path}, func(q []string) string {
					return keep(q[0]) + " && chattr -" + flag + " " + q[0]
				}),
				Evidence: []model.Evidence{{Path: f.Path, Detail: fmt.Sprintf("inode flags=0x%x (%s)", f.Flags, kind)}},
				Refs:     []string{"T1222.002"},
			})
		}
	}
	return out
}

func modules(c *model.Collection, owned map[string]string) []model.Finding {
	var out []model.Finding
	for _, m := range c.Runtime.Modules {
		detail := "no module file found under /lib/modules"
		if m.File != "" {
			if _, ok := owned[m.File]; ok {
				continue
			}
			detail = m.File + " belongs to no package"
		}
		vals := []string{m.Name}
		if m.File != "" {
			vals = append(vals, m.File)
		}
		out = append(out, model.Finding{
			Key: "heur.module:" + m.Name, ID: idModule, Source: source, Severity: model.SevBackdoor,
			Title: fmt.Sprintf("Kernel module %q is loaded but not from an installed package", m.Name),
			Why:   "Kernel modules run with full control of the machine. One with no package behind it may be a rootkit (or a locally built driver you installed yourself).",
			Fix: fix(vals, func(q []string) string {
				s := "modinfo -- " + q[0]
				if len(q) > 1 {
					s = keep(q[1]) + " && " + s
				}
				return s + "   # then unload it with rmmod only after confirming it is not yours"
			}),
			Evidence: []model.Evidence{{Path: m.File, Detail: fmt.Sprintf("%s taint=%q: %s", m.Name, m.Taint, detail)}},
			Refs:     []string{"T1547.006"},
		})
	}
	return out
}

func listeners(c *model.Collection, ctx model.ScanContext, owned map[string]string) []model.Finding {
	procs := map[int]model.Process{}
	for _, p := range c.Runtime.Processes {
		procs[p.PID] = p
	}
	seen := map[string]bool{}
	var out []model.Finding
	for _, s := range c.Runtime.Sockets {
		if !s.Listening {
			continue
		}
		p, ok := procs[s.PID]
		if !ok || p.Exe == "" {
			continue
		}
		if _, ok := owned[p.Exe]; ok {
			continue
		}
		port := s.Local[strings.LastIndex(s.Local, ":")+1:]
		if seen[port] {
			continue
		}
		seen[port] = true
		cmdline, _ := redact.Line(ctx.DigestKey, p.Cmdline)
		out = append(out, model.Finding{
			Key: "heur.unowned_listener:" + port, ID: idListener, Source: source, Severity: model.SevNote,
			Title: fmt.Sprintf("Port %s is open, served by %s which belongs to no package", port, p.Exe),
			Why:   "A service you did not install from your distribution may be fine (your own software) or a backdoor listening for connections.",
			Fix: fmt.Sprintf("%s && cp /proc/%d/exe %s/%d.exe; ls -l /proc/%d/cwd /proc/%d/fd   # investigate; stop with 'kill -STOP %d' if unrecognised",
				saveEvidence, p.PID, evidenceDir, p.PID, p.PID, p.PID, p.PID),
			Evidence: []model.Evidence{{Path: p.Exe, Detail: fmt.Sprintf("%s %s pid=%d cmdline=%s", s.Proto, s.Local, p.PID, cmdline)}},
			Refs:     []string{"T1571"},
		})
	}
	return out
}

func crossView(c *model.Collection) []model.Finding {
	var out []model.Finding
	for _, r := range c.CrossView {
		if !r.Ran || len(r.HiddenFromTool) == 0 {
			continue
		}
		f := model.Finding{
			Key: "heur.crossview:" + r.Tool, ID: idCrossView, Source: source, Severity: model.SevTampering,
			Title: fmt.Sprintf("`%s` hides %d item(s) that telltale can see directly", r.Tool, len(r.HiddenFromTool)),
			Why:   "Two independent ways of looking at the machine disagree. Something is filtering this tool's output, which is what rootkits do to hide themselves.",
			Fix:   "Do not trust this machine's own tools. Check `cat /etc/ld.so.preload`, copy telltale's collection off the host, then inspect or rebuild the machine from rescue media.",
			Refs:  []string{"T1014"},
		}
		for _, h := range r.HiddenFromTool {
			f.Evidence = append(f.Evidence, model.Evidence{Detail: h})
		}
		out = append(out, f)
	}
	return out
}

var maskedWeak = []string{"auditd", "apparmor", "ufw", "nftables", "fail2ban"}

func persistLinks(c *model.Collection) []model.Finding {
	var out []model.Finding
	for _, p := range c.Persist {
		if p.Mode&0o170000 != 0o120000 || len(p.Lines) == 0 {
			continue
		}
		target := strings.TrimSpace(p.Lines[0])
		if !path.IsAbs(target) {
			target = path.Join(path.Dir(p.Path), target)
		}
		target = path.Clean(target)
		ev := []model.Evidence{{Path: p.Path, Line: 1, After: p.Lines[0], Detail: "symlink to " + target}}
		key := "heur.persist_link:" + p.Path
		if target == "/dev/null" {
			base := path.Base(p.Path)
			for _, w := range maskedWeak {
				if strings.HasPrefix(base, w) {
					out = append(out, model.Finding{
						Key: key, ID: idPersistLink, Source: source, Severity: model.SevWeak,
						Title: fmt.Sprintf("Security service %s is masked", base),
						Why:   "A link to /dev/null stops this service from ever starting. Attackers mask logging and protection services; you may also have done it on purpose.",
						Fix: fix([]string{base}, func(q []string) string {
							return "systemctl unmask " + q[0] + "   # only if you did not mask it deliberately"
						}),
						Evidence: ev, Refs: []string{"T1543.002"},
					})
					break
				}
			}
			continue
		}
		ok := false
		for _, pre := range []string{"/usr/", "/lib/", "/etc/", "/run/systemd/"} {
			if strings.HasPrefix(target, pre) {
				ok = true
			}
		}
		if ok {
			continue
		}
		out = append(out, model.Finding{
			Key: key, ID: idPersistLink, Source: source, Severity: model.SevBackdoor,
			Title: fmt.Sprintf("%s is a link to %s, outside the system directories", p.Path, target),
			Why:   "Startup entries that point at files in temporary or user-writable places (as `systemctl link` can create) run whatever sits there, and the real code is not in the usual locations.",
			Fix: fix([]string{p.Path, target}, func(q []string) string {
				return keep(q[0]) + " && { cp -a --parents " + q[1] + " " + evidenceDir + "/ 2>/dev/null || echo 'link target not saved (missing or unreadable)'; } && rm " + q[0] + "   # inspect the saved copies first; rm only runs once the link itself is saved"
			}),
			Evidence: ev, Refs: []string{"T1543.002", "T1053.003"},
		})
	}
	return out
}

// diversionDirs are the system trees where a local diversion is suspicious.
var diversionDirs = []string{"/bin/", "/sbin/", "/usr/", "/lib/", "/lib32/", "/lib64/", "/libx32/", "/etc/", "/boot/"}

// The local diversions Ubuntu's official images make, exactly as
// /var/lib/dpkg/diversions records them in ubuntu:22.04 and ubuntu:24.04
// (read 2026-11-22): the minimised images replace man with a hint to run
// unminimize, and the container images replace initctl. Only these exact
// pairs are notes; any other local diversion is a backdoor sign.
const (
	stockUbuntuManPath       = "/usr/bin/man"
	stockUbuntuManDivert     = "/usr/bin/man.REAL"
	stockUbuntuInitctlPath   = "/sbin/initctl"
	stockUbuntuInitctlDivert = "/sbin/initctl.distrib"
)

func stockUbuntuDiversion(d model.Diversion) bool {
	return (d.Path == stockUbuntuManPath && d.DivertTo == stockUbuntuManDivert) ||
		(d.Path == stockUbuntuInitctlPath && d.DivertTo == stockUbuntuInitctlDivert)
}

// localDiversions flags diversions of system files that no installed package
// stands behind: dpkg-divert --local entries, and diversions in the name of
// a package that is not installed. Every package's version of the file is
// installed elsewhere, so whatever sits at the original path is never
// replaced by updates or checked against a package.
func localDiversions(c *model.Collection) []model.Finding {
	installed := map[string]bool{}
	for _, p := range c.Packages.Installed {
		installed[p.Name] = true
	}
	var out []model.Finding
	for _, d := range c.Packages.Diversions {
		local := d.Package == model.LocalDiversion
		if !local && installed[d.Package] {
			continue
		}
		system := false
		for _, dir := range diversionDirs {
			if strings.HasPrefix(d.Path, dir) {
				system = true
				break
			}
		}
		if !system {
			continue
		}
		sev := model.SevBackdoor
		title := fmt.Sprintf("%s is locally diverted to %s", d.Path, d.DivertTo)
		detail := "local diversion to " + d.DivertTo
		why := "A local dpkg diversion makes every package install its version of this file under another name, so the file at the original path is never replaced by updates and is not the packaged one. Image builders use it (Ubuntu's minimised images divert /usr/bin/man); an attacker can use it to keep a replaced system program in place."
		owner := "--local"
		switch {
		case !local:
			title = fmt.Sprintf("%s is diverted to %s by package %s, which is not installed", d.Path, d.DivertTo, d.Package)
			detail = "diversion to " + d.DivertTo + " by " + d.Package + ", which is not installed"
			why = "A dpkg diversion in the name of a package that is not installed has nothing behind it: whatever sits at the original path is not the packaged file, and the real one is moved aside. Removing a package removes its diversions, so one left over or added by hand is how a replaced system program can be kept in place."
			owner = "--package " + sq(d.Package)
		case c.Host.OSID == "ubuntu" && stockUbuntuDiversion(d):
			sev = model.SevNote
			why = "Ubuntu's official images make exactly this local diversion, so it is expected on machines built from them. The file at the original path is not the packaged one and is not checked against a package; if this machine was not built from such an image, treat it as a backdoor sign."
		}
		out = append(out, model.Finding{
			Key: "heur.local_diversion:" + d.Path, ID: idDiversion, Source: source, Severity: sev,
			Title: title,
			Why:   why,
			Fix: fix([]string{d.Path, d.DivertTo, d.Package}, func(q []string) string {
				return keep(q[0]) + " && { cp -a --parents " + q[1] + " " + evidenceDir + "/ 2>/dev/null || echo 'diverted file not saved (missing or unreadable)'; } && rm " + q[0] + " && dpkg-divert " + owner + " --rename --remove " + q[0] + "   # puts the packaged file back; inspect the saved copies first"
			}),
			Evidence: []model.Evidence{{Path: d.Path, Detail: detail}},
			Refs:     []string{"T1574", "T1036.005"},
		})
	}
	return out
}

func isNIS(name string) bool { return strings.HasPrefix(name, "+") || strings.HasPrefix(name, "-") }

func noLogin(shell string) bool {
	switch path.Base(shell) {
	case "", "nologin", "false", "sync", "halt", "shutdown":
		return true
	}
	return false
}
