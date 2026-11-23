// Package heuristics holds checks that flag backdoor signs on any Linux
// machine, with or without a known-good snapshot. It works only on model
// types.
package heuristics

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/donaldsteele/telltale/internal/escape"
	"github.com/donaldsteele/telltale/internal/model"
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
	idPAM          = "TT-HEUR-016"
	evidenceDir    = "/root/telltale-evidence"
	saveEvidence   = "mkdir -p " + evidenceDir
	flagImmutable  = 0x10
	flagAppendOnly = 0x20
)

// Run returns findings for a collection. owned maps path to owning package
// (c.Packages.Owners()): the paths dpkg lists, which is all that makes a file
// a package's own. Only the startup-link check also asks where a listed path
// really is (model.PhysicalOwnersOf), to tell whose file a link leads to.
// Findings are sorted by Key.
func Run(c *model.Collection, ctx model.ScanContext, owned map[string]string) []model.Finding {
	var out []model.Finding
	out = append(out, accounts(c)...)
	out = append(out, ldPreload(c)...)
	out = append(out, processes(c, ctx, owned)...)
	out = append(out, authorizedKeys(c, ctx)...)
	out = append(out, files(c, owned)...)
	out = append(out, modules(c, owned)...)
	out = append(out, listeners(c, ctx, owned)...)
	out = append(out, crossView(c)...)
	out = append(out, persistLinks(c, owned)...)
	out = append(out, persistCallbacks(c)...)
	out = append(out, pamModules(c, owned)...)
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
func sq(s string) string { return escape.ShellQuote(s) }

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

// suspiciousExe classifies a process executable. homes maps uid to home. The
// class names the situation and, with the program path, keys the finding.
func suspiciousExe(p model.Process, homes map[int]string) (class, reason string, sev model.Severity, bad bool) {
	if p.ExeDeleted {
		return "deleted", "the program file was deleted after it started", model.SevBackdoor, true
	}
	for _, d := range []string{"/tmp/", "/dev/shm/", "/var/tmp/"} {
		if strings.HasPrefix(p.Exe, d) {
			return "tmp", "it runs from " + strings.TrimSuffix(d, "/"), model.SevBackdoor, true
		}
	}
	for _, comp := range strings.Split(p.Exe, "/") {
		if strings.HasPrefix(comp, ".") && comp != "." && comp != ".." {
			if h := homes[p.UID]; p.UID > 0 && h != "" && h != "/" && strings.HasPrefix(p.Exe, strings.TrimSuffix(h, "/")+"/") {
				return "hidden_home", "its path has a hidden (dot) component, inside the owner's own home", model.SevNote, true
			}
			return "hidden", "its path has a hidden (dot) component", model.SevBackdoor, true
		}
	}
	return "", "", 0, false
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
		// A symlinked keys file is recorded with the link's target as Lines[0]
		// and the target's content after it. Line numbers count that content,
		// and fixes edit the target: sed -i on the link would replace it with
		// a plain file.
		lines, link, target := p.Lines, false, ""
		if p.Mode&0o170000 == 0o120000 {
			if len(lines) == 0 {
				continue
			}
			link = true
			if t := strings.TrimSpace(lines[0]); !strings.HasPrefix(t, "<redacted") {
				if !path.IsAbs(t) {
					t = path.Join(path.Dir(p.Path), t)
				}
				target = path.Clean(t)
			}
			lines = lines[1:]
		}
		for i, l := range lines {
			s := strings.TrimSpace(l)
			if s == "" || strings.HasPrefix(s, "#") {
				continue
			}
			blob, opts := keyBlob(s)
			if server != "" && blob == server {
				continue
			}
			n := i + 1
			ev := []model.Evidence{{Path: p.Path, Line: n, After: s}}
			del := func(note string) string {
				const several = "if you remove several lines from this file, start with the highest line number"
				switch {
				case link && target == "":
					return fix([]string{p.Path}, func(q []string) string {
						return fmt.Sprintf("%s   # %s, then remove line %d from the file this link points to; %s", keep(q[0]), note, n, several)
					})
				case link:
					return fix([]string{p.Path, target}, func(q []string) string {
						return fmt.Sprintf("%s && sed -i '%dd' %s   # %s; %s", keep(q[0], q[1]), n, q[1], note, several)
					})
				}
				return fix([]string{p.Path}, func(q []string) string {
					return fmt.Sprintf("%s && sed -i '%dd' %s   # %s; %s", keep(q[0]), n, q[0], note, several)
				})
			}
			key := fmt.Sprintf(":%s:%d", p.Path, n)
			if hasCommandOption(opts) {
				out = append(out, model.Finding{
					Key: "heur.forced_command" + key, ID: idForcedCmd, Source: source, Severity: model.SevBackdoor,
					Title:    fmt.Sprintf("SSH key in %s line %d forces a command", p.Path, n),
					Why:      "A key with command= runs a fixed program when it logs in. Attackers use it to plant a hidden shell or to run code on every connection while looking like a normal key.",
					Fix:      del("first confirm the key is not yours"),
					Evidence: ev, Refs: []string{"T1098.004"},
				})
			} else if isRoot {
				// Emitted always; the judge drops these notes when a snapshot is
				// used, since new keys are then ranked from the diff.
				out = append(out, model.Finding{
					Key: "heur.root_key" + key, ID: idRootKey, Source: source, Severity: model.SevNote,
					Title:    fmt.Sprintf("Root can log in over SSH with a key in %s line %d", p.Path, n),
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
	packaged := packagedSetuid(c, owned)
	for _, f := range c.Files {
		if f.Type == "file" && f.Mode&0o6000 != 0 {
			if _, ok := owned[f.Path]; !ok {
				if orig := packaged[setuidKey(f)]; f.SHA256 != "" && f.Err == "" && orig != "" {
					out = append(out, model.Finding{
						Key: "heur.setuid_packaged_copy:" + f.Path, ID: idSetuid, Source: source, Severity: model.SevNote,
						Title: fmt.Sprintf("%s is a copy of the setuid program %s from a package", f.Path, orig),
						Why:   "The file is identical to a package's own setuid or setgid file, so it grants nothing the original does not. It may be a backup or a second install; check that you put it there.",
						Fix: fix([]string{f.Path, orig}, func(q []string) string {
							return "cmp -- " + q[0] + " " + q[1] + "   # identical means a plain copy; remove it only if you do not need it"
						}),
						Evidence: []model.Evidence{{Path: f.Path, Detail: fmt.Sprintf("mode=%o uid=%d, same content as %s", f.Mode&0o7777, f.UID, orig)}},
						Refs:     []string{"T1548.001"},
					})
				} else {
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
		}
		if f.Type == "file" && f.Caps != "" {
			if _, ok := owned[f.Path]; !ok {
				sev := model.SevBackdoor
				if strings.HasPrefix(f.Path, "/usr/local/") {
					sev = model.SevNote
				}
				out = append(out, model.Finding{
					Key: "heur.unowned_caps:" + f.Path, ID: idSetuid, Source: source, Severity: sev,
					Title: fmt.Sprintf("%s carries file capabilities but belongs to no package", f.Path),
					Why:   "A file capability gives a program some of root's powers without the setuid bit (for example raw network access or reading any file). One no package installed may be a planted way to escalate.",
					Fix: fix([]string{f.Path}, func(q []string) string {
						return keep(q[0]) + " && setcap -r " + q[0] + "   # removes the capabilities, keeps the file; delete it only after investigating"
					}),
					Evidence: []model.Evidence{{Path: f.Path, Detail: "capabilities=" + f.Caps}},
					Refs:     []string{"T1548"},
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

func crossView(c *model.Collection) []model.Finding {
	var out []model.Finding
	for _, r := range c.CrossView {
		if !r.Ran || len(r.HiddenFromTool) == 0 {
			continue
		}
		f := model.Finding{
			Key: "heur.crossview:" + r.Tool, ID: idCrossView, Source: source, Severity: model.SevTampering,
			Title: fmt.Sprintf("`%s` hides %d %s that telltale can see directly", r.Tool, len(r.HiddenFromTool), plural(len(r.HiddenFromTool), "item", "items")),
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

// setuidKey identifies a file by content, full mode and owner: a copy must be
// the same in every respect that grants rights.
func setuidKey(f model.FileEntry) string {
	return fmt.Sprintf("%s:%o:%d:%d", f.SHA256, f.Mode&0o7777, f.UID, f.GID)
}

var interpreterNames = regexp.MustCompile(`^(?:ba|z|da|k|c|tc|a|fi)?sh$|^busybox|^python[\d.]*$|^perl[\d.]*$|^ruby[\d.]*$|^php[\d.]*$|^node(?:js)?$|^lua[\d.]*$`)

// shellOrInterpreter reports a program that can run arbitrary code. Offline
// mode cannot confirm that a package ships it setuid, so no copy of it is
// excused as a packaged copy.
func shellOrInterpreter(base string) bool { return interpreterNames.MatchString(base) }

// packagedSetuid maps setuidKey to the lowest path of a
// package-owned file with that content and those bits.
func packagedSetuid(c *model.Collection, owned map[string]string) map[string]string {
	m := map[string]string{}
	for _, f := range c.Files {
		if f.Type != "file" || f.Mode&0o6000 == 0 || f.SHA256 == "" || f.Err != "" || owned[f.Path] == "" {
			continue
		}
		if shellOrInterpreter(path.Base(f.Path)) {
			continue
		}
		k := setuidKey(f)
		if old, ok := m[k]; !ok || f.Path < old {
			m[k] = f.Path
		}
	}
	return m
}

// plural is one when n is 1 and many otherwise.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
