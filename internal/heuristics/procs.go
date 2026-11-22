package heuristics

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/redact"
)

const maxEvidence = 20

// pidList renders pids for a title: "1", "1 and 2", "1, 2 and 3", and for
// more than three "1, 2 and N more".
func pidList(pids []int) string {
	s := make([]string, len(pids))
	for i, p := range pids {
		s[i] = strconv.Itoa(p)
	}
	return nameList(s)
}

func nameList(s []string) string {
	switch {
	case len(s) == 1:
		return s[0]
	case len(s) == 2:
		return s[0] + " and " + s[1]
	case len(s) == 3:
		return s[0] + ", " + s[1] + " and " + s[2]
	}
	return fmt.Sprintf("%s, %s and %d more", s[0], s[1], len(s)-2)
}

// procGroup is the processes that share a program path and a finding.
type procGroup struct {
	class  string // deleted, tmp, hidden, hidden_home or stale
	exe    string
	reason string
	sev    model.Severity
	procs  []model.Process
}

// onlyDeleted reports whether the "deleted" reason is the only one against p.
func onlyDeleted(p model.Process, homes map[int]string) bool {
	q := p
	q.ExeDeleted = false
	_, _, _, other := suspiciousExe(q, homes)
	return !other
}

// staleAfterUpgrade reports whether the program file p runs was replaced by a
// package upgrade after p started: the path now holds a regular file that a
// package owns and that changed after the process began.
func staleAfterUpgrade(p model.Process, files map[string]model.FileEntry, owned map[string]string) bool {
	if p.Started.IsZero() || owned[p.Exe] == "" {
		return false
	}
	e, ok := files[p.Exe]
	return ok && e.Type == "file" && e.Err == "" && e.CTime.After(p.Started)
}

func processes(c *model.Collection, ctx model.ScanContext, owned map[string]string) []model.Finding {
	homes := map[int]string{}
	for _, u := range c.Accounts.Users {
		if !isNIS(u.Name) {
			homes[u.UID] = u.Home
		}
	}
	files := map[string]model.FileEntry{}
	for _, f := range c.Files {
		files[f.Path] = f
	}
	type gk struct{ class, exe string }
	idx := map[gk]int{}
	var groups []*procGroup
	for _, p := range c.Runtime.Processes {
		class, reason, sev, bad := suspiciousExe(p, homes)
		if !bad {
			continue
		}
		if p.ExeDeleted && onlyDeleted(p, homes) && staleAfterUpgrade(p, files, owned) {
			class, sev = "stale", model.SevNote
		}
		k := gk{class, p.Exe}
		i, ok := idx[k]
		if !ok {
			i = len(groups)
			idx[k] = i
			groups = append(groups, &procGroup{class: class, exe: p.Exe, reason: reason, sev: sev})
		}
		groups[i].procs = append(groups[i].procs, p)
	}
	// Keys are the situation and the program path, never a pid or port: the
	// same program in another situation never shares a key.
	sort.SliceStable(groups, func(i, j int) bool { return groups[i].sev > groups[j].sev })
	var out []model.Finding
	for _, g := range groups {
		out = append(out, g.finding(ctx))
	}
	return out
}

func (g *procGroup) finding(ctx model.ScanContext) model.Finding {
	sort.SliceStable(g.procs, func(i, j int) bool { return g.procs[i].PID < g.procs[j].PID })
	pids := make([]int, len(g.procs))
	for i, p := range g.procs {
		pids[i] = p.PID
	}
	first := g.procs[0]
	many := len(pids) > 1
	who := "Process " + pidList(pids)
	if many {
		who = "Processes " + pidList(pids)
	}
	who += " (" + nameOf(first) + ")"

	key := "heur.proc_exe:" + g.class + ":" + g.exe
	if g.class == "stale" {
		key = "heur.stale_exe:" + g.exe
	}

	fp := strconv.Itoa(first.PID)
	var others string
	if many {
		others = "; the same program also runs as " + pidsCapped(pids[1:])
	}
	f := model.Finding{Key: key, Source: source, Severity: g.sev}
	if g.class == "stale" {
		f.ID = idProcExe
		verb := "still runs"
		if many {
			verb = "still run"
		}
		f.Title = fmt.Sprintf("%s %s the old %s from before it was updated", who, verb, g.exe)
		f.Why = "a package upgrade replaced the program while it was running; restart the service to run the new version"
		f.Fix = fmt.Sprintf("%s && cp /proc/%s/exe %s/%s.exe   # then restart the service or program that runs it (systemctl restart <unit>) so it runs the new version%s",
			saveEvidence, fp, evidenceDir, fp, others)
		f.Refs = []string{"T1036"}
	} else {
		verb := "looks"
		if many {
			verb = "look"
		}
		f.ID = idProcExe
		f.Title = fmt.Sprintf("%s %s hidden: %s", who, verb, g.reason)
		f.Why = "Legitimate software is installed in system directories and stays on disk. Programs run from temporary or hidden locations, or deleted while running, are typical of malware."
		f.Fix = fmt.Sprintf("%s && cp /proc/%s/exe %s/%s.exe; ls -l /proc/%s/cwd /proc/%s/fd; kill -STOP %s   # suspends, does not kill: investigate before killing%s",
			saveEvidence, fp, evidenceDir, fp, fp, fp, fp, others)
		f.Refs = []string{"T1036"}
	}
	for i, p := range g.procs {
		if i == maxEvidence {
			f.Evidence = append(f.Evidence, model.Evidence{Path: g.exe, Detail: fmt.Sprintf("and %d more processes", len(g.procs)-i)})
			break
		}
		cmdline, _ := redact.Line(ctx.DigestKey, p.Cmdline)
		f.Evidence = append(f.Evidence, model.Evidence{Path: p.Exe, Detail: fmt.Sprintf("pid=%d exe=%s cmdline=%s uid=%d deleted=%t", p.PID, p.Exe, cmdline, p.UID, p.ExeDeleted)})
	}
	if len(f.Evidence) > 0 {
		// What accept records: the situation and the program, never a pid.
		f.Evidence[0].After = g.class + " " + g.exe
	}
	return f
}

type listenGroup struct {
	exe   string
	ports []string
	pids  []int
	cmds  []string
	first model.Process
}

func listeners(c *model.Collection, ctx model.ScanContext, owned map[string]string) []model.Finding {
	procs := map[int]model.Process{}
	for _, p := range c.Runtime.Processes {
		procs[p.PID] = p
	}
	seen := map[string]bool{} // exe + port
	idx := map[string]*listenGroup{}
	var order []*listenGroup
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
		if seen[p.Exe+"\x00"+port] {
			continue
		}
		seen[p.Exe+"\x00"+port] = true
		g := idx[p.Exe]
		if g == nil {
			g = &listenGroup{exe: p.Exe, first: p}
			idx[p.Exe] = g
			order = append(order, g)
		}
		cmdline, _ := redact.Line(ctx.DigestKey, p.Cmdline)
		g.ports = append(g.ports, port)
		g.pids = append(g.pids, p.PID)
		g.cmds = append(g.cmds, fmt.Sprintf("%s %s pid=%d cmdline=%s", s.Proto, s.Local, p.PID, cmdline))
	}
	var out []model.Finding
	for _, g := range order {
		fp := strconv.Itoa(g.first.PID)
		title := fmt.Sprintf("Port %s is open, served by %s which belongs to no package", g.ports[0], g.exe)
		if len(g.ports) > 1 {
			title = fmt.Sprintf("Ports %s are open, served by %s which belongs to no package", nameList(g.ports), g.exe)
		}
		f := model.Finding{
			Key: "heur.unowned_listener:" + g.exe, ID: idListener, Source: source, Severity: model.SevNote,
			Title: title,
			Why:   "A service you did not install from your distribution may be fine (your own software) or a backdoor listening for connections.",
			Fix: fmt.Sprintf("%s && cp /proc/%s/exe %s/%s.exe; ls -l /proc/%s/cwd /proc/%s/fd   # investigate; stop with 'kill -STOP %s' if unrecognised%s",
				saveEvidence, fp, evidenceDir, fp, fp, fp, fp, g.otherPIDs()),
			Refs: []string{"T1571"},
		}
		for i, d := range g.cmds {
			if i == maxEvidence {
				f.Evidence = append(f.Evidence, model.Evidence{Path: g.exe, Detail: fmt.Sprintf("and %d more ports", len(g.cmds)-i)})
				break
			}
			f.Evidence = append(f.Evidence, model.Evidence{Path: g.exe, Detail: d})
		}
		if len(f.Evidence) > 0 {
			f.Evidence[0].After = "listener " + g.exe
		}
		out = append(out, f)
	}
	return out
}

// otherPIDs names the further processes of the program, for a fix comment.
func (g *listenGroup) otherPIDs() string {
	var rest []int
	seen := map[int]bool{g.first.PID: true}
	for _, p := range g.pids {
		if !seen[p] {
			seen[p] = true
			rest = append(rest, p)
		}
	}
	if len(rest) == 0 {
		return ""
	}
	return "; the same program also runs as " + pidsCapped(rest)
}

// pidsCapped joins pids, at most maxEvidence of them, then "and N more".
func pidsCapped(pids []int) string {
	var s []string
	for i, p := range pids {
		if i == maxEvidence {
			s = append(s, fmt.Sprintf("and %d more", len(pids)-i))
			break
		}
		s = append(s, strconv.Itoa(p))
	}
	return strings.Join(s, ", ")
}
