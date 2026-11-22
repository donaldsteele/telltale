package heuristics

import (
	"fmt"
	"strings"

	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/pamconf"
)

// usrSpellings returns p and its merged-/usr alternate spelling.
func usrSpellings(p string) []string {
	out := []string{p}
	for _, d := range []string{"bin", "sbin", "lib", "lib32", "lib64", "libx32"} {
		if strings.HasPrefix(p, "/"+d+"/") {
			return append(out, "/usr"+p)
		}
		if strings.HasPrefix(p, "/usr/"+d+"/") {
			return append(out, strings.TrimPrefix(p, "/usr"))
		}
	}
	return out
}

// resolvePAMModule returns the path of a module, preferring the spelling that
// is present in the file inventory. ok is false when no file is found.
// existingPAMModules returns the inventory spelling of every file the name can
// resolve to. A bare name stops at the first directory that has it (the one
// the loader reaches); a name with a slash lists them all, since the path
// that really loads depends on which directory libpam prepends.
func existingPAMModules(name string, have map[string]bool, multiarch []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, cand := range pamconf.Candidates(name, multiarch) {
		for _, s := range usrSpellings(cand) {
			if have[s] {
				if !seen[s] {
					seen[s] = true
					out = append(out, s)
				}
				break
			}
		}
		if len(out) > 0 && !strings.Contains(name, "/") {
			break
		}
	}
	return out
}

func pamModules(c *model.Collection, owned map[string]string) []model.Finding {
	refs := pamconf.Refs(c.Persist)
	if len(refs) == 0 {
		return nil
	}
	have := make(map[string]bool, len(c.Files))
	for _, f := range c.Files {
		have[f.Path] = true
	}
	multi := pamconf.MultiarchDirs(c.Files)

	type group struct {
		key  string
		refs []pamconf.Ref
	}
	byKey := map[string]*group{}
	var order []string
	add := func(key string, r pamconf.Ref) {
		g := byKey[key]
		if g == nil {
			g = &group{key: key}
			byKey[key] = g
			order = append(order, key)
		}
		g.refs = append(g.refs, r)
	}
	for _, r := range refs {
		if strings.Contains(r.Module, "..") {
			add("e:"+r.Module, r)
		}
		found := false
		for _, mod := range existingPAMModules(r.Module, have, multi) {
			found = true
			if owned[mod] == "" {
				add("u:"+mod, r)
			}
		}
		if !found && !r.Quiet {
			add("m:"+r.Module, r)
		}
	}

	var out []model.Finding
	for _, k := range order {
		g := byKey[k]
		first := g.refs[0]
		ev := make([]model.Evidence, 0, len(g.refs))
		for _, r := range g.refs {
			ev = append(ev, model.Evidence{Path: r.File, Line: r.Line, After: r.Text})
		}
		name := k[2:]
		if k[0] == 'm' {
			out = append(out, model.Finding{
				Key: "heur.pam_missing:" + name, ID: idPAM, Source: source, Severity: model.SevNote,
				Title: fmt.Sprintf("%s line %d names the PAM module %q, which is not on the machine", first.File, first.Line, name),
				Why:   "PAM skips a missing module, or refuses the login when the line says required. A stale line is usually harmless; a module that was removed after use can also mean someone cleaned up.",
				Fix: fix([]string{first.File, name}, func(q []string) string {
					return keep(q[0]) + " && grep -n -- " + q[1] + " " + q[0] + "   # see which lines use it; remove them only if the module is not coming back"
				}),
				Evidence: ev, Refs: []string{"T1556.003"},
			})
			continue
		}
		if k[0] == 'e' {
			out = append(out, model.Finding{
				Key: "heur.pam_path_escape:" + name, ID: idPAM, Source: source, Severity: model.SevBackdoor,
				Title: fmt.Sprintf("%s line %d names the PAM module %q, a path that climbs out of the module directory", first.File, first.Line, name),
				Why:   "A module name containing .. reaches files outside the module directories, and which file loads depends on the directory PAM prepends, so a check against one spelling can be fooled. No stock configuration names a module this way.",
				Fix: fix([]string{first.File}, func(q []string) string {
					return fmt.Sprintf("%s && sed -i '%ds/^/#/' %s   # comments the line out, keeps the file; only if you did not write this line yourself", keep(q[0]), first.Line, q[0])
				}),
				Evidence: ev, Refs: []string{"T1556.003"},
			})
			continue
		}
		out = append(out, model.Finding{
			Key: "heur.pam_unowned:" + name, ID: idPAM, Source: source, Severity: model.SevBackdoor,
			Title: fmt.Sprintf("PAM module %s is used at login but belongs to no package", name),
			Why:   "PAM modules run inside every login and password check, and can accept a secret password or record the real ones. One that no package installed may be planted.",
			Fix: fix([]string{name, first.File}, func(q []string) string {
				return fmt.Sprintf("%s && sed -i '%ds/^/#/' %s   # comments the line out, keeps the module; only if you did not install this module yourself", keep(q[0], q[1]), first.Line, q[1])
			}),
			Evidence: ev, Refs: []string{"T1556.003"},
		})
	}
	return out
}
