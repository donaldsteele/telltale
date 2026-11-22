package heuristics

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/persistsig"
)

// pamDirs are the fixed directories PAM loads bare module names from. The
// per-architecture ones (/lib/<multiarch>/security) are found in the file
// inventory.
var pamDirs = []string{"/lib/security", "/lib64/security", "/usr/lib/security", "/usr/lib64/security"}

// pamLine is one module reference in a PAM configuration file.
type pamLine struct {
	file   string
	line   int
	text   string
	module string
	quiet  bool // a leading "-" on the type: a missing module is not logged
}

// parsePAMLine returns the module a PAM configuration line names. Lines
// are "type control module [args]", the control possibly "[a=b c=d]".
func parsePAMLine(text string) (module string, quiet, ok bool) {
	f := strings.Fields(text)
	if len(f) < 3 || strings.HasPrefix(f[0], "@") {
		return "", false, false
	}
	typ := f[0]
	if strings.HasPrefix(typ, "-") {
		quiet = true
		typ = typ[1:]
	}
	switch strings.ToLower(typ) {
	case "auth", "account", "password", "session":
	default:
		return "", false, false
	}
	i := 1
	if strings.HasPrefix(f[i], "[") {
		for i < len(f) && !strings.HasSuffix(f[i], "]") {
			i++
		}
	}
	if c := strings.ToLower(f[1]); c == "include" || c == "substack" {
		return "", false, false // names another configuration file, not a module
	}
	i++ // past the control, to the module
	if i >= len(f) {
		return "", false, false
	}
	return f[i], quiet, true
}

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
func resolvePAMModule(name string, have map[string]bool, multiarch []string) (string, bool) {
	var cands []string
	if strings.HasPrefix(name, "/") {
		cands = []string{path.Clean(name)}
	} else {
		for _, d := range pamDirs {
			cands = append(cands, d+"/"+name)
		}
		for _, d := range multiarch {
			cands = append(cands, d+"/"+name)
		}
	}
	for _, cand := range cands {
		for _, s := range usrSpellings(cand) {
			if have[s] {
				return s, true
			}
		}
	}
	return "", false
}

// multiarchPAMDirs lists /lib/<x>/security and /usr/lib/<x>/security
// directories that hold files in the inventory, sorted.
func multiarchPAMDirs(c *model.Collection) []string {
	seen := map[string]bool{}
	for _, f := range c.Files {
		d := path.Dir(f.Path)
		if path.Base(d) != "security" {
			continue
		}
		g := path.Dir(d)
		if p := path.Dir(g); p == "/lib" || p == "/usr/lib" {
			seen[d] = true
		}
	}
	var out []string
	for d := range seen {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

func pamModules(c *model.Collection, owned map[string]string) []model.Finding {
	var refs []pamLine
	for _, p := range c.Persist {
		if p.Kind != model.PersistKindPAM || p.Mode&0o170000 == 0o120000 {
			continue
		}
		for _, l := range persistsig.Join(p.Lines) {
			if l.Text == "" || isComment(l.Text) {
				continue
			}
			if m, quiet, ok := parsePAMLine(l.Text); ok {
				refs = append(refs, pamLine{file: p.Path, line: l.First, text: l.Text, module: m, quiet: quiet})
			}
		}
	}
	if len(refs) == 0 {
		return nil
	}
	have := make(map[string]bool, len(c.Files))
	for _, f := range c.Files {
		have[f.Path] = true
	}
	multi := multiarchPAMDirs(c)

	type group struct {
		key  string
		refs []pamLine
	}
	byKey := map[string]*group{}
	var order []string
	add := func(key string, r pamLine) {
		g := byKey[key]
		if g == nil {
			g = &group{key: key}
			byKey[key] = g
			order = append(order, key)
		}
		g.refs = append(g.refs, r)
	}
	for _, r := range refs {
		mod, found := resolvePAMModule(r.module, have, multi)
		if !found {
			if !r.quiet {
				add("m:"+r.module, r)
			}
			continue
		}
		if owned[mod] != "" || owned[path.Clean(r.module)] != "" && strings.HasPrefix(r.module, "/") {
			continue
		}
		add("u:"+mod, r)
	}

	var out []model.Finding
	for _, k := range order {
		g := byKey[k]
		first := g.refs[0]
		ev := make([]model.Evidence, 0, len(g.refs))
		for _, r := range g.refs {
			ev = append(ev, model.Evidence{Path: r.file, Line: r.line, After: r.text})
		}
		name := k[2:]
		if k[0] == 'm' {
			out = append(out, model.Finding{
				Key: "heur.pam_missing:" + name, ID: idPAM, Source: source, Severity: model.SevNote,
				Title: fmt.Sprintf("%s line %d names the PAM module %q, which is not on the machine", first.file, first.line, name),
				Why:   "PAM skips a missing module, or refuses the login when the line says required. A stale line is usually harmless; a module that was removed after use can also mean someone cleaned up.",
				Fix: fix([]string{first.file}, func(q []string) string {
					return keep(q[0]) + " && grep -n -- " + sq(name) + " " + q[0] + "   # see which lines use it; remove them only if the module is not coming back"
				}),
				Evidence: ev, Refs: []string{"T1556.003"},
			})
			continue
		}
		out = append(out, model.Finding{
			Key: "heur.pam_unowned:" + name, ID: idPAM, Source: source, Severity: model.SevBackdoor,
			Title: fmt.Sprintf("PAM module %s is used at login but belongs to no package", name),
			Why:   "PAM modules run inside every login and password check, and can accept a secret password or record the real ones. One that no package installed may be planted.",
			Fix: fix([]string{name, first.file}, func(q []string) string {
				return fmt.Sprintf("%s && sed -i '%ds/^/#/' %s   # comments the line out, keeps the module; only if you did not install this module yourself", keep(q[0], q[1]), first.line, q[1])
			}),
			Evidence: ev, Refs: []string{"T1556.003"},
		})
	}
	return out
}
