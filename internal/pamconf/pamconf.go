// Package pamconf reads the module references in PAM configuration files.
// The collector and the heuristics share it, so that both agree on which
// files a configuration can load.
package pamconf

import (
	"path"
	"sort"
	"strings"

	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/persistsig"
)

// Dirs are the fixed directories PAM loads bare module names from. The
// per-architecture ones (/lib/<multiarch>/security) are found in the file
// inventory.
var Dirs = []string{"/lib/security", "/lib64/security", "/usr/lib/security", "/usr/lib64/security"}

// Ref is one module reference in a PAM configuration file.
type Ref struct {
	File   string
	Line   int // first physical line
	Text   string
	Module string
	Quiet  bool // a leading "-" on the type: a missing module is not logged
}

// ParseLine returns the module a PAM configuration line names. Lines are
// "type control module [args]", the control possibly "[a=b c=d]". Lines that
// name another configuration (include, substack, @include) name no module.
func ParseLine(text string) (module string, quiet, ok bool) {
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
		return "", false, false
	}
	i++ // past the control, to the module
	if i >= len(f) {
		return "", false, false
	}
	return f[i], quiet, true
}

// Refs lists the module references in the collected PAM files.
func Refs(persist []model.PersistFile) []Ref {
	var out []Ref
	for _, p := range persist {
		if p.Kind != model.PersistKindPAM || p.Mode&0o170000 == 0o120000 {
			continue
		}
		for _, l := range persistsig.Join(p.Lines) {
			if l.Text == "" || strings.HasPrefix(l.Text, "#") {
				continue
			}
			if m, quiet, ok := ParseLine(l.Text); ok {
				out = append(out, Ref{File: p.Path, Line: l.First, Text: l.Text, Module: m, Quiet: quiet})
			}
		}
	}
	return out
}

// Candidates returns the cleaned paths PAM may load a module from, in
// order: an absolute name as it is, anything else under each directory in
// Dirs and then under extra. Cleaning matters: "../../tmp/x.so" under
// /lib/security is /tmp/x.so.
func Candidates(module string, extra []string) []string {
	if strings.HasPrefix(module, "/") {
		return []string{path.Clean(module)}
	}
	var out []string
	for _, d := range append(append([]string{}, extra...), Dirs...) {
		out = append(out, path.Clean(d+"/"+module))
	}
	return out
}

// MultiarchDirs lists the /lib/<x>/security and /usr/lib/<x>/security
// directories that hold files in the inventory, sorted.
func MultiarchDirs(files []model.FileEntry) []string {
	seen := map[string]bool{}
	for _, f := range files {
		d := path.Dir(f.Path)
		if path.Base(d) != "security" {
			continue
		}
		if p := path.Dir(path.Dir(d)); p == "/lib" || p == "/usr/lib" {
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
