package heuristics

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/donaldsteele/telltale/internal/model"
)

// ruleFor returns the rule whose key starts the finding's key, the longest
// one when several do (heur.persist_link_pkg: before heur.persist_link).
func ruleFor(key string) (Rule, bool) {
	var best Rule
	found := false
	for _, r := range Rules() {
		if strings.HasPrefix(key, r.Key) && len(r.Key) > len(best.Key) {
			best, found = r, true
		}
	}
	return best, found
}

// checkRule fails the test when a finding does not match its rule: every
// finding the tests see is held to the documented list.
func checkRule(t *testing.T, f model.Finding) {
	t.Helper()
	r, ok := ruleFor(f.Key)
	if !ok {
		t.Errorf("%s: no rule in Rules() for this key", f.Key)
		return
	}
	if f.ID != r.ID || (f.Severity != r.Severity && !slices.Contains(r.Other, f.Severity)) {
		t.Errorf("%s: ID %s severity %v, but its rule says %s %v (or %v)", f.Key, f.ID, f.Severity, r.ID, r.Severity, r.Other)
	}
}

var idRE = regexp.MustCompile(`^TT-HEUR-[0-9]{3}$`)

// The list matches the code: the finding keys and rule IDs written in the
// package's source are exactly those in Rules().
func TestRulesMatchTheCode(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	keys, ids := map[string]bool{}, map[string]bool{}
	fset := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") || name == "rules.go" {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			switch {
			case strings.HasPrefix(s, "heur."):
				keys[strings.TrimSuffix(s, ":")] = true
			case idRE.MatchString(s):
				ids[s] = true
			}
			return true
		})
	}
	ruleKeys, ruleIDs := map[string]bool{}, map[string]bool{}
	last := ""
	for _, r := range Rules() {
		k := strings.TrimSuffix(r.Key, ":")
		if ruleKeys[k] {
			t.Errorf("two rules for %s", r.Key)
		}
		ruleKeys[k], ruleIDs[r.ID] = true, true
		if r.ID < last {
			t.Errorf("%s comes after %s: Rules() must be in ID order", r.ID, last)
		}
		last = r.ID
		if r.Title == "" || r.Why == "" || (len(r.Other) > 0) != (r.When != "") {
			t.Errorf("%s: incomplete rule %+v", r.Key, r)
		}
	}
	for k := range keys {
		if !ruleKeys[k] {
			t.Errorf("the code makes %s, which Rules() does not list", k)
		}
	}
	for k := range ruleKeys {
		if !keys[k] {
			t.Errorf("Rules() lists %s, which the code never makes", k)
		}
	}
	for id := range ids {
		if !ruleIDs[id] {
			t.Errorf("the code uses %s, which Rules() does not list", id)
		}
	}
	for id := range ruleIDs {
		if !ids[id] {
			t.Errorf("Rules() lists %s, which the code never uses", id)
		}
	}
}
