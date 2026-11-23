package heuristics

import (
	"strings"
	"testing"

	"github.com/donaldsteele/telltale/internal/model"
)

// A user unit directory the collector stopped reading at its budget is said
// in the report, not only among the skipped checks.
func TestPersistFloodedIsNoted(t *testing.T) {
	c := cleanCollection()
	if fs := runOwned(c, cleanOwned()); find(fs, "heur.persist_flooded:/home/mallory/.config/systemd/user") != nil {
		t.Fatal("flood note on a clean machine")
	}
	const dir = "/home/mallory/.config/systemd/user"
	c.PersistFlooded = []string{dir, "/home/it's/.config/systemd/user"}
	fs := runOwned(c, cleanOwned())
	f := find(fs, "heur.persist_flooded:"+dir)
	if f == nil || f.Severity != model.SevNote || f.ID != "TT-HEUR-017" || len(f.Evidence) != 1 || f.Evidence[0].Path != dir {
		t.Fatalf("flood note = %+v", f)
	}
	if !strings.Contains(f.Fix, "'"+dir+"'") {
		t.Errorf("fix does not quote the directory: %q", f.Fix)
	}
	q := find(fs, "heur.persist_flooded:/home/it's/.config/systemd/user")
	if q == nil || !strings.Contains(q.Fix, `'/home/it'\''s/.config/systemd/user'`) {
		t.Errorf("a quote in the path is not escaped: %+v", q)
	}
}
