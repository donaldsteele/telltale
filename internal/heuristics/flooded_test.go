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

// The same for /tmp, /var/tmp and /dev/shm when the setuid sweep ran out of
// its budget there: whoever filled it may be hiding a setuid file behind
// the flood.
func TestSweepFloodedIsNoted(t *testing.T) {
	c := cleanCollection()
	c.SweepFlooded = []string{"/tmp", "/dev/shm", "/srv"}
	fs := runOwned(c, cleanOwned())
	for _, dir := range []string{"/tmp", "/dev/shm"} {
		f := find(fs, "heur.sweep_flooded:"+dir)
		if f == nil || f.Severity != model.SevNote || f.ID != "TT-HEUR-017" || len(f.Evidence) != 1 || f.Evidence[0].Path != dir || !strings.Contains(f.Fix, "'"+dir+"'") {
			t.Errorf("%s: %+v", dir, f)
		}
	}
	// A data directory that is simply large is not this.
	if find(fs, "heur.sweep_flooded:/srv") != nil {
		t.Error("/srv reported as flooded")
	}
}

// A link at a user's startup path that the collector did not follow is said
// in the report: what is behind it was not read.
func TestRefusedPersistLinkIsNoted(t *testing.T) {
	c := cleanCollection()
	const link = "/home/mallory/.config/systemd/user"
	c.PersistRefused = []string{link}
	f := find(runOwned(c, cleanOwned()), "heur.persist_link_refused:"+link)
	if f == nil || f.Severity != model.SevNote || f.ID != "TT-HEUR-018" || len(f.Evidence) != 1 || f.Evidence[0].Path != link || !strings.Contains(f.Fix, "'"+link+"'") {
		t.Fatalf("note = %+v", f)
	}
	if find(runOwned(cleanCollection(), cleanOwned()), "heur.persist_link_refused:"+link) != nil {
		t.Error("note on a clean machine")
	}
}
