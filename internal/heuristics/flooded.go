package heuristics

import (
	"github.com/donaldsteele/telltale/internal/model"
)

// flooded notes each directory the collector stopped reading at a budget,
// so that it shows in the report and not only among the skipped checks.
func flooded(c *model.Collection) []model.Finding {
	var out []model.Finding
	seen := map[string]bool{}
	for _, dir := range c.PersistFlooded {
		if seen[dir] {
			continue
		}
		seen[dir] = true
		out = append(out, model.Finding{
			Key: "heur.persist_flooded:" + dir, ID: idFlooded, Source: source, Severity: model.SevNote,
			Title: dir + " holds more than telltale reads from one user's unit directory",
			Why:   "Anyone can fill their own systemd unit directory. telltale stops at a fixed number of entries and amount of text there, so that no user can make a scan run out of memory or time. What lies past that was not read, and a unit hidden among the rest was not seen. Look at what fills the directory.",
			Fix: fix([]string{dir}, func(q []string) string {
				return "ls -la " + q[0] + " | head -50   # see what fills it; remove what does not belong, then scan again"
			}),
			Evidence: []model.Evidence{{Path: dir, Detail: "reading stopped at the budget for a user's unit directory"}},
		})
	}
	return out
}
