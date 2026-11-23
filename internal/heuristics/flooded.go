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
	// Links at a user's startup paths that were not followed.
	for _, link := range c.PersistRefused {
		if seen["link\x00"+link] {
			continue
		}
		seen["link\x00"+link] = true
		out = append(out, model.Finding{
			Key: "heur.persist_link_refused:" + link, ID: idRefusedLink, Source: source, Severity: model.SevNote,
			Title: link + " is a link telltale did not follow, so what is behind it was not read",
			Why:   "This symbolic link is at, or on the way to, a user's startup files (shell start-up files, SSH keys, systemd user units). It belongs to another account than the one whose files those are, or it leads somewhere that user could not read, so a scan running as root does not read through it: doing so would let a user aim the scan at files that are not theirs. Units, keys or start-up lines behind it were not seen. The link itself is listed among the startup entries and compared with the snapshot.",
			Fix: fix([]string{link}, func(q []string) string {
				return "ls -ld " + q[0] + "; ls -la " + q[0] + "/ 2>/dev/null | head -50   # see where it leads and what is there; replace the link with a real directory if you want its contents checked"
			}),
			Evidence: []model.Evidence{{Path: link, Detail: "a symbolic link the scan did not follow"}},
		})
	}
	// The world-writable temporary directories: anyone can fill those, and
	// a setuid file planted behind the flood was not looked at.
	for _, dir := range c.SweepFlooded {
		if (dir != "/tmp" && dir != "/var/tmp" && dir != "/dev/shm") || seen["sweep\x00"+dir] {
			continue
		}
		seen["sweep\x00"+dir] = true
		out = append(out, model.Finding{
			Key: "heur.sweep_flooded:" + dir, ID: idFlooded, Source: source, Severity: model.SevNote,
			Title: dir + " holds more files than telltale looks through for setuid programs",
			Why:   "telltale looks through every local filesystem for setuid, setgid and capability files, and stops at a fixed number of entries in each world-writable temporary directory so that nobody can make a scan run for ever by filling one. It stopped in this one: a setuid file among the rest was not seen. That many files in a temporary directory are themselves unusual.",
			Fix: fix([]string{dir}, func(q []string) string {
				return "find " + q[0] + " -xdev -maxdepth 2 | head -50; find " + q[0] + " -xdev -perm /6000 -ls   # see what fills it, and look for setuid files there yourself"
			}),
			Evidence: []model.Evidence{{Path: dir, Detail: "the search for setuid files stopped at this directory's budget"}},
		})
	}
	return out
}
