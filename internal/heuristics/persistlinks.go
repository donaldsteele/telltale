package heuristics

import (
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/donaldsteele/telltale/internal/model"
)

var maskedWeak = []string{"auditd", "apparmor", "ufw", "nftables", "fail2ban"}

// systemLinkPrefixes are where a startup link may point without a finding.
var systemLinkPrefixes = []string{"/usr/", "/lib/", "/etc/", "/run/systemd/"}

func inSystemDir(target string) bool {
	for _, pre := range systemLinkPrefixes {
		if strings.HasPrefix(target, pre) {
			return true
		}
	}
	return false
}

// linkDest says where a startup link leads, resolved the way the kernel
// resolves it (model.ResolveInInventory), never from the link's text alone:
// "dir/../file" through a planted directory link reads as one file and opens
// another.
type linkDest struct {
	// shown is the target for titles and evidence: file when known, else
	// the text of the link made absolute.
	shown string
	// file is the path of what the link opens; "" when the inventory
	// cannot tell (the target does not exist or lies where the scan does
	// not look, the text was redacted, or too many links are involved).
	file string
	// dangling is where the target would be when everything on the way
	// to it resolved and only the file itself is missing; else "".
	dangling string
	// null: the link is a plain link to /dev/null (a systemd mask).
	null bool
}

// cut says the collector did not follow this link to the end (see
// Collection.LinkRefused): it is then not walked here either, and stays
// unresolved.
func resolveLink(inv map[string]*model.FileEntry, p model.PersistFile, cut bool) (linkDest, bool) {
	lexical, ok := p.LinkTarget()
	if !ok {
		return linkDest{}, false
	}
	d := linkDest{shown: lexical}
	if p.TargetRedacted() { // the target text is not what the link holds
		return d, true
	}
	if p.Lines[0] == "/dev/null" {
		d.null = true
		return d, true
	}
	if cut {
		return d, true
	}
	// Walk from the link's directory through the target as written (not
	// cleaned), so that the directory the link is really in and every link
	// inside the target are followed.
	reached, rest, end := model.WalkInventory(inv, model.LinkWalk(p.Path, p.Lines[0]), model.LinkHops)
	switch {
	case end == model.WalkDone:
		d.file, d.shown = reached, reached
	case end == model.WalkMissing && len(rest) == 1 && rest[0] != "..":
		// Everything on the way resolved; only the last name is not there.
		d.dangling = path.Join(reached, rest[0])
		d.shown = d.dangling
	}
	return d, true
}

// PackageLinkTargets returns the targets of startup links that lie outside
// the system directories and are owned by an installed package. The scan has
// them verified against the package. owned is c.Packages.Owners(); a target
// is a package's also when it is where one of those paths really is.
func PackageLinkTargets(c *model.Collection, owned map[string]string) []string {
	var out []string
	seen := map[string]bool{}
	inv := model.Inventory(c.Files)
	owned, _ = model.PhysicalOwnersOf(owned, inv)
	cut := cutLinks(c)
	for _, p := range c.Persist {
		d, ok := resolveLink(inv, p, cut[p.Path])
		if !ok || d.file == "" || inSystemDir(d.file) || owned[d.file] == "" || seen[d.file] {
			continue
		}
		seen[d.file] = true
		out = append(out, d.file)
	}
	return out
}

// LinkFile is the file a startup link opens, resolved as the heuristics here
// resolve it; ok is false when the inventory cannot tell.
func LinkFile(inv map[string]*model.FileEntry, p model.PersistFile) (string, bool) {
	d, ok := resolveLink(inv, p, false)
	return d.file, ok && d.file != ""
}

// userUnitOwner returns the owner of the user unit that the link enables, when
// the link has the layout `systemctl --user enable` creates: a link inside
// <home>/.config/systemd/user/<x>.wants (or .requires) whose target is a unit
// in the same home's user unit directories or in the system-wide user unit
// directories. target is the file the link really opens, so the unit
// directories are compared where they really are: a home whose
// ~/.config/systemd is a link into a dotfiles directory of the same home
// still counts, one that leads out of the home does not.
func userUnitOwner(c *model.Collection, inv map[string]*model.FileEntry, link, target string) (string, bool) {
	dir := path.Dir(link)
	if b := path.Base(dir); !strings.HasSuffix(b, ".wants") && !strings.HasSuffix(b, ".requires") {
		return "", false
	}
	unitDir := path.Dir(dir)
	under := func(dir string) bool { return dir != "" && strings.HasPrefix(target, dir+"/") }
	physical := func(dir string) string {
		real, _ := model.ResolveInInventory(inv, dir, model.LinkHops)
		return real
	}
	for _, u := range c.Accounts.Users {
		h := path.Clean(u.Home)
		if isNIS(u.Name) || u.Home == "" || h == "/" || tempDir(h) || unitDir != h+"/.config/systemd/user" {
			continue
		}
		home := physical(h)
		if home == "" || home == "/" || tempDir(home) {
			continue
		}
		for _, d := range []string{h + "/.config/systemd/user", h + "/.local/share/systemd/user"} {
			// The user's own unit directory, wherever in the home it is.
			if real := physical(d); under(real) && strings.HasPrefix(real, home+"/") {
				return u.Name, true
			}
		}
		for _, d := range []string{"/etc/systemd/user", "/usr/lib/systemd/user"} {
			if under(physical(d)) {
				return u.Name, true
			}
		}
	}
	return "", false
}

// execStarts returns the ExecStart lines of the collected unit file at p.
func execStarts(c *model.Collection, inv map[string]*model.FileEntry, p string) []string {
	var out []string
	for _, f := range c.Persist {
		if f.Mode&0o170000 == 0o120000 || !samePlace(inv, f.Path, p) {
			continue
		}
		for _, l := range f.Lines {
			if s := strings.TrimSpace(l); strings.HasPrefix(s, "ExecStart") {
				out = append(out, s)
			}
		}
	}
	return out
}

func persistLinks(c *model.Collection, owned map[string]string) []model.Finding {
	var out []model.Finding
	inv := model.Inventory(c.Files)
	// Whose file a link leads to is asked of the place the file really is.
	owned, _ = model.PhysicalOwnersOf(owned, inv)
	cut := cutLinks(c)
	for _, p := range c.Persist {
		d, ok := resolveLink(inv, p, cut[p.Path])
		if !ok {
			continue
		}
		// target is what the link opens when that is known. The quiet
		// outcomes below all need it (or, for the location check, the path
		// as far as it can be followed); a link that cannot be resolved
		// falls through to the finding at the end.
		target := d.shown
		ev := []model.Evidence{{Path: p.Path, Line: 1, After: p.Lines[0], Detail: "symlink to " + target}}
		key := "heur.persist_link:" + p.Path
		resolved := d.file != ""
		if d.null {
			base := path.Base(p.Path)
			for _, w := range maskedWeak {
				if strings.HasPrefix(base, w) {
					out = append(out, model.Finding{
						Key: key, ID: idPersistLink, Source: source, Severity: model.SevWeak,
						Title: fmt.Sprintf("Security service %s is masked", base),
						Why:   "A link to /dev/null stops this service from ever starting. Attackers mask logging and protection services; you may also have done it on purpose.",
						Fix: fix([]string{base}, func(q []string) string {
							return "systemctl unmask " + q[0] + "   # only if you did not mask it deliberately"
						}),
						Evidence: ev, Refs: []string{"T1543.002"},
					})
					break
				}
			}
			continue
		}
		if owner, ok := userUnitOwner(c, inv, p.Path, target); ok && resolved && collectedUnit(c, inv, target) {
			unit := path.Base(p.Path)
			for _, l := range execStarts(c, inv, target) {
				ev = append(ev, model.Evidence{Path: target, Detail: l})
			}
			out = append(out, model.Finding{
				Key: "heur.user_unit:" + p.Path, ID: idPersistLink, Source: source, Severity: model.SevNote,
				Title: fmt.Sprintf("User %s starts %s at login", owner, unit),
				Why:   "A unit enabled with `systemctl --user enable` runs for this user at every login, with no root needed. That is how users start their own services, and also how a foothold in one account survives a reboot. The unit's contents are judged separately.",
				Fix: fix([]string{owner + "@", unit, target}, func(q []string) string {
					return keep(q[2]) + " && systemctl --user -M " + q[0] + " disable " + q[1] + "   # only if " + "this user did not enable it themselves"
				}),
				Evidence: ev, Refs: []string{"T1543.002"},
			})
			continue
		}
		// A system directory counts only for a target that is really
		// there (this is also what makes /run/systemd acceptable: the chain
		// through it was followed to an existing file).
		if resolved && inSystemDir(target) {
			continue
		}
		// Everything on the way resolved inside a system directory and only
		// the file is gone: the enable link of a unit that was removed.
		// Nothing runs from it. A missing file on a mount the scan stays
		// out of is not known to be missing, and is not this case.
		if d.dangling != "" && inSystemDir(d.dangling) && !notLookedAt(c, d.dangling) {
			out = append(out, model.Finding{
				Key: "heur.persist_link_dangling:" + p.Path, ID: idPersistLink, Source: source, Severity: model.SevNote,
				Title: fmt.Sprintf("%s is a link to %s, which does not exist", p.Path, target),
				Why:   "The link is left over from something that was removed (a unit of an uninstalled package, usually). Nothing runs from it now, but whatever is put at that path later would.",
				Fix: fix([]string{p.Path}, func(q []string) string {
					return "rm " + q[0] + "   # if nothing you use needs it"
				}),
				Evidence: ev, Refs: []string{"T1543.002"},
			})
			continue
		}
		if pkg := owned[target]; pkg != "" && resolved && !tempDir(target) && regularFile(c, target) {
			out = append(out, model.Finding{
				Key: "heur.persist_link_pkg:" + p.Path, ID: idPersistLink, Source: source, Severity: model.SevNote,
				Title: fmt.Sprintf("%s runs %s from package %s, outside the system directories", p.Path, target, pkg),
				Why:   "The package placed this file outside the usual locations. Its contents are checked against the package where a trusted source exists.",
				Fix: fix([]string{pkg}, func(q []string) string {
					return "dpkg --verify " + q[0] + "   # compares with the machine's own checksums, which root can edit; a clean result is weak evidence"
				}),
				Evidence: ev, Refs: []string{"T1543.002", "T1053.003"},
			})
			continue
		}
		out = append(out, model.Finding{
			Key: key, ID: idPersistLink, Source: source, Severity: model.SevBackdoor,
			Title: fmt.Sprintf("%s is a link to %s, outside the system directories", p.Path, target),
			Why:   "Startup entries that point at files in temporary or user-writable places (as `systemctl link` can create) run whatever sits there, and the real code is not in the usual locations.",
			Fix: fix([]string{p.Path, target}, func(q []string) string {
				return keep(q[0]) + " && { cp -a --parents " + q[1] + " " + evidenceDir + "/ 2>/dev/null || echo 'link target not saved (missing or unreadable)'; } && rm " + q[0] + "   # inspect the saved copies first; rm only runs once the link itself is saved"
			}),
			Evidence: ev, Refs: []string{"T1543.002", "T1053.003"},
		})
	}
	return out
}

// cutLinks is the set of paths the collector lists as not looked at. A
// startup link among them was cut off in its walk or never followed.
func cutLinks(c *model.Collection) map[string]bool {
	if len(c.LinkRefused) == 0 {
		return nil
	}
	cut := make(map[string]bool, len(c.LinkRefused))
	for _, p := range c.LinkRefused {
		cut[p] = true
	}
	return cut
}

// notLookedAt reports whether p is at or below a path the collector refused
// to look at when it followed startup links (the file scan records a mount
// point it stays out of, so what is inside only seems to be missing).
func notLookedAt(c *model.Collection, p string) bool {
	return slices.ContainsFunc(c.LinkRefused, func(r string) bool { return p == r || strings.HasPrefix(p, r+"/") })
}

// tempDir reports whether p is in a world-writable temporary tree.
func tempDir(p string) bool {
	for _, d := range []string{"/tmp", "/var/tmp", "/dev/shm"} {
		if p == d || strings.HasPrefix(p, d+"/") {
			return true
		}
	}
	return false
}

// collectedUnit reports whether p is a regular unit file whose contents were
// collected. Persistence files are recorded at the path they were found
// through, which need not be where they are.
func collectedUnit(c *model.Collection, inv map[string]*model.FileEntry, p string) bool {
	for _, f := range c.Persist {
		if samePlace(inv, f.Path, p) {
			return f.Mode&0o170000 == 0o100000
		}
	}
	return false
}

// samePlace reports whether the persistence file recorded at recorded is the
// file at the resolved path p.
func samePlace(inv map[string]*model.FileEntry, recorded, p string) bool {
	if recorded == p {
		return true
	}
	if path.Base(recorded) != path.Base(p) {
		return false
	}
	real, ok := model.ResolveInInventory(inv, path.Dir(recorded), model.LinkHops)
	return ok && path.Join(real, path.Base(recorded)) == p
}

// regularFile reports whether the file scan saw p as a regular file it could
// read.
func regularFile(c *model.Collection, p string) bool {
	for _, f := range c.Files {
		if f.Path == p {
			return f.Type == "file" && f.Err == ""
		}
	}
	return false
}
