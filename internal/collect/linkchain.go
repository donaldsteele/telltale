package collect

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/donaldsteele/telltale/internal/model"
	"golang.org/x/sys/unix"
)

// Bounds on the link-chain pass. Any user can put links under their own
// ~/.config/systemd/user, so the work a root scan does for them is capped.
const (
	// linkChainMaxDepth is the deepest path looked at, in components.
	linkChainMaxDepth = 256
	// linkChainBudget is how many lookups the whole pass may make, answers
	// it already has included. The walk under way when it is reached is
	// finished (model.MaxWalkSteps bounds it); no further one is started.
	linkChainBudget = 200_000
	linkChainCheck  = "link_chains"
)

// linkSkipFS says which filesystem types the link-chain pass stays out of.
// It is the file scan's list without tmpfs: a tmpfs is local memory, cannot
// hang, and /run is one, so a link chain through /run/systemd has to be
// followed like any other. Kernel pseudo-filesystems and network and FUSE
// filesystems stay refused.
func linkSkipFS(t string) bool { return t != "tmpfs" && skipFS(t) }

// RefusedForLinks reports whether the link-chain pass does not look at p: it
// lies in a kernel or device tree, or on a mount of a type linkSkipFS names.
func RefusedForLinks(p string, mounts []model.Mount) bool {
	return underNeverRead(p) || underMountOf(p, mounts, linkSkipFS)
}

// linkResult is what the link-chain pass found.
type linkResult struct {
	// chain lists every path looked at that exists, once, in the order met.
	chain []string
	// refused lists the paths at which a walk stopped without an answer:
	// refuse said so, lstat failed for a reason other than the path not
	// being there, or the path is deeper than linkChainMaxDepth. A link
	// whose walk was cut off, or never started because the budget was
	// spent, is listed by its own path. Nothing is known about what is at
	// or below these, not even that it is missing.
	refused []string
	// missing lists the paths lstat said are not there. Unlike a path the
	// inventory merely lacks, such a path was looked at.
	missing []string
	skips   []model.Skip
	// spent counts lookups, remembered answers included; cut the links
	// whose walk ended at the depth or length cap; unwalked those not
	// started because the budget was spent.
	spent, cut, unwalked int
}

// linkChains lists every path the kernel passes through when it follows each
// symbolic link among the persistence files, and when it reaches each start
// path of the file scan: the directories on the way, the links, their
// targets, and the directories on the way to those. With an entry for each
// of them in the inventory, the judge can resolve a link the way the kernel
// does (model.ResolveInInventory) instead of trusting the link's text, which
// "dir/../file" through a planted directory link makes lie.
//
// refused lists the paths at which a walk stopped without an answer; see
// linkResult.
func linkChains(root string, persist []model.PersistFile, starts []string, refuse func(string) bool) (chain, refused []string, skips []model.Skip) {
	return linkChainsWithin(root, persist, starts, refuse, linkChainBudget)
}

// linkChainsWithin is linkChains with the budget given.
func linkChainsWithin(root string, persist []model.PersistFile, starts []string, refuse func(string) bool, budget int) (chain, refused []string, skips []model.Skip) {
	res := followLinks(root, persist, nil, starts, refuse, budget)
	return res.chain, res.refused, res.skips
}

// linkWalker follows paths on the machine the way the kernel does, within a
// work budget, and remembers what it met.
//
// Only lstat and readlink are used; nothing is opened. Paths for which
// refuse answers true are not looked at, and a walk ends there. Each path is
// lstat'ed once however many walks pass through it, but every lookup is
// counted, remembered answers too: a walk through a padded target ("x/../"
// four thousand bytes long, link after link) is work without one new lstat.
// One walk looks at no more than model.MaxWalkSteps components and at no
// path deeper than linkChainMaxDepth. Once budget lookups are spent no
// further walk is started; the one under way is finished.
type linkWalker struct {
	root       string
	refuse     func(string) bool
	budget     int
	memo       map[string]walkAnswer
	unanswered map[string]bool
	tooDeep    bool // the walk under way met a path past the depth cap
	res        linkResult
}

type walkAnswer struct {
	node  model.PathNode
	known bool
}

func newLinkWalker(root string, refuse func(string) bool, budget int) *linkWalker {
	return &linkWalker{root: strings.TrimRight(root, "/"), refuse: refuse, budget: budget, memo: map[string]walkAnswer{}, unanswered: map[string]bool{}}
}

// noAnswer records p among the paths nothing is known about.
func (w *linkWalker) noAnswer(p string) {
	if !w.unanswered[p] {
		w.unanswered[p] = true
		w.res.refused = append(w.res.refused, p)
	}
}

func (w *linkWalker) lookup(p string) (model.PathNode, bool) {
	w.res.spent++
	if a, ok := w.memo[p]; ok {
		return a.node, a.known
	}
	if strings.Count(p, "/") > linkChainMaxDepth {
		w.tooDeep = true
		w.noAnswer(p)
		return model.PathNode{}, false
	}
	var a walkAnswer
	defer func() { w.memo[p] = a }()
	if w.refuse(p) {
		w.noAnswer(p)
		return a.node, false
	}
	var st unix.Stat_t
	if err := unix.Lstat(w.root+p, &st); err != nil {
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) {
			w.res.missing = append(w.res.missing, p)
		} else {
			w.noAnswer(p)
		}
		return a.node, false
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFLNK:
		target, err := os.Readlink(w.root + p)
		if err != nil {
			w.noAnswer(p)
			return a.node, false
		}
		a.node = model.PathNode{Type: "symlink", Target: target}
	case unix.S_IFDIR:
		a.node = model.PathNode{Type: "dir"}
	case unix.S_IFREG:
		a.node = model.PathNode{Type: "file"}
	default:
		a.node = model.PathNode{Type: "other"}
	}
	a.known = true
	w.res.chain = append(w.res.chain, p)
	return a.node, true
}

// walk follows the path p, unless the budget is spent. A path cut off or
// not started is recorded as one nothing is known about.
func (w *linkWalker) walk(p string) {
	if w.res.spent >= w.budget {
		w.res.unwalked++
		w.noAnswer(p)
		return
	}
	w.tooDeep = false
	if _, _, end := model.WalkPathEnd(w.lookup, p, model.LinkHops); end == model.WalkTooLong || w.tooDeep {
		w.res.cut++
		w.noAnswer(p)
	}
}

// done returns what was found, with a Skip for the paths left; what names
// them ("links", "package files").
func (w *linkWalker) done(what string) linkResult {
	if w.res.unwalked > 0 {
		w.res.skips = append(w.res.skips, model.Skip{Check: linkChainCheck, Reason: fmt.Sprintf(
			"stopped following %s after %d lookups; %d %s were not followed and are reported as %s telltale could not resolve", what, w.res.spent, w.res.unwalked, what, what)})
	}
	if w.res.cut > 0 {
		w.res.skips = append(w.res.skips, model.Skip{Check: linkChainCheck, Reason: fmt.Sprintf(
			"%d %s lead through paths more than %d directories deep or %d components long; they were not followed to the end and are reported as %s telltale could not resolve",
			w.res.cut, what, linkChainMaxDepth, model.MaxWalkSteps, what)})
	}
	return w.res
}

// followLinks is the link-chain pass. A link the inventory (files) already
// follows to the end is not looked at again and costs nothing of the
// budget. The others are walked on the machine, in this order:
//
//  1. the start paths of the file scan;
//  2. the startup links in the system paths (SystemPaths) and root's
//     runtime units (/run/systemd/system), which root made;
//  3. the links the file scan recorded whose target the inventory cannot
//     follow, because a path on the way is not recorded;
//  4. the startup links outside the system paths (any user can plant them
//     under a home directory) and the links among the supplementary entries
//     (the targets of those startup links).
//
// The order is what keeps a user from spending the budget before a system
// link is followed: with a hundred padded links in one home directory the
// budget is gone, and every link not yet walked is then reported as one
// telltale could not resolve. Links cut off or not started are recorded (see
// linkResult.refused) and reported with a Skip; they stay unresolvable,
// which the judge reports rather than trusts.
func followLinks(root string, persist []model.PersistFile, files []model.FileEntry, starts []string, refuse func(string) bool, budget int) linkResult {
	w := newLinkWalker(root, refuse, budget)
	inv := model.Inventory(files)
	// follow walks the link at p unless the inventory resolves it. Whether
	// it does is answered from memory, within the cap on one walk.
	follow := func(p string) {
		switch _, _, end := model.WalkInventory(inv, p, model.LinkHops); end {
		case model.WalkMissing:
			w.walk(p)
		case model.WalkTooLong:
			w.res.cut++
			w.noAnswer(p)
		}
	}
	isLink := func(p model.PersistFile) bool { return p.Mode&0o170000 == 0o120000 && path.IsAbs(p.Path) }
	for _, s := range starts {
		model.WalkPath(w.lookup, filepath.Clean("/"+s), model.LinkHops)
	}
	for _, p := range persist {
		if isLink(p) && rootStartupPath(p.Path) {
			follow(p.Path)
		}
	}
	for i := range files {
		if e := &files[i]; e.Type == "symlink" && !e.Supplementary && path.IsAbs(e.Path) {
			follow(e.Path)
		}
	}
	for _, p := range persist {
		if isLink(p) && !rootStartupPath(p.Path) {
			follow(p.Path)
		}
	}
	for i := range files {
		if e := &files[i]; e.Type == "symlink" && e.Supplementary && path.IsAbs(e.Path) {
			follow(e.Path)
		}
	}
	return w.done("links")
}

// rootStartupPath reports whether a startup link at p is one only root can
// have made: it is in the file scan's paths or among root's runtime units,
// which the file scan does not walk (/run is a tmpfs).
func rootStartupPath(p string) bool {
	return underSystemPath(p) || strings.HasPrefix(p, "/run/systemd/system/")
}

// underSystemPath reports whether p is in one of the file scan's paths.
func underSystemPath(p string) bool {
	for _, d := range SystemPaths {
		if p == d || strings.HasPrefix(p, d+"/") {
			return true
		}
	}
	return false
}

// packageDirPaths lists the paths packages list below a directory that is a
// symbolic link now (model.Packages.DirLinks) for which the inventory has no
// entry where the path really is. A package directory moved out of the
// scanned paths leaves every file behind it unrecorded, and so uncompared.
func packageDirPaths(pkgs model.Packages, files []model.FileEntry) []string {
	inv := model.Inventory(files)
	var out []string
	seen := map[string]bool{}
	phys := model.NewPhysicalResolver(inv)
	for _, l := range pkgs.DirLinks(inv) {
		if l.To == "" {
			continue // nowhere to look; the judge reports the link
		}
		for _, p := range l.Below {
			if seen[p] {
				continue
			}
			seen[p] = true
			if at, ok := phys.Path(p); !ok || inv[at] == nil {
				out = append(out, p)
			}
		}
	}
	return out
}

// ensurePackageDirEntries records what is behind each package directory that
// is a symbolic link now: for every path a package lists below it, the entry
// at the place the path really is, and everything passed on the way. The
// work is bounded by the packages' own file lists and by the walker's
// budget. With these entries package verification can compare the files
// where they are; a listed file that still has none afterwards is one the
// judge reports as not checked. refused and missing are as in linkResult.
func ensurePackageDirEntries(root string, files []model.FileEntry, pkgs model.Packages, mounts []model.Mount, maxHash int64) (out []model.FileEntry, refused, missing []string, skips []model.Skip) {
	w := newLinkWalker(root, func(p string) bool { return RefusedForLinks(p, mounts) }, linkChainBudget)
	// A link found behind a link shows more paths to look for: go round
	// again, a few times at most.
	tried := map[string]bool{}
	for round := 0; round < 4; round++ {
		before, was := len(w.res.chain), len(files)
		for _, p := range packageDirPaths(pkgs, files) {
			if !tried[p] {
				tried[p] = true
				w.walk(p)
			}
		}
		var s []model.Skip
		files, s = ensureEntriesIn(root, files, w.res.chain[before:], mounts, maxHash, underNeverRead, linkSkipFS)
		skips = append(skips, s...)
		if len(files) == was {
			break
		}
	}
	res := w.done("package files")
	return files, res.refused, res.missing, append(skips, res.skips...)
}

// ensureChainEntries records the paths of a link chain (ensureEntriesIn) and
// marks those on a tmpfs Volatile: /run is made anew at every boot, and all
// that a link through it depends on is what each path is and where it leads.
// Only chain entries are marked. The target of a startup link and a PAM
// module on a tmpfs are files something runs, and stay compared in full.
func ensureChainEntries(root string, files []model.FileEntry, chain []string, mounts []model.Mount, maxHash int64) ([]model.FileEntry, []model.Skip) {
	was := len(files)
	files, skips := ensureEntriesIn(root, files, chain, mounts, maxHash, underNeverRead, linkSkipFS)
	for i := was; i < len(files); i++ {
		files[i].Volatile = underMountOf(files[i].Path, mounts, func(t string) bool { return t == "tmpfs" })
	}
	return files, skips
}
