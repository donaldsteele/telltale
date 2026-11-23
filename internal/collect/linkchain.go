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

// followLinks is the link-chain pass. It walks, in this order: the start
// paths of the file scan; every symbolic link in files (the inventory so
// far) that the inventory cannot follow to the end because a path on the way
// is not recorded; every symbolic link among the persistence files. The
// inventory's own links come before the persistence files because any user
// can plant startup links in a home directory, and the budget they can spend
// must not be what keeps a system link from being followed. A link the
// inventory resolves is not looked at again.
//
// Only lstat and readlink are used; nothing is opened. Paths for which
// refuse answers true are not looked at, and a walk ends there. Each path is
// lstat'ed once however many chains pass through it, but every lookup is
// counted, remembered answers too: a walk through a padded target ("x/../"
// four thousand bytes long, link after link) is work without one new lstat.
// One walk looks at no more than model.MaxWalkSteps components and at no
// path deeper than linkChainMaxDepth. Once budget lookups are spent no
// further walk is started. Links cut off or not started are recorded (see
// linkResult.refused) and reported with a Skip; they stay unresolvable,
// which the judge reports rather than trusts.
func followLinks(root string, persist []model.PersistFile, files []model.FileEntry, starts []string, refuse func(string) bool, budget int) linkResult {
	root = strings.TrimRight(root, "/")
	type answer struct {
		node  model.PathNode
		known bool
	}
	var res linkResult
	memo := map[string]answer{}
	unanswered := map[string]bool{}
	noAnswer := func(p string) {
		if !unanswered[p] {
			unanswered[p] = true
			res.refused = append(res.refused, p)
		}
	}
	tooDeep := false // set by lookup when the walk under way met a path past the depth cap
	lookup := func(p string) (model.PathNode, bool) {
		res.spent++
		if a, ok := memo[p]; ok {
			return a.node, a.known
		}
		if strings.Count(p, "/") > linkChainMaxDepth {
			tooDeep = true
			noAnswer(p)
			return model.PathNode{}, false
		}
		var a answer
		defer func() { memo[p] = a }()
		if refuse(p) {
			noAnswer(p)
			return a.node, false
		}
		var st unix.Stat_t
		if err := unix.Lstat(root+p, &st); err != nil {
			if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) {
				res.missing = append(res.missing, p)
			} else {
				noAnswer(p)
			}
			return a.node, false
		}
		switch st.Mode & unix.S_IFMT {
		case unix.S_IFLNK:
			target, err := os.Readlink(root + p)
			if err != nil {
				noAnswer(p)
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
		res.chain = append(res.chain, p)
		return a.node, true
	}
	// walk follows the link at p, unless the budget is spent.
	walk := func(p string) {
		if res.spent >= budget {
			res.unwalked++
			noAnswer(p)
			return
		}
		tooDeep = false
		if _, _, end := model.WalkPathEnd(lookup, p, model.LinkHops); end == model.WalkTooLong || tooDeep {
			res.cut++
			noAnswer(p)
		}
	}
	// The scan's own start paths first: they are few and root's.
	for _, s := range starts {
		model.WalkPath(lookup, filepath.Clean("/"+s), model.LinkHops)
	}
	// Links of the inventory that it cannot follow to the end. Whether it
	// can is answered from memory, within the cap on one walk.
	var inv map[string]*model.FileEntry
	for i := range files {
		e := &files[i]
		if e.Type != "symlink" || !path.IsAbs(e.Path) {
			continue
		}
		if inv == nil {
			inv = model.Inventory(files)
		}
		byInventory := func(p string) (model.PathNode, bool) {
			if f := inv[p]; f != nil {
				return model.PathNode{Type: f.Type, Target: f.Target}, true
			}
			return model.PathNode{}, false
		}
		switch _, _, end := model.WalkPathEnd(byInventory, e.Path, model.LinkHops); end {
		case model.WalkMissing:
			walk(e.Path)
		case model.WalkTooLong:
			res.cut++
			noAnswer(e.Path)
		}
	}
	for _, p := range persist {
		if p.Mode&0o170000 != 0o120000 || !path.IsAbs(p.Path) {
			continue
		}
		walk(p.Path)
	}
	if res.unwalked > 0 {
		res.skips = append(res.skips, model.Skip{Check: linkChainCheck, Reason: fmt.Sprintf(
			"stopped following links after %d lookups; %d links were not followed and are reported as links telltale could not resolve", res.spent, res.unwalked)})
	}
	if res.cut > 0 {
		res.skips = append(res.skips, model.Skip{Check: linkChainCheck, Reason: fmt.Sprintf(
			"%d links lead through paths more than %d directories deep or %d components long; they were not followed to the end and are reported as links telltale could not resolve",
			res.cut, linkChainMaxDepth, model.MaxWalkSteps)})
	}
	return res
}
