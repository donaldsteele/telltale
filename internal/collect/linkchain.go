package collect

import (
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
	// linkChainBudget is how many paths the whole pass may lstat.
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

// linkChains lists every path the kernel passes through when it follows each
// symbolic link among the persistence files, and when it reaches each start
// path of the file scan: the directories on the way, the links, their
// targets, and the directories on the way to those. With an entry for each
// of them in the inventory, the judge can resolve a link the way the kernel
// does (model.ResolveInInventory) instead of trusting the link's text, which
// "dir/../file" through a planted directory link makes lie.
//
// Only lstat and readlink are used; nothing is opened. Paths for which
// refuse answers true are not looked at, and a walk ends there. Each path is
// looked at once however many chains pass through it. Paths deeper than
// linkChainMaxDepth are not looked at, and after linkChainBudget paths the
// pass stops with a Skip: the links it did not get to stay unresolvable,
// which the judge reports rather than trusts.
//
// refused lists the paths at which a walk stopped because refuse said so.
func linkChains(root string, persist []model.PersistFile, starts []string, refuse func(string) bool) (chain, refused []string, skips []model.Skip) {
	return linkChainsWithin(root, persist, starts, refuse, linkChainBudget)
}

// linkChainsWithin is linkChains with the budget given.
func linkChainsWithin(root string, persist []model.PersistFile, starts []string, refuse func(string) bool, budget int) (chain, refused []string, skips []model.Skip) {
	root = strings.TrimRight(root, "/")
	type answer struct {
		node  model.PathNode
		known bool
	}
	memo := map[string]answer{}
	var out []string
	spent, tooDeep := 0, 0
	lookup := func(p string) (model.PathNode, bool) {
		if a, ok := memo[p]; ok {
			return a.node, a.known
		}
		if strings.Count(p, "/") > linkChainMaxDepth {
			tooDeep++
			return model.PathNode{}, false
		}
		if spent >= budget {
			return model.PathNode{}, false // not remembered: it was never looked at
		}
		var a answer
		defer func() { memo[p] = a }()
		if refuse(p) {
			refused = append(refused, p)
			return a.node, false
		}
		spent++
		var st unix.Stat_t
		if err := unix.Lstat(root+p, &st); err != nil {
			return a.node, false
		}
		switch st.Mode & unix.S_IFMT {
		case unix.S_IFLNK:
			target, err := os.Readlink(root + p)
			if err != nil {
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
		out = append(out, p)
		return a.node, true
	}
	// The scan's own start paths first: they are few and root's.
	for _, s := range starts {
		model.WalkPath(lookup, filepath.Clean("/"+s), model.LinkHops)
	}
	left := 0
	for _, p := range persist {
		if p.Mode&0o170000 != 0o120000 || !path.IsAbs(p.Path) {
			continue
		}
		if spent >= budget {
			left++
			continue
		}
		model.WalkPath(lookup, p.Path, model.LinkHops)
	}
	if spent >= budget {
		skips = append(skips, model.Skip{Check: linkChainCheck, Reason: fmt.Sprintf(
			"stopped following startup links after looking at %d paths; %d links were not followed and are reported as links telltale could not resolve", spent, left)})
	}
	if tooDeep > 0 {
		skips = append(skips, model.Skip{Check: linkChainCheck, Reason: fmt.Sprintf(
			"startup links lead through paths more than %d directories deep, which were not followed", linkChainMaxDepth)})
	}
	return out, refused, skips
}
