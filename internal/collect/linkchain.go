package collect

import (
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/donaldsteele/telltale/internal/model"
	"golang.org/x/sys/unix"
)

// linkChains lists every path the kernel passes through when it follows each
// symbolic link among the persistence files, and when it reaches each start
// path of the file scan: the directories on the way, the links, their
// targets, and the directories on the way to those. With an entry for each
// of them in the inventory, the judge can resolve a link the way the kernel
// does (model.ResolveInInventory) instead of trusting the link's text, which
// "dir/../file" through a planted directory link makes lie.
//
// Only lstat and readlink are used; nothing is opened. Paths for which
// refuse answers true (kernel and device trees, mounts the file scan skips)
// are not looked at, and a walk ends there.
func linkChains(root string, persist []model.PersistFile, starts []string, refuse func(string) bool) []string {
	root = strings.TrimRight(root, "/")
	seen := map[string]bool{}
	var out []string
	lookup := func(p string) (model.PathNode, bool) {
		if refuse(p) {
			return model.PathNode{}, false
		}
		var st unix.Stat_t
		if err := unix.Lstat(root+p, &st); err != nil {
			return model.PathNode{}, false
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
		switch st.Mode & unix.S_IFMT {
		case unix.S_IFLNK:
			target, err := os.Readlink(root + p)
			if err != nil {
				return model.PathNode{}, false
			}
			return model.PathNode{Type: "symlink", Target: target}, true
		case unix.S_IFDIR:
			return model.PathNode{Type: "dir"}, true
		case unix.S_IFREG:
			return model.PathNode{Type: "file"}, true
		}
		return model.PathNode{Type: "other"}, true
	}
	for _, p := range persist {
		if p.Mode&0o170000 == 0o120000 && path.IsAbs(p.Path) {
			model.WalkPath(lookup, p.Path, model.LinkHops)
		}
	}
	for _, s := range starts {
		model.WalkPath(lookup, filepath.Clean("/"+s), model.LinkHops)
	}
	return out
}
