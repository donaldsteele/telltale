package model

import (
	"path"
	"strings"
)

// LinkHops is how many symbolic links one path resolution may follow.
const LinkHops = 8

// PathNode is what a resolver needs to know about one path: its type as in
// FileEntry.Type ("file", "dir", "symlink", "other") and, for a symlink, the
// target text exactly as stored.
type PathNode struct {
	Type   string
	Target string
}

// WalkPath resolves an absolute path the way the kernel does, one component
// at a time, asking lookup about each path it reaches. Every symbolic link on
// the way is replaced by its target, directory links in the middle of the
// path included; a relative target continues from the directory the link is
// really in; ".." goes to the parent of the directory really reached, never
// of the text. Cleaning the text first (path.Clean) gets this wrong: with
// "dir/../file" and dir a link to /a/b, the kernel opens /a/file.
//
// reached is the resolved path so far and rest the components not yet
// walked. ok is true when the whole path resolved to something that exists
// (rest is then empty). Otherwise missing tells why it stopped: true when
// lookup did not know the next component, false when the path cannot be
// followed at all (a component that is not a directory, more than maxHops
// links, an empty link target, a path that is not absolute).
func WalkPath(lookup func(p string) (PathNode, bool), p string, maxHops int) (reached string, rest []string, ok, missing bool) {
	if !path.IsAbs(p) {
		return "", nil, false, false
	}
	reached = "/"
	rest = splitPath(p)
	hops := 0
	for len(rest) > 0 {
		comp := rest[0]
		if comp == ".." {
			reached = path.Dir(reached)
			rest = rest[1:]
			continue
		}
		next := path.Join(reached, comp)
		n, known := lookup(next)
		if !known {
			return reached, rest, false, true
		}
		rest = rest[1:]
		switch {
		case n.Type == "symlink":
			if hops++; hops > maxHops || n.Target == "" {
				return reached, rest, false, false
			}
			if path.IsAbs(n.Target) {
				reached = "/"
			}
			rest = append(splitPath(n.Target), rest...)
		case n.Type != "dir" && len(rest) > 0:
			return next, rest, false, false
		default:
			reached = next
		}
	}
	return reached, nil, true, false
}

// splitPath returns the components of p that mean something: no empty ones
// and no ".".
func splitPath(p string) []string {
	var out []string
	for _, c := range strings.Split(p, "/") {
		if c != "" && c != "." {
			out = append(out, c)
		}
	}
	return out
}

// Inventory indexes collected file entries by path, for ResolveInInventory.
func Inventory(files []FileEntry) map[string]*FileEntry {
	inv := make(map[string]*FileEntry, len(files))
	for i := range files {
		inv[files[i].Path] = &files[i]
	}
	return inv
}

func inventoryLookup(files map[string]*FileEntry) func(string) (PathNode, bool) {
	return func(p string) (PathNode, bool) {
		e := files[p]
		if e == nil {
			return PathNode{}, false
		}
		return PathNode{Type: e.Type, Target: e.Target}, true
	}
}

// ResolveInInventory resolves p against the collected file inventory (see
// WalkPath) and returns the path of what the kernel would open. ok is false
// when that cannot be told from the inventory: a component is not in it
// (missing on the machine, or in a place the scan does not record), a
// component in the middle is neither a directory nor a link, or more than
// maxHops links are involved. Nothing is assumed about merged /usr: /lib is
// followed when the inventory records it as the link it is.
func ResolveInInventory(files map[string]*FileEntry, p string, maxHops int) (resolved string, ok bool) {
	resolved, _, ok, _ = WalkPath(inventoryLookup(files), p, maxHops)
	if !ok {
		return "", false
	}
	return resolved, true
}

// ResolveToInventoryEdge is ResolveInInventory for a question about where a
// path lies rather than what is there. When the walk stops only because the
// inventory does not know the next component (the file does not exist, or
// lies somewhere the scan does not record, such as /run), it returns the
// path resolved so far with the remaining components as written, provided
// none of them is "..". Everything up to the edge is physical; what lies
// beyond could not be looked at.
func ResolveToInventoryEdge(files map[string]*FileEntry, p string, maxHops int) (string, bool) {
	reached, rest, ok, missing := WalkPath(inventoryLookup(files), p, maxHops)
	if ok {
		return reached, true
	}
	if !missing {
		return "", false
	}
	for _, c := range rest {
		if c == ".." {
			return "", false
		}
	}
	return path.Join(append([]string{reached}, rest...)...), true
}
