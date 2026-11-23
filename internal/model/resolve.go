package model

import (
	"path"
	"sort"
	"strings"
)

// LinkHops is how many symbolic links one path resolution may follow.
const LinkHops = 8

// MaxWalkSteps is how many path components one resolution may look at, the
// components of every link target on the way included. A path the kernel
// accepts is at most 4,096 bytes; padding a chain of links with "x/../"
// would otherwise buy thousands of lookups per link.
const MaxWalkSteps = 4096

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
// links, an empty link target, a path that is not absolute, more than
// MaxWalkSteps components).
func WalkPath(lookup func(p string) (PathNode, bool), p string, maxHops int) (reached string, rest []string, ok, missing bool) {
	reached, rest, end := WalkPathEnd(lookup, p, maxHops)
	return reached, rest, end == WalkDone, end == WalkMissing
}

// WalkEnd says how a walk ended.
type WalkEnd int

const (
	WalkDone    WalkEnd = iota // the whole path resolved
	WalkMissing                // lookup did not know the next component
	WalkBlocked                // the path cannot be followed: see WalkPath
	WalkTooLong                // more than MaxWalkSteps components
)

// WalkPathEnd is WalkPath telling apart the ways a walk can fail.
func WalkPathEnd(lookup func(p string) (PathNode, bool), p string, maxHops int) (reached string, rest []string, end WalkEnd) {
	if !path.IsAbs(p) {
		return "", nil, WalkBlocked
	}
	reached = "/"
	rest = splitPath(p)
	hops, steps := 0, 0
	for len(rest) > 0 {
		if steps++; steps > MaxWalkSteps {
			return reached, rest, WalkTooLong
		}
		comp := rest[0]
		if comp == ".." {
			reached = path.Dir(reached)
			rest = rest[1:]
			continue
		}
		next := path.Join(reached, comp)
		n, known := lookup(next)
		if !known {
			return reached, rest, WalkMissing
		}
		rest = rest[1:]
		switch {
		case n.Type == "symlink":
			if hops++; hops > maxHops || n.Target == "" {
				return reached, rest, WalkBlocked
			}
			if path.IsAbs(n.Target) {
				reached = "/"
			}
			rest = append(splitPath(n.Target), rest...)
		case n.Type != "dir" && len(rest) > 0:
			return next, rest, WalkBlocked
		default:
			reached = next
		}
	}
	return reached, nil, WalkDone
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

// WalkInventory is WalkPathEnd against the collected file inventory.
func WalkInventory(files map[string]*FileEntry, p string, maxHops int) (reached string, rest []string, end WalkEnd) {
	return WalkPathEnd(inventoryLookup(files), p, maxHops)
}

// ResolveInInventory resolves p against the collected file inventory (see
// WalkPath) and returns the path of what the kernel would open. ok is false
// when that cannot be told from the inventory: a component is not in it
// (missing on the machine, or in a place the scan does not record), a
// component in the middle is neither a directory nor a link, more than
// maxHops links are involved, or the walk is longer than MaxWalkSteps. Nothing is assumed about merged /usr: /lib is
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

// ResolveDangling answers for a path that does not resolve only because its
// last component is missing: every directory on the way resolved, and the
// name looked for in the last of them is not there (a link to a file that
// was removed). It returns where that file would be. ok is false for a path
// that resolves, and for one that fails any other way.
func ResolveDangling(files map[string]*FileEntry, p string, maxHops int) (would string, ok bool) {
	reached, rest, done, missing := WalkPath(inventoryLookup(files), p, maxHops)
	if done || !missing || len(rest) != 1 || rest[0] == ".." {
		return "", false
	}
	return path.Join(reached, rest[0]), true
}

// LinkWalk is the path to resolve for a symbolic link at linkPath with the
// given target text: the target itself when absolute, else the link's
// directory followed by the target, joined as text and NOT cleaned, so that
// a resolver sees every component the kernel will.
func LinkWalk(linkPath, target string) string {
	if path.IsAbs(target) {
		return target
	}
	return path.Dir(linkPath) + "/" + target
}

// PhysicalOwners is Owners with every path also listed where it really is.
// dpkg records the path a package was unpacked through; when a directory on
// that path is a link (/opt -> /data/opt), the file a link or the linker
// reaches is somewhere else, and is still the package's. For each owned path
// whose directory resolves in the inventory to a different place, the
// physical path gets the same owner, and literal maps it back to dpkg's
// spelling (package verification and dpkg's checksums use that one).
//
// This map answers "whose file does this link lead to", and nothing else. It
// must never decide whether a file found on the machine is a package's own:
// root can turn a package's directory into a link, and every name the
// package lists is then "owned" wherever the link leads. File ownership is
// Owners; what is really behind a moved directory is compared with the
// package by package verification.
func (p Packages) PhysicalOwners(files map[string]*FileEntry) (owners, literal map[string]string) {
	return PhysicalOwnersOf(p.Owners(), files)
}

// PhysicalOwnersOf is PhysicalOwners for an owner map already built (see
// Packages.Owners), which it does not change. When two of dpkg's paths
// really are the same file, the first in path order gives the owner.
func PhysicalOwnersOf(byList map[string]string, files map[string]*FileEntry) (owners, literal map[string]string) {
	owners = make(map[string]string, len(byList))
	lits := make([]string, 0, len(byList))
	for lit, pkg := range byList {
		owners[lit] = pkg
		lits = append(lits, lit)
	}
	sort.Strings(lits)
	literal = map[string]string{}
	dirs := map[string]string{} // directory as dpkg spells it -> where it is ("" = not resolvable)
	type add struct{ phys, lit, pkg string }
	var adds []add
	for _, lit := range lits {
		pkg := byList[lit]
		dir := path.Dir(lit)
		real, seen := dirs[dir]
		if !seen {
			real, _ = ResolveInInventory(files, dir, LinkHops)
			dirs[dir] = real
		}
		if real == "" || real == dir {
			continue
		}
		adds = append(adds, add{path.Join(real, path.Base(lit)), lit, pkg})
	}
	for _, a := range adds {
		if _, taken := owners[a.phys]; !taken {
			owners[a.phys] = a.pkg
			literal[a.phys] = a.lit
		}
	}
	return owners, literal
}

// mergedTop are the top-level directories that are links into /usr on a
// merged-/usr machine. Packages still list paths below them.
var mergedTop = []string{"/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32"}

// PackageDirLink is a directory dpkg lists that is a symbolic link now.
type PackageDirLink struct {
	Dir     string // as dpkg spells it
	At      string // where the link itself is
	Target  string // the link's text
	Package string // the first package listing something below Dir
	To      string // where the link leads; "" when the inventory cannot follow it
	// Below lists, sorted, every path any package lists below Dir that is
	// not itself a listed directory: the files (and links) dpkg unpacked
	// through Dir.
	Below []string
}

// DirLinks returns each directory the installed packages list that is a
// symbolic link in the inventory, sorted by Dir. dpkg unpacks a package into
// real directories; a link in the place of one means every file listed below
// it is really somewhere else. The links merged /usr consists of (/bin ->
// usr/bin and so on, when they lead exactly there) are left out. A directory
// below a link that cannot be followed is not looked at: nothing is known
// about it.
func (p Packages) DirLinks(files map[string]*FileEntry) []PackageDirLink {
	lister := map[string]string{} // listed directory -> the first package listing something below it
	for i := range p.Installed {
		pk := &p.Installed[i]
		for _, f := range pk.Files {
			if !path.IsAbs(f) {
				continue
			}
			for d := path.Dir(path.Clean(f)); d != "/"; d = path.Dir(d) {
				if _, seen := lister[d]; seen {
					break // its parents were entered with it
				}
				lister[d] = pk.Name
			}
		}
	}
	dirs := make([]string, 0, len(lister))
	for d := range lister {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	parents := map[string]string{} // directory as dpkg spells it -> where it is ("" = cannot be told)
	var out []PackageDirLink
	for _, d := range dirs {
		up := path.Dir(d)
		real, seen := parents[up]
		if !seen {
			real, _ = ResolveInInventory(files, up, LinkHops)
			parents[up] = real
		}
		if real == "" {
			continue
		}
		at := path.Join(real, path.Base(d))
		e := files[at]
		if e == nil || e.Type != "symlink" {
			continue
		}
		to, ok := ResolveInInventory(files, LinkWalk(at, e.Target), LinkHops)
		if ok && to == "/usr"+d {
			merged := false
			for _, m := range mergedTop {
				merged = merged || m == d
			}
			if merged {
				continue
			}
		}
		out = append(out, PackageDirLink{Dir: d, At: at, Target: e.Target, Package: lister[d], To: to})
	}
	if len(out) == 0 {
		return nil
	}
	seen := map[string]bool{}
	for i := range p.Installed {
		for _, f := range p.Installed[i].Files {
			if !path.IsAbs(f) {
				continue
			}
			f = path.Clean(f)
			if _, isDir := lister[f]; isDir || seen[f] {
				continue
			}
			seen[f] = true
			for j := range out {
				if strings.HasPrefix(f, out[j].Dir+"/") {
					out[j].Below = append(out[j].Below, f)
				}
			}
		}
	}
	for j := range out {
		sort.Strings(out[j].Below)
	}
	return out
}

// PhysicalPath returns where the listed path p is when the directories on
// the way to it are followed in the inventory; its own last component is not
// followed. ok is false when the directory cannot be resolved.
func PhysicalPath(files map[string]*FileEntry, p string) (string, bool) {
	real, ok := ResolveInInventory(files, path.Dir(p), LinkHops)
	if !ok {
		return "", false
	}
	return path.Join(real, path.Base(p)), true
}
