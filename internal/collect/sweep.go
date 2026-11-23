package collect

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/donaldsteele/telltale/internal/model"
	"golang.org/x/sys/unix"
)

// sweepMaxEntries bounds one sweep: after this many directory entries it
// stops descending and records a skip.
var sweepMaxEntries = 2_000_000

// maxSweepDirSkips bounds the skips recorded for unreadable directories; the
// rest are summarised in one line.
const maxSweepDirSkips = 20

// sweepSkipFS are filesystem types the sweep never enters: kernel
// pseudo-filesystems and network or user-space mounts. tmpfs is not among
// them: /tmp, /dev/shm and /run are where a planted setuid file would sit.
// The mount at "/" is never skipped by type: it holds the system being
// examined (a container or lab machine has an overlay root), and overlay is
// not skipped at all; image stores are skipped by path instead.
var sweepSkipFS = map[string]bool{
	"proc": true, "sysfs": true, "devtmpfs": true, "devpts": true, "cgroup": true, "cgroup2": true,
	"securityfs": true, "debugfs": true, "tracefs": true, "bpf": true, "pstore": true, "configfs": true,
	"autofs": true, "efivarfs": true, "mqueue": true, "binfmt_misc": true, "nfs": true, "nfs4": true,
	"cifs": true, "smb3": true, "sshfs": true, "fusectl": true, "rpc_pipefs": true, "nsfs": true,
	"selinuxfs": true, "hugetlbfs": true, "fuseblk": true,
	// Read-only or layered images of other systems: their setuid files belong
	// to the image, not to this machine's packages.
	"squashfs": true, "erofs": true, "iso9660": true,
}

// sweepSkipDirs hold other systems' file trees (container, VM, snapshot and chroot
// copies, flatpak runtimes). Their setuid files are the copy's own, and their
// paths change between scans, so a sweep that looked there would call every one
// a stranger. Each entry matches itself and everything below it.
var sweepSkipDirs = []string{"/var/lib/docker", "/var/lib/containerd", "/var/lib/containers", "/var/lib/flatpak", "/var/lib/lxc", "/var/lib/lxd", "/var/lib/incus", "/var/lib/machines",
	"/run/containerd", "/run/k3s/containerd", "/run/docker", "/var/lib/kubelet/pods", "/var/snap/lxd/common/lxd", "/var/lib/rancher", "/timeshift", "/.snapshots", "/var/cache/pbuilder", "/srv/chroot"}

// sweepFirstBudget is the entry budget of each directory in sweepFirst, so
// that a flood in one cannot starve the others.
var sweepFirstBudget = 500_000

// userImageDirs are per-user container image stores (~/.local/share/containers,
// rootless Docker).
var userImageDirs = []string{"/.local/share/containers", "/.local/share/docker"}

// sweepFirst are walked before everything else, so that a bounded walk never
// runs out before reaching them: the world-writable and service-owned places
// an intruder uses.
var sweepFirst = []string{"/tmp", "/var/tmp", "/dev/shm", "/run", "/var/www", "/srv", "/opt"}

// sweepLast are walked after everything else: large, and mostly the users' own.
var sweepLast = []string{"/home", "/mnt", "/media"}

func sweepSkipType(t string) bool {
	return sweepSkipFS[t] || t == "fuse" || strings.HasPrefix(t, "fuse.")
}

func hasPathPrefix(p, dir string) bool {
	return p == dir || strings.HasPrefix(p, strings.TrimRight(dir, "/")+"/")
}

// Sweep walks every local filesystem in the mount table, below root, for
// regular files that carry a setuid or setgid bit or a security.capability
// attribute, and returns an entry for each (hashed within opt.MaxHashBytes).
// have lists entries already collected; those paths are skipped. Directories
// are only listed and files only lstat'ed: nothing is read except the
// candidates themselves, through the same guarded open as the system-path
// walk. Mounts holds machine paths.
func Sweep(root string, mounts []model.Mount, have []model.FileEntry, opt FileOptions) ([]model.FileEntry, []model.Skip) {
	e, s, _ := sweepFull(root, mounts, have, opt)
	return e, s
}

// sweepFull is Sweep that also returns the path prefixes where the walk stopped
// early (the entry bound or a directory budget ran out): files there were not
// all looked at, so a snapshot comparison must not call them added or removed.
func sweepFull(root string, mounts []model.Mount, have []model.FileEntry, opt FileOptions) ([]model.FileEntry, []model.Skip, []string) {
	e, s, incomplete, _ := sweepAll(root, mounts, have, opt)
	return e, s, incomplete
}

// sweepAll is sweepFull, also naming the priority directories (sweepFirst)
// whose own budget ran out: someone filled them.
func sweepAll(root string, mounts []model.Mount, have []model.FileEntry, opt FileOptions) ([]model.FileEntry, []model.Skip, []string, []string) {
	var entries []model.FileEntry
	var skips []model.Skip
	var flooded []string
	root = strings.TrimRight(root, "/")

	haveSet := make(map[string]bool, len(have))
	for _, e := range have {
		haveSet[e.Path] = true
	}

	// Start points: each local mount. Every other mount, local or not, is a
	// boundary: a local one is walked from its own start.
	type start struct{ path, fstype string }
	var starts []start
	boundary := map[string]bool{"/proc": true, "/sys": true}
	seenStart := map[string]bool{}
	for _, m := range mounts {
		p := filepath.Clean("/" + m.Path)
		boundary[p] = true
		if (sweepSkipType(m.FSType) && p != "/") || seenStart[p] {
			continue
		}
		seenStart[p] = true
		starts = append(starts, start{p, m.FSType})
	}
	if !seenStart["/"] {
		starts = append(starts, start{"/", ""})
	}
	delete(boundary, "/")
	sort.Slice(starts, func(i, j int) bool { return starts[i].path < starts[j].path })

	// The system-path walk already lstat's everything under these trees (but
	// skips tmpfs and the like nested in them, which the sweep does cover).
	systemTree := make(map[string]bool, len(SystemPaths))
	for _, p := range SystemPaths {
		systemTree[filepath.Clean("/"+p)] = true
	}
	coveredByFiles := func(p string, fstype string) bool {
		if skipFS(fstype) {
			return false
		}
		for s := range systemTree {
			if hasPathPrefix(p, s) {
				return true
			}
		}
		return false
	}

	// The directories in sweepFirst each have their own budget; everything
	// else shares sweepMaxEntries, counted apart from them.
	visited, limit := 0, sweepMaxEntries
	stopped, phaseStop, inFirst, phaseDir := false, false, false, ""
	incompleteSet := map[string]bool{}
	// remaining records the unvisited entries of a directory the walk left.
	remaining := func(mp string, des []fs.DirEntry, i int) {
		if len(des)-i > 50 {
			incompleteSet[mp] = true
			return
		}
		for _, d := range des[i:] {
			incompleteSet[path.Join(mp, d.Name())] = true
		}
	}
	dirSkips, droppedSkips := 0, 0
	dirSkip := func(mp string, err error) {
		if dirSkips >= maxSweepDirSkips {
			droppedSkips++
			return
		}
		dirSkips++
		skips = append(skips, model.Skip{Check: checkName, Reason: "sweep: " + mp + ": " + err.Error()})
	}

	// Directories that are deferred (walked after the rest) or already walked.
	var deferred []string
	deferredSet := map[string]bool{}
	done := map[string]bool{}
	skipNoted := map[string]bool{}
	isLate := func(p string) bool {
		for _, l := range sweepLast {
			if hasPathPrefix(p, l) {
				return true
			}
		}
		return false
	}
	later := func(p string) {
		if !deferredSet[p] {
			deferredSet[p] = true
			deferred = append(deferred, p)
		}
	}
	imageDir := func(p string) bool {
		hit := false
		for _, u := range userImageDirs {
			hit = hit || strings.HasSuffix(p, u)
		}
		for _, d := range sweepSkipDirs {
			hit = hit || p == d
		}
		if hit && !skipNoted[p] {
			skipNoted[p] = true
			skips = append(skips, model.Skip{Check: checkName, Reason: "sweep: " + p + ": not searched (holds the files of other systems: container, VM or package-runtime images)"})
		}
		return hit
	}
	// ownerType is the filesystem type of the mount that holds p.
	mountType := make(map[string]string, len(mounts))
	for _, m := range mounts {
		mountType[filepath.Clean("/"+m.Path)] = m.FSType
	}
	ownerType := func(p string) (t, mountPath string) {
		for q := p; ; q = filepath.Dir(q) {
			if t, ok := mountType[q]; ok {
				return t, q
			}
			if q == "/" {
				return "", "/"
			}
		}
	}

	var walk func(mp string)
	walk = func(mp string) {
		des, err := os.ReadDir(root + mp)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, unix.ENOTDIR) {
				dirSkip(mp, err)
			}
			return
		}
		for i, d := range des {
			if stopped || phaseStop {
				remaining(mp, des, i)
				return
			}
			if visited++; visited > limit {
				if inFirst {
					phaseStop = true
					flooded = append(flooded, phaseDir)
					skips = append(skips, model.Skip{Check: checkName, Reason: fmt.Sprintf("sweep: %s: stopped after %d entries; the rest of it was not looked at", phaseDir, sweepFirstBudget)})
				} else {
					stopped = true
					skips = append(skips, model.Skip{Check: checkName, Reason: fmt.Sprintf("sweep: stopped after %d entries; setuid, setgid and capability files beyond this point were not looked for", sweepMaxEntries)})
				}
				remaining(mp, des, i)
				return
			}
			child := mp + "/" + d.Name()
			if mp == "/" {
				child = "/" + d.Name()
			}
			switch t := d.Type(); {
			case t.IsDir():
				if boundary[child] || systemTree[child] || done[child] || imageDir(child) {
					continue
				}
				if isLate(child) && !isLate(mp) {
					later(child)
					continue
				}
				walk(child)
			case t.IsRegular():
				if haveSet[child] {
					continue
				}
				info, err := d.Info()
				if err != nil {
					continue // vanished
				}
				real := root + child
				if info.Mode()&(fs.ModeSetuid|fs.ModeSetgid) == 0 {
					n, err := unix.Lgetxattr(real, "security.capability", nil)
					if err != nil || n <= 0 {
						continue
					}
				}
				if e, ok := statEntry(real, child, opt, &skips); ok {
					e.Swept = true
					entries = append(entries, e)
					haveSet[child] = true
				}
			}
		}
	}

	// walkable reports whether p may be walked on its own: its filesystem is
	// local, it is not an image store and the system-path walk has not
	// already covered it.
	walkable := func(p string) bool {
		t, mp := ownerType(p)
		if (sweepSkipType(t) && mp != "/") || coveredByFiles(p, t) {
			return false
		}
		for _, d := range sweepSkipDirs {
			if hasPathPrefix(p, d) {
				imageDir(d)
				return false
			}
		}
		for _, u := range userImageDirs {
			if i := strings.Index(p+"/", u+"/"); i >= 0 {
				imageDir(p[:i+len(u)])
				return false
			}
		}
		return true
	}

	// 1. the places an intruder uses, each with its own budget so a flood in
	// one cannot starve the others (or the rest of the sweep)
	for _, p := range sweepFirst {
		if fi, err := os.Lstat(root + p); err != nil || !fi.IsDir() || !walkable(p) {
			continue
		}
		done[p] = true
		saved := visited
		visited, limit, inFirst, phaseStop, phaseDir = 0, sweepFirstBudget, true, false, p
		walk(p)
		visited, limit, inFirst, phaseStop = saved, sweepMaxEntries, false, false
	}
	// 2. every local mount
	for _, s := range starts {
		switch {
		case done[s.path] || !walkable(s.path):
		case isLate(s.path):
			later(s.path)
		case stopped:
			incompleteSet[s.path] = true
		default:
			walk(s.path)
		}
	}
	// 3. the users' own trees
	for _, d := range deferred {
		switch {
		case !walkable(d):
		case stopped:
			incompleteSet[d] = true
		default:
			walk(d)
		}
	}
	if droppedSkips > 0 {
		skips = append(skips, model.Skip{Check: checkName, Reason: fmt.Sprintf("sweep: %d more directories could not be read", droppedSkips)})
	}
	var incomplete []string
	for p := range incompleteSet {
		incomplete = append(incomplete, p)
	}
	sort.Strings(incomplete)
	return entries, skips, incomplete, flooded
}
