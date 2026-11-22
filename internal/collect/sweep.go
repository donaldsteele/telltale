package collect

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
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
var sweepSkipFS = map[string]bool{
	"proc": true, "sysfs": true, "devtmpfs": true, "devpts": true, "cgroup": true, "cgroup2": true,
	"securityfs": true, "debugfs": true, "tracefs": true, "bpf": true, "pstore": true, "configfs": true,
	"autofs": true, "efivarfs": true, "mqueue": true, "binfmt_misc": true, "nfs": true, "nfs4": true,
	"cifs": true, "smb3": true, "sshfs": true, "fusectl": true, "rpc_pipefs": true, "nsfs": true,
	"selinuxfs": true, "hugetlbfs": true,
	// Read-only or layered images of other systems: their setuid files belong
	// to the image, not to this machine's packages.
	"squashfs": true, "erofs": true, "iso9660": true, "overlay": true,
}

// sweepSkipDirs hold other systems' file trees (container and VM images, snap
// and flatpak runtimes). Their setuid files are the image's own, so a sweep
// that looked there would call every one a stranger.
var sweepSkipDirs = []string{"/var/lib/docker", "/var/lib/containers", "/var/lib/lxc", "/var/lib/lxd", "/var/lib/incus", "/var/lib/machines", "/var/lib/flatpak", "/var/lib/snapd/snap", "/snap"}

// sweepFirst are walked before everything else, so that a bounded walk never
// runs out before reaching them: the world-writable and service-owned places
// an intruder uses.
var sweepFirst = []string{"/tmp", "/var/tmp", "/dev/shm", "/run", "/var/www", "/srv", "/opt", "/mnt", "/media"}

// sweepLast are walked after everything else: large, and mostly the users' own.
var sweepLast = []string{"/home"}

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
	var entries []model.FileEntry
	var skips []model.Skip
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
		if sweepSkipType(m.FSType) || seenStart[p] {
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

	visited := 0
	stopped := false
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
		for _, d := range sweepSkipDirs {
			if p == d {
				if !skipNoted[p] {
					skipNoted[p] = true
					skips = append(skips, model.Skip{Check: checkName, Reason: "sweep: " + p + ": not searched (holds the files of other systems: container, VM or package-runtime images)"})
				}
				return true
			}
		}
		return false
	}
	// ownerType is the filesystem type of the mount that holds p.
	mountType := make(map[string]string, len(mounts))
	for _, m := range mounts {
		mountType[filepath.Clean("/"+m.Path)] = m.FSType
	}
	ownerType := func(p string) string {
		for q := p; ; q = filepath.Dir(q) {
			if t, ok := mountType[q]; ok {
				return t
			}
			if q == "/" {
				return ""
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
		for _, d := range des {
			if stopped {
				return
			}
			if visited++; visited > sweepMaxEntries {
				stopped = true
				skips = append(skips, model.Skip{Check: checkName, Reason: fmt.Sprintf("sweep: stopped after %d entries; setuid, setgid and capability files beyond this point were not looked for", sweepMaxEntries)})
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
		if t := ownerType(p); sweepSkipType(t) || coveredByFiles(p, t) {
			return false
		}
		for _, d := range sweepSkipDirs {
			if hasPathPrefix(p, d) {
				imageDir(d)
				return false
			}
		}
		return true
	}

	// 1. the places an intruder uses, so the bound never starves them
	for _, p := range sweepFirst {
		if stopped {
			break
		}
		if fi, err := os.Lstat(root + p); err != nil || !fi.IsDir() || !walkable(p) {
			continue
		}
		done[p] = true
		walk(p)
	}
	// 2. every local mount
	for _, s := range starts {
		if stopped {
			break
		}
		switch {
		case done[s.path] || !walkable(s.path):
		case isLate(s.path):
			later(s.path)
		default:
			walk(s.path)
		}
	}
	// 3. the users' own trees
	for i := 0; i < len(deferred) && !stopped; i++ {
		if walkable(deferred[i]) {
			walk(deferred[i])
		}
	}
	if droppedSkips > 0 {
		skips = append(skips, model.Skip{Check: checkName, Reason: fmt.Sprintf("sweep: %d more directories could not be read", droppedSkips)})
	}
	return entries, skips
}
