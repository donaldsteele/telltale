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
}

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
				if boundary[child] || systemTree[child] {
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

	for _, s := range starts {
		if stopped {
			break
		}
		if coveredByFiles(s.path, s.fstype) {
			continue
		}
		walk(s.path)
	}
	if droppedSkips > 0 {
		skips = append(skips, model.Skip{Check: checkName, Reason: fmt.Sprintf("sweep: %d more directories could not be read", droppedSkips)})
	}
	return entries, skips
}
