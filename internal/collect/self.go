package collect

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// Self is the collector's own binary in the temporary directory a server
// visit made for it. The file inventory leaves out that one file, matched
// by its device and inode, and the directory's own entry; whatever else is
// in the directory is walked as usual.
type Self struct {
	Dir      string // the directory, a machine path
	Dev, Ino uint64 // the binary's device and inode
}

// selfName is the collector's name in a visit's directory.
const selfName = "telltale"

// FindSelf checks dir as the directory a server visit made for the running
// collector and returns the binary to leave out. All of this must hold, or
// ok is false and nothing is left out: dir is a directory itself, not a
// link to one, owned by uid, with mode exactly 0700 (mktemp -d's); it holds
// exactly one entry, "telltale", a regular file; and that file is the
// running program: it has the device and inode of exe, which Stat follows
// (/proc/self/exe).
func FindSelf(dir, exe string, uid uint32) (Self, bool) {
	var st unix.Stat_t
	if unix.Lstat(dir, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != uid || st.Mode&0o7777 != 0o700 {
		return Self{}, false
	}
	f, err := os.Open(dir)
	if err != nil {
		return Self{}, false
	}
	names, err := f.Readdirnames(2)
	f.Close()
	if err != nil || len(names) != 1 || names[0] != selfName {
		return Self{}, false
	}
	var bin, run unix.Stat_t
	if unix.Lstat(filepath.Join(dir, selfName), &bin) != nil || bin.Mode&unix.S_IFMT != unix.S_IFREG {
		return Self{}, false
	}
	if unix.Stat(exe, &run) != nil || uint64(bin.Dev) != uint64(run.Dev) || bin.Ino != run.Ino {
		return Self{}, false
	}
	return Self{Dir: filepath.Clean(dir), Dev: uint64(bin.Dev), Ino: bin.Ino}, true
}

// leaves reports whether the walk leaves out the entry at machine path mp
// (host path p): the directory's own entry, which is still walked into, or
// the binary itself, still the same file.
func (s Self) leaves(mp, p string, isDir bool) bool {
	if s.Dir == "" {
		return false
	}
	if isDir {
		return mp == s.Dir
	}
	if mp != s.Dir+"/"+selfName {
		return false
	}
	var st unix.Stat_t
	return unix.Lstat(p, &st) == nil && uint64(st.Dev) == s.Dev && st.Ino == s.Ino
}
