package collect

import (
	"errors"
	"io/fs"
	"strconv"
	"sync"

	"golang.org/x/sys/unix"
)

// Opening a file can do something before a single byte is read: opening a
// watchdog device arms a timer that reboots the machine, a tape drive
// rewinds, a FIFO blocks. Many of the paths the collector reads are chosen
// by someone else (a user's link at a start-up path, a package's file
// list). So nothing is opened for reading until it is known to be a regular
// file: the collector first takes a handle that opens nothing (O_PATH),
// looks at what it refers to, and only then opens that same file through
// the handle.

var (
	errIsSymlink  = errors.New("is a symlink")
	errNotRegular = errors.New("not a regular file")
)

// reopenFn opens for reading the file an O_PATH descriptor refers to; tests
// wrap it to see what is opened. /proc/self/fd/N names the very file the
// descriptor holds, whatever its path leads to by now.
var reopenFn = func(pfd int) (int, error) {
	return unix.Open("/proc/self/fd/"+strconv.Itoa(pfd), unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
}

// devFS is the device number of a root's /dev when that is a mount of its
// own (devtmpfs, or a tmpfs holding device nodes).
type devFS struct {
	dev uint64
	ok  bool
}

var (
	devFSMu    sync.Mutex
	devFSCache = map[string]devFS{}
)

// devFSOf finds root's device filesystem. It has no magic number of its own
// (it reports tmpfs, as /run and /dev/shm do), so it is told by /dev's
// device number, when that differs from the root filesystem's.
func devFSOf(root string) devFS {
	if root == "" {
		root = "/"
	}
	devFSMu.Lock()
	defer devFSMu.Unlock()
	if d, ok := devFSCache[root]; ok {
		return d
	}
	var d devFS
	var r, dv unix.Stat_t
	if unix.Stat(root, &r) == nil && unix.Lstat(root+"/dev", &dv) == nil && dv.Mode&unix.S_IFMT == unix.S_IFDIR && dv.Dev != r.Dev {
		d = devFS{dev: uint64(dv.Dev), ok: true}
	}
	devFSCache[root] = d
	return d
}

// onDevFS reports whether a file with device number dev lies on the device
// filesystem d.
func onDevFS(dev uint64, d devFS) bool { return d.ok && dev == d.dev }

// openMode says what openChecked accepts besides "a regular file".
type openMode struct {
	// follow lets the last name be a symbolic link (the kernel's own
	// /proc/<pid>/exe); otherwise a link there is errIsSymlink.
	follow bool
	// kernel lets the file lie on a kernel or device filesystem: for the
	// fixed files of /proc and /sys the collector reads on purpose.
	kernel bool
	// root is the examined root, to tell its device filesystem.
	root string
}

// openChecked opens name (relative to dirfd, or a path with unix.AT_FDCWD)
// for reading, only once it is known to be a regular file. Anything else is
// never opened: errIsSymlink, errNotRegular, or errKernelFS for a file on a
// kernel or device filesystem. The Stat_t describes the file that was
// opened.
func openChecked(dirfd int, name string, m openMode) (int, unix.Stat_t, error) {
	var st unix.Stat_t
	flags := unix.O_PATH | unix.O_CLOEXEC
	if !m.follow {
		flags |= unix.O_NOFOLLOW
	}
	pfd, err := unix.Openat(dirfd, name, flags, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return -1, st, errIsSymlink
		}
		return -1, st, &fs.PathError{Op: "open", Path: name, Err: err}
	}
	defer unix.Close(pfd)
	if err := unix.Fstat(pfd, &st); err != nil {
		return -1, st, err
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFREG:
	case unix.S_IFLNK:
		return -1, st, errIsSymlink
	default:
		return -1, st, errNotRegular
	}
	if !m.kernel && (kernelFS(pfd) || onDevFS(uint64(st.Dev), devFSOf(m.root))) {
		return -1, st, errKernelFS
	}
	fd, err := reopenFn(pfd)
	if err != nil {
		// Without /proc there is no way to open what the handle holds;
		// opening the name again could open something else by now.
		return -1, st, &fs.PathError{Op: "open", Path: name, Err: err}
	}
	var now unix.Stat_t
	if err := unix.Fstat(fd, &now); err != nil || now.Dev != st.Dev || now.Ino != st.Ino || now.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(fd)
		return -1, st, errNotRegular
	}
	return fd, now, nil
}
