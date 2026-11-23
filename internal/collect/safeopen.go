package collect

import (
	"errors"
	"io/fs"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// The scan runs as root and reads what it finds at the persistence paths.
// Some of those paths belong to ordinary users (their shell start-up files,
// their systemd user units), who can put a symbolic link there, or anywhere
// on the way, and so choose what root opens. The rules here keep a user
// from getting root to read, and report, a file the user could not read:
//
//   - a path is resolved one component at a time, each opened relative to
//     the directory before it, so nothing can be swapped between the check
//     and the open;
//   - a symbolic link on the way that a non-root account owns is not
//     followed;
//   - nothing below a kernel filesystem (/proc, /sys) is passed through;
//   - what a non-root account's link leads to is read only when that
//     account could read it (readableBy).

var (
	// errUserLink: a symbolic link on the way belongs to a non-root account.
	errUserLink = errors.New("a directory on the way is a symbolic link owned by a non-root user")
	// errLinkLoop: more links on the way than the kernel would follow.
	errLinkLoop = errors.New("too many symbolic links on the way")
)

// Fixed reasons for content the collector decided not to keep.
const (
	skipSecretTarget   = "target is a secret file, content not kept"
	skipUserLinkTarget = "target lies behind a symbolic link owned by a non-root user, content not kept"
	skipUnreadable     = "target is not readable by the link's owner, content not kept"
	skipHardLink       = "has more than one hard link and belongs to another account, content not kept"
	skipUserLinkPath   = "a directory on the way is a symbolic link owned by a non-root user: not followed"
)

const (
	// maxLinkHops is the kernel's own limit on links followed in one walk.
	maxLinkHops = 40
	// maxWalkSteps bounds the components one walk looks at.
	maxWalkSteps = 4096
)

// selfUID is the account the collector runs as. Its links are trusted like
// root's: following them reads nothing the collector could not read anyway.
var selfUID = uint32(os.Geteuid())

// ownerOf is the owner of the file st describes. Tests replace it to stand
// in for files of other accounts, which only root can create.
var ownerOf = func(st *unix.Stat_t) uint32 { return st.Uid }

// trustedOwner reports whether links owned by uid are followed freely.
func trustedOwner(uid uint32) bool { return uid == 0 || uid == selfUID }

// place is the directory a walk reached, held open, and the last name of
// the walked path inside it. The name is not resolved: it may be a symbolic
// link, which the caller decides about.
type place struct {
	dir  int    // O_PATH descriptor of the directory; -1 when unset
	name string // "" when the path names the directory itself
	real string // the machine path of the directory really reached
	// shut is true when a directory on the way can be searched neither by
	// everyone nor by its owner being the account the walk was made for.
	shut bool
	// link is the machine path of the link the walk refused (errUserLink).
	link string
}

func (p place) close() {
	if p.dir >= 0 {
		unix.Close(p.dir)
	}
}

// path is the machine path of the name really reached.
func (p place) path() string {
	if p.name == "" {
		return p.real
	}
	if p.real == "/" {
		return "/" + p.name
	}
	return p.real + "/" + p.name
}

// lstat describes the name itself, not what a link there leads to.
func (p place) lstat() (unix.Stat_t, error) {
	var st unix.Stat_t
	if p.name == "" {
		return st, unix.Fstat(p.dir, &st)
	}
	return st, unix.Fstatat(p.dir, p.name, &st, unix.AT_SYMLINK_NOFOLLOW)
}

// readlink reads the link at the name.
func (p place) readlink() (string, error) {
	if p.name == "" {
		return "", unix.EINVAL
	}
	return readlinkat(p.dir, p.name)
}

// open opens the name without following a link there and verifies the
// descriptor is a regular file off the kernel filesystems (a FIFO must not
// block). The returned Stat_t describes the opened descriptor.
func (p place) open() (*os.File, unix.Stat_t, error) {
	var st unix.Stat_t
	if p.name == "" {
		return nil, st, errors.New("not a regular file")
	}
	fd, err := unix.Openat(p.dir, p.name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, st, errors.New("is a symlink")
		}
		return nil, st, &fs.PathError{Op: "open", Path: p.path(), Err: err}
	}
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, st, err
	}
	if kernelFS(fd) {
		unix.Close(fd)
		return nil, st, errKernelFS
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(fd)
		return nil, st, errors.New("not a regular file")
	}
	return os.NewFile(uintptr(fd), p.path()), st, nil
}

func readlinkat(dir int, name string) (string, error) {
	for n := 256; ; n *= 2 {
		buf := make([]byte, n)
		got, err := unix.Readlinkat(dir, name, buf)
		if err != nil {
			return "", err
		}
		if got < n {
			return string(buf[:got]), nil
		}
		if n > 1<<16 {
			return "", unix.ENAMETOOLONG
		}
	}
}

// readableBy reports whether the account uid could read the regular file st
// describes, reached by a walk made for uid: it owns the file, or everyone
// may read it and search every directory on the way. Group membership is
// not looked at: a file only a group can read counts as unreadable.
func readableBy(uid uint32, st *unix.Stat_t, shut bool) bool {
	return ownerOf(st) == uid || (st.Mode&0o004 != 0 && !shut)
}

// walkTo resolves every component of the machine path mp but the last,
// below root, the way the kernel does, and returns the directory reached
// with the last name. forUID is the account the walk is made for (place.shut
// is relative to it). The caller closes the place.
//
// A walk never leaves root: an absolute link starts again at root and ".."
// at root stays there.
func walkTo(root, mp string, forUID uint32) (place, error) {
	none := place{dir: -1}
	if root == "" {
		root = "/"
	}
	rootfd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return none, &fs.PathError{Op: "open", Path: root, Err: err}
	}
	type level struct {
		fd   int
		name string
	}
	stack := []level{{rootfd, ""}}
	keep := -1
	defer func() {
		for _, l := range stack {
			if l.fd != keep {
				unix.Close(l.fd)
			}
		}
	}()
	real := func() string {
		var b strings.Builder
		for _, l := range stack[1:] {
			b.WriteByte('/')
			b.WriteString(l.name)
		}
		if b.Len() == 0 {
			return "/"
		}
		return b.String()
	}
	comps := strings.Split(mp, "/")
	shut := false
	hops, steps := 0, 0
	for {
		// Drop what names no step: empty components and ".".
		for len(comps) > 0 && (comps[0] == "" || comps[0] == ".") {
			comps = comps[1:]
		}
		top := stack[len(stack)-1].fd
		if len(comps) == 0 {
			keep = top
			return place{dir: top, real: real(), shut: shut}, nil
		}
		name := comps[0]
		if steps++; steps > maxWalkSteps {
			return none, errLinkLoop
		}
		if name == ".." {
			if len(stack) > 1 {
				unix.Close(top)
				stack = stack[:len(stack)-1]
			}
			comps = comps[1:]
			continue
		}
		last := true
		for _, c := range comps[1:] {
			if c != "" && c != "." {
				last = false
				break
			}
		}
		if last && len(comps) == 1 {
			keep = top
			return place{dir: top, name: name, real: real(), shut: shut}, nil
		}
		fd, err := unix.Openat(top, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return none, &fs.PathError{Op: "open", Path: mp, Err: err}
		}
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			unix.Close(fd)
			return none, &fs.PathError{Op: "stat", Path: mp, Err: err}
		}
		switch st.Mode & unix.S_IFMT {
		case unix.S_IFLNK:
			if !trustedOwner(ownerOf(&st)) {
				unix.Close(fd)
				pl := none
				pl.link = strings.TrimSuffix(real(), "/") + "/" + name
				return pl, errUserLink
			}
			target, err := readlinkat(fd, "")
			unix.Close(fd)
			if err != nil {
				return none, &fs.PathError{Op: "readlink", Path: mp, Err: err}
			}
			if hops++; hops > maxLinkHops {
				return none, errLinkLoop
			}
			if target == "" {
				return none, &fs.PathError{Op: "open", Path: mp, Err: unix.ENOENT}
			}
			if strings.HasPrefix(target, "/") {
				for _, l := range stack[1:] {
					unix.Close(l.fd)
				}
				stack = stack[:1]
			}
			comps = append(strings.Split(target, "/"), comps[1:]...)
		case unix.S_IFDIR:
			if kernelFS(fd) {
				unix.Close(fd)
				return none, errKernelFS
			}
			if st.Mode&0o001 == 0 && ownerOf(&st) != forUID {
				shut = true
			}
			stack = append(stack, level{fd, name})
			comps = comps[1:]
		default:
			unix.Close(fd)
			return none, &fs.PathError{Op: "open", Path: mp, Err: unix.ENOTDIR}
		}
	}
}
