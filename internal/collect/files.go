// Package collect gathers raw facts from the machine being examined.
package collect

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/donaldsteele/telltale/internal/model"
	"golang.org/x/sys/unix"
)

// SystemPaths are the trees the file inventory walks by default. Entries that
// are symlinks (merged /usr) are recorded as symlinks and not walked twice.
var SystemPaths = []string{"/bin", "/sbin", "/usr", "/lib", "/lib32", "/lib64", "/libx32", "/etc", "/boot", "/root", "/var/spool/cron", "/var/lib/dpkg/info"}

// skipFSTypes are filesystem types never descended into when nested under a
// walked path. "fuse.*" also matches plain "fuse".
var skipFSTypes = []string{"nfs", "nfs4", "cifs", "smb3", "sshfs", "fuse.*", "proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "cgroup", "cgroup2", "securityfs", "debugfs", "tracefs", "bpf", "pstore", "configfs", "autofs"}

// FileOptions tunes Files. MaxHashBytes 0 means no limit. Mounts are machine
// paths (without the root prefix).
type FileOptions struct {
	MaxHashBytes int64
	Mounts       []model.Mount
	// MD5 also records the md5 of regular files, to compare with dpkg.
	MD5 bool
}

// testHookBeforeOpen, when non-nil, runs just before a file is opened for
// hashing. Tests only.
var testHookBeforeOpen func(path string)

const checkName = "files"

func skipFS(t string) bool {
	for _, s := range skipFSTypes {
		if s == "fuse.*" {
			if t == "fuse" || strings.HasPrefix(t, "fuse.") {
				return true
			}
		} else if s == t {
			return true
		}
	}
	return false
}

// Files walks each of paths under root (never following symlinks) and returns
// one entry per path found. Paths in entries are machine paths, byte-exact.
func Files(root string, paths []string, opt FileOptions) ([]model.FileEntry, []model.Skip) {
	var entries []model.FileEntry
	var skips []model.Skip
	root = strings.TrimRight(root, "/")

	skipMounts := make(map[string]string)
	for _, m := range opt.Mounts {
		if skipFS(m.FSType) {
			skipMounts[filepath.Clean(m.Path)] = m.FSType
		}
	}
	skip := func(path, reason string) {
		skips = append(skips, model.Skip{Check: checkName, Reason: path + ": " + reason})
	}

	seen := make(map[string]int)
	add := func(e model.FileEntry) {
		seen[e.Path] = len(entries)
		entries = append(entries, e)
	}

	for _, start := range paths {
		start = filepath.Clean("/" + start)
		real := filepath.Clean(root + start)
		_ = filepath.WalkDir(real, func(p string, d fs.DirEntry, err error) error {
			mp := p[len(root):]
			if mp == "" {
				mp = "/"
			}
			if err != nil {
				if i, ok := seen[mp]; ok {
					// Already recorded by the pre-read call (e.g. unreadable dir).
					entries[i].Err = err.Error()
				} else if errors.Is(err, fs.ErrNotExist) {
					skip(mp, "vanished: "+err.Error())
				} else {
					add(model.FileEntry{Path: mp, Err: err.Error()})
				}
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if d.IsDir() && mp != start {
				if t, ok := skipMounts[mp]; ok {
					skip(mp, "not descending into "+t+" mount")
					// Still record the mount point itself.
					if e, ok := statEntry(p, mp, opt, &skips); ok {
						add(e)
					}
					return fs.SkipDir
				}
			}
			e, ok := statEntry(p, mp, opt, &skips)
			if ok {
				add(e)
			}
			return nil
		})
	}
	return entries, skips
}

// statEntry builds the entry for one path. ok is false when the path vanished
// (a Skip is appended instead).
func statEntry(p, mp string, opt FileOptions, skips *[]model.Skip) (model.FileEntry, bool) {
	vanished := func(err error) {
		*skips = append(*skips, model.Skip{Check: checkName, Reason: mp + ": vanished: " + err.Error()})
	}
	var st unix.Stat_t
	if err := unix.Lstat(p, &st); err != nil {
		if errors.Is(err, unix.ENOENT) {
			vanished(err)
			return model.FileEntry{}, false
		}
		return model.FileEntry{Path: mp, Err: err.Error()}, true
	}
	e := model.FileEntry{
		Path:  mp,
		Mode:  st.Mode,
		UID:   st.Uid,
		GID:   st.Gid,
		Size:  st.Size,
		MTime: time.Unix(st.Mtim.Unix()).UTC(),
		CTime: time.Unix(st.Ctim.Unix()).UTC(),
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		e.Type = "file"
	case unix.S_IFDIR:
		e.Type = "dir"
	case unix.S_IFLNK:
		e.Type = "symlink"
		if t, err := os.Readlink(p); err == nil {
			e.Target = t
		} else {
			e.Err = err.Error()
		}
	default:
		e.Type = "other"
	}
	if e.Type != "symlink" {
		e.Caps = fileCaps(p)
	}
	switch e.Type {
	case "file":
		if testHookBeforeOpen != nil {
			testHookBeforeOpen(p)
		}
		fd, err := unix.Open(p, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			if errors.Is(err, unix.ENOENT) {
				vanished(err)
				return model.FileEntry{}, false
			}
			e.Err = err.Error()
			return e, true
		}
		var fst unix.Stat_t
		if err := unix.Fstat(fd, &fst); err != nil || fst.Mode&unix.S_IFMT != unix.S_IFREG || fst.Dev != st.Dev || fst.Ino != st.Ino {
			unix.Close(fd)
			e.Err = "changed while reading"
			return e, true
		}
		f := os.NewFile(uintptr(fd), p)
		defer f.Close()
		e.Flags = inodeFlags(fd)
		if opt.MaxHashBytes > 0 && st.Size > opt.MaxHashBytes {
			e.Err = "too large to hash"
			return e, true
		}
		var r io.Reader = f
		if opt.MaxHashBytes > 0 {
			r = io.LimitReader(f, opt.MaxHashBytes) // file may have grown since Lstat
		}
		h := sha256.New()
		m := md5.New()
		var w io.Writer = h
		if opt.MD5 {
			w = io.MultiWriter(h, m)
		}
		if _, err := io.Copy(w, r); err != nil {
			e.Err = fmt.Sprintf("read: %v", err)
			return e, true
		}
		e.SHA256 = hex.EncodeToString(h.Sum(nil))
		if opt.MD5 {
			e.MD5 = hex.EncodeToString(m.Sum(nil))
		}
	case "dir":
		fd, err := unix.Open(p, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err == nil {
			e.Flags = inodeFlags(fd)
			unix.Close(fd)
		}
	}
	return e, true
}
