package collect

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/persistsig"
	"github.com/donaldsteele/telltale/internal/redact"
	"golang.org/x/sys/unix"
)

const persistCheck = "persistence"

// maxPersistBytes is the largest persistence file whose text is kept.
const maxPersistBytes = 256 << 10

func isNotExist(err error) bool { return errors.Is(err, fs.ErrNotExist) }

// openRegular opens root+mp without following a final symlink and verifies
// the descriptor is a regular file (a FIFO must not block).
func openRegular(root, mp string) (*os.File, unix.Stat_t, error) {
	p := filepath.Join(root, mp)
	var st unix.Stat_t
	fd, err := unix.Open(p, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, st, errors.New("is a symlink")
		}
		return nil, st, &fs.PathError{Op: "open", Path: mp, Err: err}
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
	return os.NewFile(uintptr(fd), p), st, nil
}

// readRaw reads a whole regular file of at most max bytes.
func readRaw(root, mp string, max int64) ([]byte, error) {
	f, _, err := openRegular(root, mp)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, errors.New("too large")
	}
	return b, nil
}

func splitLines(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	s := strings.TrimSuffix(string(b), "\n")
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimSuffix(l, "\r")
	}
	return lines
}

type collector struct {
	root  string
	key   []byte
	out   []model.PersistFile
	skips []model.Skip
	seen  map[string]bool
	// user is set while a user's own paths are read: the account they
	// belong to.
	user *model.User
	// kept counts the bytes of text kept so far; userText those from the
	// users' unit directories.
	kept, userText int
	// hashOnly makes file record a regular file without its text, and
	// without reading one too large to keep.
	hashOnly bool
	// flooded lists the user unit directories cut short at a budget;
	// refused the links that were not followed.
	flooded, refused []string
}

func (c *collector) skip(mp, reason string) {
	c.skips = append(c.skips, model.Skip{Check: persistCheck, Reason: mp + ": " + reason})
}

func (c *collector) meta(st unix.Stat_t, pf *model.PersistFile) {
	pf.Mode = st.Mode
	pf.UID = st.Uid
	pf.MTime = time.Unix(st.Mtim.Unix()).UTC()
}

// maxHashBytes caps how much of one persistence file is read for hashing;
// larger files (e.g. a sparse ~/.bashrc) get metadata and a Skip only.
const maxHashBytes = 64 << 20

// file records one file at a persistence location. Missing files are
// silent; symlinks are recorded via link; anything else that cannot be read
// becomes a Skip.
func (c *collector) file(mp, kind string) {
	mp = path.Clean(mp)
	if c.seen[kind+"\x00"+mp] {
		return
	}
	// A user's own link on the way to the user's own file is followed
	// (pl.own): what it leads to is then read only if the user could.
	var uid uint32
	if c.user != nil {
		uid = uint32(c.user.UID)
	}
	pl, err := walkTo(c.root, mp, uid, c.user != nil)
	if err != nil {
		switch {
		case errors.Is(err, errUserLink):
			// Not followed, but not lost either: the link is recorded, so
			// it is seen and compared like any link at a persistence path.
			c.skip(mp, skipUserLinkPath)
			c.refuse(pl.link, kind)
		case !isNotExist(err) && !errors.Is(err, unix.ENOTDIR):
			c.skip(mp, err.Error())
		}
		return
	}
	defer pl.close()
	lst, err := pl.lstat()
	if err != nil {
		if !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ENOTDIR) {
			c.skip(mp, err.Error())
		}
		return
	}
	if lst.Mode&unix.S_IFMT == unix.S_IFLNK {
		c.seen[kind+"\x00"+mp] = true
		c.link(pl, mp, kind, lst, true)
		return
	}
	f, st, err := pl.open()
	if err != nil {
		if !isNotExist(err) && !errors.Is(err, unix.ENOTDIR) {
			c.skip(mp, err.Error())
		}
		return
	}
	defer f.Close()
	c.seen[kind+"\x00"+mp] = true
	if pl.own && !readableBy(uid, &st, pl.shut) {
		// Nothing of the file is recorded, not even its size or dates:
		// the user could not have seen those either.
		c.skip(mp, skipOwnLinkPath)
		c.refuse(pl.link, kind)
		return
	}

	pf := model.PersistFile{Path: mp, Kind: kind}
	c.meta(st, &pf)
	// A user's own path, in a directory that user (or anyone) can make
	// names in: the file may be a hard link the user made to a file the
	// user cannot read, so its content is kept only if the user could read
	// it. The link count proves nothing (once the original is replaced,
	// one name is left). A directory only root writes is different: a
	// root-owned key file there (AuthorizedKeysFile /etc/ssh/keys/%u) is
	// root's to place and is read.
	if c.user != nil && pl.userControlled() && !readableBy(uid, &st, pl.shut) {
		reason := skipNotReadable
		if st.Nlink > 1 {
			reason = skipHardLink
		}
		c.skip(mp, reason)
		c.out = append(c.out, pf)
		return
	}
	if c.hashOnly && st.Size > maxPersistBytes {
		c.out = append(c.out, pf)
		return
	}
	// A second name for a file of another account that not everyone may
	// read (ln /etc/shadow ~/.bashrc, where the kernel still allows it):
	// the user chose what is read here.
	if c.user != nil && st.Nlink > 1 && st.Mode&0o004 == 0 && int64(ownerOf(&st)) != int64(c.user.UID) {
		c.skip(mp, skipHardLink)
		c.out = append(c.out, pf)
		return
	}
	if st.Size > maxHashBytes {
		c.skip(mp, fmt.Sprintf("larger than %d bytes: metadata only, not read", maxHashBytes))
		c.out = append(c.out, pf)
		return
	}
	h := sha256.New()
	buf, err := io.ReadAll(io.LimitReader(f, maxPersistBytes+1))
	if err != nil {
		c.skip(mp, "read: "+err.Error())
		return
	}
	h.Write(buf)
	large := len(buf) > maxPersistBytes
	if large {
		if _, err := io.Copy(h, io.LimitReader(f, maxHashBytes)); err != nil {
			c.skip(mp, "read: "+err.Error())
			return
		}
		c.skip(mp, fmt.Sprintf("larger than %d bytes: hash and metadata only", maxPersistBytes))
	}
	pf.SHA256 = hex.EncodeToString(h.Sum(nil))
	if !large && !c.hashOnly {
		// Matched on the raw text: redaction can swallow the rest of a line.
		pf.Signals = persistsig.Detect(kind, splitLines(buf))
		pf.Lines = c.redactLines(buf, &pf)
		c.kept += len(buf)
	}
	c.out = append(c.out, pf)
}

func (c *collector) redactLines(b []byte, pf *model.PersistFile) []string {
	lines := []string{}
	for _, l := range splitLines(b) {
		r, n := redact.Line(c.key, l)
		lines = append(lines, r)
		pf.Redactions += n
	}
	return lines
}

// secretTarget reports whether a symlink target must never have its content
// kept: the password files' hashes, the backups the account tools and
// editors leave of them and of passwd and group, and the SSH host keys.
func secretTarget(tp string) bool {
	switch tp {
	case "/etc/shadow", "/etc/gshadow", "/etc/security/opasswd":
		return true
	}
	if name, ok := strings.CutPrefix(tp, "/etc/"); ok {
		for _, base := range []string{"passwd", "shadow", "gshadow", "group"} {
			for _, suffix := range []string{"-", "~", ".bak", ".old"} {
				if name == base+suffix {
					return true
				}
			}
		}
	}
	return strings.HasPrefix(tp, "/etc/ssh/") && strings.HasSuffix(tp, "_key")
}

// hasPrivateKey reports whether any line of the text starts a PEM private
// key block.
func hasPrivateKey(b []byte) bool {
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimLeft(l, " \t\ufeff"); strings.HasPrefix(l, "-----BEGIN") && strings.Contains(l, "PRIVATE KEY") {
			return true
		}
	}
	return false
}

// linkTarget resolves a symlink's target text to a machine path.
func linkTarget(mp, target string) string {
	if path.IsAbs(target) {
		return path.Clean(target)
	}
	return path.Join(path.Dir(mp), target)
}

// link records the symlink at mp, which is the name in pl. Lines[0] is the
// redacted target text. When readContent is set and the target resolves to
// a regular file whose content may be kept, its redacted lines follow and
// SHA256 is the hash of the target's raw bytes; otherwise SHA256 is the hash
// of the target text.
//
// The content is not kept, and a Skip with a fixed reason says so, when the
// target is a secret file by name or holds a private key, lies on a kernel
// filesystem or behind a link a non-root account owns, or is a file the
// link's owner could not read (see safeopen.go).
func (c *collector) link(pl place, mp, kind string, lst unix.Stat_t, readContent bool) {
	target, err := pl.readlink()
	if err != nil {
		c.skip(mp, err.Error())
		return
	}
	sum := sha256.Sum256([]byte(target))
	r, n := redact.Line(c.key, target)
	pf := model.PersistFile{Path: mp, Kind: kind, SHA256: hex.EncodeToString(sum[:]), Lines: []string{r}, Redactions: n}
	c.meta(lst, &pf)
	defer func() { c.out = append(c.out, pf) }()
	if !readContent {
		return
	}
	if secretTarget(linkTarget(mp, target)) {
		c.skip(mp, skipSecretTarget)
		return
	}
	// Walked from the directory the link is really in, through the target
	// as written, so that ".." and every link on the way mean what they
	// mean to the kernel.
	owner := ownerOf(&lst)
	if pl.own && c.user != nil {
		// Reached through the user's own link: whoever owns this one, the
		// user chose it.
		owner = uint32(c.user.UID)
	}
	from := target
	if !path.IsAbs(target) {
		from = pl.real + "/" + target
	}
	tpl, err := walkTo(c.root, from, owner, false)
	if err != nil {
		switch {
		case errors.Is(err, errUserLink):
			c.skip(mp, skipUserLinkTarget)
		case errors.Is(err, errKernelFS):
			c.skip(mp, "target: "+err.Error())
		}
		return // dangling: target text only
	}
	defer tpl.close()
	if secretTarget(tpl.path()) {
		c.skip(mp, skipSecretTarget)
		return
	}
	f, st, err := tpl.open()
	if err != nil {
		if errors.Is(err, errKernelFS) {
			c.skip(mp, "target: "+err.Error())
		}
		return // dangling, device, FIFO or another symlink: target text only
	}
	defer f.Close()
	// Decided on the opened file, so it cannot be swapped afterwards.
	if !trustedOwner(owner) && !readableBy(owner, &st, tpl.shut) {
		c.skip(mp, skipUnreadable)
		return
	}
	if st.Size > maxPersistBytes {
		c.skip(mp, fmt.Sprintf("target larger than %d bytes: content not kept", maxPersistBytes))
		return
	}
	buf, err := io.ReadAll(io.LimitReader(f, maxPersistBytes+1))
	if err != nil || len(buf) > maxPersistBytes {
		return
	}
	if hasPrivateKey(buf) {
		c.skip(mp, skipSecretTarget)
		return
	}
	raw := sha256.Sum256(buf)
	pf.SHA256 = hex.EncodeToString(raw[:])
	pf.Lines = append(pf.Lines, c.redactLines(buf, &pf)...)
	c.kept += len(buf)
}

// dir records the files and symlinks directly inside dir; subdirectories
// are ignored.
func (c *collector) dir(dir, kind string) {
	ents, err := os.ReadDir(filepath.Join(c.root, dir))
	if err != nil {
		if !isNotExist(err) && !errors.Is(err, unix.ENOTDIR) {
			c.skip(dir, err.Error())
		}
		return
	}
	for _, e := range ents {
		if e.Type().IsRegular() || e.Type()&fs.ModeSymlink != 0 {
			c.file(path.Join(dir, e.Name()), kind)
		}
	}
}

// enabledLink records a systemd *.wants/*.requires/*.upholds link: the
// target text is the only line.
func (c *collector) enabledLink(mp string) {
	c.refusedLink(mp, model.PersistKindSystemdEnabled)
}

// refuse records a link that was not followed: as a persistence entry with
// its target text (refusedLink), so it is compared and ranked like any link
// at a startup path, and by name for a note in the report. A link that is
// not followed is never only a Skip.
func (c *collector) refuse(link, kind string) {
	if link == "" {
		return
	}
	c.refusedLink(link, kind)
	if !slices.Contains(c.refused, link) {
		c.refused = append(c.refused, link)
	}
}

// refusedLink records the symbolic link at mp by its target text alone.
func (c *collector) refusedLink(mp, kind string) {
	if mp == "" || c.seen[kind+"\x00"+mp] {
		return
	}
	var uid uint32
	if c.user != nil {
		uid = uint32(c.user.UID)
	}
	pl, err := walkTo(c.root, mp, uid, c.user != nil)
	if err != nil {
		return
	}
	defer pl.close()
	st, err := pl.lstat()
	if err != nil || st.Mode&unix.S_IFMT != unix.S_IFLNK {
		return
	}
	c.seen[kind+"\x00"+mp] = true
	c.link(pl, mp, kind, st, false)
}

// isUnitName reports whether systemd reads a file of this name as a unit.
func isUnitName(n string) bool {
	for _, s := range []string{".service", ".timer", ".socket", ".path", ".mount", ".target"} {
		if strings.HasSuffix(n, s) {
			return true
		}
	}
	return false
}

// unitBudget counts what one walk of a user's unit directory has used.
type unitBudget struct {
	dir           string
	entries, text int
	stopped       bool
	// own is set when the tree was reached through a link of the user's
	// own: every directory in it is then entered only if uid could.
	own bool
	uid uint32
}

// maxUnitDepth is how deep a unit tree is walked.
const maxUnitDepth = 8

// unitDirInSystem reports whether a unit directory that is a link leads
// somewhere only root and packages write.
func unitDirInSystem(real string) bool {
	for _, pre := range []string{"/usr/", "/lib/", "/etc/", "/run/systemd/"} {
		if strings.HasPrefix(real+"/", pre) {
			return true
		}
	}
	return false
}

// systemd walks a unit tree without following symbolic links inside it.
// Unit-named files and drop-in .conf files are read; with all, every regular
// file is.
//
// With a budget b the tree is a user's own (anyone can fill theirs): the
// walk stops at the budget, with a Skip and an entry in c.flooded, and a
// file that is no unit is recorded by hash only.
//
// The directory itself may be a symbolic link. It is walked where it leads
// when root made the link and it leads into the system directories;
// otherwise it is not walked and a Skip says so. A link on the way to it
// that a non-root account owns is never followed.
func (c *collector) systemd(dir string, all bool, b *unitBudget) {
	dir = path.Clean(dir)
	const kind = model.PersistKindSystemdUnit
	// A user's own unit directory: links that user owns on the way are
	// followed (~/.config kept in a dotfiles directory), and what is
	// reached is read only where that user could read it.
	var uid uint32
	own := c.user != nil && b != nil
	if own {
		uid = uint32(c.user.UID)
	}
	pl, err := walkTo(c.root, dir, uid, own)
	if err != nil {
		switch {
		case errors.Is(err, errUserLink):
			c.skip(dir, skipUserLinkPath)
			c.refuse(pl.link, kind)
		case !isNotExist(err) && !errors.Is(err, unix.ENOTDIR):
			c.skip(dir, err.Error())
		}
		return
	}
	defer pl.close()
	lst, err := pl.lstat()
	if err != nil {
		if !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ENOTDIR) {
			c.skip(dir, err.Error())
		}
		return
	}
	var fd int
	via, shut, link := pl.own, pl.shut, pl.link
	switch lst.Mode & unix.S_IFMT {
	case unix.S_IFLNK:
		owner := ownerOf(&lst)
		byRoot := trustedOwner(owner)
		if !byRoot && !(own && owner == uid) {
			c.skip(dir, skipLinkedUnitDir)
			c.refuse(dir, kind)
			return
		}
		rp, err := walkTo(c.root, dir+"/.", uid, own)
		if err != nil {
			switch {
			case errors.Is(err, errUserLink):
				c.skip(dir, skipLinkedUnitDir)
				c.refuse(dir, kind)
			case !isNotExist(err) && !errors.Is(err, unix.ENOTDIR):
				c.skip(dir, err.Error())
			}
			return // a dangling link: nothing to walk
		}
		defer rp.close()
		if byRoot && !rp.own {
			if !unitDirInSystem(rp.real) {
				c.skip(dir, skipLinkedUnitDir)
				c.refuse(dir, kind)
				return
			}
		} else {
			via, shut = true, rp.shut
			if link == "" {
				link = dir
			}
		}
		fd, err = unix.Openat(rp.dir, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			c.skip(dir, err.Error())
			return
		}
	case unix.S_IFDIR:
		fd, err = unix.Openat(pl.dir, pl.name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			c.skip(dir, err.Error())
			return
		}
	default:
		return
	}
	if via {
		// Reached through the user's own link: listed only if the user
		// could list it.
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil || !dirReadableBy(uid, &st, shut) {
			unix.Close(fd)
			c.skip(dir, skipOwnLinkPath)
			c.refuse(link, kind)
			return
		}
		b.own, b.uid = true, uid
	}
	c.unitTree(fd, dir, all, b, 0)
}

// flood stops a budgeted walk and says so.
func (c *collector) flood(b *unitBudget, why string) {
	if b.stopped {
		return
	}
	b.stopped = true
	c.skip(b.dir, fmt.Sprintf("stopped after %d entries and %d bytes of kept text (%s); the rest of this directory was not read", b.entries, b.text, why))
	c.flooded = append(c.flooded, b.dir)
}

// unitTree walks the open directory fd, which is the machine path mp, and
// closes it.
func (c *collector) unitTree(fd int, mp string, all bool, b *unitBudget, depth int) {
	f := os.NewFile(uintptr(fd), mp)
	defer f.Close()
	if kernelFS(fd) {
		c.skip(mp, errKernelFS.Error())
		return
	}
	// No more names are read than the budget leaves room for.
	var ents []fs.DirEntry
	for {
		batch, err := f.ReadDir(512)
		ents = append(ents, batch...)
		if err != nil || len(batch) == 0 {
			if err != nil && !errors.Is(err, io.EOF) {
				c.skip(mp, err.Error())
			}
			break
		}
		if b != nil && len(ents) > userDirMaxEntries {
			break
		}
	}
	sort.Slice(ents, func(i, j int) bool { return ents[i].Name() < ents[j].Name() })
	parent := path.Base(mp)
	for _, d := range ents {
		if b != nil {
			switch {
			case b.stopped:
				return
			case b.entries >= userDirMaxEntries:
				c.flood(b, fmt.Sprintf("the limit is %d entries for one user's unit directory", userDirMaxEntries))
				return
			case b.text >= userDirMaxText:
				c.flood(b, fmt.Sprintf("the limit is %d bytes of text for one user's unit directory", userDirMaxText))
				return
			case c.userText >= usersMaxText:
				c.flood(b, fmt.Sprintf("the limit is %d bytes of text for all users' unit directories together", usersMaxText))
				return
			}
			b.entries++
		}
		child := path.Join(mp, d.Name())
		before := c.kept
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			if strings.HasSuffix(parent, ".wants") || strings.HasSuffix(parent, ".requires") || strings.HasSuffix(parent, ".upholds") {
				c.enabledLink(child)
			} else {
				c.file(child, model.PersistKindSystemdUnit)
			}
		case d.Type().IsRegular():
			dropin := strings.HasSuffix(parent, ".d") && strings.HasSuffix(d.Name(), ".conf")
			switch {
			case all || isUnitName(d.Name()) || dropin:
				c.file(child, model.PersistKindSystemdUnit)
			case b != nil:
				c.hashOnly = true
				c.file(child, model.PersistKindSystemdUnit)
				c.hashOnly = false
			}
		case d.IsDir():
			if depth >= maxUnitDepth {
				c.skip(child, fmt.Sprintf("more than %d directories deep: not walked", maxUnitDepth))
				continue
			}
			sub, err := unix.Openat(fd, d.Name(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				if !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ENOTDIR) && !errors.Is(err, unix.ELOOP) {
					c.skip(child, err.Error())
				}
				continue
			}
			if b != nil && b.own {
				var st unix.Stat_t
				if err := unix.Fstat(sub, &st); err != nil || !dirReadableBy(b.uid, &st, false) {
					unix.Close(sub)
					c.skip(child, skipOwnLinkPath)
					continue
				}
			}
			c.unitTree(sub, child, all, b, depth+1)
		}
		if b != nil {
			b.text += c.kept - before
			c.userText += c.kept - before
		}
	}
}

// PersistenceScan reads every place a backdoor typically hides, with text
// redacted. users supplies the home directories for per-user files.
func PersistenceScan(root string, users []model.User, key []byte) PersistResult {
	c := &collector{root: strings.TrimRight(root, "/"), key: key, seen: map[string]bool{}}

	c.file("/etc/sudoers", model.PersistKindSudoers)
	c.dir("/etc/sudoers.d", model.PersistKindSudoers)

	sshdFiles, akf := c.sshdConfig()
	for _, p := range sshdFiles {
		c.file(p, model.PersistKindSSHD)
	}
	c.file("/etc/ssh/ssh_config", model.PersistKindSSHClient)
	c.dir("/etc/ssh/ssh_config.d", model.PersistKindSSHClient)

	c.file("/etc/crontab", model.PersistKindCron)
	c.dir("/etc/cron.d", model.PersistKindCron)
	for _, p := range []string{"hourly", "daily", "weekly", "monthly"} {
		c.dir("/etc/cron."+p, model.PersistKindCron)
	}
	c.dir("/var/spool/cron/crontabs", model.PersistKindCron)
	c.dir("/var/spool/cron/atjobs", model.PersistKindAt)

	c.systemd("/etc/systemd/system", false, nil)
	c.systemd("/run/systemd/system", true, nil)

	c.file("/etc/rc.local", model.PersistKindRC)
	c.dir("/etc/init.d", model.PersistKindRC)
	c.file("/etc/profile", model.PersistKindProfile)
	c.dir("/etc/profile.d", model.PersistKindProfile)
	c.file("/etc/bash.bashrc", model.PersistKindProfile)
	c.file("/etc/environment", model.PersistKindProfile)
	c.file("/etc/ld.so.preload", model.PersistKindLDPreload)
	c.file("/etc/ld.so.conf", model.PersistKindLDConf)
	c.dir("/etc/ld.so.conf.d", model.PersistKindLDConf)
	c.dir("/etc/pam.d", model.PersistKindPAM)
	c.file("/etc/hosts", model.PersistKindHosts)
	c.file("/etc/resolv.conf", model.PersistKindResolver)
	c.file("/etc/nsswitch.conf", model.PersistKindResolver)
	c.file("/etc/modules", model.PersistKindModulesLoad)
	c.dir("/etc/modules-load.d", model.PersistKindModulesLoad)
	c.dir("/etc/modprobe.d", model.PersistKindModprobe)

	for _, u := range users {
		home := path.Clean(u.Home)
		if u.Home == "" || !path.IsAbs(home) {
			continue
		}
		c.user = &u
		for _, n := range []string{".bashrc", ".profile", ".bash_profile", ".bash_login", ".zshrc"} {
			c.file(path.Join(home, n), model.PersistKindShellRC)
		}
		for _, d := range []string{".config/systemd/user", ".local/share/systemd/user"} {
			dir := path.Join(home, d)
			c.systemd(dir, false, &unitBudget{dir: dir})
		}
		for _, pat := range akf {
			c.file(expandAKF(pat, home, u.Name), model.PersistKindAuthorizedKeys)
		}
		c.user = nil
	}

	sort.Slice(c.out, func(i, j int) bool {
		if c.out[i].Path != c.out[j].Path {
			return c.out[i].Path < c.out[j].Path
		}
		return c.out[i].Kind < c.out[j].Kind
	})
	sort.Strings(c.flooded)
	sort.Strings(c.refused)
	return PersistResult{Files: c.out, Skips: c.skips, Flooded: c.flooded, Refused: c.refused}
}

// expandAKF expands %h, %u and %% in an AuthorizedKeysFile pattern; relative
// results are relative to home.
func expandAKF(pat, home, user string) string {
	var b strings.Builder
	for i := 0; i < len(pat); i++ {
		if pat[i] != '%' || i+1 == len(pat) {
			b.WriteByte(pat[i])
			continue
		}
		i++
		switch pat[i] {
		case 'h':
			b.WriteString(home)
		case 'u':
			b.WriteString(user)
		case '%':
			b.WriteByte('%')
		default:
			b.WriteByte('%')
			b.WriteByte(pat[i])
		}
	}
	p := b.String()
	if !path.IsAbs(p) {
		p = path.Join(home, p)
	}
	return path.Clean(p)
}

// Budgets for what one user can make a scan keep from the user's own unit
// directories (anyone can fill those).
var (
	// userDirMaxEntries is how many entries of one user unit directory
	// tree are looked at.
	userDirMaxEntries = 2000
	// userDirMaxText is how much text is kept from one such tree.
	userDirMaxText = 8 << 20
	// usersMaxText is how much text is kept from all of them together.
	usersMaxText = 64 << 20
)

const skipLinkedUnitDir = "the unit directory is a symbolic link that root did not make or that leads outside the system directories: not walked"

// PersistResult is what PersistenceScan found.
type PersistResult struct {
	Files []model.PersistFile
	Skips []model.Skip
	// Flooded lists the user unit directories whose walk stopped at a
	// budget, sorted.
	Flooded []string
	// Refused lists the symbolic links at or on the way to a user's
	// startup paths that were not followed, sorted. Each is also among
	// Files, by its target text.
	Refused []string
}

// Persistence is PersistenceScan without the list of directories cut short.
func Persistence(root string, users []model.User, key []byte) ([]model.PersistFile, []model.Skip) {
	r := PersistenceScan(root, users, key)
	return r.Files, r.Skips
}
