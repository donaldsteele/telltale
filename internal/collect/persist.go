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
			c.refusedLink(pl.link, kind)
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
		c.refusedLink(pl.link, kind)
		return
	}

	pf := model.PersistFile{Path: mp, Kind: kind}
	c.meta(st, &pf)
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
	if !large {
		// Matched on the raw text: redaction can swallow the rest of a line.
		pf.Signals = persistsig.Detect(kind, splitLines(buf))
		pf.Lines = c.redactLines(buf, &pf)
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

// refusedLink records the symbolic link at mp by its target text alone.
func (c *collector) refusedLink(mp, kind string) {
	if mp == "" || c.seen[kind+"\x00"+mp] {
		return
	}
	pl, err := walkTo(c.root, mp, 0, false)
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

func isUnitName(n string) bool {
	for _, s := range []string{".service", ".timer", ".socket", ".path"} {
		if strings.HasSuffix(n, s) {
			return true
		}
	}
	return false
}

// systemd walks a unit tree without following symlinks. When all is true
// every regular file counts as a unit, otherwise only unit-named files and
// drop-in .conf files do.
func (c *collector) systemd(dir string, all bool) {
	base := filepath.Join(c.root, dir)
	_ = filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == base && !isNotExist(err) && !errors.Is(err, unix.ENOTDIR) {
				c.skip(dir, err.Error())
			}
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		mp := path.Join("/", filepath.ToSlash(p[len(strings.TrimRight(c.root, "/")):]))
		parent := path.Base(path.Dir(mp))
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			if strings.HasSuffix(parent, ".wants") || strings.HasSuffix(parent, ".requires") || strings.HasSuffix(parent, ".upholds") {
				c.enabledLink(mp)
			} else {
				c.file(mp, model.PersistKindSystemdUnit)
			}
		case d.Type().IsRegular():
			name := d.Name()
			dropin := strings.HasSuffix(parent, ".d") && strings.HasSuffix(name, ".conf")
			if all || isUnitName(name) || dropin {
				c.file(mp, model.PersistKindSystemdUnit)
			}
		}
		return nil
	})
}

// Persistence reads every place a backdoor typically hides, with text
// redacted. users supplies the home directories for per-user files.
func Persistence(root string, users []model.User, key []byte) ([]model.PersistFile, []model.Skip) {
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

	c.systemd("/etc/systemd/system", false)
	c.systemd("/run/systemd/system", true)

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
		c.systemd(path.Join(home, ".config/systemd/user"), true)
		c.systemd(path.Join(home, ".local/share/systemd/user"), true)
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
	return c.out, c.skips
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
