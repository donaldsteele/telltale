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
}

func (c *collector) skip(mp, reason string) {
	c.skips = append(c.skips, model.Skip{Check: persistCheck, Reason: mp + ": " + reason})
}

func (c *collector) meta(st unix.Stat_t, pf *model.PersistFile) {
	pf.Mode = st.Mode
	pf.UID = st.Uid
	pf.MTime = time.Unix(st.Mtim.Unix()).UTC()
}

// file records one regular file. Missing files are silent; anything else
// that cannot be read becomes a Skip.
func (c *collector) file(mp, kind string) {
	mp = path.Clean(mp)
	if c.seen[kind+"\x00"+mp] {
		return
	}
	f, st, err := openRegular(c.root, mp)
	if err != nil {
		if !isNotExist(err) && !errors.Is(err, unix.ENOTDIR) {
			c.skip(mp, err.Error())
		}
		return
	}
	defer f.Close()
	c.seen[kind+"\x00"+mp] = true

	pf := model.PersistFile{Path: mp, Kind: kind}
	c.meta(st, &pf)
	h := sha256.New()
	buf, err := io.ReadAll(io.LimitReader(f, maxPersistBytes+1))
	if err != nil {
		c.skip(mp, "read: "+err.Error())
		return
	}
	h.Write(buf)
	large := len(buf) > maxPersistBytes
	if large {
		if _, err := io.Copy(h, f); err != nil {
			c.skip(mp, "read: "+err.Error())
			return
		}
		c.skip(mp, fmt.Sprintf("larger than %d bytes: hash and metadata only", maxPersistBytes))
	}
	pf.SHA256 = hex.EncodeToString(h.Sum(nil))
	if !large {
		pf.Lines = []string{}
		for _, l := range splitLines(buf) {
			r, n := redact.Line(c.key, l)
			pf.Lines = append(pf.Lines, r)
			pf.Redactions += n
		}
	}
	c.out = append(c.out, pf)
}

// dir records the regular files directly inside dir, ignoring symlinked
// entries and subdirectories.
func (c *collector) dir(dir, kind string) {
	ents, err := os.ReadDir(filepath.Join(c.root, dir))
	if err != nil {
		if !isNotExist(err) && !errors.Is(err, unix.ENOTDIR) {
			c.skip(dir, err.Error())
		}
		return
	}
	for _, e := range ents {
		if e.Type().IsRegular() {
			c.file(path.Join(dir, e.Name()), kind)
		}
	}
}

// symlink records a systemd enabled link: its target text is the only line.
func (c *collector) symlink(mp string) {
	var st unix.Stat_t
	if err := unix.Lstat(filepath.Join(c.root, mp), &st); err != nil {
		return
	}
	target, err := os.Readlink(filepath.Join(c.root, mp))
	if err != nil {
		c.skip(mp, err.Error())
		return
	}
	sum := sha256.Sum256([]byte(target))
	r, n := redact.Line(c.key, target)
	pf := model.PersistFile{Path: mp, Kind: model.PersistKindSystemdEnabled, SHA256: hex.EncodeToString(sum[:]), Lines: []string{r}, Redactions: n}
	c.meta(st, &pf)
	c.out = append(c.out, pf)
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
			if strings.HasSuffix(parent, ".wants") || strings.HasSuffix(parent, ".requires") {
				c.symlink(mp)
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
		if u.Home == "" || !path.IsAbs(home) || home == "/nonexistent" {
			continue
		}
		for _, n := range []string{".bashrc", ".profile", ".bash_profile", ".bash_login", ".zshrc"} {
			c.file(path.Join(home, n), model.PersistKindShellRC)
		}
		c.systemd(path.Join(home, ".config/systemd/user"), true)
		for _, pat := range akf {
			c.file(expandAKF(pat, home, u.Name), model.PersistKindAuthorizedKeys)
		}
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
