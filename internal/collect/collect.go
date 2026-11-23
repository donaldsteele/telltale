package collect

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/donaldsteele/telltale/internal/crossview"
	"github.com/donaldsteele/telltale/internal/model"
)

// defaultMaxHash is the largest file All will hash (2 GiB).
const defaultMaxHash = 2 << 30

// Options tunes a collection run.
type Options struct {
	Root, ProcRoot, SysRoot string
	DigestKey               []byte // empty: a random key is generated for this run
	CrossView               bool
	Now                     func() time.Time
	// OwnDir is the directory the collector itself runs from when a
	// server visit put it there: a temporary directory the visit made and
	// removes again. It is left out of the file inventory with all it
	// holds, as the collector leaves its own process out of the process
	// list: it is telltale, not the machine. A machine path; "" leaves
	// nothing out.
	OwnDir string
}

// All runs every collector and assembles a Collection.
func All(opt Options) (*model.Collection, error) {
	if opt.Root == "" {
		opt.Root = "/"
	}
	if opt.ProcRoot == "" {
		opt.ProcRoot = "/proc"
	}
	if opt.SysRoot == "" {
		opt.SysRoot = "/sys"
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	key := opt.DigestKey
	if len(key) == 0 {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("generate digest key: %w", err)
		}
	}

	c := &model.Collection{
		Schema: model.CollectionSchema,
		Time:   opt.Now().UTC(),
		AsRoot: os.Geteuid() == 0,
	}
	add := func(s []model.Skip) { c.Skipped = append(c.Skipped, s...) }
	if !c.AsRoot {
		add([]model.Skip{{Check: "privileges", Reason: "not running as root: some checks were skipped (listed below)"}})
	}

	c.Host = Host(opt.Root, opt.ProcRoot)

	var s []model.Skip
	c.Accounts, s = Accounts(opt.Root, key)
	add(s)
	c.Persist, s = Persistence(opt.Root, c.Accounts.Users, key)
	add(s)
	// Runtime must run before Files: Files needs the mount table to avoid
	// crossing into network and proc mounts.
	c.Runtime, c.Sysctl, s = Runtime(opt.ProcRoot, opt.SysRoot, opt.Root)
	add(s)
	c.Files, s = Files(opt.Root, SystemPaths, FileOptions{MaxHashBytes: defaultMaxHash, Mounts: c.Runtime.Mounts, Exclude: opt.OwnDir})
	add(s)
	// Setuid, setgid and capability files on every local filesystem, outside
	// the system paths too. Before ensureEntries so that a swept file is a
	// normal entry, not a supplementary one.
	var swept []model.FileEntry
	swept, s, c.SweepIncomplete = sweepFull(opt.Root, c.Runtime.Mounts, c.Files, FileOptions{MaxHashBytes: defaultMaxHash})
	c.Files = append(c.Files, swept...)
	add(s)
	// Files the file scan did not walk but something refers to: the program
	// behind a deleted exe, the targets of startup links.
	c.Files, s = ensureEntries(opt.Root, c.Files, exePaths(c.Runtime.Processes), c.Runtime.Mounts, defaultMaxHash)
	add(s)
	// Link targets may lie on a tmpfs (/run is one); see linkSkipFS.
	c.Files, s = ensureEntriesIn(opt.Root, c.Files, linkTargets(c.Persist), c.Runtime.Mounts, defaultMaxHash, underNeverRead, linkSkipFS)
	add(s)
	// Every directory and link the kernel passes through on the way to a
	// startup link's target, and to the target of any link of the inventory
	// that leads out of what the file scan recorded, so that links can be
	// resolved as the kernel resolves them. These exist and are not in
	// refused places, so recording them adds entries and no skips of its own.
	links := followLinks(opt.Root, c.Persist, c.Files, SystemPaths, func(p string) bool { return RefusedForLinks(p, c.Runtime.Mounts) }, linkChainBudget)
	c.LinkRefused, c.LinkMissing = links.refused, links.missing
	add(links.skips)
	c.Files, s = ensureChainEntries(opt.Root, c.Files, links.chain, c.Runtime.Mounts, defaultMaxHash)
	add(s)
	// Modules the PAM configuration loads from outside the system paths.
	c.Files, s = ensurePAMEntries(opt.Root, c.Files, c.Runtime.Mounts, c.Persist, defaultMaxHash)
	add(s)
	c.Packages, s = Packages(opt.Root)
	add(s)
	// What is behind a package directory that is a symbolic link now, so
	// that package verification can compare the files where they are.
	var refused, missing []string
	c.Files, refused, missing, s = ensurePackageDirEntries(opt.Root, c.Files, c.Packages, c.Runtime.Mounts, defaultMaxHash)
	c.LinkRefused, c.LinkMissing = append(c.LinkRefused, refused...), append(c.LinkMissing, missing...)
	add(s)
	c.LinkerCache, s = LinkerCache(opt.Root)
	add(s)
	c.Firewall, s = Firewall(opt.Root)
	add(s)

	if opt.CrossView {
		if filepath.Clean(opt.Root) != "/" || filepath.Clean(opt.ProcRoot) != "/proc" {
			c.CrossView = crossview.SkipAll("cross-view needs the live system (root / and /proc)", nil)
		} else {
			c.CrossView = crossview.Collect(c.Runtime, opt.Root, nil)
		}
	}
	return c, nil
}
