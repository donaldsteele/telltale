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
	c.Files, s = Files(opt.Root, SystemPaths, FileOptions{MaxHashBytes: defaultMaxHash, Mounts: c.Runtime.Mounts})
	add(s)
	c.Packages, s = Packages(opt.Root)
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
