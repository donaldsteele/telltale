package collect

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/donaldsteele/telltale/internal/model"
)

// The collector records everything on the way to a startup link's target, so
// that the link resolves in the inventory to the file the kernel opens.
func TestLinkChainsMakeLinksResolvable(t *testing.T) {
	root := t.TempDir()
	mk := func(p string) { os.MkdirAll(filepath.Join(root, p), 0o755) }
	touch := func(p string) { os.WriteFile(filepath.Join(root, p), []byte("x"), 0o755) }
	ln := func(target, p string) {
		if err := os.Symlink(target, filepath.Join(root, p)); err != nil {
			t.Fatal(err)
		}
	}
	mk("etc/cron.daily")
	mk("opt/pkg")
	mk("srv/evil/a/b")
	mk("proc/1")
	mk("usr/lib")
	touch("opt/pkg/file")
	touch("srv/evil/a/file")
	ln("/srv/evil/a/b", "opt/pkg/qdir")
	ln("/opt/pkg/qdir/../file", "etc/cron.daily/planted") // opens /srv/evil/a/file
	ln("/opt/pkg/file", "etc/cron.daily/honest")
	ln("../../opt/pkg/missing", "etc/cron.daily/dangling")
	ln("/proc/1/root", "etc/cron.daily/kernel")
	ln("usr/lib", "lib")

	persist := []model.PersistFile{}
	for _, n := range []string{"planted", "honest", "dangling", "kernel"} {
		target, _ := os.Readlink(filepath.Join(root, "etc/cron.daily", n))
		persist = append(persist, model.PersistFile{Path: "/etc/cron.daily/" + n, Mode: 0o120777, Lines: []string{target}})
	}
	refuse := func(p string) bool { return underNeverRead(p) }
	chain, _, chainSkips := linkChains(root, persist, []string{"/lib", "/usr", "/var/lib/dpkg/info"}, refuse)
	if len(chainSkips) != 0 {
		t.Errorf("skips: %+v", chainSkips)
	}
	for _, want := range []string{"/etc", "/etc/cron.daily", "/etc/cron.daily/planted", "/opt", "/opt/pkg", "/opt/pkg/qdir",
		"/srv", "/srv/evil", "/srv/evil/a", "/srv/evil/a/b", "/srv/evil/a/file", "/opt/pkg/file", "/lib", "/usr", "/usr/lib"} {
		if !slices.Contains(chain, want) {
			t.Errorf("chain lacks %s: %q", want, chain)
		}
	}
	for _, p := range chain {
		if underNeverRead(p) {
			t.Errorf("chain went into %s", p)
		}
	}

	files, skips := ensureEntries(root, nil, chain, nil, 1<<20)
	if len(skips) != 0 {
		t.Errorf("recording the chain added skips: %+v", skips)
	}
	inv := model.Inventory(files)
	for link, want := range map[string]string{
		"/etc/cron.daily/planted":  "/srv/evil/a/file",
		"/etc/cron.daily/honest":   "/opt/pkg/file",
		"/etc/cron.daily/dangling": "",
		"/etc/cron.daily/kernel":   "",
		"/lib":                     "/usr/lib",
	} {
		got, ok := model.ResolveInInventory(inv, link, model.LinkHops)
		if ok != (want != "") || got != want {
			t.Errorf("%s resolves to %q (ok %v), want %q", link, got, ok, want)
		}
	}
}

// A link chain through /run (a tmpfs) is followed to its end: /run/systemd is
// a place links may point into, so what sits there has to be looked at.
func TestLinkChainsFollowTmpfs(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"etc/cron.daily", "run/systemd", "tmp", "mnt/nfs"} {
		os.MkdirAll(filepath.Join(root, d), 0o755)
	}
	os.WriteFile(filepath.Join(root, "tmp/payload"), []byte("#!/bin/sh\n"), 0o755)
	os.WriteFile(filepath.Join(root, "mnt/nfs/job"), []byte("#!/bin/sh\n"), 0o755)
	os.Symlink("/tmp/payload", filepath.Join(root, "run/systemd/x"))
	os.Symlink("/run/systemd/x", filepath.Join(root, "etc/cron.daily/x"))
	os.Symlink("/mnt/nfs/job", filepath.Join(root, "etc/cron.daily/remote"))
	mounts := []model.Mount{{Path: "/", FSType: "ext4"}, {Path: "/run", FSType: "tmpfs"}, {Path: "/tmp", FSType: "tmpfs"},
		{Path: "/mnt/nfs", FSType: "nfs4"}, {Path: "/proc", FSType: "proc"}}
	persist := []model.PersistFile{
		{Path: "/etc/cron.daily/x", Mode: 0o120777, Lines: []string{"/run/systemd/x"}},
		{Path: "/etc/cron.daily/remote", Mode: 0o120777, Lines: []string{"/mnt/nfs/job"}},
	}
	chain, refused, _ := linkChains(root, persist, nil, func(p string) bool { return RefusedForLinks(p, mounts) })
	if !slices.Equal(refused, []string{"/mnt/nfs"}) {
		t.Errorf("refused %q, want the NFS mount point", refused)
	}
	files, _ := ensureEntriesIn(root, nil, chain, mounts, 1<<20, underNeverRead, linkSkipFS)
	files, _ = ensureEntriesIn(root, files, linkTargets(persist), mounts, 1<<20, underNeverRead, linkSkipFS)
	inv := model.Inventory(files)
	if got, ok := model.ResolveInInventory(inv, "/etc/cron.daily/x", model.LinkHops); !ok || got != "/tmp/payload" {
		t.Errorf("the chain through /run resolves to %q (ok %v), want /tmp/payload", got, ok)
	}
	if e := inv["/tmp/payload"]; e == nil || e.SHA256 == "" {
		t.Errorf("the payload on the tmpfs was not recorded with its hash: %+v", e)
	}
	// A network mount is still not entered.
	if got, ok := model.ResolveInInventory(inv, "/etc/cron.daily/remote", model.LinkHops); ok {
		t.Errorf("a link into an NFS mount resolved to %q", got)
	}
	if inv["/mnt/nfs/job"] != nil || slices.Contains(chain, "/mnt/nfs/job") {
		t.Errorf("the NFS mount was entered")
	}
	if !RefusedForLinks("/proc/1/root", mounts) || !RefusedForLinks("/mnt/nfs/job", mounts) || RefusedForLinks("/run/systemd/x", mounts) {
		t.Errorf("RefusedForLinks: proc and nfs are refused, tmpfs is not")
	}
}

// Any user can plant startup links in their own home. A very deep tree and a
// very large number of links must not buy minutes of a root scan.
func TestLinkChainsWorkIsBounded(t *testing.T) {
	root := t.TempDir()
	depth := (4000 - len(root) - 40) / 2
	deep := "/home/alice/d" + strings.Repeat("/a", depth)
	if err := os.MkdirAll(root+deep, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 8; i++ {
		target := deep + "/L" + string(rune('0'+i+1))
		if i == 8 {
			target = deep + "/end"
		}
		if err := os.Symlink(target, root+deep+"/L"+string(rune('0'+i))); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(root+deep+"/end", []byte("x"), 0o644)
	wants := "/home/alice/.config/systemd/user/default.target.wants"
	os.MkdirAll(root+wants, 0o755)
	var persist []model.PersistFile
	for i := 0; i < 1000; i++ {
		p := fmt.Sprintf("%s/x%d.service", wants, i)
		os.Symlink(deep+"/L1", root+p)
		persist = append(persist, model.PersistFile{Path: p, Mode: 0o120777, Lines: []string{deep + "/L1"}})
	}
	start := time.Now()
	chain, _, skips := linkChains(root, persist, nil, underNeverRead)
	if el := time.Since(start); el > 2*time.Second {
		t.Errorf("%d links into a tree %d deep took %v", len(persist), depth, el)
	}
	if !slices.ContainsFunc(skips, func(s model.Skip) bool { return s.Check == linkChainCheck && strings.Contains(s.Reason, "deep") }) {
		t.Errorf("no skip says the deep paths were not followed: %+v", skips)
	}
	for _, p := range chain {
		if strings.Count(p, "/") > linkChainMaxDepth {
			t.Fatalf("looked at a path %d deep", strings.Count(p, "/"))
		}
	}
	// The links are in the chain; where they lead is not, so they do not
	// resolve.
	files, _ := ensureEntriesIn(root, nil, chain, nil, 1<<20, underNeverRead, linkSkipFS)
	if got, ok := model.ResolveInInventory(model.Inventory(files), persist[0].Path, model.LinkHops); ok {
		t.Errorf("a link into the deep tree resolved to a path of %d bytes", len(got))
	}
}

func TestLinkChainsBudget(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(root+"/etc/cron.daily", 0o755)
	os.MkdirAll(root+"/opt/t", 0o755)
	var persist []model.PersistFile
	const n = 300
	for i := 0; i < n; i++ {
		target := fmt.Sprintf("/opt/t/f%d", i)
		os.WriteFile(root+target, nil, 0o755)
		p := fmt.Sprintf("/etc/cron.daily/l%d", i)
		os.Symlink(target, root+p)
		persist = append(persist, model.PersistFile{Path: p, Mode: 0o120777, Lines: []string{target}})
	}
	// Each link costs two new paths (the link and its target) after the
	// shared directories: a budget of 100 covers fewer than 50 of them.
	chain, _, skips := linkChainsWithin(root, persist, nil, underNeverRead, 100)
	if len(chain) > 100 {
		t.Errorf("looked at %d paths with a budget of 100", len(chain))
	}
	if len(skips) != 1 || skips[0].Check != linkChainCheck || !strings.Contains(skips[0].Reason, "not followed") {
		t.Fatalf("skips: %+v", skips)
	}
	inv := model.Inventory(func() []model.FileEntry {
		f, _ := ensureEntriesIn(root, nil, chain, nil, 1<<20, underNeverRead, linkSkipFS)
		return f
	}())
	if _, ok := model.ResolveInInventory(inv, persist[0].Path, model.LinkHops); !ok {
		t.Errorf("a link followed before the budget ran out does not resolve")
	}
	if _, ok := model.ResolveInInventory(inv, persist[n-1].Path, model.LinkHops); ok {
		t.Errorf("a link past the budget resolves")
	}
	// The same links looked at again cost nothing more: every path once.
	all, _, skips := linkChains(root, append(persist, persist...), nil, underNeverRead)
	if len(skips) != 0 || len(all) != 2*n+4 {
		t.Errorf("%d paths (want %d), skips %+v", len(all), 2*n+4, skips)
	}
}
