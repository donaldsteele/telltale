package collect

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

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
	chain := linkChains(root, persist, []string{"/lib", "/usr", "/var/lib/dpkg/info"}, refuse)
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
