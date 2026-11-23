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
	// Each link costs six lookups (three components to the link, three to
	// its target), new or remembered: a budget of 100 covers under 20.
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

// Memo hits are work too. Links whose targets are 4 KB of "x/../" through a
// chain of such links cost thousands of lookups each without one new lstat:
// every lookup is counted, one walk is cut at model.MaxWalkSteps, and the
// pass stops at its budget with the links it left named as not looked at.
func TestLinkChainsCountEveryLookup(t *testing.T) {
	root := t.TempDir()
	const home = "/home/alice"
	wants := home + "/.config/systemd/user/default.target.wants"
	os.MkdirAll(root+wants, 0o755)
	os.MkdirAll(root+home+"/x", 0o755)
	pad := strings.Repeat("x/../", 800)
	for i := 1; i <= 8; i++ {
		next := fmt.Sprintf("L%d", i+1)
		if i == 8 {
			next = "end"
		}
		os.Symlink(pad+next, fmt.Sprintf("%s%s/L%d", root, home, i))
	}
	os.WriteFile(root+home+"/end", []byte("x"), 0o644)
	const n = 2000
	var persist []model.PersistFile
	for i := 0; i < n; i++ {
		p := fmt.Sprintf("%s/u%d.service", wants, i)
		tgt := "../../../../" + pad[:len(pad)-25*5] + "L1"
		os.Symlink(tgt, root+p)
		persist = append(persist, model.PersistFile{Path: p, Mode: 0o120777, Lines: []string{tgt}})
	}
	start := time.Now()
	res := followLinks(root, persist, nil, nil, underNeverRead, linkChainBudget)
	if el := time.Since(start); el > time.Second {
		t.Errorf("%d padded links took %v", n, el)
	}
	if res.spent > linkChainBudget+model.MaxWalkSteps {
		t.Errorf("%d lookups with a budget of %d", res.spent, linkChainBudget)
	}
	var budget, long string
	for _, s := range res.skips {
		if s.Check != linkChainCheck {
			t.Errorf("skip %+v", s)
		}
		if strings.Contains(s.Reason, "stopped following") {
			budget = s.Reason
		} else {
			long = s.Reason
		}
	}
	if budget == "" || long == "" {
		t.Fatalf("want a budget skip and a cut-off skip, got %+v", res.skips)
	}
	// Every link is accounted for: cut off in its walk, or never started.
	if res.cut == 0 || res.unwalked == 0 || res.cut+res.unwalked != n {
		t.Errorf("%d cut off + %d not started, want %d in all", res.cut, res.unwalked, n)
	}
	if !strings.Contains(budget, fmt.Sprintf("%d links were not followed", res.unwalked)) || !strings.Contains(long, fmt.Sprintf("%d links", res.cut)) {
		t.Errorf("counts in the skips: %q / %q", budget, long)
	}
	// None of them can pass for a link to a file that is merely missing.
	for _, i := range []int{0, n / 2, n - 1} {
		if !slices.Contains(res.refused, persist[i].Path) {
			t.Errorf("link %d is not among the paths not looked at", i)
		}
	}
}

// A link the file scan recorded whose target the inventory cannot follow to
// the end (it leads through /run, which the file scan stays out of) is
// walked on the machine, so that it is judged by where it really leads. A
// link that resolves in the inventory costs nothing.
func TestInventoryLinksAreFollowedToTheEnd(t *testing.T) {
	root := t.TempDir()
	mk := func(p string) { os.MkdirAll(filepath.Join(root, p), 0o755) }
	ln := func(target, p string) {
		if err := os.Symlink(target, filepath.Join(root, p)); err != nil {
			t.Fatal(err)
		}
	}
	mk("etc/alternatives")
	mk("usr/bin")
	mk("usr/share")
	mk("run/systemd")
	mk("var/tmp/x")
	os.WriteFile(root+"/usr/bin/mawk", []byte("mawk"), 0o755)
	os.WriteFile(root+"/var/tmp/x/mawk", []byte("evil"), 0o755)
	ln("/var/tmp/x", "run/systemd/q")
	ln("/run/systemd/q/mawk", "etc/alternatives/awk")
	ln("/usr/bin/mawk", "etc/alternatives/nawk")
	ln("/usr/share/man/man1/mawk.1.gz", "etc/alternatives/awk.1.gz")
	ln("/proc/1/root/x", "etc/alternatives/kernel")

	// What the file scan records: the system paths only.
	files, _ := Files(root, []string{"/etc", "/usr"}, FileOptions{})
	var looked []string
	refuse := func(p string) bool { looked = append(looked, p); return underNeverRead(p) }
	res := followLinks(root, nil, files, nil, refuse, linkChainBudget)
	for _, want := range []string{"/run", "/run/systemd", "/run/systemd/q", "/var", "/var/tmp", "/var/tmp/x", "/var/tmp/x/mawk"} {
		if !slices.Contains(res.chain, want) {
			t.Errorf("chain lacks %s: %q", want, res.chain)
		}
	}
	if slices.Contains(looked, "/usr/bin/mawk") || slices.Contains(looked, "/etc/alternatives/nawk") {
		t.Errorf("a link that resolves in the inventory was looked at again: %q", looked)
	}
	// The dangling link: the first name that is not there is known to be
	// missing, which is different from not having been looked at.
	if !slices.Contains(res.missing, "/usr/share/man") || slices.Contains(res.refused, "/usr/share/man") {
		t.Errorf("missing %q refused %q", res.missing, res.refused)
	}
	if !slices.Contains(res.refused, "/proc") || slices.Contains(res.missing, "/proc") {
		t.Errorf("a kernel tree is refused, not missing: missing %q refused %q", res.missing, res.refused)
	}
	files, _ = ensureEntriesIn(root, files, res.chain, nil, 1<<20, underNeverRead, linkSkipFS)
	if got, ok := model.ResolveInInventory(model.Inventory(files), "/etc/alternatives/awk", model.LinkHops); !ok || got != "/var/tmp/x/mawk" {
		t.Errorf("awk resolves to %q (ok %v), want the file in /var/tmp", got, ok)
	}

	// Past the budget an inventory link is not walked, and says so.
	res = followLinks(root, nil, []model.FileEntry{{Path: "/etc/alternatives/awk", Type: "symlink", Target: "/run/systemd/q/mawk"}}, nil, underNeverRead, 0)
	if res.unwalked != 1 || !slices.Contains(res.refused, "/etc/alternatives/awk") || len(res.skips) != 1 {
		t.Errorf("no budget: %+v", res)
	}
}

// Entries recorded along a link chain on a tmpfs are marked: what is in /run
// is rewritten at every boot.
func TestChainEntriesOnTmpfsAreMarkedVolatile(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(root+"/run/systemd/resolve", 0o755)
	os.MkdirAll(root+"/opt/pkg", 0o755)
	os.WriteFile(root+"/run/systemd/resolve/stub-resolv.conf", []byte("nameserver 127.0.0.53\n"), 0o644)
	os.WriteFile(root+"/opt/pkg/file", []byte("x"), 0o644)
	mounts := []model.Mount{{Path: "/", FSType: "ext4"}, {Path: "/run", FSType: "tmpfs"}}
	files, _ := ensureChainEntries(root, nil, []string{"/run", "/run/systemd/resolve/stub-resolv.conf", "/opt/pkg/file"}, mounts, 1<<20)
	// The same paths recorded for another reason (the target of a startup
	// link, a PAM module) are files something runs: compared in full.
	plain, _ := ensureEntriesIn(root, nil, []string{"/run/systemd/resolve/stub-resolv.conf"}, mounts, 1<<20, underNeverRead, linkSkipFS)
	if len(plain) != 1 || plain[0].Volatile || !plain[0].Supplementary {
		t.Errorf("an entry outside the chain walk is marked volatile: %+v", plain)
	}
	got := map[string]bool{}
	for _, f := range files {
		got[f.Path] = f.Volatile
	}
	if len(got) != 3 || !got["/run"] || !got["/run/systemd/resolve/stub-resolv.conf"] || got["/opt/pkg/file"] {
		t.Errorf("volatile marks: %v", got)
	}
}

// A package directory moved to where the file scan does not go (/srv), with
// a link left in its place: the collector records what is behind the link
// for every path the package lists there, so that package verification has
// the files to compare. A file that is not there, or lies where the
// collector does not look, gets no entry.
func TestPackageDirectoryContentsAreRecorded(t *testing.T) {
	root := t.TempDir()
	const sec = "/usr/lib/x86_64-linux-gnu/security"
	os.MkdirAll(root+"/usr/lib/x86_64-linux-gnu", 0o755)
	os.MkdirAll(root+"/usr/bin", 0o755)
	os.MkdirAll(root+"/etc", 0o755)
	os.MkdirAll(root+"/srv/pam/sub", 0o755)
	os.MkdirAll(root+"/srv/deeper", 0o755)
	os.MkdirAll(root+"/proc/1", 0o755)
	os.WriteFile(root+"/srv/pam/pam_unix.so", []byte("evil"), 0o644)
	os.WriteFile(root+"/srv/pam/sub/x.so", []byte("x"), 0o644)
	os.WriteFile(root+"/srv/deeper/y.so", []byte("y"), 0o644)
	os.WriteFile(root+"/usr/bin/ls", []byte("ls"), 0o755)
	os.Symlink("/srv/pam", root+sec)
	os.Symlink("/var/lib/x/evil", root+"/srv/pam/pam_link.so")
	os.Symlink("/srv/deeper", root+"/srv/pam/nested")
	os.Symlink("usr/bin", root+"/bin")
	os.Symlink("/proc/1", root+"/usr/lib/kern")
	pkgs := model.Packages{Installed: []model.Package{
		{Name: "libpam-modules", Files: []string{sec, sec + "/pam_unix.so", sec + "/pam_gone.so", sec + "/pam_link.so", sec + "/sub", sec + "/sub/x.so", sec + "/nested", sec + "/nested/y.so"}},
		{Name: "coreutils", Files: []string{"/bin", "/bin/ls"}},
		{Name: "kern", Files: []string{"/usr/lib/kern", "/usr/lib/kern/secret"}},
	}}
	files, _ := Files(root, []string{"/usr", "/etc", "/bin"}, FileOptions{})
	res := followLinks(root, nil, files, nil, underNeverRead, linkChainBudget)
	files, _ = ensureChainEntries(root, files, res.chain, nil, 1<<20)
	if model.Inventory(files)["/srv/pam/pam_unix.so"] != nil {
		t.Fatal("the link pass alone recorded the file: this test no longer shows anything")
	}
	files, _, missing, skips := ensurePackageDirEntries(root, files, pkgs, nil, 1<<20)
	inv := model.Inventory(files)
	for _, p := range []string{"/srv/pam/pam_unix.so", "/srv/pam/sub/x.so", "/srv/deeper/y.so"} {
		e := inv[p]
		if e == nil || e.Type != "file" || e.SHA256 == "" || !e.Supplementary || e.Volatile {
			t.Errorf("%s: want a hashed supplementary entry, got %+v", p, e)
		}
	}
	if e := inv["/srv/pam/pam_link.so"]; e == nil || e.Type != "symlink" || e.Target != "/var/lib/x/evil" {
		t.Errorf("a link where the package has a file is not recorded as one: %+v", e)
	}
	if inv["/srv/pam/pam_gone.so"] != nil || !slices.Contains(missing, "/srv/pam/pam_gone.so") {
		t.Errorf("a file that is not there: entry %+v, missing %q", inv["/srv/pam/pam_gone.so"], missing)
	}
	// A package directory that leads into a kernel tree cannot be followed
	// in the inventory: nothing is looked for there (the judge reports the
	// link itself).
	for p := range inv {
		if strings.HasPrefix(p, "/proc") {
			t.Errorf("recorded %s", p)
		}
	}
	if len(skips) != 0 {
		t.Errorf("skips: %+v", skips)
	}
	// Nothing left to look for but what could not be found.
	if left := packageDirPaths(pkgs, files); !slices.Equal(left, []string{sec + "/pam_gone.so"}) {
		t.Errorf("still without an entry: %q", left)
	}
}

// Any user can plant padded startup links in a home directory; a hundred of
// them spend the whole budget. System startup links are followed first, and
// one the inventory already resolves is not walked at all, so neither ends
// up among the links telltale could not resolve.
func TestUserLinksCannotStarveSystemLinks(t *testing.T) {
	root := t.TempDir()
	const home = "/home/u"
	wants := home + "/.config/systemd/user/default.target.wants"
	os.MkdirAll(root+wants, 0o755)
	os.MkdirAll(root+home+"/x", 0o755)
	os.MkdirAll(root+"/usr/lib/systemd/system", 0o755)
	os.MkdirAll(root+"/etc/systemd/system/multi-user.target.wants", 0o755)
	os.MkdirAll(root+"/etc/cron.daily", 0o755)
	os.MkdirAll(root+"/opt/vendor", 0o755)
	os.WriteFile(root+"/usr/lib/systemd/system/ssh.service", []byte("[Service]\n"), 0o644)
	os.WriteFile(root+"/opt/vendor/job", []byte("#!/bin/sh\n"), 0o755)
	const sys, cron = "/etc/systemd/system/multi-user.target.wants/ssh.service", "/etc/cron.daily/vendor"
	os.Symlink("/usr/lib/systemd/system/ssh.service", root+sys)
	os.Symlink("/opt/vendor/job", root+cron)
	pad := strings.Repeat("x/../", 800)
	for i := 1; i <= 8; i++ {
		next := fmt.Sprintf("L%d", i+1)
		if i == 8 {
			next = "end"
		}
		os.Symlink(pad+next, fmt.Sprintf("%s%s/L%d", root, home, i))
	}
	// The user's links come first in the list, as they may on a machine.
	var persist []model.PersistFile
	const n = 100
	for i := 0; i < n; i++ {
		a := fmt.Sprintf("%s/A%d", home, i)
		os.Symlink(pad+"L1", root+a)
		p := fmt.Sprintf("%s/u%d.service", wants, i)
		os.Symlink(a, root+p)
		persist = append(persist, model.PersistFile{Path: p, Mode: 0o120777, Lines: []string{a}})
	}
	persist = append(persist,
		model.PersistFile{Path: sys, Mode: 0o120777, Lines: []string{"/usr/lib/systemd/system/ssh.service"}},
		model.PersistFile{Path: cron, Mode: 0o120777, Lines: []string{"/opt/vendor/job"}})
	files, _ := Files(root, []string{"/usr", "/etc"}, FileOptions{})
	files, _ = ensureEntriesIn(root, files, linkTargets(persist), nil, 1<<20, underNeverRead, linkSkipFS)
	res := followLinks(root, persist, files, nil, underNeverRead, linkChainBudget)
	if res.unwalked == 0 || len(res.skips) == 0 {
		t.Fatalf("the user's links did not spend the budget: this test shows nothing (%d lookups)", res.spent)
	}
	for _, l := range []string{sys, cron} {
		if slices.Contains(res.refused, l) {
			t.Errorf("%s is among the links not looked at", l)
		}
	}
	if !slices.ContainsFunc(res.refused, func(p string) bool { return strings.HasPrefix(p, home+"/") }) {
		t.Errorf("no user link is recorded as not followed: %q", res.refused)
	}
	files, _ = ensureChainEntries(root, files, res.chain, nil, 1<<20)
	inv := model.Inventory(files)
	for l, want := range map[string]string{sys: "/usr/lib/systemd/system/ssh.service", cron: "/opt/vendor/job"} {
		if got, ok := model.ResolveInInventory(inv, l, model.LinkHops); !ok || got != want {
			t.Errorf("%s resolves to %q (ok %v), want %s", l, got, ok, want)
		}
	}
}
