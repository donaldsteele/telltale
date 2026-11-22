package diff

import (
	"fmt"
	"testing"
	"time"

	"github.com/donaldsteele/telltale/internal/model"
)

func snap(c *model.Collection, checks ...model.CheckResult) *model.Snapshot {
	return &model.Snapshot{Collection: c, Checks: checks}
}

func find(t *testing.T, cs []Change, kind, subj string) Change {
	t.Helper()
	for _, c := range cs {
		if c.Kind == kind && c.Subject == subj {
			return c
		}
	}
	t.Fatalf("no %s %q in %+v", kind, subj, cs)
	return Change{}
}

func TestCompareFileModifiedFields(t *testing.T) {
	old := &model.Collection{Files: []model.FileEntry{
		{Path: "/bin/su", Type: "file", SHA256: "3f2a1b2c3d4e5f60aaaa", Mode: 0755, Size: 10},
		{Path: "/etc/x", Type: "file", SHA256: "aa", Mode: 0644},
		{Path: "/gone", Type: "file"},
	}}
	cur := &model.Collection{Files: []model.FileEntry{
		{Path: "/bin/su", Type: "file", SHA256: "9c1d1b2c3d4e5f60bbbb", Mode: 04755, Size: 10},
		{Path: "/etc/x", Type: "file", SHA256: "aa", Mode: 0644, MTime: timeAt(5), CTime: timeAt(6)},
		{Path: "/new", Type: "file"},
	}}
	cs := Compare(snap(old), cur, nil)
	m := find(t, cs, "file_modified", "/bin/su")
	if m.Before != "sha256 3f2a1b2c3d4e… mode 0755" || m.After != "sha256 9c1d1b2c3d4e… mode 4755" {
		t.Errorf("got %q -> %q", m.Before, m.After)
	}
	find(t, cs, "file_added", "/new")
	find(t, cs, "file_removed", "/gone")
	if len(cs) != 3 {
		t.Errorf("mtime-only change must not count: %+v", cs)
	}
	// Err transition.
	cur2 := &model.Collection{Files: []model.FileEntry{{Path: "/gone", Type: "file", Err: "permission denied"}}}
	cs = Compare(snap(&model.Collection{Files: []model.FileEntry{{Path: "/gone", Type: "file", SHA256: "ab"}}}), cur2, nil)
	if c := find(t, cs, "file_modified", "/gone"); c.After == "" {
		t.Errorf("err not in After: %+v", c)
	}
}

func TestComparePersistLineDiff(t *testing.T) {
	mk := func(v string) []string {
		l := make([]string, 40)
		for i := range l {
			l[i] = fmt.Sprintf("line %d", i+1)
		}
		l[31] = "PermitRootLogin " + v
		return l
	}
	old := &model.Collection{Persist: []model.PersistFile{{Path: "/etc/ssh/sshd_config", SHA256: "a", Lines: mk("no")}}}
	cur := &model.Collection{Persist: []model.PersistFile{{Path: "/etc/ssh/sshd_config", SHA256: "b", Lines: mk("yes")}}}
	cs := Compare(snap(old), cur, nil)
	c := find(t, cs, "persist_changed", "/etc/ssh/sshd_config")
	if len(c.Lines) != 2 || c.Lines[0] != (LineChange{32, "PermitRootLogin no", "", "del"}) ||
		c.Lines[1] != (LineChange{32, "", "PermitRootLogin yes", "add"}) {
		t.Errorf("lines: %+v", c.Lines)
	}
	// Hash-only change.
	old.Persist[0].Lines, cur.Persist[0].Lines = nil, nil
	c = find(t, Compare(snap(old), cur, nil), "persist_changed", "/etc/ssh/sshd_config")
	if len(c.Lines) != 0 || c.Before != "a" || c.After != "b" {
		t.Errorf("hash-only: %+v", c)
	}
	// Added and removed.
	cs = Compare(snap(&model.Collection{}), &model.Collection{Persist: []model.PersistFile{{Path: "/p", Lines: []string{"x", "y"}}}}, nil)
	c = find(t, cs, "persist_changed", "/p")
	if c.Before != "absent" || len(c.Lines) != 2 || c.Lines[1].Line != 2 || c.Lines[1].Op != "add" {
		t.Errorf("added: %+v", c)
	}
	cs = Compare(snap(&model.Collection{Persist: []model.PersistFile{{Path: "/p", Lines: []string{"x"}}}}), &model.Collection{}, nil)
	c = find(t, cs, "persist_changed", "/p")
	if c.After != "absent" || c.Lines[0].Op != "del" {
		t.Errorf("removed: %+v", c)
	}
}

func TestCompareUsers(t *testing.T) {
	u := func(n string, uid int, dig string) model.User {
		return model.User{Name: n, UID: uid, Shell: "/bin/sh", Password: model.PasswordState{Known: true, Set: true, Digest: dig}}
	}
	old := &model.Collection{Accounts: model.Accounts{
		Users:  []model.User{u("root", 0, "$6$old"), u("bob", 1000, "x")},
		Groups: []model.Group{{Name: "sudo", GID: 27, Members: []string{"bob"}}},
	}}
	cur := &model.Collection{Accounts: model.Accounts{
		Users:  []model.User{u("root", 0, "$6$new"), u("eve", 0, "y")},
		Groups: []model.Group{{Name: "sudo", GID: 27, Members: []string{"bob", "eve"}}},
	}}
	cs := Compare(snap(old), cur, nil)
	find(t, cs, "user_added", "eve")
	find(t, cs, "user_removed", "bob")
	r := find(t, cs, "user_changed", "root")
	if r.Before != "password" && r.Before == "" {
		t.Errorf("%+v", r)
	}
	if r.After != "password changed" || r.Before != "password" {
		t.Errorf("digest leaked or wrong: %+v", r)
	}
	g := find(t, cs, "group_changed", "sudo")
	if g.Before == g.After {
		t.Errorf("%+v", g)
	}
	cur.Accounts.Users[0].Shell = "/bin/bash"
	r = find(t, Compare(snap(old), cur, nil), "user_changed", "root")
	if r.Before != "shell /bin/sh password" || r.After != "shell /bin/bash password changed" {
		t.Errorf("%+v", r)
	}
}

func TestComparePackagesUpDownNewRemoved(t *testing.T) {
	p := func(n, v string) model.Package { return model.Package{Name: n, Version: v, Arch: "amd64"} }
	old := &model.Collection{Packages: model.Packages{Installed: []model.Package{
		p("up", "1.0-1"), p("down", "2.0"), p("rm", "1"), p("same", "1"),
	}}}
	cur := &model.Collection{Packages: model.Packages{Installed: []model.Package{
		p("up", "1.0-2"), p("down", "1.9"), p("new", "3"), p("same", "1"),
	}}}
	cs := Compare(snap(old), cur, nil)
	if len(cs) != 4 {
		t.Fatalf("%+v", cs)
	}
	u := find(t, cs, "pkg_upgraded", "up")
	if u.Pkg == nil || u.Pkg.Old != "1.0-1" || u.Pkg.New != "1.0-2" || u.Pkg.Name != "up" {
		t.Errorf("%+v", u.Pkg)
	}
	find(t, cs, "pkg_downgraded", "down")
	if find(t, cs, "pkg_installed", "new").Pkg.New != "3" {
		t.Error("installed")
	}
	if find(t, cs, "pkg_removed", "rm").Pkg.Old != "1" {
		t.Error("removed")
	}
}

func TestCompareVersionsDebianRules(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"1.0-1", "1.0-2", -1},
		{"1:0.9", "2.0", 1},
		{"1.0~rc1", "1.0", -1},
		{"2.30-1ubuntu1", "2.30-1", 1},
		{"1.0", "1.0-0", 0},
		{"1:1.0", "1.0", 1},
		{"1.0a", "1.0+", -1},
		{"1.0~~", "1.0~", -1},
		{"1.10", "1.9", 1},
		{"1.0", "1.0", 0},
		{"1.0-1", "1.0", 1},
		{"1.x", "1.2", 1},
		{"1.+", "1.2", 1},
		{"1.0-a1", "1.0-1", 1},
		{"1.0", "1.0.0", -1},
		{"1.0~rc1", "1.0~rc1.1", -1},
		{"2:1.0", "1:9.9", 1},
	} {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
		if got := CompareVersions(c.b, c.a); got != -c.want {
			t.Errorf("CompareVersions(%q,%q)=%d want %d", c.b, c.a, got, -c.want)
		}
	}
}

func TestCompareListenersModulesChecks(t *testing.T) {
	old := &model.Collection{Runtime: model.Runtime{
		Sockets: []model.Socket{{Proto: "tcp", Local: "0.0.0.0:22", Listening: true}},
		Modules: []model.KernelModule{{Name: "ext4"}},
	}}
	cur := &model.Collection{Runtime: model.Runtime{
		Sockets: []model.Socket{
			{Proto: "tcp", Local: "[::]:22", Listening: true},
			{Proto: "tcp", Local: "0.0.0.0:22", Listening: true},
			{Proto: "udp", Local: "[::]:53", Listening: true, PID: 7},
			{Proto: "tcp", Local: "1.2.3.4:5555", Remote: "5.6.7.8:80"},
		},
		Processes: []model.Process{{PID: 7, Exe: "/usr/sbin/named"}},
		Modules:   []model.KernelModule{{Name: "ext4"}, {Name: "rootkit"}},
	}}
	old.Runtime.Sockets = append(old.Runtime.Sockets, model.Socket{Proto: "tcp", Local: "127.0.0.1:80", Listening: true})
	cur.Runtime.Sockets = append(cur.Runtime.Sockets, model.Socket{Proto: "tcp", Local: "0.0.0.0:80", Listening: true})
	cs := Compare(snap(old), cur, nil)
	find(t, cs, "listener_added", "tcp 0.0.0.0:80")
	find(t, cs, "listener_added", "tcp6 [::]:22")
	u := find(t, cs, "listener_added", "udp6 [::]:53")
	if u.After != "/usr/sbin/named" {
		t.Errorf("%+v", u)
	}
	find(t, cs, "module_added", "rootkit")
	if len(cs) != 4 {
		t.Errorf("%+v", cs)
	}
}

func TestCompareCheckRegressed(t *testing.T) {
	c := &model.Collection{}
	old := snap(c,
		model.CheckResult{ID: "a", Pass: true}, model.CheckResult{ID: "b", Pass: false},
		model.CheckResult{ID: "c", Pass: true}, model.CheckResult{ID: "d", Pass: true, Skipped: "no root"})
	cs := Compare(old, c, []model.CheckResult{
		{ID: "a", Pass: false, Observed: "yes"}, {ID: "b", Pass: true},
		{ID: "c", Skipped: "no root"}, {ID: "d", Pass: false}})
	if len(cs) != 2 {
		t.Fatalf("%+v", cs)
	}
	if find(t, cs, "check_regressed", "a").CheckID != "a" {
		t.Error("id")
	}
	find(t, cs, "check_fixed", "b")
}

func TestCompareNoChanges(t *testing.T) {
	c := &model.Collection{
		Files:   []model.FileEntry{{Path: "/a", SHA256: "x"}},
		Persist: []model.PersistFile{{Path: "/p", SHA256: "y", Lines: []string{"l"}}},
	}
	if cs := Compare(snap(c), c, nil); len(cs) != 0 {
		t.Errorf("%+v", cs)
	}
}

func timeAt(s int) time.Time { return time.Unix(int64(s), 0) }

func TestComparePersistMetadata(t *testing.T) {
	old := &model.Collection{Persist: []model.PersistFile{{Path: "/k", SHA256: "a", Lines: []string{"x"}, Mode: 0600, UID: 1000, MTime: timeAt(1)}}}
	cur := &model.Collection{Persist: []model.PersistFile{{Path: "/k", SHA256: "a", Lines: []string{"x"}, Mode: 0666, UID: 0, MTime: timeAt(2)}}}
	c := find(t, Compare(snap(old), cur, nil), "persist_changed", "/k")
	if c.Before != "mode 0600 owner 1000" || c.After != "mode 0666 owner 0" || len(c.Lines) != 0 {
		t.Errorf("%+v", c)
	}
	cur.Persist[0].Mode, cur.Persist[0].UID = 0600, 1000
	if cs := Compare(snap(old), cur, nil); len(cs) != 0 {
		t.Errorf("mtime only: %+v", cs)
	}
}

func TestDiffLinesLargeBounded(t *testing.T) {
	a := make([]string, 50000)
	b := make([]string, 50000)
	for i := range a {
		a[i] = fmt.Sprintf("a%d", i)
		b[i] = fmt.Sprintf("b%d", i)
	}
	start := time.Now()
	ls := diffLines(a, b)
	if len(ls) != 100000 || time.Since(start) > 5*time.Second {
		t.Errorf("len %d in %v", len(ls), time.Since(start))
	}
}

func TestCompareGroupShadow(t *testing.T) {
	sh := func(pw bool, admins ...string) *model.GroupShadow {
		return &model.GroupShadow{PasswordSet: pw, Admins: admins}
	}
	old := &model.Collection{Accounts: model.Accounts{Groups: []model.Group{
		{Name: "sudo", GID: 27, Shadow: sh(false)},
		{Name: "staff", GID: 50, Shadow: sh(false)},
		{Name: "adm", GID: 4, Shadow: sh(false)},
		{Name: "users", GID: 100, Shadow: sh(false)},
	}}}
	cur := &model.Collection{Accounts: model.Accounts{Groups: []model.Group{
		{Name: "sudo", GID: 27, Shadow: sh(false, "eve")},
		{Name: "staff", GID: 50, Shadow: sh(true)},
		{Name: "adm", GID: 4, Shadow: sh(false)},
		{Name: "users", GID: 100}, // gshadow not read this time
	}}}
	cs := Compare(snap(old), cur, nil)
	if g := find(t, cs, GroupChanged, "sudo"); g.After != "gid 27 members  gshadow no password admins eve members " {
		t.Errorf("sudo after %q", g.After)
	}
	if g := find(t, cs, GroupChanged, "staff"); g.Before != "gid 50 members  gshadow no password admins  members " || g.After != "gid 50 members  gshadow password set admins  members " {
		t.Errorf("staff %q -> %q", g.Before, g.After)
	}
	for _, c := range cs {
		if c.Subject == "adm" || c.Subject == "users" {
			t.Errorf("unexpected change %+v", c)
		}
	}
}

// The first entry for a name is the one that counts, as for glibc; later
// duplicates neither hide nor fake a change.
func TestCompareAccountsFirstEntryCounts(t *testing.T) {
	old := &model.Collection{Accounts: model.Accounts{
		Users:  []model.User{{Name: "root", UID: 0, Shell: "/bin/bash"}, {Name: "root", UID: 0, Shell: "/bin/sh"}},
		Groups: []model.Group{{Name: "sudo", GID: 27, Members: []string{"alice"}}},
	}}
	cur := &model.Collection{Accounts: model.Accounts{
		Users:  []model.User{{Name: "root", UID: 0, Shell: "/bin/bash"}},
		Groups: []model.Group{{Name: "sudo", GID: 27, Members: []string{"alice"}}, {Name: "sudo", GID: 27, Members: []string{"alice", "eve"}}},
	}}
	for _, c := range Compare(snap(old), cur, nil) {
		if c.Subject == "root" || c.Subject == "sudo" {
			t.Errorf("a later duplicate line was compared: %+v", c)
		}
	}
}
