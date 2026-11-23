package judge

import (
	"strings"
	"testing"

	"github.com/donaldsteele/telltale/internal/model"
)

// A fix that edits a file by line number runs only while the file is still
// what the scan saw: between the scan and the paste the file may have
// changed, and line 2 may be another line by then.
func TestFixVerifiesTheFileBeforeEditingLines(t *testing.T) {
	old := clean()
	old.Persist = []model.PersistFile{cron("0 3 * * * root /usr/local/bin/backup")}
	old.Files = append(old.Files, file("/etc/cron.d/backup", "0 3 * * * root /usr/local/bin/backup", 0o644))
	cur := clone(old)
	cur.Persist = []model.PersistFile{cron("0 3 * * * root /usr/local/bin/backup", "* * * * * root /tmp/.x")}
	setFile(cur, file("/etc/cron.d/backup", "0 3 * * * root /usr/local/bin/backup\n* * * * * root /tmp/.x", 0o644))

	f := must(t, run(cur, snapOf(old), nil), "snap.persist:/etc/cron.d/backup", model.SevBackdoor)
	want := evidenceCopy + "'/etc/cron.d/backup' /root/telltale-evidence/ && [ \"$(sha256sum < '/etc/cron.d/backup' | cut -d' ' -f1)\" = '" + cur.Persist[0].SHA256 + "' ] && sed -i '2d' '/etc/cron.d/backup'"
	if !strings.HasPrefix(f.Fix, want) {
		t.Errorf("fix %q\nwant prefix %q", f.Fix, want)
	}
	if strings.Contains(f.Fix, "check first") {
		t.Errorf("a root-owned path needs no ownership check: %q", f.Fix)
	}

	// Without the file's hash nothing can be verified: no line edit is offered.
	cur.Persist[0].SHA256 = ""
	f = must(t, run(cur, snapOf(old), nil), "snap.persist:/etc/cron.d/backup", model.SevBackdoor)
	if strings.Contains(f.Fix, "sed -i") {
		t.Errorf("a line edit without a check: %q", f.Fix)
	}
	// A hash that is not a hash never reaches a command.
	cur.Persist[0].SHA256 = "x' ] ; reboot ; [ '"
	f = must(t, run(cur, snapOf(old), nil), "snap.persist:/etc/cron.d/backup", model.SevBackdoor)
	if strings.Contains(f.Fix, "reboot") {
		t.Errorf("text from the collection reached the command: %q", f.Fix)
	}
}

// A fix run as root on a path below a directory another account owns says
// to look at that directory first: its owner can change what the path leads
// to between the scan and the command.
func TestFixOnPathsUnderAnotherAccountsDirectory(t *testing.T) {
	alice := model.User{Name: "alice", UID: 1000, GID: 1000, Home: "/home/alice", Shell: "/bin/bash", Password: model.PasswordState{Known: true, Locked: true, LastChange: 20000}}
	unit := func(lines ...string) model.PersistFile {
		return model.PersistFile{Path: "/home/alice/.config/systemd/user/sync.service", Kind: model.PersistKindSystemdUnit, Mode: 0o100644, UID: 1000,
			SHA256: h(strings.Join(lines, "\n")), Lines: lines, MTime: changed}
	}
	home := dirAt("/home/alice")
	home.UID = 1000
	old := clean()
	old.Accounts.Users = append(old.Accounts.Users, alice)
	old.Files = append(old.Files, home)
	old.Persist = []model.PersistFile{unit("[Service]", "ExecStart=/usr/bin/sync-files")}
	cur := clone(old)
	cur.Persist = []model.PersistFile{unit("[Service]", "ExecStart=/usr/bin/sync-files", "ExecStartPost=/tmp/.x")}

	f := must(t, run(cur, snapOf(old), nil), "snap.persist:/home/alice/.config/systemd/user/sync.service", model.SevBackdoor)
	first, rest, _ := strings.Cut(f.Fix, "\n")
	if !strings.HasPrefix(first, "# check first: ls -ld '/home/alice'") {
		t.Errorf("fix does not start with the ownership check: %q", f.Fix)
	}
	if !strings.Contains(rest, "sed -i '3d' '/home/alice/.config/systemd/user/sync.service'") || !strings.Contains(rest, "sha256sum") {
		t.Errorf("the command itself: %q", rest)
	}

	// A new file there: the same, on a removal.
	added := clone(old)
	added.Files = append(added.Files, file("/home/alice/.local/bin/helper", "x", 0o4755))
	for _, f := range run(added, snapOf(old), nil).Findings {
		if hasEvidencePath(&f, "/home/alice/.local/bin/helper") && f.Fix != "" && !strings.HasPrefix(f.Fix, "# check first: ls -ld '/home/alice'") {
			t.Errorf("%s: fix %q", f.Key, f.Fix)
		}
	}

	// A quote in the directory's name stays quoted in the comment too.
	q := clone(old)
	qh := dirAt("/home/it's")
	qh.UID = 1001
	q.Files = append(q.Files, qh, file("/home/it's/tool", "x", 0o4755))
	for _, f := range run(q, snapOf(old), nil).Findings {
		if hasEvidencePath(&f, "/home/it's/tool") && f.Fix != "" && !strings.HasPrefix(f.Fix, `# check first: ls -ld '/home/it'\''s'`) {
			t.Errorf("%s: fix %q", f.Key, f.Fix)
		}
	}
}
