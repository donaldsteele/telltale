package collect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/donaldsteele/telltale/internal/model"
	"golang.org/x/sys/unix"
)

func persistFixture(t *testing.T) []model.PersistFile {
	t.Helper()
	acc, _ := Accounts("testdata/root1", testKey)
	pf, _ := Persistence("testdata/root1", acc.Users, testKey)
	return pf
}

func findPersist(pf []model.PersistFile, path string) (model.PersistFile, bool) {
	for _, f := range pf {
		if f.Path == path {
			return f, true
		}
	}
	return model.PersistFile{}, false
}

func TestPersistenceFindsEveryKind(t *testing.T) {
	pf := persistFixture(t)
	kinds := map[string]bool{}
	for _, f := range pf {
		kinds[f.Kind] = true
		if f.SHA256 == "" {
			t.Errorf("%s has no hash", f.Path)
		}
	}
	for _, k := range []string{
		model.PersistKindSudoers, model.PersistKindSSHD, model.PersistKindSSHClient, model.PersistKindAuthorizedKeys,
		model.PersistKindCron, model.PersistKindAt, model.PersistKindSystemdUnit, model.PersistKindSystemdEnabled,
		model.PersistKindRC, model.PersistKindProfile, model.PersistKindShellRC, model.PersistKindLDPreload,
		model.PersistKindLDConf, model.PersistKindPAM, model.PersistKindHosts, model.PersistKindResolver,
		model.PersistKindModulesLoad, model.PersistKindModprobe,
	} {
		if !kinds[k] {
			t.Errorf("kind %s not found", k)
		}
	}
	en, ok := findPersist(pf, "/etc/systemd/system/multi-user.target.wants/backdoor.service")
	if !ok || en.Kind != model.PersistKindSystemdEnabled || len(en.Lines) != 1 || en.Lines[0] != "/etc/systemd/system/backdoor.service" {
		t.Fatalf("enabled link = %+v", en)
	}
	for _, p := range []string{"/run/systemd/system/runtime.service", "/home/alice/.config/systemd/user/sync.service", "/var/spool/cron/crontabs/alice", "/etc/cron.daily/logrotate"} {
		if _, ok := findPersist(pf, p); !ok {
			t.Errorf("missing %s", p)
		}
	}
}

func TestPersistenceFollowsSSHDInclude(t *testing.T) {
	pf := persistFixture(t)
	f, ok := findPersist(pf, "/etc/ssh/sshd_config.d/10-local.conf")
	if !ok || f.Kind != model.PersistKindSSHD {
		t.Fatalf("include target = %+v ok=%v", f, ok)
	}
}

func TestPersistenceAuthorizedKeysForAllUsers(t *testing.T) {
	pf := persistFixture(t)
	for _, p := range []string{"/home/alice/.ssh/authorized_keys", "/root/.ssh/authorized_keys", "/etc/ssh/keys/alice"} {
		f, ok := findPersist(pf, p)
		if !ok || f.Kind != model.PersistKindAuthorizedKeys || len(f.Lines) != 1 {
			t.Errorf("%s = %+v ok=%v", p, f, ok)
		}
	}
}

func TestPersistenceRedactsSecrets(t *testing.T) {
	pf := persistFixture(t)
	f, ok := findPersist(pf, "/etc/systemd/system/backdoor.service")
	if !ok {
		t.Fatal("unit missing")
	}
	if f.Redactions != 1 {
		t.Errorf("redactions = %d", f.Redactions)
	}
	if strings.Contains(strings.Join(f.Lines, "\n"), "abc123") {
		t.Errorf("secret kept: %v", f.Lines)
	}
}

func TestPersistenceLargeFileHashOnly(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc/cron.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	big := strings.Repeat("0 * * * * root /bin/true\n", 20000)
	if err := os.WriteFile(filepath.Join(root, "etc/cron.d/big"), []byte(big), 0o644); err != nil {
		t.Fatal(err)
	}
	pf, skips := Persistence(root, nil, testKey)
	f, ok := findPersist(pf, "/etc/cron.d/big")
	if !ok || f.Lines != nil || f.SHA256 == "" || f.Mode == 0 {
		t.Fatalf("big = %+v ok=%v", f, ok)
	}
	if len(skips) != 1 || !strings.Contains(skips[0].Reason, "/etc/cron.d/big") {
		t.Fatalf("skips = %+v", skips)
	}
}

func writeFile(t *testing.T, root, mp, content string) {
	t.Helper()
	p := filepath.Join(root, mp)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func symlinkAt(t *testing.T, root, mp, target string) {
	t.Helper()
	p := filepath.Join(root, mp)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, p); err != nil {
		t.Fatal(err)
	}
}

func TestPersistenceFIFOGivesSkip(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(root, "etc/resolv.conf"), 0o644); err != nil {
		t.Fatal(err)
	}
	pf, skips := Persistence(root, nil, testKey)
	if len(pf) != 0 || len(skips) != 1 || !strings.Contains(skips[0].Reason, "/etc/resolv.conf") {
		t.Fatalf("pf=%+v skips=%+v", pf, skips)
	}
}

func TestPersistenceRecordsSymlinks(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "var/tmp/x.service", "[Service]\nEnvironment=TOKEN=abc123\nExecStart=/bin/x\n")
	symlinkAt(t, root, "etc/systemd/system/x.service", "/var/tmp/x.service")
	symlinkAt(t, root, "etc/systemd/system/masked.service", "/dev/null")
	writeFile(t, root, "var/tmp/.k", "ssh-ed25519 AAAA evil\n")
	symlinkAt(t, root, "root/.ssh/authorized_keys", "../../var/tmp/.k")
	writeFile(t, root, "etc/shadow", "root:$6$salt$SECRETHASHVALUE:19000:0:99999:7:::\n")
	symlinkAt(t, root, "etc/cron.d/sh", "/etc/shadow")
	pf, skips := Persistence(root, []model.User{{Name: "root", Home: "/root"}}, testKey)

	u, ok := findPersist(pf, "/etc/systemd/system/x.service")
	if !ok || u.Kind != model.PersistKindSystemdUnit || u.Lines[0] != "/var/tmp/x.service" || len(u.Lines) != 4 || u.Mode&unix.S_IFMT != unix.S_IFLNK {
		t.Fatalf("unit link = %+v", u)
	}
	if strings.Contains(strings.Join(u.Lines, "\n"), "abc123") || u.Redactions != 1 {
		t.Fatalf("secret kept: %+v", u)
	}
	m, ok := findPersist(pf, "/etc/systemd/system/masked.service")
	if !ok || len(m.Lines) != 1 || m.Lines[0] != "/dev/null" {
		t.Fatalf("mask = %+v", m)
	}
	ak, ok := findPersist(pf, "/root/.ssh/authorized_keys")
	if !ok || ak.Kind != model.PersistKindAuthorizedKeys || len(ak.Lines) != 2 || ak.Lines[1] != "ssh-ed25519 AAAA evil" {
		t.Fatalf("authorized_keys link = %+v", ak)
	}
	sh, ok := findPersist(pf, "/etc/cron.d/sh")
	if !ok || len(sh.Lines) != 1 {
		t.Fatalf("shadow link = %+v", sh)
	}
	found := false
	for _, s := range skips {
		found = found || strings.Contains(s.Reason, "secret file")
	}
	js, _ := json.Marshal(struct {
		P []model.PersistFile
		S []model.Skip
	}{pf, skips})
	if !found || strings.Contains(string(js), "SECRETHASHVALUE") {
		t.Fatalf("found=%v json=%s", found, js)
	}
}

func TestPersistenceSSHDUnparsedStillRecorded(t *testing.T) {
	root := t.TempDir()
	big := "AuthorizedKeysFile /var/tmp/k\n" + strings.Repeat("# pad\n", 60000)
	writeFile(t, root, "etc/ssh/sshd_config", big)
	pf, _ := Persistence(root, []model.User{{Name: "u", Home: "/home/u"}}, testKey)
	f, ok := findPersist(pf, "/etc/ssh/sshd_config")
	if !ok || f.Lines != nil || f.SHA256 == "" {
		t.Fatalf("sshd_config = %+v ok=%v", f, ok)
	}
	writeFile(t, root, "var/tmp/k", "ssh-ed25519 AAAA k\n")
	pf, _ = Persistence(root, []model.User{{Name: "u", Home: "/home/u"}}, testKey)
	if _, ok := findPersist(pf, "/var/tmp/k"); !ok {
		t.Fatal("AuthorizedKeysFile from large config not honoured")
	}
}

func TestPersistenceAuthorizedKeysUnionAndNonexistentHome(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "etc/ssh/sshd_config", "Include conf.d/*.conf\nAuthorizedKeysFile .ssh/ak\nMatch User x\n  AuthorizedKeysFile /var/tmp/m/%u\n")
	writeFile(t, root, "etc/ssh/conf.d/a.conf", "Match Group y\nAuthorizedKeysFile %h/.keys\n")
	writeFile(t, root, "var/tmp/m/svc", "ssh-ed25519 AAAA m\n")
	writeFile(t, root, "nonexistent/.keys", "ssh-ed25519 AAAA n\n")
	writeFile(t, root, "nonexistent/.ssh/authorized_keys", "ssh-ed25519 AAAA t\n")
	pf, _ := Persistence(root, []model.User{{Name: "svc", Home: "/nonexistent"}}, testKey)
	for _, p := range []string{"/var/tmp/m/svc", "/nonexistent/.keys", "/nonexistent/.ssh/authorized_keys"} {
		if _, ok := findPersist(pf, p); !ok {
			t.Errorf("missing %s", p)
		}
	}
}

func TestPersistenceHugeFileNotRead(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "home/u/.bashrc", "")
	if err := os.Truncate(filepath.Join(root, "home/u/.bashrc"), maxHashBytes+1); err != nil {
		t.Fatal(err)
	}
	pf, skips := Persistence(root, []model.User{{Name: "u", Home: "/home/u"}}, testKey)
	f, ok := findPersist(pf, "/home/u/.bashrc")
	if !ok || f.SHA256 != "" || f.Lines != nil || f.Mode == 0 || len(skips) != 1 {
		t.Fatalf("f=%+v ok=%v skips=%+v", f, ok, skips)
	}
}
