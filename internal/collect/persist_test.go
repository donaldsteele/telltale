package collect

import (
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
	if _, ok := findPersist(pf, "/nowhere"); ok {
		t.Error("Match-block AuthorizedKeysFile must not be used")
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

func TestPersistenceIgnoresSymlinksAndFIFOs(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc/cron.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "outside"), []byte("secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "outside"), filepath.Join(root, "etc/cron.d/link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "outside"), filepath.Join(root, "etc/hosts")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(root, "etc/resolv.conf"), 0o644); err != nil {
		t.Fatal(err)
	}
	pf, _ := Persistence(root, nil, testKey)
	if len(pf) != 0 {
		t.Fatalf("got %+v", pf)
	}
}
