package alerts

import (
	"crypto/sha256"
	"encoding/hex"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/donaldsteele/telltale/internal/checklist"
	"github.com/donaldsteele/telltale/internal/judge"
	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/pkgverify"
)

// Findings as the judge produces them, for the alert mapping: a machine
// that was snapshotted clean, then got a cron job with a beacon line
// added, a replaced /usr/bin/ls, and a weak setting.

var (
	judgedTaken = time.Date(2026, 11, 2, 9, 30, 0, 0, time.UTC)
	judgedNow   = time.Date(2026, 11, 22, 8, 0, 0, 0, time.UTC)
	judgedCtx   = model.ScanContext{DigestKey: []byte("test-digest-key"), ServerAddr: "192.0.2.10",
		ServerKeyLine: `from="192.0.2.10" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIServerKeyBlob telltale-server`}
)

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func judgedFile(p, content string, perm uint32) model.FileEntry {
	return model.FileEntry{Path: p, Type: "file", SHA256: sum(content), Mode: 0o100000 | perm, Size: int64(len(content)), MTime: judgedTaken, CTime: judgedTaken}
}

func judgedCron(lines ...string) model.PersistFile {
	return model.PersistFile{Path: "/etc/cron.d/backup", Kind: model.PersistKindCron, Mode: 0o100644, SHA256: sum(strings.Join(lines, "\n")), Lines: lines, MTime: judgedNow}
}

func judgedMachine(cron model.PersistFile, weak bool) *model.Collection {
	yes := true
	c := &model.Collection{
		Schema: model.CollectionSchema,
		Host:   model.Host{Hostname: "web01", OSID: "debian", OSVersionID: "12", OSPretty: "Debian GNU/Linux 12 (bookworm)", Arch: "amd64", Kernel: "6.1.0-25-amd64"},
		Time:   judgedNow,
		AsRoot: true,
		Files: []model.FileEntry{
			judgedFile("/usr/bin/openssl", "openssl 3.0.14", 0o755),
			judgedFile("/usr/bin/ls", "ls 9.1", 0o755),
			judgedFile("/etc/hostname", "web01", 0o644),
			judgedFile(cron.Path, strings.Join(cron.Lines, "\n"), 0o644),
		},
		Persist: []model.PersistFile{cron},
		Accounts: model.Accounts{
			Users: []model.User{{Name: "root", UID: 0, GID: 0, Home: "/root", Shell: "/bin/bash",
				Password: model.PasswordState{Known: true, Set: true, Algo: "yescrypt", Digest: "digest-root-1", LastChange: 20000}}},
			Groups: []model.Group{{Name: "root", GID: 0}, {Name: "sudo", GID: 27}, {Name: "staff", GID: 50}, {Name: "users", GID: 100}},
		},
		Packages: model.Packages{Installed: []model.Package{
			{Name: "openssl", Version: "3.0.14-1~deb12u2", Arch: "amd64", Status: "install ok installed", Files: []string{"/usr/bin/openssl"}},
			{Name: "coreutils", Version: "9.1-1", Arch: "amd64", Status: "install ok installed", Files: []string{"/usr/bin/ls"}},
			{Name: "auditd", Version: "1:3.0.9-1", Arch: "amd64", Status: "install ok installed"},
			{Name: "unattended-upgrades", Version: "2.9.1+nmu3", Arch: "amd64", Status: "install ok installed"},
			{Name: "ufw", Version: "0.36.2-1", Arch: "amd64", Status: "install ok installed"},
		}},
		Firewall: model.Firewall{Backend: "nftables", InputPolicy: "drop", InputRules: 3, UFWEnabled: &yes},
		Sysctl:   map[string]string{"kernel.randomize_va_space": "2", "apparmor.enabled": "Y"},
	}
	if weak {
		c.Sysctl["kernel.randomize_va_space"] = "0"
	}
	// What the collector records on a real machine: every directory on the
	// way to each file.
	have := map[string]bool{}
	for _, f := range c.Files {
		have[f.Path] = true
	}
	for _, f := range append([]model.FileEntry{}, c.Files...) {
		for d := path.Dir(f.Path); d != "/" && d != "."; d = path.Dir(d) {
			if !have[d] {
				have[d] = true
				c.Files = append(c.Files, model.FileEntry{Path: d, Type: "dir", Mode: 0o40755, MTime: judgedTaken, CTime: judgedTaken, Supplementary: true})
			}
		}
	}
	return c
}

// judgedReport is the judge's report on the changed machine.
func judgedReport(t *testing.T) *model.Report {
	t.Helper()
	old := judgedMachine(judgedCron("0 3 * * * root /usr/local/bin/backup"), false)
	cur := judgedMachine(judgedCron("0 3 * * * root /usr/local/bin/backup", "* * * * * root /tmp/.x/beacon"), true)
	snap := &model.Snapshot{Schema: model.SnapshotSchema, Taken: judgedTaken, Collection: old, Checks: checklist.Evaluate(old, judgedCtx), DigestKey: judgedCtx.DigestKey}
	res := &pkgverify.Result{Mode: pkgverify.ModeArchive, SourcesUsed: []string{"https://deb.debian.org/debian bookworm"},
		Mismatch: []pkgverify.FileVerdict{{Path: "/usr/bin/ls", Package: "coreutils", Version: "9.1-1", Expected: sum("ls 9.1"), Actual: sum("evil ls"),
			Reason: "differs from the file in the signed package", Source: "archive"}}}
	return judge.Judge(judge.Input{Collection: cur, Snapshot: snap, Context: judgedCtx, Pkg: res, Now: judgedNow})
}

func judgedFinding(t *testing.T, r *model.Report, key string) model.Finding {
	t.Helper()
	for _, f := range r.Findings {
		if f.Key == key {
			return f
		}
	}
	var keys []string
	for _, f := range r.Findings {
		keys = append(keys, f.Key)
	}
	t.Fatalf("the judge produced no %q; it produced %v", key, keys)
	return model.Finding{}
}
