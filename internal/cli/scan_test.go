package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/donaldsteele/telltale/internal/model"
)

func scanArgs(root string, extra ...string) []string {
	return append([]string{"scan", "--offline", "--no-color", "--root", root,
		"--proc-root", "../collect/testdata/proc1", "--sys-root", root}, extra...)
}

func fixtureRoot(t *testing.T) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "root")
	if out, err := exec.Command("cp", "-a", "../collect/testdata/root1", dst).CombinedOutput(); err != nil {
		t.Fatalf("cp: %v %s", err, out)
	}
	return dst
}

func TestScanFixtureExitCode(t *testing.T) {
	root := fixtureRoot(t)
	snap := filepath.Join(t.TempDir(), "snap.tt")
	t.Setenv(passphraseEnv, "correct horse")
	var out, errb bytes.Buffer
	code := Run([]string{"snapshot", "--allow-non-root", "--out", snap, "--root", root,
		"--proc-root", "../collect/testdata/proc1", "--sys-root", root}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("snapshot: %d %s", code, errb.String())
	}

	// Nothing changed: no tampering and no backdoor sign.
	out.Reset()
	errb.Reset()
	code = Run(scanArgs(root, "--snapshot", snap, "--json", "-"), strings.NewReader(""), &out, &errb)
	var rep model.Report
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("json on stdout: %v\n%s\nstderr %s", err, out.String(), errb.String())
	}
	if code != rep.ExitCode || code == 3 {
		t.Fatalf("unchanged machine: exit %d, report exit %d", code, rep.ExitCode)
	}
	for _, k := range titles(&rep) {
		if strings.HasPrefix(k, "snap.") {
			t.Errorf("a change reported on an unchanged machine: %s", k)
		}
	}
	fi, err := os.Stat(snap + ".last-report.json")
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("last report: %v %v", err, fi)
	}

	// An attacker adds a root SSH key.
	keys := filepath.Join(root, "root/.ssh/authorized_keys")
	f, _ := os.OpenFile(keys, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMallory0000000000000000000000000000000000 mallory\n")
	f.Close()
	htmlPath := filepath.Join(t.TempDir(), "r.html")
	out.Reset()
	errb.Reset()
	code = Run(scanArgs(root, "--snapshot", snap, "--html", htmlPath), strings.NewReader(""), &out, &errb)
	if code != 2 {
		t.Fatalf("a new root key: exit %d\n%s\n%s", code, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), "BACKDOOR") && !strings.Contains(out.String(), "TAMPERING") {
		t.Errorf("text report: %s", out.String())
	}
	if h, err := os.ReadFile(htmlPath); err != nil || !strings.Contains(string(h), "<style>") {
		t.Errorf("html: %v", err)
	}
	b, _ := os.ReadFile(snap + ".last-report.json")
	if err := json.Unmarshal(b, &rep); err != nil || rep.ExitCode != 2 {
		t.Errorf("last report: %v exit %d", err, rep.ExitCode)
	}
	sawKey := false
	for _, f := range rep.Findings {
		if strings.HasPrefix(f.Key, "snap.") && strings.Contains(f.Key+f.Title, "authorized_keys") || strings.Contains(f.Key, "root_key") {
			sawKey = true
		}
	}
	if !sawKey {
		t.Errorf("the added root key is not a finding: %v", titles(&rep))
	}

	// A wrong passphrase means the scan could not run.
	t.Setenv(passphraseEnv, "wrong")
	out.Reset()
	errb.Reset()
	if code = Run(scanArgs(root, "--snapshot", snap), strings.NewReader(""), &out, &errb); code != 3 || out.Len() != 0 {
		t.Errorf("wrong passphrase: exit %d out %q", code, out.String())
	}
}

func titles(r *model.Report) []string {
	var s []string
	for _, f := range r.Findings {
		s = append(s, f.Key)
	}
	return s
}

func TestScanNonRootReportSaysWhatWasSkipped(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("needs a non-root user")
	}
	var out, errb bytes.Buffer
	code := Run(scanArgs("../collect/testdata/root1"), strings.NewReader(""), &out, &errb)
	if code == 3 {
		t.Fatalf("scan could not run: %s", errb.String())
	}
	if !strings.Contains(out.String(), "checks that need root were skipped") {
		t.Errorf("no statement of what root would add:\n%s", out.String())
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Error("colour in a non-terminal report")
	}
}

func TestScanUsageErrors(t *testing.T) {
	for _, args := range [][]string{{"scan", "--bogus"}, {"scan", "extra"}, {"scan", "--snapshot", "/nonexistent/x"}} {
		if code, out, _ := run(args...); code != 3 || out != "" {
			t.Errorf("%v: exit %d out %q", args, code, out)
		}
	}
}

func TestChangedOwnedPathsAddsMaintainerScripts(t *testing.T) {
	file := func(p, sha string) model.FileEntry { return model.FileEntry{Path: p, Type: "file", SHA256: sha} }
	old := &model.Collection{
		Packages: model.Packages{Installed: []model.Package{{Name: "ssh", Files: []string{"/usr/bin/ssh", "/usr/bin/scp"}}}},
		Files:    []model.FileEntry{file("/usr/bin/ssh", "a"), file("/usr/bin/scp", "b"), file("/usr/bin/stray", "c"), file("/var/lib/dpkg/info/ssh.postinst", "d")},
	}
	cur := &model.Collection{
		Packages: old.Packages,
		Files: []model.FileEntry{file("/usr/bin/ssh", "A"), file("/usr/bin/scp", "b"), file("/usr/bin/stray", "C"),
			file("/var/lib/dpkg/info/ssh.postinst", "D"), file("/var/lib/dpkg/info/libc6:amd64.preinst", "e"), file("/var/lib/dpkg/info/ssh.list", "f")},
	}
	got := changedOwnedPaths(&model.Snapshot{Collection: old}, cur)
	want := map[string]bool{"/usr/bin/ssh": true, "/var/lib/dpkg/info/ssh.postinst": true, "/var/lib/dpkg/info/libc6:amd64.preinst": true}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for p := range want {
		if !got[p] {
			t.Errorf("missing %s in %v", p, got)
		}
	}
}

func TestChangedOwnedPathsMergedUsr(t *testing.T) {
	file := func(p, sha string) model.FileEntry { return model.FileEntry{Path: p, Type: "file", SHA256: sha} }
	pk := model.Packages{Installed: []model.Package{{Name: "ssh", Files: []string{"/bin/ssh"}}}}
	old := &model.Collection{Packages: pk, Files: []model.FileEntry{file("/usr/bin/ssh", "a")}}
	cur := &model.Collection{Packages: pk, Files: []model.FileEntry{file("/usr/bin/ssh", "b")}}
	if got := changedOwnedPaths(&model.Snapshot{Collection: old}, cur); !got["/usr/bin/ssh"] {
		t.Fatalf("got %v", got)
	}
}

func TestScanCancelledRemovesTheCache(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	old := scanContext
	scanContext = func() (context.Context, context.CancelFunc) {
		c, cancel := context.WithCancel(context.Background())
		cancel()
		return c, cancel
	}
	t.Cleanup(func() { scanContext = old })
	var out, errb bytes.Buffer
	code := Run([]string{"scan", "--no-color", "--root", "../collect/testdata/root1", "--proc-root", "../collect/testdata/proc1",
		"--sys-root", "../collect/testdata/root1"}, strings.NewReader(""), &out, &errb)
	if code != 3 {
		t.Fatalf("exit %d, stderr %s", code, errb.String())
	}
	if ents, _ := os.ReadDir(tmp); len(ents) != 0 {
		t.Fatalf("left behind: %v", ents)
	}
}
