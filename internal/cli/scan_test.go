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

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/pkgverify"
	"github.com/donaldsteele/telltale/internal/repokeys"
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

// firstWrite runs check when the first byte of output arrives.
type firstWrite struct {
	buf   bytes.Buffer
	check func()
	done  bool
}

func (w *firstWrite) Write(p []byte) (int, error) {
	if !w.done {
		w.done = true
		w.check()
	}
	return w.buf.Write(p)
}

func TestScanRemovesTheCacheBeforeAnyOutput(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	old := verifyPackages
	verifyPackages = func(_ context.Context, _ *model.Collection, opt pkgverify.Options) *pkgverify.Result {
		if opt.CacheDir == "" {
			t.Error("no cache dir given")
		}
		os.WriteFile(filepath.Join(opt.CacheDir, "index"), []byte("x"), 0o600)
		return &pkgverify.Result{Mode: pkgverify.ModeArchive}
	}
	t.Cleanup(func() { verifyPackages = old })
	out := &firstWrite{}
	out.check = func() {
		if ents, _ := os.ReadDir(tmp); len(ents) != 0 {
			t.Errorf("the cache still exists when output starts: %v", ents)
		}
	}
	var errb bytes.Buffer
	code := Run([]string{"scan", "--no-color", "--root", "../collect/testdata/root1", "--proc-root", "../collect/testdata/proc1",
		"--sys-root", "../collect/testdata/root1"}, strings.NewReader(""), out, &errb)
	if code == 3 || !out.done {
		t.Fatalf("exit %d, output %v, stderr %s", code, out.done, errb.String())
	}
}

// A NUL cannot be in a shell word: an account named root\0x must not get a
// command that bash would run on root.
func TestScanNULAccountNamesNoCommandOnRoot(t *testing.T) {
	root := fixtureRoot(t)
	pw := filepath.Join(root, "etc/passwd")
	f, err := os.OpenFile(pw, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("root\x00x:x:0:0::/root:/bin/bash\n")
	f.Close()
	var out, errb bytes.Buffer
	Run(scanArgs(root, "--json", "-"), strings.NewReader(""), &out, &errb)
	var rep model.Report
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("%v: %s", err, errb.String())
	}
	sawNote := false
	for _, f := range rep.Findings {
		for _, line := range strings.Split(f.Fix, "\n") {
			if strings.Contains(line, "x00x") || strings.Contains(line, "root\\x00") {
				if !strings.HasPrefix(line, "# ") || !strings.Contains(line, "NUL byte") {
					t.Errorf("%s: a command names the NUL account: %q", f.Key, line)
				}
				sawNote = true
			}
			for _, bad := range []string{"userdel -f root", "passwd -l root", "passwd -e root", "-s /usr/sbin/nologin root"} {
				if strings.Contains(line, bad) && !strings.HasPrefix(line, "#") {
					t.Errorf("%s: %q", f.Key, line)
				}
			}
		}
	}
	if !sawNote {
		t.Error("no note about the NUL account")
	}
}

func writeTestKeyring(t *testing.T, file string) string {
	t.Helper()
	e, err := openpgp.NewEntity("vendor", "", "vendor@example.test", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA})
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := e.Serialize(&b); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, b.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return repokeys.Fingerprint(e)
}

// The keys a scan verifies a third-party repository with come from the
// snapshot, never from the keyring the examined machine has now.
func TestScanTrustsOnlyTheSnapshotsRepoKeys(t *testing.T) {
	root := fixtureRoot(t)
	keyring := filepath.Join(root, "usr/share/keyrings/vendor.gpg")
	os.MkdirAll(filepath.Join(root, "etc/apt/sources.list.d"), 0o755)
	if err := os.WriteFile(filepath.Join(root, "etc/apt/sources.list.d/vendor.list"),
		[]byte("deb [signed-by=/usr/share/keyrings/vendor.gpg] https://repo.vendor.test/apt stable main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	atSnapshot := writeTestKeyring(t, keyring)
	snap := filepath.Join(t.TempDir(), "snap")
	var out, errb bytes.Buffer
	if code := Run([]string{"snapshot", "--out", snap, "--no-encrypt", "--allow-non-root", "--root", root, "--proc-root", "../collect/testdata/proc1", "--sys-root", root},
		strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("snapshot: exit %d: %s", code, errb.String())
	}
	// The machine's keyring is replaced after the snapshot.
	now := writeTestKeyring(t, keyring)

	var got []pkgverify.Options
	old := verifyPackages
	verifyPackages = func(_ context.Context, _ *model.Collection, opt pkgverify.Options) *pkgverify.Result {
		got = append(got, opt)
		return &pkgverify.Result{Mode: pkgverify.ModeArchive}
	}
	t.Cleanup(func() { verifyPackages = old })
	scan := func(extra ...string) {
		t.Helper()
		out.Reset()
		errb.Reset()
		if code := Run(append(scanArgs(root, "--no-color"), extra...), strings.NewReader(""), &out, &errb); code == 3 {
			t.Fatalf("scan: exit %d: %s", code, errb.String())
		}
	}
	scan("--snapshot", snap)
	scan()
	if len(got) != 2 {
		t.Fatalf("package verification ran %d times", len(got))
	}
	with := got[0].RepoTrust
	if len(with) != 1 || with[0].URL != "https://repo.vendor.test/apt" || with[0].Suite != "stable" || len(with[0].Keys) != 1 || with[0].Keys[0].Fingerprint != atSnapshot {
		t.Errorf("with a snapshot: RepoTrust = %+v, want the snapshot's key %s", with, atSnapshot)
	}
	for _, tr := range with {
		for _, k := range tr.Keys {
			if k.Fingerprint == now {
				t.Errorf("the machine's present key %s was passed as trusted", now)
			}
		}
	}
	if len(got[1].RepoTrust) != 0 {
		t.Errorf("without a snapshot nothing vouches for the repository, got %+v", got[1].RepoTrust)
	}
	// The changed key is reported.
	scan("--snapshot", snap, "--json", "-")
	if !strings.Contains(out.String(), "pkg.repo_key_changed:https://repo.vendor.test/apt") {
		t.Errorf("no pkg.repo_key_changed finding in the report")
	}
}

// A scan of the machine it runs on uses only signed sources: HTTPS there is
// checked with that machine's own CA store and resolver. With --refs,
// --offline, or a filesystem mounted somewhere else, nothing changes.
func TestScanOfTheLiveMachineUsesSignedSourcesOnly(t *testing.T) {
	for _, tc := range []struct {
		root, refs string
		offline    bool
		want       bool
	}{
		{"/", "", false, true},
		{"", "", false, true},
		{"//", "", false, true},
		{"/mnt/disk", "", false, false},
		{"/", "/media/refs", false, false},
		{"/", "", true, false},
	} {
		if got := signedSourcesOnly(tc.root, tc.refs, tc.offline); got != tc.want {
			t.Errorf("signedSourcesOnly(%q, %q, %v) = %v, want %v", tc.root, tc.refs, tc.offline, got, tc.want)
		}
	}

	// The option reaches package verification as scan computes it.
	old, oldLive := verifyPackages, signedSourcesOnly
	var got []bool
	verifyPackages = func(_ context.Context, _ *model.Collection, opt pkgverify.Options) *pkgverify.Result {
		got = append(got, opt.SignedOnly)
		return &pkgverify.Result{Mode: pkgverify.ModeArchive, SignedOnly: opt.SignedOnly, SourcesUsed: []string{"https://deb.debian.org/debian bookworm"}}
	}
	t.Cleanup(func() { verifyPackages, signedSourcesOnly = old, oldLive })
	args := []string{"scan", "--no-color", "--root", "../collect/testdata/root1", "--proc-root", "../collect/testdata/proc1", "--sys-root", "../collect/testdata/root1"}
	var out, errb bytes.Buffer
	Run(args, strings.NewReader(""), &out, &errb)
	// Stand in for a scan of "/": the fixture tree is the machine.
	signedSourcesOnly = func(string, string, bool) bool { return true }
	var live bytes.Buffer
	Run(args, strings.NewReader(""), &live, &errb)
	if len(got) != 2 || got[0] || !got[1] {
		t.Fatalf("SignedOnly passed to package verification: %v", got)
	}
	const said = "sources trusted through HTTPS alone"
	if strings.Contains(out.String(), said) || !strings.Contains(live.String(), said) {
		t.Errorf("the report must say so exactly when they were left out:\nmounted: %v\nlive: %v", strings.Contains(out.String(), said), strings.Contains(live.String(), said))
	}
}
