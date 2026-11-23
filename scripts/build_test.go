// Package scripts tests the shell scripts beside it.
package scripts

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func needBash(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not installed")
	}
}

// exitCode runs cmd and returns its exit code and stderr.
func exitCode(t *testing.T, cmd *exec.Cmd) (int, string) {
	t.Helper()
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, stderr.String()
	case errors.As(err, &ee):
		return ee.ExitCode(), stderr.String()
	}
	t.Fatalf("%v: %v", cmd.Args, err)
	return -1, ""
}

func write(t *testing.T, p, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

const (
	sumLine = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  telltale_0.1.0_linux_amd64.tar.gz\n"
	sumHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  "
)

// previousDist lays out what build.sh leaves behind.
func previousDist(t *testing.T, d string) {
	t.Helper()
	var sums strings.Builder
	for _, name := range []string{
		"telltale_0.1.0_linux_amd64.tar.gz", "telltale_0.1.0_linux_arm64.tar.gz",
		"telltale-carry_0.1.0_linux_amd64.tar.gz", "telltale-carry_0.1.0_linux_arm64.tar.gz",
		"telltale_0.1.0-1_amd64.deb", "telltale_0.0.0~ci-abc1234-1_arm64.deb",
	} {
		write(t, filepath.Join(d, name), "x")
		sums.WriteString(sumHash + name + "\n")
	}
	write(t, filepath.Join(d, "SHA256SUMS"), sums.String())
	for _, dir := range []string{"bin", "collector"} {
		write(t, filepath.Join(d, dir, "telltale-linux-amd64"), "x")
		write(t, filepath.Join(d, dir, "telltale-linux-arm64"), "x")
	}
}

// build.sh never empties an output directory it did not write: one
// holding someone's file is refused before anything is built, and the file
// stays.
func TestBuildRefusesAnotherDirectory(t *testing.T) {
	needBash(t)
	d := t.TempDir()
	write(t, filepath.Join(d, "notes.txt"), "mine")
	cmd := exec.Command("bash", "build.sh")
	cmd.Env = append(os.Environ(), "TELLTALE_DIST_DIR="+d, "VERSION=0.0.0-test")
	code, stderr := exitCode(t, cmd)
	if code != 2 || !strings.Contains(stderr, "will not empty it") {
		t.Errorf("exit %d, stderr %q; want exit 2 and a refusal", code, stderr)
	}
	if b, err := os.ReadFile(filepath.Join(d, "notes.txt")); err != nil || string(b) != "mine" {
		t.Errorf("notes.txt after build.sh: %q, %v", b, err)
	}
}

func TestPrepareDist(t *testing.T) {
	needBash(t)
	for name, c := range map[string]struct {
		make func(t *testing.T, d string)
		ok   bool
	}{
		"missing":            {func(*testing.T, string) {}, true},
		"empty":              {func(t *testing.T, d string) { os.Mkdir(d, 0o755) }, true},
		"a previous build's": {previousDist, true},
		"someone's file":     {func(t *testing.T, d string) { write(t, filepath.Join(d, "notes.txt"), "mine") }, false},
		"a previous build's and someone's file": {func(t *testing.T, d string) {
			previousDist(t, d)
			write(t, filepath.Join(d, ".keep"), "")
		}, false},
		"another file in collector": {func(t *testing.T, d string) {
			previousDist(t, d)
			write(t, filepath.Join(d, "collector", "tool"), "x")
		}, false},
		"a package build.sh did not name": {func(t *testing.T, d string) {
			previousDist(t, d)
			write(t, filepath.Join(d, "other_1.0_amd64.deb"), "x")
		}, false},
		"another file in bin": {func(t *testing.T, d string) {
			previousDist(t, d)
			write(t, filepath.Join(d, "bin", "tool"), "x")
		}, false},
		"no SHA256SUMS": {func(t *testing.T, d string) {
			previousDist(t, d)
			os.Remove(filepath.Join(d, "SHA256SUMS"))
		}, false},
		"a SHA256SUMS build.sh did not write": {func(t *testing.T, d string) {
			previousDist(t, d)
			write(t, filepath.Join(d, "SHA256SUMS"), sumLine+"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  ../../etc/passwd\n")
		}, false},
		"a link": {func(t *testing.T, d string) {
			other := t.TempDir()
			previousDist(t, other)
			os.Symlink(other, d)
		}, false},
		"a file": {func(t *testing.T, d string) { write(t, d, "x") }, false},
	} {
		t.Run(name, func(t *testing.T) {
			d := filepath.Join(t.TempDir(), "dist")
			c.make(t, d)
			cmd := exec.Command("bash", "-c", `. ./dist-dir.sh && prepare_dist "$1"`, "test", d)
			code, stderr := exitCode(t, cmd)
			_, err := os.Lstat(d)
			switch {
			case c.ok && (code != 0 || !errors.Is(err, os.ErrNotExist)):
				t.Errorf("exit %d (%s), lstat %v; want it emptied", code, stderr, err)
			case !c.ok && (code != 1 || err != nil || !strings.Contains(stderr, "will not empty it")):
				t.Errorf("exit %d (%s), lstat %v; want it refused and left alone", code, stderr, err)
			}
		})
	}
}

// prepareDistIn runs prepare_dist on the name d from the directory dir.
func prepareDistIn(t *testing.T, dir, d string) (int, string) {
	t.Helper()
	script, err := filepath.Abs("dist-dir.sh")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", `. "$1" && prepare_dist "$2"`, "test", script, d)
	cmd.Dir = dir
	return exitCode(t, cmd)
}

// A relative name that starts with "-" is listed like any other: find
// must not read it as an option, fail, and leave nothing listed and
// everything to delete.
func TestPrepareDistDashName(t *testing.T) {
	needBash(t)
	dir := t.TempDir()
	write(t, filepath.Join(dir, "-build", "notes.txt"), "mine")
	code, stderr := prepareDistIn(t, dir, "-build")
	if code != 1 || !strings.Contains(stderr, "will not empty it") {
		t.Errorf("exit %d, stderr %q; want it refused", code, stderr)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "-build", "notes.txt")); err != nil || string(b) != "mine" {
		t.Errorf("notes.txt after prepare_dist: %q, %v", b, err)
	}

	previousDist(t, filepath.Join(dir, "-old"))
	if code, stderr := prepareDistIn(t, dir, "-old"); code != 0 {
		t.Errorf("a previous build's output named -old: exit %d (%s), want it emptied", code, stderr)
	}
	if _, err := os.Lstat(filepath.Join(dir, "-old")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("-old after prepare_dist: %v", err)
	}
}

// A directory that cannot be listed is refused, never taken for empty.
func TestPrepareDistUnlistable(t *testing.T) {
	needBash(t)
	if os.Geteuid() == 0 {
		t.Skip("root can list any directory")
	}
	d := filepath.Join(t.TempDir(), "dist")
	write(t, filepath.Join(d, "notes.txt"), "mine")
	if err := os.Chmod(d, 0o300); err != nil { // writable and searchable, not readable
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(d, 0o755) })
	code, stderr := prepareDistIn(t, t.TempDir(), d)
	os.Chmod(d, 0o755)
	if code != 1 || !strings.Contains(stderr, "will not empty it") {
		t.Errorf("exit %d, stderr %q; want it refused", code, stderr)
	}
	if b, err := os.ReadFile(filepath.Join(d, "notes.txt")); err != nil || string(b) != "mine" {
		t.Errorf("notes.txt after prepare_dist: %q, %v", b, err)
	}
}

// A link written with a trailing slash (lnk/) is still a link: it is
// refused, and the directory it points at is left alone.
func TestPrepareDistLinkWithSlash(t *testing.T) {
	needBash(t)
	dir := t.TempDir()
	other := filepath.Join(dir, "other")
	previousDist(t, other)
	if err := os.Symlink(other, filepath.Join(dir, "lnk")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"lnk/", "lnk//", filepath.Join(dir, "lnk") + "/"} {
		code, stderr := prepareDistIn(t, dir, name)
		if code != 1 || !strings.Contains(stderr, "symbolic link") {
			t.Errorf("%s: exit %d, stderr %q; want it refused as a link", name, code, stderr)
		}
		if _, err := os.Stat(filepath.Join(other, "SHA256SUMS")); err != nil {
			t.Errorf("%s: the link's target lost its files: %v", name, err)
		}
	}
}

// release-notes.sh prints a version's entry from the changelog, and fails
// for a version the changelog does not have: a release needs its notes.
func TestReleaseNotes(t *testing.T) {
	needBash(t)
	changelog := filepath.Join(t.TempDir(), "CHANGELOG.md")
	write(t, changelog, "# Changelog\n\nIntro.\n\n## v0.2.0 (2026-12-01)\n\n- Two.\n\n## v0.1.0 (2026-11-23)\n\nFirst release.\n\n- One.\n")
	notes := func(v string) (int, string, string) {
		t.Helper()
		var out bytes.Buffer
		cmd := exec.Command("bash", "release-notes.sh", v, changelog)
		cmd.Stdout = &out
		code, stderr := exitCode(t, cmd)
		return code, out.String(), stderr
	}
	if code, out, stderr := notes("v0.1.0"); code != 0 || out != "First release.\n\n- One.\n" {
		t.Errorf("v0.1.0: exit %d, notes %q (%s)", code, out, stderr)
	}
	if code, out, stderr := notes("0.2.0"); code != 0 || out != "- Two.\n" {
		t.Errorf("0.2.0: exit %d, notes %q (%s)", code, out, stderr)
	}
	for _, v := range []string{"v0.3.0", "v0.1", "v0.1.0.1", ""} {
		if code, out, stderr := notes(v); code == 0 || out != "" || !strings.Contains(stderr, "CHANGELOG") {
			t.Errorf("%q: exit %d, notes %q, stderr %q; want a failure", v, code, out, stderr)
		}
	}
}
