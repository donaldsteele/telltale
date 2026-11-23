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

const sumLine = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  telltale_0.1.0_linux_amd64.tar.gz\n"

// previousDist lays out what build.sh leaves behind.
func previousDist(t *testing.T, d string) {
	t.Helper()
	write(t, filepath.Join(d, "SHA256SUMS"), sumLine+strings.Replace(sumLine, "amd64", "arm64", 1))
	write(t, filepath.Join(d, "telltale_0.1.0_linux_amd64.tar.gz"), "x")
	write(t, filepath.Join(d, "telltale_0.1.0_linux_arm64.tar.gz"), "x")
	write(t, filepath.Join(d, "bin", "telltale-linux-amd64"), "x")
	write(t, filepath.Join(d, "bin", "telltale-linux-arm64"), "x")
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
