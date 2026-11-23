package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func run(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := Run(args, strings.NewReader(""), &out, &errb)
	return code, out.String(), errb.String()
}

func TestVersionPrints(t *testing.T) {
	code, out, _ := run("version")
	if code != 0 || out != "telltale dev\n" {
		t.Fatalf("code=%d out=%q", code, out)
	}
}

func TestUnknownCommandExit3(t *testing.T) {
	code, out, errs := run("bogus")
	if code != 3 || out != "" || !strings.Contains(errs, "Usage") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errs)
	}
}

func TestNoArgsExit3(t *testing.T) {
	if code, _, _ := run(); code != 3 {
		t.Fatalf("code=%d", code)
	}
}

func TestHelpListsVisibleCommandsOnly(t *testing.T) {
	code, out, _ := run("help")
	if code != 0 {
		t.Fatalf("code=%d", code)
	}
	if !strings.Contains(out, "scan") {
		t.Errorf("help lacks scan: %q", out)
	}
	// collect is a documented command: fetch-refs and offline analysis
	// take its output.
	if !strings.Contains(out, "collect     write this machine's raw collection as JSON, for fetch-refs or offline analysis") {
		t.Errorf("help lacks collect: %q", out)
	}
	for _, c := range all() {
		if c.Hidden && strings.Contains(out, "  "+c.Name+" ") {
			t.Errorf("help shows hidden %s: %q", c.Name, out)
		}
	}
}

func TestStubExit3(t *testing.T) {
	// Every planned command is built now; the stub still answers for any
	// that is not.
	var errb bytes.Buffer
	code := notImplemented("later")(&Context{Stderr: &errb})
	if code != 3 || !strings.Contains(errb.String(), "not implemented yet") {
		t.Fatalf("code=%d err=%q", code, errb.String())
	}
}

func TestMCPRefusesBadSetup(t *testing.T) {
	dir := t.TempDir()
	open := filepath.Join(dir, "open")
	if err := os.WriteFile(open, []byte("token\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o644); err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(dir, "private")
	if err := os.WriteFile(private, []byte("token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fp := "SHA256:" + strings.TrimSuffix(strings.Repeat("AB:", 32), ":")
	for _, tc := range []struct {
		args []string
		want string
	}{
		{nil, "usage: telltale mcp"},
		{[]string{"--server", "https://192.0.2.10:8443", "--token-file", private}, "usage: telltale mcp"},
		{[]string{"--server", "https://192.0.2.10:8443", "--token-file", open, "--fingerprint", fp}, "chmod 600"},
		{[]string{"--server", "http://192.0.2.10:8443", "--token-file", private, "--fingerprint", fp}, "https://"},
		{[]string{"--server", "https://192.0.2.10:8443", "--token-file", private, "--fingerprint", "SHA256:AB"}, "64 hex digits"},
	} {
		code, out, errs := run(append([]string{"mcp"}, tc.args...)...)
		if code != 3 || out != "" || !strings.Contains(errs, tc.want) {
			t.Errorf("%q: code=%d out=%q err=%q", tc.args, code, out, errs)
		}
	}
}
