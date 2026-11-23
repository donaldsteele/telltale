//go:build !collector

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, text string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "telltale.toml")
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestServerRefusesWildcardListenWithoutFlag(t *testing.T) {
	t.Setenv(passphraseEnv, "")
	dir := t.TempDir()
	for _, listen := range []string{"0.0.0.0:8443", "[::]:8443"} {
		p := writeConfig(t, "listen = \""+listen+"\"\nserver_addr = \"192.0.2.10\"\ndata_dir = \""+dir+"\"\n")
		code, _, errs := run("server", "--config", p)
		if code != ExitUsage || !strings.Contains(errs, "--allow-all-interfaces") {
			t.Errorf("listen %s: code=%d err=%q", listen, code, errs)
		}
		// Refused before anything was set up.
		if entries, _ := os.ReadDir(dir); len(entries) != 0 {
			t.Errorf("listen %s: the data directory was touched: %v", listen, entries)
		}
	}
}

// A loopback server_addr set on purpose is allowed, but the owner is told
// the enrolment snippets will not work on other machines.
func TestServerWarnsAboutLoopbackServerAddr(t *testing.T) {
	t.Setenv(passphraseEnv, "")
	p := writeConfig(t, "listen = \"0.0.0.0:8443\"\nserver_addr = \"127.0.0.1\"\ndata_dir = \""+t.TempDir()+"\"\n")
	code, _, errs := run("server", "--config", p)
	if code != ExitUsage || !strings.Contains(errs, "warning: server_addr 127.0.0.1 is a loopback address") {
		t.Errorf("code=%d err=%q", code, errs)
	}
}

func TestServerNeedsAConfig(t *testing.T) {
	code, _, errs := run("server")
	if code != ExitUsage || !strings.Contains(errs, "--config") {
		t.Errorf("code=%d err=%q", code, errs)
	}
	p := writeConfig(t, "listen = \"192.0.2.10:8443\"\nnope = \"1\"\n")
	code, _, errs = run("server", "--config", p)
	if code != ExitUsage || !strings.Contains(errs, "line 2") {
		t.Errorf("bad config: code=%d err=%q", code, errs)
	}
}

func TestServerPassphraseSources(t *testing.T) {
	ctx := &Context{Stdin: strings.NewReader(""), Stderr: &strings.Builder{}}
	t.Setenv(passphraseEnv, "from the environment")
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	if p, err := serverPassphrase(ctx, false); err != nil || p != "from the environment" {
		t.Errorf("environment: %q %v", p, err)
	}
	// systemd's LoadCredential: the file's content, without the newline.
	t.Setenv(passphraseEnv, "")
	creds := t.TempDir()
	if err := os.WriteFile(filepath.Join(creds, "passphrase"), []byte("from systemd\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", creds)
	if p, err := serverPassphrase(ctx, false); err != nil || p != "from systemd" {
		t.Errorf("credential: %q %v", p, err)
	}
	// Neither, and no terminal: an error, never a read from a pipe.
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	if _, err := serverPassphrase(ctx, false); err == nil {
		t.Error("no passphrase source: no error")
	}
}
