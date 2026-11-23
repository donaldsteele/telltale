//go:build !collector

package cli

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/donaldsteele/telltale/internal/server"
)

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

func TestMCPStartupCheck(t *testing.T) {
	status := http.StatusTooManyRequests
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write([]byte(`{"error":"Too many failed token attempts from your address. Wait a minute and try again."}`))
	}))
	defer srv.Close()
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"mcp", "--server", srv.URL, "--token-file", tokenFile, "--fingerprint", "SHA256:" + server.Fingerprint(srv.Certificate().Raw)}

	// A server that is rate-limiting this address is not a wrong token: a
	// warning, and the MCP server runs (here until stdin ends).
	code, out, errs := run(args...)
	if code != 0 || out != "" || !strings.Contains(errs, "the server is rate-limiting this address; try again in a minute") || strings.Contains(errs, "refused the token") {
		t.Errorf("429 at start: code=%d out=%q err=%q", code, out, errs)
	}
	// A refused token is a hard error.
	status = http.StatusUnauthorized
	code, out, errs = run(args...)
	if code != 3 || out != "" || !strings.Contains(errs, "the server refused the token") {
		t.Errorf("401 at start: code=%d out=%q err=%q", code, out, errs)
	}
}
