//go:build !collector

package cli

import (
	"strings"
	"testing"
)

func TestVersionPrints(t *testing.T) {
	code, out, _ := run("version")
	if code != 0 || out != "telltale dev\n" {
		t.Fatalf("code=%d out=%q", code, out)
	}
}

// The full build has every command, the server's included.
func TestFullBuildHasEveryCommand(t *testing.T) {
	_, help, _ := run("help")
	for _, name := range []string{"accept", "collect", "fetch-refs", "mcp", "scan", "server", "snapshot", "version"} {
		if !strings.Contains(help, "  "+name+" ") {
			t.Errorf("help lacks %s: %q", name, help)
		}
	}
}
