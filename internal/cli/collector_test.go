//go:build collector

package cli

import (
	"strings"
	"testing"
)

// The collector build says what it is, and points to the full build for
// the commands it leaves out.
func TestCollectorBuild(t *testing.T) {
	if code, out, _ := run("version"); code != 0 || out != "telltale dev (collector build)\n" {
		t.Errorf("version: code=%d out=%q", code, out)
	}
	_, help, _ := run("help")
	for _, name := range []string{"collect", "scan", "snapshot", "accept", "fetch-refs"} {
		if !strings.Contains(help, "  "+name+" ") {
			t.Errorf("help lacks %s: %q", name, help)
		}
	}
	for _, name := range []string{"server", "mcp"} {
		if strings.Contains(help, "  "+name+" ") {
			t.Errorf("help lists %s: %q", name, help)
		}
		code, out, errs := run(name)
		if code != ExitUsage || out != "" || !strings.Contains(errs, "collector build") || !strings.Contains(errs, "full build") {
			t.Errorf("%s: code=%d out=%q err=%q", name, code, out, errs)
		}
	}
}
