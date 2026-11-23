package cli

import (
	"bytes"
	"strings"
	"testing"
)

func run(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := Run(args, strings.NewReader(""), &out, &errb)
	return code, out.String(), errb.String()
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
