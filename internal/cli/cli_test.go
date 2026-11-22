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
	if strings.Contains(out, "collect") {
		t.Errorf("help shows hidden collect: %q", out)
	}
}

func TestStubExit3(t *testing.T) {
	code, _, errs := run("scan")
	if code != 3 || !strings.Contains(errs, "not implemented yet") {
		t.Fatalf("code=%d err=%q", code, errs)
	}
}
