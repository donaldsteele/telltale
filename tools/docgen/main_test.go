package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// docgen runs the command with args and returns its exit code and output.
func docgen(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

// docs/checks.md is generated from the checklist and the heuristics, and
// the committed copy must match what they say now: "docgen -check" fails
// on a stale copy, and passes on the committed one.
func TestDocsChecksUpToDate(t *testing.T) {
	const committed = "../../docs/checks.md"
	if code, _, errs := docgen("-check", "-out", committed); code != 0 {
		t.Fatalf("docs/checks.md is stale (exit %d): %s\nregenerate it with: go run ./tools/docgen", code, errs)
	}

	data, err := os.ReadFile(committed)
	if err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(t.TempDir(), "checks.md")
	if err := os.WriteFile(stale, bytes.Replace(data, []byte("TT-SSH-001"), []byte("TT-SSH-999"), 1), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := docgen("-check", "-out", stale); code == 0 || !strings.Contains(errs, "go run ./tools/docgen") {
		t.Errorf("a stale copy passed the check (exit %d, %q)", code, errs)
	}
	if code, _, errs := docgen("-check", "-out", filepath.Join(t.TempDir(), "missing.md")); code == 0 {
		t.Errorf("a missing file passed the check (exit %d, %q)", code, errs)
	}

	// Without -check it writes the file, and the check then passes.
	if code, _, errs := docgen("-out", stale); code != 0 {
		t.Fatalf("write: exit %d: %s", code, errs)
	}
	if code, _, errs := docgen("-check", "-out", stale); code != 0 {
		t.Errorf("check after write: exit %d: %s", code, errs)
	}
}
