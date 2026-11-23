package scripts

import (
	"bytes"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// gofmt-check.sh looks at every directory that holds Go code, not only cmd
// and internal.
func TestGofmtCheckCoversEveryGoDirectory(t *testing.T) {
	needBash(t)
	if _, err := exec.LookPath("gofmt"); err != nil {
		t.Skip("gofmt is not installed")
	}
	root := t.TempDir()
	script, err := os.ReadFile("gofmt-check.sh")
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(root, "scripts", "gofmt-check.sh"), string(script))
	const bad = "package x\nfunc  f( ){}\n"
	dirs := []string{"cmd", "internal", "lab", "tools", "scripts", "web"}
	for _, d := range dirs {
		write(t, filepath.Join(root, d, "sub", "x.go"), bad)
	}
	// Build output is not source.
	write(t, filepath.Join(root, "dist", "x.go"), bad)
	cmd := exec.Command("bash", filepath.Join(root, "scripts", "gofmt-check.sh"))
	var out bytes.Buffer
	cmd.Stdout = &out
	code, _ := exitCode(t, cmd)
	if code != 1 {
		t.Fatalf("exit %d with unformatted files, want 1", code)
	}
	for _, d := range dirs {
		if !strings.Contains(out.String(), filepath.Join(d, "sub", "x.go")) {
			t.Errorf("%s is not checked:\n%s", d, out.String())
		}
	}
	if strings.Contains(out.String(), "dist") {
		t.Errorf("dist is checked:\n%s", out.String())
	}
	for _, d := range dirs {
		write(t, filepath.Join(root, d, "sub", "x.go"), "package x\n\nfunc f() {}\n")
	}
	if code, stderr := exitCode(t, exec.Command("bash", filepath.Join(root, "scripts", "gofmt-check.sh"))); code != 0 {
		t.Errorf("exit %d with formatted files: %s", code, stderr)
	}
}

// The release tarballs are the same bytes whoever builds them and whenever:
// names sorted, one fixed time, root as owner, no time in the gzip header.
func TestReproTarIsReproducible(t *testing.T) {
	needBash(t)
	build := func(dir, out string) {
		t.Helper()
		cmd := exec.Command("bash", "-c", `set -euo pipefail; . ./repro-tar.sh; out=$1; dir=$2; shift 2; repro_tar "$out" "$dir" "$@"`, "sh", out, dir, "telltale", "README.md", "LICENSE")
		cmd.Env = append(os.Environ(), "SOURCE_DATE_EPOCH=1700000000")
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("repro_tar: %v\n%s", err, b)
		}
	}
	a, b := t.TempDir(), t.TempDir()
	for i, dir := range []string{a, b} {
		// Written in another order, at another time, with another mode.
		names := []string{"telltale", "README.md", "LICENSE"}
		if i == 1 {
			names = []string{"LICENSE", "README.md", "telltale"}
		}
		for _, n := range names {
			write(t, filepath.Join(dir, n), "content of "+n+"\n")
		}
		if err := os.Chmod(filepath.Join(dir, "telltale"), 0o755); err != nil {
			t.Fatal(err)
		}
		when := time.Unix(1600000000+int64(i)*86400*400, 0)
		for _, n := range names {
			os.Chtimes(filepath.Join(dir, n), when, when)
		}
	}
	os.Chmod(filepath.Join(b, "README.md"), 0o600)
	out := t.TempDir()
	build(a, filepath.Join(out, "a.tar.gz"))
	time.Sleep(1100 * time.Millisecond) // a gzip header holds a time in seconds
	build(b, filepath.Join(out, "b.tar.gz"))
	x, _ := os.ReadFile(filepath.Join(out, "a.tar.gz"))
	y, _ := os.ReadFile(filepath.Join(out, "b.tar.gz"))
	if len(x) == 0 || !bytes.Equal(x, y) {
		t.Fatalf("two builds of the same content differ (%d and %d bytes)", len(x), len(y))
	}
	list, err := exec.Command("tar", "--numeric-owner", "-tvzf", filepath.Join(out, "a.tar.gz")).Output()
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(list)), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "-rw-r--r-- 0/0") || !strings.HasSuffix(lines[0], "LICENSE") || !strings.HasPrefix(lines[2], "-rwxr-xr-x 0/0") || !strings.HasSuffix(lines[2], "telltale") {
		t.Errorf("listing:\n%s", list)
	}
	for _, l := range lines {
		if !strings.Contains(l, "2023-11-14") {
			t.Errorf("an entry does not carry SOURCE_DATE_EPOCH: %s", l)
		}
	}
}

// Invisible and direction-changing characters never appear literally in a
// source file: a reader cannot see them and a reviewer cannot tell what the
// code says. Tests that need one write it as an escape.
func TestNoInvisibleCharactersInSources(t *testing.T) {
	bad := func(r rune) bool {
		switch {
		case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069, r >= 0x200B && r <= 0x200F,
			r == 0x061C, r == 0x2028, r == 0x2029, r == 0xFEFF, r == 0x00A0, r == 0x00AD, r >= 0x80 && r <= 0x9F:
			return true
		}
		return false
	}
	exts := map[string]bool{".go": true, ".sh": true, ".md": true, ".html": true, ".css": true, ".js": true, ".yml": true, ".yaml": true, ".toml": true, ".json": true, ".sql": true, ".service": true, ".in": true}
	skip := map[string]bool{".git": true, "dist": true, "third_party": true, "node_modules": true}
	err := filepath.WalkDir("..", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skip[d.Name()] || p == filepath.Join("..", "site", "reports") {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || !exts[filepath.Ext(p)] {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		line := 1
		for _, r := range string(b) {
			if r == '\n' {
				line++
			}
			if bad(r) {
				t.Errorf("%s:%d holds a literal U+%04X: write it as an escape", strings.TrimPrefix(p, "../"), line, r)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// The release workflow attests where each artifact was built. The action is
// pinned by its full commit, the two permissions it needs are given to the
// release job alone, and the attestation covers everything SHA256SUMS
// names, before anything is published.
func TestReleaseWorkflowAttestsProvenance(t *testing.T) {
	b, err := os.ReadFile("../.github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	wf := string(b)
	head, jobs, ok := strings.Cut(wf, "\njobs:\n")
	if !ok {
		t.Fatal("no jobs")
	}
	testJob, releaseJob, ok := strings.Cut(jobs, "\n  release:\n")
	if !ok {
		t.Fatal("no release job")
	}
	for _, p := range []string{"id-token: write", "attestations: write"} {
		if strings.Contains(head, p) || strings.Contains(testJob, p) {
			t.Errorf("%q is granted outside the release job", p)
		}
		if !strings.Contains(releaseJob, "      "+p+"\n") {
			t.Errorf("the release job lacks %q", p)
		}
	}
	uses := ""
	for _, l := range strings.Split(releaseJob, "\n") {
		if strings.Contains(l, "uses: actions/attest-build-provenance@") {
			uses = strings.TrimSpace(l)
		}
	}
	_, ref, _ := strings.Cut(uses, "actions/attest-build-provenance@")
	ref, _, _ = strings.Cut(ref, " ")
	if len(ref) != 40 || strings.Trim(ref, "0123456789abcdef") != "" {
		t.Fatalf("the attestation action is not pinned by a full commit SHA: %q", uses)
	}
	if !strings.Contains(releaseJob, "subject-checksums: dist/SHA256SUMS") {
		t.Error("the attestation does not cover what SHA256SUMS names")
	}
	if a, c := strings.Index(releaseJob, "attest-build-provenance@"), strings.Index(releaseJob, "gh release create"); a < 0 || c < 0 || a > c {
		t.Error("the artifacts are published before they are attested")
	}
	// Every action in every workflow is pinned by a full commit SHA.
	files, _ := filepath.Glob("../.github/workflows/*.yml")
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, l := range strings.Split(string(b), "\n") {
			_, u, ok := strings.Cut(l, "uses: ")
			if !ok || strings.HasPrefix(strings.TrimSpace(l), "#") {
				continue
			}
			u, _, _ = strings.Cut(u, " ")
			_, at, ok := strings.Cut(u, "@")
			if !ok || len(at) != 40 || strings.Trim(at, "0123456789abcdef") != "" {
				t.Errorf("%s:%d: %q is not pinned by a full commit SHA", filepath.Base(f), i+1, u)
			}
		}
	}
	for _, doc := range []string{"../README.md", "../SECURITY.md"} {
		b, err := os.ReadFile(doc)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), "gh attestation verify") {
			t.Errorf("%s does not say how to verify the provenance", filepath.Base(doc))
		}
	}
}
