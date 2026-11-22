package collect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/donaldsteele/telltale/internal/heuristics"
	"github.com/donaldsteele/telltale/internal/model"
)

func TestPAMModulesOutsideSystemPathsAreCollected(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "etc/pam.d"), 0o755)
	os.MkdirAll(filepath.Join(root, "opt"), 0o755)
	os.MkdirAll(filepath.Join(root, "var/lib/.c"), 0o755)
	os.WriteFile(filepath.Join(root, "opt/x.so"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(root, "var/lib/.c/pam_y.so"), []byte("y"), 0o644)
	os.WriteFile(filepath.Join(root, "opt/z.so"), []byte("z"), 0o644)
	os.WriteFile(filepath.Join(root, "etc/pam.d/sshd"), []byte(strings.Join([]string{
		"auth optional /opt/x.so",
		"auth optional /var/lib/.c/pam_y.so",
		"auth optional ../../../../opt/z.so",
		"auth optional /opt/gone.so",
		"auth optional pam_a\x00b.so",
		"auth optional pam_a\x1bb.so",
	}, "\n")+"\n"), 0o644)
	persist, _ := Persistence(root, nil, []byte("k"))
	// c.Files is NOT pre-seeded: the collector has to find the modules
	files, _ := ensurePAMEntries(root, nil, nil, persist, defaultMaxHash)
	got := byPath(files)
	for _, p := range []string{"/opt/x.so", "/var/lib/.c/pam_y.so", "/opt/z.so"} {
		if e, ok := got[p]; !ok || !e.Supplementary {
			t.Errorf("%s not collected: %v", p, files)
		}
	}
	c := &model.Collection{Persist: persist, Files: files}
	fs := heuristics.Run(c, model.ScanContext{}, map[string]string{})
	has := map[string]model.Finding{}
	for _, f := range fs {
		has[f.Key] = f
	}
	for _, k := range []string{"heur.pam_unowned:/opt/x.so", "heur.pam_unowned:/var/lib/.c/pam_y.so", "heur.pam_unowned:/opt/z.so"} {
		if f, ok := has[k]; !ok || f.Severity != model.SevBackdoor {
			t.Errorf("missing %s", k)
		}
	}
	if f, ok := has["heur.pam_missing:/opt/gone.so"]; !ok || f.Severity != model.SevNote {
		t.Errorf("a module that does not exist stays missing")
	}
	for k, f := range has {
		if strings.HasPrefix(k, "heur.pam_missing:pam_a") && (strings.Contains(f.Fix, "grep") || strings.Contains(f.Fix, "\x00") || strings.Contains(f.Fix, "\x1b")) {
			t.Errorf("control-character module name got a command: %q", f.Fix)
		}
	}
}

func TestPAMNeverRule(t *testing.T) {
	for p, want := range map[string]bool{"/dev/shm/x.so": false, "/dev/null": true, "/dev/sda": true, "/proc/1/x": true, "/opt/x": false} {
		if pamNever(p) != want {
			t.Errorf("pamNever(%q) != %v", p, want)
		}
	}
}
