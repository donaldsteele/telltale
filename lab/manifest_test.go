//go:build lab

package lab

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/lab/labkit"
)

func report(fs ...model.Finding) *model.Report {
	r := &model.Report{}
	for _, f := range fs {
		if f.Severity == model.SevExplained {
			r.Explained = append(r.Explained, f)
		} else {
			r.Findings = append(r.Findings, f)
		}
	}
	return r
}

func fnd(key string, sev model.Severity) model.Finding {
	return model.Finding{Key: key, Severity: sev}
}

const sample = `{
  "requires": {"variant": "hardened", "ext4": true},
  "with_snapshot": {
    "must": [{"key_prefix": "snap.persist:/etc/ld.so.preload", "severity": "backdoor sign"}],
    "must_not_severity_above": "tampering"
  },
  "without_snapshot": {
    "must": [{"key_prefix": "heur.ld_preload", "severity": "backdoor sign"}],
    "must_not_severity_above": "backdoor sign"
  }
}`

func load(t *testing.T, text string) *Manifest {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := LoadManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestManifestMatcher(t *testing.T) {
	m := load(t, sample)
	if m.Requires.Variant != "hardened" || !m.Requires.Ext4 {
		t.Fatalf("requires = %+v", m.Requires)
	}

	t.Run("must hit", func(t *testing.T) {
		r := report(fnd("heur.ld_preload", model.SevBackdoor), fnd("check:TT-SSH-001", model.SevWeak))
		if p := Check(m, r, false); len(p) != 0 {
			t.Fatalf("problems: %v", p)
		}
	})
	t.Run("must hit by prefix, in the explained list", func(t *testing.T) {
		mm := load(t, `{"with_snapshot":{"must":[{"key_prefix":"pkg.","severity":"explained"}]},"without_snapshot":{}}`)
		r := report(fnd("pkg.upgraded:openssl", model.SevExplained))
		if p := Check(mm, r, true); len(p) != 0 {
			t.Fatalf("problems: %v", p)
		}
	})
	t.Run("must miss", func(t *testing.T) {
		r := report(fnd("check:TT-SSH-001", model.SevWeak))
		p := Check(m, r, false)
		if len(p) != 1 || !strings.Contains(p[0], "heur.ld_preload") {
			t.Fatalf("problems: %v", p)
		}
	})
	t.Run("severity mismatch", func(t *testing.T) {
		r := report(fnd("heur.ld_preload", model.SevNote))
		p := Check(m, r, false)
		if len(p) != 1 || !strings.Contains(p[0], "heur.ld_preload") || !strings.Contains(p[0], "note") {
			t.Fatalf("problems: %v", p)
		}
	})
	t.Run("a prefix match with the wrong severity does not hide a right one", func(t *testing.T) {
		r := report(fnd("heur.ld_preload", model.SevNote), fnd("heur.ld_preload.x", model.SevBackdoor))
		if p := Check(m, r, false); len(p) != 0 {
			t.Fatalf("problems: %v", p)
		}
	})
	t.Run("must_not_severity_above violated", func(t *testing.T) {
		r := report(fnd("heur.ld_preload", model.SevBackdoor), fnd("heur.crossview:ps", model.SevTampering))
		p := Check(m, r, false)
		if len(p) != 1 || !strings.Contains(p[0], "heur.crossview:ps") {
			t.Fatalf("problems: %v", p)
		}
	})
	t.Run("must_not_severity_above allows the level itself", func(t *testing.T) {
		mm := load(t, `{"with_snapshot":{"must_not_severity_above":"note"},"without_snapshot":{"must_not_severity_above":"weak setting"}}`)
		if p := Check(mm, report(fnd("a", model.SevNote), fnd("b", model.SevExplained)), true); len(p) != 0 {
			t.Fatalf("problems: %v", p)
		}
		if p := Check(mm, report(fnd("a", model.SevWeak)), true); len(p) != 1 {
			t.Fatalf("weak above note should fail once: %v", p)
		}
		if p := Check(mm, report(fnd("a", model.SevWeak)), false); len(p) != 0 {
			t.Fatalf("weak at weak should pass: %v", p)
		}
	})
	t.Run("the section follows withSnapshot", func(t *testing.T) {
		r := report(fnd("heur.ld_preload", model.SevBackdoor))
		p := Check(m, r, true)
		if len(p) != 1 || !strings.Contains(p[0], "snap.persist:/etc/ld.so.preload") {
			t.Fatalf("with snapshot should want the snap key: %v", p)
		}
		r = report(fnd("snap.persist:/etc/ld.so.preload", model.SevBackdoor), fnd("heur.ld_preload", model.SevBackdoor))
		if p := Check(m, r, true); len(p) != 0 {
			t.Fatalf("problems: %v", p)
		}
	})
	t.Run("a missing section is a problem, not a pass", func(t *testing.T) {
		mm := load(t, `{"with_snapshot":{}}`)
		p := Check(mm, report(), false)
		if len(p) != 1 || !strings.Contains(p[0], "without_snapshot") {
			t.Fatalf("problems: %v", p)
		}
	})
	t.Run("bad manifests are refused", func(t *testing.T) {
		for _, bad := range []string{
			`{"with_snapshot":{"must":[{"key_prefix":"x","severity":"loud"}]}}`,
			`{"with_snapshot":{"must":[{"key_prefix":"","severity":"note"}]}}`,
			`{"with_snapshot":{"mst":[]}}`,
			`{"requires":{"variant":"nonesuch"}}`,
		} {
			dir := t.TempDir()
			os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(bad), 0o644)
			if _, err := LoadManifest(dir); err == nil {
				t.Errorf("accepted %s", bad)
			}
		}
	})
}

// Every committed manifest must load, every break and scenario must have a
// script that parses, and every variant must have a baseline manifest.
func TestCommittedManifests(t *testing.T) {
	breaks := []string{"root-key", "uid0-account", "sudo-nopasswd", "cron-callback", "systemd-callback", "profile-script",
		"ld-preload", "pam-module", "replaced-binary", "setuid-shell", "immutable-file", "devshm-process", "deleted-exe-process",
		"listener-port", "hider-rootkit", "regress-root-login", "regress-firewall-off", "regress-empty-password",
		"downgrade-package", "new-service-package", "package-dir-link", "package-dir-outside"}
	scenarios := []string{"weak-password-to-root", "web-shell-persistence", "upgrade-while-running"}
	check := func(dir string) {
		if _, err := LoadManifest(dir); err != nil {
			t.Errorf("%v", err)
		}
		script := filepath.Join(dir, "apply.sh")
		if out, err := exec.Command("bash", "-n", script).CombinedOutput(); err != nil {
			t.Errorf("%s: %v\n%s", script, err, out)
		}
	}
	for _, id := range breaks {
		check(filepath.Join("breaks", id))
	}
	for _, id := range scenarios {
		check(filepath.Join("scenarios", id))
	}
	for _, v := range labkit.Variants {
		m, err := LoadManifestFile(filepath.Join("variants", v+".manifest.json"))
		if err != nil {
			t.Errorf("%v", err)
			continue
		}
		if m.Requires.Variant != v || m.WithoutSnapshot == nil || m.WithSnapshot == nil {
			t.Errorf("variant %s: baseline manifest incomplete: %+v", v, m)
		}
	}
}
