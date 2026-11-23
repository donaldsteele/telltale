package judge

import (
	"slices"
	"strings"
	"testing"

	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/pkgverify"
)

// The machine's dpkg status (which root can edit) lists a root key file, a
// cron job and the preload list as conffiles of a package whose upgrade the
// signed archive confirms. Package verification says nothing about them: the
// signed package ships none. Nothing explains them and nothing rolls them
// into the baseline.
func TestJudgeStatusConffilesExplainNothing(t *testing.T) {
	const (
		keys    = "/root/.ssh/authorized_keys"
		job     = "/etc/cron.d/zz"
		preload = "/etc/ld.so.preload"
	)
	old := clean()
	old.Persist = []model.PersistFile{rootKeys(ownerKey)}
	old.Files = append(old.Files, file(keys, ownerKey, 0o600))

	cur := clone(old)
	setVersion(cur, "openssl", "3.0.15-1~deb12u1")
	nf := file("/usr/bin/openssl", "openssl 3.0.15", 0o755)
	nf.CTime = changed
	setFile(cur, nf)
	for i := range cur.Packages.Installed {
		if pk := &cur.Packages.Installed[i]; pk.Name == "openssl" {
			pk.Conffiles = map[string]string{keys: "0123456789abcdef0123456789abcdef", job: "0123456789abcdef0123456789abcdef", preload: "0123456789abcdef0123456789abcdef"}
			pk.Files = append(pk.Files, keys, job, preload)
		}
	}
	jobLine, lib := "* * * * * root /tmp/.x", "/tmp/.hide.so"
	cur.Persist = []model.PersistFile{
		rootKeys(ownerKey, evilKey),
		{Path: job, Kind: model.PersistKindCron, Mode: 0o100644, SHA256: h(jobLine), Lines: []string{jobLine}, MTime: changed},
		{Path: preload, Kind: model.PersistKindLDPreload, Mode: 0o100644, SHA256: h(lib), Lines: []string{lib}, MTime: changed},
	}
	setFile(cur, file(keys, ownerKey+"\n"+evilKey, 0o600))
	cur.Files = append(cur.Files, file(job, jobLine, 0o644), file(preload, lib, 0o644))

	v := pkgverify.FileVerdict{Path: "/usr/bin/openssl", Package: "openssl", Version: "3.0.15-1~deb12u1", Expected: nf.SHA256, Actual: nf.SHA256, Source: "archive"}
	r, rb := rebaseRun(cur, snapOf(old), archive(v))

	must(t, r, "snap.root_key:"+keys+":2", model.SevBackdoor)
	must(t, r, "snap.persist:"+job, model.SevBackdoor)
	must(t, r, "snap.persist:"+preload, model.SevBackdoor)
	if g := explained(r, "explained:openssl"); g != nil {
		for _, p := range []string{keys, job, preload} {
			if hasEvidencePath(g, p) {
				t.Errorf("%s explained by the upgrade: %+v", p, g.Evidence)
			}
		}
	}
	if rb == nil {
		t.Fatal("no rebase")
	}
	for _, p := range []string{keys, job, preload} {
		if slices.Contains(rb.Routine.Paths, p) {
			t.Errorf("%s rolls into the baseline: %+v", p, rb.Routine.Paths)
		}
	}

	// The same for a package that was newly installed.
	inst := clone(cur)
	inst.Packages.Installed = append(inst.Packages.Installed, func() model.Package {
		pk := pkg("zz", "1.0-1", "/usr/bin/zz", job)
		pk.Conffiles = map[string]string{job: "0123456789abcdef0123456789abcdef"}
		return pk
	}())
	for i := range inst.Packages.Installed {
		if pk := &inst.Packages.Installed[i]; pk.Name == "openssl" {
			pk.Conffiles, pk.Files = nil, pk.Files[:2]
		}
	}
	zz := file("/usr/bin/zz", "zz", 0o755)
	inst.Files = append(inst.Files, zz)
	r, rb = rebaseRun(inst, snapOf(old), archive(v, pkgverify.FileVerdict{Path: zz.Path, Package: "zz", Version: "1.0-1", Expected: zz.SHA256, Actual: zz.SHA256, Source: "archive"}))
	for _, f := range r.Explained {
		if hasEvidencePath(&f, job) && f.Severity == model.SevExplained && !strings.HasPrefix(f.Key, "snap.") {
			t.Errorf("%s explained by %s", job, f.Key)
		}
	}
	if find(r, "snap.persist:"+job) == nil && !slices.ContainsFunc(r.Findings, func(f model.Finding) bool { return hasEvidencePath(&f, job) && f.Severity == model.SevBackdoor }) {
		t.Errorf("new cron job listed as a new package's conffile is not a backdoor sign: %v", keysOf(r))
	}
	if rb != nil && slices.Contains(rb.Routine.Paths, job) {
		t.Errorf("%s rolls into the baseline", job)
	}
}

func keysOf(r *model.Report) []string { return keys(r) }

// Only the signed package's own verdict explains a conffile: one the upgrade
// reset to the package default.
func TestJudgeConffileDefaultVerdictExplains(t *testing.T) {
	const p = "/etc/security/limits.conf"
	old := clean()
	old.Packages.Installed = append(old.Packages.Installed, pkg("libpam-modules", "1.5.2-6", p))
	old.Files = append(old.Files, file(p, "limits", 0o644))
	cur := clone(old)
	setVersion(cur, "libpam-modules", "1.5.2-6+deb12u1")
	nf := file(p, "limits, new default", 0o644)
	setFile(cur, nf)

	def := pkgverify.FileVerdict{Path: p, Package: "libpam-modules", Version: "1.5.2-6+deb12u1", Expected: nf.SHA256, Actual: nf.SHA256, Source: "archive", Kind: pkgverify.KindConffileDefault}
	res := archive()
	res.ConffileDefaults = []pkgverify.FileVerdict{def}
	r := run(cur, snapOf(old), res)
	absent(t, r, "snap.file_modified:"+p)
	if g := explained(r, "explained:libpam-modules"); g == nil || !hasEvidencePath(g, p) {
		t.Errorf("conffile reset to the signed default not explained: %+v", g)
	}

	// Silence confirms nothing, whatever dpkg status lists.
	for i := range cur.Packages.Installed {
		if pk := &cur.Packages.Installed[i]; pk.Name == "libpam-modules" {
			pk.Conffiles = map[string]string{p: "0123456789abcdef0123456789abcdef"}
		}
	}
	must(t, run(cur, snapOf(old), archive()), "snap.file_modified:"+p, model.SevBackdoor)

	// A verdict for other content, or for another version, does not cover
	// the file as it is now.
	stale := def
	stale.Actual, stale.Expected = h("other"), h("other")
	res = archive()
	res.ConffileDefaults = []pkgverify.FileVerdict{stale}
	must(t, run(cur, snapOf(old), res), "snap.file_modified:"+p, model.SevBackdoor)
	older := def
	older.Version = "1.5.2-6"
	res = archive()
	res.ConffileDefaults = []pkgverify.FileVerdict{older}
	must(t, run(cur, snapOf(old), res), "snap.file_modified:"+p, model.SevBackdoor)
}

// A package's file changed, package verification ran, and it said nothing
// about the file: that never happens to a file the signed package accounts
// for, so it is a backdoor sign, not a note (the probe: a trojan with its
// execute bits dropped so that it no longer looks like a program).
func TestJudgeOwnedChangedFileWithoutVerdict(t *testing.T) {
	const p = "/usr/share/doc/openssl/README"
	old := clean()
	cur := clone(old)
	setFile(cur, file(p, "trojan, mode 0644", 0o644))

	f := must(t, run(cur, snapOf(old), archive()), "snap.file_modified:"+p, model.SevBackdoor)
	if !strings.Contains(f.Why, "openssl") || !strings.Contains(f.Why, "said nothing") {
		t.Errorf("why %q", f.Why)
	}
	// Any verdict about it decides instead.
	v := pkgverify.FileVerdict{Path: p, Package: "openssl", Version: "3.0.14-1~deb12u2", Expected: h("trojan, mode 0644"), Actual: h("trojan, mode 0644"), Source: "archive"}
	if r := run(cur, snapOf(old), archive(v)); find(r, "snap.file_modified:"+p) != nil {
		t.Errorf("a verified file is still ranked: %v", keys(r))
	}
	// Package verification did not run, or used the machine's own
	// checksums: there was nobody to say anything, and the report says so.
	must(t, run(cur, snapOf(old), nil), "snap.file_modified:"+p, model.SevNote)
	must(t, run(cur, snapOf(old), &pkgverify.Result{Mode: pkgverify.ModeOfflineLocal}), "snap.file_modified:"+p, model.SevNote)
	// A file no package owns stays a note.
	other := clone(old)
	other.Files = append(other.Files, file("/usr/share/doc/mine/README", "mine", 0o644))
	must(t, run(other, snapOf(old), archive()), "snap.file_added:/usr/share/doc/mine/README", model.SevNote)
}
