package judge

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/donaldsteele/telltale/internal/checklist"
	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/pkgverify"
)

var (
	now     = time.Date(2026, 11, 22, 14, 5, 0, 0, time.UTC)
	taken   = time.Date(2026, 11, 2, 9, 30, 0, 0, time.UTC)
	changed = time.Date(2026, 11, 21, 3, 12, 0, 0, time.UTC)
)

const (
	serverKey = `from="192.0.2.10" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIServerKeyBlob telltale-server`
	ownerKey  = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOwnerKeyBlob owner@laptop"
	evilKey   = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEvilKeyBlobXX mallory"
)

var ctx = model.ScanContext{DigestKey: []byte("test-digest-key"), ServerAddr: "192.0.2.10", ServerKeyLine: serverKey}

func h(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func file(p, content string, perm uint32) model.FileEntry {
	return model.FileEntry{Path: p, Type: "file", SHA256: h(content), Mode: 0o100000 | perm, Size: int64(len(content)), MTime: taken, CTime: taken}
}

func pkg(name, version string, files ...string) model.Package {
	return model.Package{Name: name, Version: version, Arch: "amd64", Status: "install ok installed", Files: files}
}

// clean is a machine on which every checklist item that can be judged
// passes and no heuristic fires.
func clean() *model.Collection {
	yes := true
	return &model.Collection{
		Schema: model.CollectionSchema,
		Host:   model.Host{Hostname: "web01", OSID: "debian", OSVersionID: "12", OSPretty: "Debian GNU/Linux 12 (bookworm)", Arch: "amd64", Kernel: "6.1.0-25-amd64"},
		Time:   now,
		AsRoot: true,
		Files: []model.FileEntry{
			file("/usr/bin/openssl", "openssl 3.0.14", 0o755),
			file("/usr/bin/ls", "ls 9.1", 0o755),
			file("/usr/share/doc/openssl/README", "readme", 0o644),
			file("/etc/hostname", "web01", 0o644),
		},
		Accounts: model.Accounts{
			Users: []model.User{{Name: "root", UID: 0, GID: 0, Home: "/root", Shell: "/bin/bash",
				Password: model.PasswordState{Known: true, Set: true, Algo: "yescrypt", Digest: "digest-root-1", LastChange: 20000}}},
			Groups: []model.Group{{Name: "root", GID: 0}, {Name: "sudo", GID: 27}, {Name: "staff", GID: 50}},
		},
		Packages: model.Packages{Installed: []model.Package{
			pkg("openssl", "3.0.14-1~deb12u2", "/usr/bin/openssl", "/usr/share/doc/openssl/README"),
			pkg("coreutils", "9.1-1", "/usr/bin/ls"),
			pkg("auditd", "1:3.0.9-1"),
			pkg("unattended-upgrades", "2.9.1+nmu3"),
			pkg("ufw", "0.36.2-1"),
		}},
		Firewall: model.Firewall{Backend: "nftables", InputPolicy: "drop", InputRules: 3, UFWEnabled: &yes},
		Sysctl:   map[string]string{"kernel.randomize_va_space": "2", "apparmor.enabled": "Y"},
	}
}

func clone(c *model.Collection) *model.Collection {
	b, err := json.Marshal(c)
	if err != nil {
		panic(err)
	}
	var out model.Collection
	if err := json.Unmarshal(b, &out); err != nil {
		panic(err)
	}
	return &out
}

func snapOf(c *model.Collection) *model.Snapshot {
	return &model.Snapshot{Schema: model.SnapshotSchema, Taken: taken, Collection: clone(c), Checks: checklist.Evaluate(c, ctx), DigestKey: ctx.DigestKey}
}

func archive(verified ...pkgverify.FileVerdict) *pkgverify.Result {
	return &pkgverify.Result{Mode: pkgverify.ModeArchive, Verified: verified, SourcesUsed: []string{"https://deb.debian.org/debian bookworm"}}
}

func run(c *model.Collection, s *model.Snapshot, r *pkgverify.Result) *model.Report {
	return Judge(Input{Collection: c, Snapshot: s, Context: ctx, Pkg: r, Now: now})
}

func find(r *model.Report, key string) *model.Finding {
	for i := range r.Findings {
		if r.Findings[i].Key == key {
			return &r.Findings[i]
		}
	}
	return nil
}

func explained(r *model.Report, key string) *model.Finding {
	for i := range r.Explained {
		if r.Explained[i].Key == key {
			return &r.Explained[i]
		}
	}
	return nil
}

func keys(r *model.Report) []string {
	var out []string
	for _, f := range r.Findings {
		out = append(out, f.Key)
	}
	return out
}

func must(t *testing.T, r *model.Report, key string, sev model.Severity) *model.Finding {
	t.Helper()
	f := find(r, key)
	if f == nil {
		t.Fatalf("no finding %q; have %v", key, keys(r))
	}
	if f.Severity != sev {
		t.Fatalf("%s: severity %v, want %v", key, f.Severity, sev)
	}
	return f
}

func absent(t *testing.T, r *model.Report, key string) {
	t.Helper()
	if f := find(r, key); f != nil {
		t.Fatalf("unexpected finding %q (%v): %s", key, f.Severity, f.Title)
	}
}

func hasEvidencePath(f *model.Finding, p string) bool {
	return slices.ContainsFunc(f.Evidence, func(e model.Evidence) bool { return e.Path == p })
}

func setFile(c *model.Collection, e model.FileEntry) {
	for i := range c.Files {
		if c.Files[i].Path == e.Path {
			c.Files[i] = e
			return
		}
	}
	c.Files = append(c.Files, e)
}

func setVersion(c *model.Collection, name, version string) {
	for i := range c.Packages.Installed {
		if c.Packages.Installed[i].Name == name {
			c.Packages.Installed[i].Version = version
			return
		}
	}
	panic("no package " + name)
}

func removePkg(c *model.Collection, name string) {
	c.Packages.Installed = slices.DeleteFunc(c.Packages.Installed, func(p model.Package) bool { return p.Name == name })
}

const evidenceCopy = "mkdir -p /root/telltale-evidence && cp -a --parents "

// --- the brief's tests ---

func TestJudgeRegressionIsTampering(t *testing.T) {
	old := clean()
	cur := clone(old)
	cur.Sysctl["kernel.randomize_va_space"] = "0"

	r := run(cur, snapOf(old), nil)
	f := must(t, r, "check:TT-KERN-001", model.SevTampering)
	if f.Source != "checklist" {
		t.Errorf("source %q", f.Source)
	}
	if e := f.Evidence[0]; e.Before != "kernel.randomize_va_space = 2" || e.After != "kernel.randomize_va_space = 0" {
		t.Errorf("evidence %+v", e)
	}
	if !strings.Contains(f.Fix, "sysctl -w kernel.randomize_va_space=2") {
		t.Errorf("fix %q", f.Fix)
	}
	if r.ExitCode != 2 {
		t.Errorf("exit %d", r.ExitCode)
	}

	// The same failure without a snapshot is only a weak setting.
	r = run(cur, nil, nil)
	must(t, r, "check:TT-KERN-001", model.SevWeak)
	if r.ExitCode != 1 {
		t.Errorf("exit %d", r.ExitCode)
	}
}

func TestJudgeUpgradeExplained(t *testing.T) {
	old := clean()
	cur := clone(old)
	setVersion(cur, "openssl", "3.0.15-1~deb12u1")
	nf := file("/usr/bin/openssl", "openssl 3.0.15", 0o755)
	nf.CTime = changed
	setFile(cur, nf)
	v := pkgverify.FileVerdict{Path: "/usr/bin/openssl", Package: "openssl", Version: "3.0.15-1~deb12u1", Expected: nf.SHA256, Actual: nf.SHA256, Source: "archive"}

	r := run(cur, snapOf(old), archive(v))
	if len(r.Findings) != 0 {
		t.Fatalf("findings %v", keys(r))
	}
	if r.ExitCode != 0 {
		t.Errorf("exit %d", r.ExitCode)
	}
	e := explained(r, "explained:openssl")
	if e == nil {
		t.Fatalf("no explained group; explained %+v", r.Explained)
	}
	if e.Severity != model.SevExplained || !hasEvidencePath(e, "/usr/bin/openssl") {
		t.Errorf("group %+v", e)
	}
	if e.Evidence[0].Before != "3.0.14-1~deb12u2" || e.Evidence[0].After != "3.0.15-1~deb12u1" {
		t.Errorf("version evidence %+v", e.Evidence[0])
	}
	if want := "openssl upgraded from 3.0.14-1~deb12u2 to 3.0.15-1~deb12u1; 1 file changed with it"; e.Title != want || e.Why == "" {
		t.Errorf("group title %q, want %q (why %q)", e.Title, want, e.Why)
	}

	// Without verification the same changed program is not explained.
	r = run(cur, snapOf(old), nil)
	must(t, r, "snap.file_modified:/usr/bin/openssl", model.SevBackdoor)
}

func TestJudgeKernelPackageExplained(t *testing.T) {
	old := clean()
	old.Packages.Installed = append(old.Packages.Installed,
		pkg("linux-image-6.1.0-25-amd64", "6.1.106-3"), pkg("linux-headers-6.1.0-25-amd64", "6.1.106-3"))

	cur := clone(old)
	cur.Packages.Installed = append(cur.Packages.Installed,
		pkg("linux-image-6.1.0-27-amd64", "6.1.115-1"), pkg("linux-headers-6.1.0-27-amd64", "6.1.115-1"))
	newKernel := cur
	r := run(cur, snapOf(old), nil)
	for _, n := range []string{"linux-image-6.1.0-27-amd64", "linux-headers-6.1.0-27-amd64"} {
		absent(t, r, "snap.pkg_installed:"+n)
		if explained(r, "explained:"+n) == nil {
			t.Errorf("%s not explained", n)
		}
	}

	// Another flavour, or an older version, is not routine.
	cur = clone(old)
	cur.Packages.Installed = append(cur.Packages.Installed,
		pkg("linux-image-6.1.0-27-rt-amd64", "6.1.115-1"), pkg("linux-image-6.1.0-20-amd64", "6.1.85-1"))
	r = run(cur, snapOf(old), nil)
	must(t, r, "snap.pkg_installed:linux-image-6.1.0-27-rt-amd64", model.SevNote)
	must(t, r, "snap.pkg_installed:linux-image-6.1.0-20-amd64", model.SevNote)

	// Removing the old kernel once a newer one is installed is routine too;
	// removing the only kernel of a flavour is not.
	cur2 := clone(newKernel)
	removePkg(cur2, "linux-image-6.1.0-25-amd64")
	r = run(cur2, snapOf(newKernel), nil)
	absent(t, r, "snap.pkg_removed:linux-image-6.1.0-25-amd64")
	if explained(r, "explained:linux-image-6.1.0-25-amd64") == nil {
		t.Errorf("old kernel removal not explained")
	}
	cur3 := clone(old)
	removePkg(cur3, "linux-image-6.1.0-25-amd64")
	must(t, run(cur3, snapOf(old), nil), "snap.pkg_removed:linux-image-6.1.0-25-amd64", model.SevNote)
}

func TestJudgeNewPackageWithSetuidIsBackdoor(t *testing.T) {
	old := clean()
	cur := clone(old)
	helper := file("/usr/bin/helper", "helper", 0o4755)
	jq := file("/usr/bin/jq", "jq", 0o755)
	cur.Files = append(cur.Files, helper, jq)
	cur.Packages.Installed = append(cur.Packages.Installed, pkg("helperpkg", "1.0-1", "/usr/bin/helper"), pkg("jq", "1.6-2.1", "/usr/bin/jq"))
	res := archive(
		pkgverify.FileVerdict{Path: "/usr/bin/helper", Package: "helperpkg", Version: "1.0-1", Expected: helper.SHA256, Actual: helper.SHA256, Source: "archive"},
		pkgverify.FileVerdict{Path: "/usr/bin/jq", Package: "jq", Version: "1.6-2.1", Expected: jq.SHA256, Actual: jq.SHA256, Source: "archive"})

	r := run(cur, snapOf(old), res)
	f := must(t, r, "snap.pkg_installed:helperpkg", model.SevBackdoor)
	if !hasEvidencePath(f, "/usr/bin/helper") {
		t.Errorf("evidence does not name the setuid program: %+v", f.Evidence)
	}
	if !strings.Contains(f.Fix, "apt-get purge 'helperpkg'") || !strings.HasPrefix(f.Fix, "mkdir -p /root/telltale-evidence && ") {
		t.Errorf("fix %q", f.Fix)
	}
	n := must(t, r, "snap.pkg_installed:jq", model.SevNote)
	// The packages' own verified files are evidence on the package's
	// finding, not ranked again.
	absent(t, r, "snap.file_added:/usr/bin/helper")
	absent(t, r, "snap.file_added:/usr/bin/jq")
	if !hasEvidencePath(n, "/usr/bin/jq") || explained(r, "explained:jq") != nil {
		t.Errorf("verified file of a new package not on its finding: %+v", n.Evidence)
	}
}

func TestJudgeDowngradeIsBackdoor(t *testing.T) {
	old := clean()
	old.Packages.Installed = append(old.Packages.Installed, pkg("openssh-server", "1:9.2p1-2+deb12u3"))
	cur := clone(old)
	setVersion(cur, "openssh-server", "1:9.2p1-2+deb12u1")

	r := run(cur, snapOf(old), nil)
	f := must(t, r, "snap.pkg_downgraded:openssh-server", model.SevBackdoor)
	if !strings.Contains(f.Fix, "apt-get install 'openssh-server=1:9.2p1-2+deb12u3'") {
		t.Errorf("fix %q", f.Fix)
	}
	if f.Evidence[0].Before != "1:9.2p1-2+deb12u3" || f.Evidence[0].After != "1:9.2p1-2+deb12u1" {
		t.Errorf("evidence %+v", f.Evidence[0])
	}
}

func TestJudgeMismatchIsTampering(t *testing.T) {
	c := clean()
	res := archive()
	res.Mismatch = []pkgverify.FileVerdict{
		{Path: "/usr/bin/ls", Package: "coreutils", Version: "9.1-1", Expected: h("ls 9.1"), Actual: h("evil ls"), Reason: "differs from the file in the signed package", Source: "archive"},
		{Path: "/usr/bin/openssl", Package: "openssl", Version: "3.0.14-1~deb12u2", Expected: h("openssl 3.0.14"), Actual: h("openssl 3.0.14"), Reason: "mode differs: deb 0755, disk 4755", Source: "snapshot"},
	}
	r := run(c, nil, res)
	f := must(t, r, "pkg.mismatch:/usr/bin/ls", model.SevTampering)
	if f.Source != "package" {
		t.Errorf("source %q", f.Source)
	}
	if e := f.Evidence[0]; e.Before != h("ls 9.1") || e.After != h("evil ls") || !strings.Contains(e.Detail, "archive") {
		t.Errorf("evidence %+v", e)
	}
	want := evidenceCopy + "'/usr/bin/ls' /root/telltale-evidence/ && apt-get install --reinstall 'coreutils'"
	if !strings.HasPrefix(f.Fix, want) {
		t.Errorf("fix %q, want prefix %q", f.Fix, want)
	}
	m := must(t, r, "pkg.mismatch:/usr/bin/openssl", model.SevTampering)
	if !strings.Contains(m.Evidence[0].Detail, "mode differs: deb 0755, disk 4755") {
		t.Errorf("mode evidence %+v", m.Evidence[0])
	}
	if r.ExitCode != 2 {
		t.Errorf("exit %d", r.ExitCode)
	}
}

func TestJudgeUnverifiableGrouped(t *testing.T) {
	c := clean()
	special := []model.FileEntry{
		file("/usr/bin/su", "su", 0o4755),
		file("/lib/modules/6.1.0-25-amd64/kernel/fs/x.ko", "ko", 0o644),
		file("/usr/lib/x86_64-linux-gnu/security/pam_x.so", "pam", 0o644),
		file("/boot/vmlinuz-6.1.0-25-amd64", "kernel", 0o644),
	}
	plain := []model.FileEntry{
		file("/usr/bin/a", "a", 0o755),
		file("/usr/bin/b", "b", 0o755),
		file("/usr/lib/x86_64-linux-gnu/libx.so.1", "lib", 0o644),
	}
	c.Files = append(append(c.Files, special...), plain...)
	notOfficial := pkgverify.ReasonNotOfficial + " or a snapshot of it"
	res := archive()
	for _, e := range special {
		res.Unverifiable = append(res.Unverifiable, pkgverify.FileVerdict{Path: e.Path, Package: "localpkg", Version: "1", Reason: notOfficial})
	}
	res.Unverifiable = append(res.Unverifiable,
		pkgverify.FileVerdict{Path: "/usr/bin/a", Package: "localpkg", Reason: notOfficial},
		pkgverify.FileVerdict{Path: "/usr/bin/b", Package: "localpkg", Reason: notOfficial},
		pkgverify.FileVerdict{Path: "/usr/lib/x86_64-linux-gnu/libx.so.1", Package: "pro", Reason: pkgverify.ReasonPro})

	r := run(c, nil, res)
	g := must(t, r, "pkg.unverifiable", model.SevNote)
	if !strings.Contains(g.Title, "3") {
		t.Errorf("title %q does not count the 3 grouped files", g.Title)
	}
	var details []string
	for _, e := range g.Evidence {
		details = append(details, e.Detail)
	}
	all := strings.Join(details, "\n")
	if !strings.Contains(all, "2 files: "+notOfficial) || !strings.Contains(all, "1 file: "+pkgverify.ReasonPro) {
		t.Errorf("grouped evidence lacks reasons and counts:\n%s", all)
	}
	for _, e := range plain {
		absent(t, r, "pkg.unverifiable:"+e.Path)
	}
	for _, e := range special {
		must(t, r, "pkg.unverifiable:"+e.Path, model.SevBackdoor)
	}
}

func TestJudgeExceptionDropsMatchingValue(t *testing.T) {
	old := clean()
	old.Sysctl["kernel.randomize_va_space"] = "0"
	s := snapOf(old)
	s.Exceptions = []model.Exception{{FindingKey: "check:TT-KERN-001", AcceptedValue: "kernel.randomize_va_space = 0", Note: "lab box", At: taken}}

	r := run(clone(old), s, nil)
	absent(t, r, "check:TT-KERN-001")
	if len(r.Exceptions) != 1 || r.Exceptions[0].FindingKey != "check:TT-KERN-001" {
		t.Errorf("exceptions %+v", r.Exceptions)
	}
	if r.ExitCode != 0 {
		t.Errorf("exit %d (findings %v)", r.ExitCode, keys(r))
	}
}

func TestJudgeExceptionReappearsOnChange(t *testing.T) {
	old := clean()
	old.Sysctl["kernel.randomize_va_space"] = "1"
	s := snapOf(old)
	s.Exceptions = []model.Exception{{FindingKey: "check:TT-KERN-001", AcceptedValue: "kernel.randomize_va_space = 1", At: taken}}
	cur := clone(old)
	cur.Sysctl["kernel.randomize_va_space"] = "0"

	r := run(cur, s, nil)
	// The accepted value is the baseline: a different failing value is a
	// regression from it.
	f := must(t, r, "check:TT-KERN-001", model.SevTampering)
	if f.Evidence[0].Before != "kernel.randomize_va_space = 1" || f.Evidence[0].After != "kernel.randomize_va_space = 0" {
		t.Errorf("evidence %+v", f.Evidence[0])
	}
	if len(r.Exceptions) != 0 {
		t.Errorf("exception listed as applied: %+v", r.Exceptions)
	}

	// Any finding: the accepted value matches -> dropped; it changed -> back.
	mis := func(actual string) *pkgverify.Result {
		res := archive()
		res.Mismatch = []pkgverify.FileVerdict{{Path: "/usr/bin/ls", Package: "coreutils", Version: "9.1-1", Expected: h("ls 9.1"), Actual: actual, Reason: "differs from the file in the signed package", Source: "archive"}}
		return res
	}
	s2 := snapOf(clean())
	s2.Exceptions = []model.Exception{{FindingKey: "pkg.mismatch:/usr/bin/ls", AcceptedValue: h("local build"), At: taken}}
	r = run(clean(), s2, mis(h("local build")))
	absent(t, r, "pkg.mismatch:/usr/bin/ls")
	r = run(clean(), s2, mis(h("something else")))
	must(t, r, "pkg.mismatch:/usr/bin/ls", model.SevTampering)
}

func TestJudgeRankingOrder(t *testing.T) {
	older := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	newer := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	fs := []model.Finding{
		{Key: "z", Severity: model.SevNote, Source: "checklist"},
		{Key: "a", Severity: model.SevTampering, Source: "checklist"},
		{Key: "b", Severity: model.SevTampering, Source: "package"},
		{Key: "c", Severity: model.SevTampering, Source: "crossview"},
		{Key: "d", Severity: model.SevBackdoor, Source: "heuristic", Evidence: []model.Evidence{{When: &older}}},
		{Key: "e", Severity: model.SevBackdoor, Source: "heuristic", Evidence: []model.Evidence{{When: &older}, {When: &newer}}},
		{Key: "g", Severity: model.SevBackdoor, Source: "heuristic"},
		{Key: "f", Severity: model.SevBackdoor, Source: "heuristic"},
		{Key: "h", Severity: model.SevBackdoor, Source: "snapshot"},
		{Key: "i", Severity: model.SevWeak, Source: "heuristic"},
	}
	sortFindings(fs)
	var got []string
	for _, f := range fs {
		got = append(got, f.Key)
	}
	want := []string{"c", "b", "a", "h", "e", "d", "f", "g", "i", "z"}
	if !slices.Equal(got, want) {
		t.Errorf("order %v, want %v", got, want)
	}

	// End to end: a cross-view mismatch outranks a package mismatch, which
	// outranks regressed checklist items (the new system account also
	// breaks TT-ACCT-003); among notes the snapshot comes before heuristics.
	old := clean()
	cur := clone(old)
	cur.Sysctl["kernel.randomize_va_space"] = "0"
	cur.CrossView = []model.CrossViewResult{{Tool: "ps", Ran: true, HiddenFromTool: []string{"pid 4242 (evil)"}}}
	cur.Accounts.Users = append(cur.Accounts.Users, model.User{Name: "svc", UID: 998, GID: 998, Home: "/var/lib/svc", Shell: "/bin/sh",
		Password: model.PasswordState{Known: true, Locked: true, LastChange: 20000}})
	res := archive()
	res.Mismatch = []pkgverify.FileVerdict{{Path: "/usr/bin/ls", Package: "coreutils", Version: "9.1-1", Expected: h("ls 9.1"), Actual: h("evil"), Reason: "differs from the file in the signed package", Source: "archive"}}
	r := run(cur, snapOf(old), res)
	order := keys(r)
	wantOrder := []string{"heur.crossview:ps", "pkg.mismatch:/usr/bin/ls", "check:TT-ACCT-003", "check:TT-KERN-001", "snap.user_added:svc", "heur.system_shell:svc"}
	if !slices.Equal(order, wantOrder) {
		t.Fatalf("order %v, want %v", order, wantOrder)
	}
	if r.Findings[0].Source != "crossview" {
		t.Errorf("cross-view source %q", r.Findings[0].Source)
	}
	for i := 1; i < len(r.Findings); i++ {
		if r.Findings[i].Severity > r.Findings[i-1].Severity {
			t.Errorf("not ranked by severity: %v", order)
		}
	}
}

func TestJudgeExitCodes(t *testing.T) {
	r := run(clean(), nil, archive())
	if r.ExitCode != 0 || len(r.Findings) != 0 {
		t.Fatalf("clean machine: exit %d, findings %v", r.ExitCode, keys(r))
	}

	weak := clean()
	weak.Sysctl["kernel.randomize_va_space"] = "1"
	if r := run(weak, nil, nil); r.ExitCode != 1 {
		t.Errorf("weak setting: exit %d (%v)", r.ExitCode, keys(r))
	}

	note := clean()
	note.Accounts.Users = append(note.Accounts.Users, model.User{Name: "svc", UID: 998, GID: 998, Home: "/var/lib/svc", Shell: "/bin/sh",
		Password: model.PasswordState{Known: true, Locked: true, Algo: "!", LastChange: 20000}})
	if r := run(note, nil, nil); r.ExitCode != 1 || find(r, "heur.system_shell:svc") == nil {
		t.Errorf("note: exit %d (%v)", r.ExitCode, keys(r))
	}

	bad := clean()
	res := archive()
	res.Mismatch = []pkgverify.FileVerdict{{Path: "/usr/bin/ls", Package: "coreutils", Expected: "a", Actual: "b", Reason: "differs from the file in the signed package", Source: "archive"}}
	if r := run(bad, nil, res); r.ExitCode != 2 {
		t.Errorf("tampering: exit %d", r.ExitCode)
	}
	back := clean()
	back.Accounts.Users = append(back.Accounts.Users, model.User{Name: "toor", UID: 0, Home: "/root", Shell: "/bin/bash",
		Password: model.PasswordState{Known: true, Set: true, Algo: "yescrypt", Digest: "d", LastChange: 20000}})
	if r := run(back, nil, nil); r.ExitCode != 2 {
		t.Errorf("backdoor sign: exit %d", r.ExitCode)
	}
}

func TestJudgeAlwaysStatesKernelLimit(t *testing.T) {
	for name, r := range map[string]*model.Report{
		"nil collection": Judge(Input{Now: now}),
		"no snapshot":    run(clean(), nil, archive()),
		"snapshot":       run(clean(), snapOf(clean()), archive()),
	} {
		if !slices.Contains(r.CouldNotRuleOut, "kernel-level rootkits (any on-machine check can be fooled)") {
			t.Errorf("%s: could not rule out %q", name, r.CouldNotRuleOut)
		}
	}
}

func TestJudgeNoSnapshotComparedAgainstText(t *testing.T) {
	c := clean()
	judged := 0
	for _, res := range checklist.Evaluate(c, ctx) {
		if res.Skipped == "" {
			judged++
		}
	}
	items := "checklist (" + itoa(judged) + " items)"

	r := run(c, nil, archive())
	if want := []string{"Debian packages", items}; !slices.Equal(r.ComparedAgainst, want) {
		t.Errorf("compared against %q, want %q", r.ComparedAgainst, want)
	}
	if !slices.ContainsFunc(r.CouldNotRuleOut, func(s string) bool { return strings.Contains(s, "no snapshot") }) {
		t.Errorf("no-snapshot limit not stated: %q", r.CouldNotRuleOut)
	}

	ub := clean()
	ub.Host.OSID = "ubuntu"
	if r := run(ub, nil, archive()); !slices.Contains(r.ComparedAgainst, "Ubuntu packages") {
		t.Errorf("ubuntu: %q", r.ComparedAgainst)
	}

	r = run(clean(), snapOf(clean()), archive())
	if len(r.ComparedAgainst) == 0 || r.ComparedAgainst[0] != "snapshot of 2026-11-02" {
		t.Errorf("with snapshot: %q", r.ComparedAgainst)
	}

	off := &pkgverify.Result{Mode: pkgverify.ModeOfflineLocal, Errors: []string{pkgverify.OfflineWarning},
		SourcesUsed: []string{"the machine's own package checksums (/var/lib/dpkg)"}}
	r = run(clean(), nil, off)
	if want := []string{"the machine's own package checksums (root can edit these)", items}; !slices.Equal(r.ComparedAgainst, want) {
		t.Errorf("offline: %q", r.ComparedAgainst)
	}
	for _, s := range r.Skipped {
		if s.Reason == pkgverify.OfflineWarning {
			t.Errorf("offline warning listed as a skipped check")
		}
	}

	refs := &pkgverify.Result{Mode: pkgverify.ModeRefs, SourcesUsed: []string{"reference bundle /mnt/refs"}}
	if r := run(clean(), nil, refs); !slices.Equal(r.ComparedAgainst, []string{"reference bundle", items}) {
		t.Errorf("refs: %q", r.ComparedAgainst)
	}

	// Verification ran but could reach no reference: nothing is claimed.
	unreachable := &pkgverify.Result{Mode: pkgverify.ModeArchive, Errors: []string{"fetch https://deb.debian.org/debian/dists/bookworm/InRelease: no route to host"},
		Unverifiable: []pkgverify.FileVerdict{{Path: "/usr/bin/ls", Package: "coreutils", Reason: "no route to host"}}}
	r = run(clean(), nil, unreachable)
	if !slices.Equal(r.ComparedAgainst, []string{items}) {
		t.Errorf("unreachable archive: %q", r.ComparedAgainst)
	}
	if !slices.ContainsFunc(r.CouldNotRuleOut, func(s string) bool { return strings.Contains(s, "no package reference could be used") }) {
		t.Errorf("unreachable archive gap not stated: %q", r.CouldNotRuleOut)
	}

	// No package verification: no package reference is claimed, and the
	// gap is stated.
	r = run(clean(), nil, nil)
	if !slices.Equal(r.ComparedAgainst, []string{items}) {
		t.Errorf("no verification: %q", r.ComparedAgainst)
	}
	if !slices.ContainsFunc(r.CouldNotRuleOut, func(s string) bool { return strings.Contains(s, "package verification did not run") }) {
		t.Errorf("missing verification gap: %q", r.CouldNotRuleOut)
	}
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// --- package verification rulings ---

func TestJudgeSuspiciousIsBackdoor(t *testing.T) {
	res := archive()
	reason := "privilege granted by a local statoverride: deb 0755, disk 4755"
	res.Suspicious = []pkgverify.FileVerdict{{Path: "/usr/bin/ls", Package: "coreutils", Version: "9.1-1", Expected: h("ls 9.1"), Actual: h("ls 9.1"), Reason: reason, Source: "archive"}}
	r := run(clean(), nil, res)
	f := must(t, r, "pkg.suspicious:/usr/bin/ls", model.SevBackdoor)
	if !strings.Contains(f.Why, reason) || !strings.Contains(f.Evidence[0].Detail, reason) {
		t.Errorf("reason missing: why %q evidence %+v", f.Why, f.Evidence[0])
	}
	if !strings.HasPrefix(f.Fix, evidenceCopy+"'/usr/bin/ls' /root/telltale-evidence/ && ") {
		t.Errorf("fix %q", f.Fix)
	}
}

func TestJudgeModeRelaxedIsNote(t *testing.T) {
	ls := clean().Files[1]
	res := archive(
		pkgverify.FileVerdict{Path: "/usr/bin/ls", Package: "coreutils", Expected: ls.SHA256, Actual: ls.SHA256, Reason: "mode differs (less permissive): deb 4755, disk 0755", Source: "archive"},
		pkgverify.FileVerdict{Path: "/usr/bin/openssl", Package: "openssl", Expected: "x", Actual: "x", Source: "archive"})
	r := run(clean(), nil, res)
	must(t, r, "pkg.mode_relaxed:/usr/bin/ls", model.SevNote)
	absent(t, r, "pkg.mode_relaxed:/usr/bin/openssl")
}

func TestJudgeConffilesExplainedQuietly(t *testing.T) {
	res := archive()
	res.Conffiles = []pkgverify.ConffileDiff{
		{Path: "/etc/ssh/sshd_config", Package: "openssh-server", Version: "1:9.2p1-2+deb12u3", Expected: h("default"), Actual: h("edited"), Source: "archive"},
		{Path: "/etc/ssh/moduli", Package: "openssh-server", Version: "1:9.2p1-2+deb12u3", Expected: h("m"), Actual: h("m2"), Source: "archive"},
	}
	r := run(clean(), nil, res)
	for _, f := range r.Findings {
		if hasEvidencePath(&f, "/etc/ssh/sshd_config") {
			t.Errorf("conffile ranked as finding %s", f.Key)
		}
	}
	g := explained(r, "pkg.conffiles:openssh-server")
	if g == nil || !hasEvidencePath(g, "/etc/ssh/sshd_config") || !hasEvidencePath(g, "/etc/ssh/moduli") {
		t.Fatalf("conffiles group %+v", g)
	}
	if r.ExitCode != 0 {
		t.Errorf("exit %d", r.ExitCode)
	}
}

func TestJudgeIndexSignatureErrors(t *testing.T) {
	bad := "BAD SIGNATURE: https://deb.debian.org/debian/dists/bookworm/InRelease: no valid signature (the index was tampered with or intercepted, or telltale's built-in keys are out of date; nothing that depends on it was verified)"
	other := "could not download 2 package(s); first error: timeout"
	res := archive()
	res.Errors = []string{bad, other}
	r := run(clean(), nil, res)
	f := must(t, r, "pkg.index_signature", model.SevNote)
	if f.Evidence[0].Detail != bad {
		t.Errorf("evidence %+v", f.Evidence)
	}
	if !slices.Contains(r.CouldNotRuleOut, bad) {
		t.Errorf("could not rule out %q", r.CouldNotRuleOut)
	}
	if !slices.Contains(r.Skipped, model.Skip{Check: "packages", Reason: other}) {
		t.Errorf("skipped %+v", r.Skipped)
	}
	if slices.Contains(r.Skipped, model.Skip{Check: "packages", Reason: bad}) {
		t.Errorf("signature error hidden among skipped checks")
	}
}

func TestJudgeLowerTrustSourcesNote(t *testing.T) {
	res := archive(
		pkgverify.FileVerdict{Path: "/usr/bin/a", Package: "a", Source: "snapshot"},
		pkgverify.FileVerdict{Path: "/usr/bin/b", Package: "b", Source: "snapshot"},
		pkgverify.FileVerdict{Path: "/usr/bin/c", Package: "c", Source: "launchpad"},
		pkgverify.FileVerdict{Path: "/usr/bin/d", Package: "d", Source: "archive"})
	r := run(clean(), nil, res)
	f := must(t, r, "pkg.lower_trust", model.SevNote)
	if !strings.Contains(f.Title, "3") {
		t.Errorf("title %q", f.Title)
	}
	if r := run(clean(), nil, archive(pkgverify.FileVerdict{Path: "/usr/bin/d", Package: "d", Source: "archive"})); find(r, "pkg.lower_trust") != nil {
		t.Errorf("lower-trust note without lower-trust sources")
	}
}

// --- snapshot change rulings ---

func rootKeys(lines ...string) model.PersistFile {
	return model.PersistFile{Path: "/root/.ssh/authorized_keys", Kind: model.PersistKindAuthorizedKeys, Mode: 0o100600,
		SHA256: h(strings.Join(lines, "\n")), Lines: lines, MTime: changed}
}

func TestJudgeRootKeyNotesDroppedWithSnapshot(t *testing.T) {
	c := clean()
	c.Persist = []model.PersistFile{rootKeys(ownerKey)}
	if r := run(c, nil, nil); find(r, "heur.root_key:/root/.ssh/authorized_keys:1") == nil {
		t.Fatalf("no-snapshot scan lost the root key note: %v", keys(r))
	}
	r := run(c, snapOf(c), nil)
	for _, k := range keys(r) {
		if strings.HasPrefix(k, "heur.root_key:") {
			t.Errorf("root key note kept with a snapshot: %s", k)
		}
	}
}

func TestJudgeNewRootKeyIsBackdoor(t *testing.T) {
	old := clean()
	old.Persist = []model.PersistFile{rootKeys(ownerKey)}
	cur := clone(old)
	cur.Persist = []model.PersistFile{rootKeys(ownerKey, serverKey, evilKey)}

	r := run(cur, snapOf(old), nil)
	f := must(t, r, "snap.root_key:/root/.ssh/authorized_keys:3", model.SevBackdoor)
	if e := f.Evidence[0]; e.Path != "/root/.ssh/authorized_keys" || e.Line != 3 || e.After != evilKey || e.When == nil {
		t.Errorf("evidence %+v", e)
	}
	want := evidenceCopy + "'/root/.ssh/authorized_keys' /root/telltale-evidence/ && sed -i '3d' '/root/.ssh/authorized_keys'"
	if !strings.HasPrefix(f.Fix, want) {
		t.Errorf("fix %q", f.Fix)
	}
	// The telltale server's own key is expected, and the only other change
	// is the new key itself, so there is no second, generic finding.
	absent(t, r, "snap.root_key:/root/.ssh/authorized_keys:2")
	absent(t, r, "snap.persist:/root/.ssh/authorized_keys")
}

func TestJudgeUserAdded(t *testing.T) {
	old := clean()
	cur := clone(old)
	cur.Accounts.Users = append(cur.Accounts.Users,
		model.User{Name: "toor", UID: 0, GID: 0, Home: "/root", Shell: "/bin/bash", Password: model.PasswordState{Known: true, Set: true, Algo: "yescrypt", Digest: "d2", LastChange: 20000}},
		model.User{Name: "deploy", UID: 1001, GID: 1001, Home: "/home/deploy", Shell: "/bin/bash", Password: model.PasswordState{Known: true, Locked: true, LastChange: 20000}})
	r := run(cur, snapOf(old), nil)
	f := must(t, r, "snap.user_added:toor", model.SevBackdoor)
	if !strings.Contains(f.Fix, "userdel -f 'toor'") || !strings.HasPrefix(f.Fix, evidenceCopy) {
		t.Errorf("fix %q", f.Fix)
	}
	must(t, r, "snap.user_added:deploy", model.SevNote)

	// An existing account given user id 0 is as bad as a new one.
	old2 := clone(cur)
	cur2 := clone(old2)
	for i := range cur2.Accounts.Users {
		if cur2.Accounts.Users[i].Name == "deploy" {
			cur2.Accounts.Users[i].UID = 0
		}
	}
	must(t, run(cur2, snapOf(old2), nil), "snap.user_changed:deploy", model.SevBackdoor)
}

func TestJudgePasswordChangeShowsNoSecret(t *testing.T) {
	old := clean()
	cur := clone(old)
	cur.Accounts.Users[0].Password.Digest = "digest-root-2"
	r := run(cur, snapOf(old), nil)
	f := must(t, r, "snap.user_changed:root", model.SevNote)
	if !strings.Contains(f.Evidence[0].After, "password changed") {
		t.Errorf("evidence %+v", f.Evidence[0])
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "digest-root") {
		t.Errorf("password digest leaked into the report")
	}
}

func TestJudgePrivilegedGroupMember(t *testing.T) {
	old := clean()
	cur := clone(old)
	for i := range cur.Accounts.Groups {
		switch cur.Accounts.Groups[i].Name {
		case "sudo":
			cur.Accounts.Groups[i].Members = []string{"deploy"}
		case "staff":
			cur.Accounts.Groups[i].Members = []string{"deploy"}
		}
	}
	r := run(cur, snapOf(old), nil)
	f := must(t, r, "snap.group:sudo", model.SevBackdoor)
	if !strings.Contains(f.Fix, "gpasswd -d 'deploy' 'sudo'") {
		t.Errorf("fix %q", f.Fix)
	}
	must(t, r, "snap.group:staff", model.SevNote)
}

func TestJudgeListenerAdded(t *testing.T) {
	old := clean()
	old.Packages.Installed = append(old.Packages.Installed, pkg("openssh-server", "1:9.2p1-2+deb12u3", "/usr/sbin/sshd"))
	old.Files = append(old.Files, file("/usr/sbin/sshd", "sshd", 0o755))
	cur := clone(old)
	cur.Runtime.Processes = []model.Process{
		{PID: 10, UID: 0, Exe: "/usr/sbin/sshd", Comm: "sshd"},
		{PID: 11, UID: -1, Exe: "/usr/local/bin/agent", Comm: "agent"},
		{PID: 12, UID: 1000, Exe: "/tmp/.x/y", Comm: "y"},
	}
	cur.Runtime.Sockets = []model.Socket{
		{Proto: "tcp", Local: "0.0.0.0:2222", State: "LISTEN", Listening: true, PID: 10},
		{Proto: "tcp", Local: "0.0.0.0:4444", State: "LISTEN", Listening: true, PID: 11},
		{Proto: "tcp", Local: "0.0.0.0:31337", State: "LISTEN", Listening: true, PID: 12},
		{Proto: "udp", Local: "0.0.0.0:5353", Listening: true},
	}
	r := run(cur, snapOf(old), nil)
	must(t, r, "snap.listener:tcp:0.0.0.0:2222", model.SevNote)
	f := must(t, r, "snap.listener:tcp:0.0.0.0:4444", model.SevBackdoor)
	if !strings.Contains(f.Fix, "cp /proc/11/exe /root/telltale-evidence/11.exe") {
		t.Errorf("fix %q", f.Fix)
	}
	must(t, r, "snap.listener:tcp:0.0.0.0:31337", model.SevBackdoor)
	must(t, r, "snap.listener:udp:0.0.0.0:5353", model.SevNote)
}

func TestJudgeModuleAdded(t *testing.T) {
	old := clean()
	old.Packages.Installed = append(old.Packages.Installed, pkg("linux-image-6.1.0-25-amd64", "6.1.106-3", "/lib/modules/6.1.0-25-amd64/kernel/net/wg.ko"))
	cur := clone(old)
	cur.Runtime.Modules = []model.KernelModule{
		{Name: "wg", File: "/lib/modules/6.1.0-25-amd64/kernel/net/wg.ko"},
		{Name: "diamorphine", File: "/lib/modules/6.1.0-25-amd64/extra/diamorphine.ko"},
	}
	r := run(cur, snapOf(old), nil)
	must(t, r, "snap.module:wg", model.SevNote)
	f := must(t, r, "snap.module:diamorphine", model.SevBackdoor)
	if !strings.Contains(f.Fix, "modinfo -- 'diamorphine'") || !strings.HasPrefix(f.Fix, evidenceCopy+"'/lib/modules/6.1.0-25-amd64/extra/diamorphine.ko'") {
		t.Errorf("fix %q", f.Fix)
	}
}

func TestJudgeFileChangeRankedByLocation(t *testing.T) {
	old := clean()
	old.Files = append(old.Files, file("/etc/security/limits.conf", "limits", 0o644))
	cur := clone(old)
	setFile(cur, file("/usr/bin/ls", "ls trojan", 0o755))
	setFile(cur, file("/usr/share/doc/openssl/README", "readme 2", 0o644))
	setFile(cur, file("/etc/hostname", "web02", 0o644))
	setFile(cur, file("/etc/security/limits.conf", "limits 2", 0o644))
	setFile(cur, file("/usr/local/bin/tool", "tool", 0o755))
	setFile(cur, file("/usr/bin/openssl", "openssl patched", 0o755))
	res := archive()
	res.Mismatch = []pkgverify.FileVerdict{{Path: "/usr/bin/openssl", Package: "openssl", Version: "3.0.14-1~deb12u2", Expected: h("openssl 3.0.14"), Actual: h("openssl patched"), Reason: "differs from the file in the signed package", Source: "archive"}}

	r := run(cur, snapOf(old), res)
	f := must(t, r, "snap.file_modified:/usr/bin/ls", model.SevBackdoor)
	if !strings.HasPrefix(f.Fix, evidenceCopy+"'/usr/bin/ls' /root/telltale-evidence/ && apt-get install --reinstall 'coreutils'") {
		t.Errorf("fix %q", f.Fix)
	}
	must(t, r, "snap.file_modified:/etc/security/limits.conf", model.SevBackdoor)
	must(t, r, "snap.file_modified:/usr/share/doc/openssl/README", model.SevNote)
	must(t, r, "snap.file_modified:/etc/hostname", model.SevNote)
	a := must(t, r, "snap.file_added:/usr/local/bin/tool", model.SevBackdoor)
	if a.Fix != evidenceCopy+"'/usr/local/bin/tool' /root/telltale-evidence/ && rm -- '/usr/local/bin/tool'   # only if you did not put it there" {
		t.Errorf("fix %q", a.Fix)
	}
	// The change behind a package mismatch is evidence on that finding.
	absent(t, r, "snap.file_modified:/usr/bin/openssl")
	m := must(t, r, "pkg.mismatch:/usr/bin/openssl", model.SevTampering)
	if len(m.Evidence) < 2 {
		t.Errorf("snapshot change not folded into the mismatch: %+v", m.Evidence)
	}
}

func TestJudgeRoutineChangesAreNotBackdoorSigns(t *testing.T) {
	old := clean()
	old.Files = append(old.Files,
		model.FileEntry{Path: "/usr/share/doc", Type: "dir", Mode: 0o40755, Size: 4096},
		file("/boot/initrd.img-6.1.0-25-amd64", "initrd", 0o644),
		file("/etc/shadow", "shadow", 0o640),
		file("/var/lib/dpkg/info/openssl.md5sums", "sums", 0o644))
	cur := clone(old)
	setFile(cur, model.FileEntry{Path: "/usr/share/doc", Type: "dir", Mode: 0o40755, Size: 8192})
	setFile(cur, file("/boot/initrd.img-6.1.0-25-amd64", "initrd 2", 0o644))
	setFile(cur, file("/etc/shadow", "shadow 2", 0o640))
	cur.Accounts.Users[0].Password.Digest = "digest-root-2"
	setFile(cur, model.FileEntry{Path: "/usr/bin/awk", Type: "symlink", Target: "/etc/alternatives/awk", Mode: 0o120777})

	// Nothing was updated: a rebuilt initrd is a backdoor sign.
	r := run(cur, snapOf(old), nil)
	must(t, r, "snap.file_modified:/boot/initrd.img-6.1.0-25-amd64", model.SevBackdoor)

	// After a package update it is a note; dpkg's own records of the
	// updated package are explained with it.
	setVersion(cur, "openssl", "3.0.15-1~deb12u1")
	setFile(cur, file("/var/lib/dpkg/info/openssl.md5sums", "sums 2", 0o644))
	r = run(cur, snapOf(old), archive())
	must(t, r, "snap.file_modified:/boot/initrd.img-6.1.0-25-amd64", model.SevNote)
	absent(t, r, "snap.file_modified:/var/lib/dpkg/info/openssl.md5sums")
	if g := explained(r, "explained:openssl"); g == nil || !hasEvidencePath(g, "/var/lib/dpkg/info/openssl.md5sums") {
		t.Errorf("dpkg records not explained with the update: %+v", g)
	}
	absent(t, r, "snap.file_modified:/usr/share/doc")
	absent(t, r, "snap.file_modified:/etc/shadow")
	must(t, r, "snap.user_changed:root", model.SevNote)
	must(t, r, "snap.file_added:/usr/bin/awk", model.SevNote)
}

func TestJudgeKernelUpdateGeneratedFilesFoldIntoKernelPackage(t *testing.T) {
	old := clean()
	old.Packages.Installed = append(old.Packages.Installed, pkg("linux-image-6.1.0-25-amd64", "6.1.106-3"))
	old.Files = append(old.Files,
		file("/boot/initrd.img-6.1.0-25-amd64", "initrd 25", 0o644),
		file("/lib/modules/6.1.0-25-amd64/modules.dep", "dep 25", 0o644),
		file("/boot/grub/grub.cfg", "menu 25", 0o444),
		file("/etc/default/grub", "GRUB_CMDLINE_LINUX=\"\"", 0o644))
	cur := clone(old)
	removePkg(cur, "linux-image-6.1.0-25-amd64")
	cur.Packages.Installed = append(cur.Packages.Installed, pkg("linux-image-6.1.0-27-amd64", "6.1.115-1"))
	cur.Files = slices.DeleteFunc(cur.Files, func(e model.FileEntry) bool { return strings.Contains(e.Path, "6.1.0-25") })
	cur.Files = append(cur.Files,
		file("/boot/initrd.img-6.1.0-27-amd64", "initrd 27", 0o644),
		file("/lib/modules/6.1.0-27-amd64/modules.dep", "dep 27", 0o644))
	setFile(cur, file("/boot/grub/grub.cfg", "menu 27", 0o444))

	r := run(cur, snapOf(old), archive())
	for _, k := range []string{"snap.file_added:/boot/initrd.img-6.1.0-27-amd64", "snap.file_added:/lib/modules/6.1.0-27-amd64/modules.dep",
		"snap.file_removed:/boot/initrd.img-6.1.0-25-amd64", "snap.file_removed:/lib/modules/6.1.0-25-amd64/modules.dep"} {
		absent(t, r, k)
	}
	g := explained(r, "explained:linux-image-6.1.0-27-amd64")
	if g == nil || !hasEvidencePath(g, "/boot/initrd.img-6.1.0-27-amd64") || !hasEvidencePath(g, "/lib/modules/6.1.0-27-amd64/modules.dep") {
		t.Errorf("new kernel's generated files not shown with it: %+v", g)
	}
	// The old kernel's removal is routine too, and its generated files went
	// with it.
	absent(t, r, "snap.pkg_removed:linux-image-6.1.0-25-amd64")
	if o := explained(r, "explained:linux-image-6.1.0-25-amd64"); o == nil || !hasEvidencePath(o, "/boot/initrd.img-6.1.0-25-amd64") {
		t.Errorf("old kernel's initrd not shown with its removal: %+v", o)
	}
	// The boot menu is rebuilt for any kernel change: a note.
	must(t, r, "snap.file_modified:/boot/grub/grub.cfg", model.SevNote)

	// The kernel command line is a persistence location.
	setFile(cur, file("/etc/default/grub", "GRUB_CMDLINE_LINUX=\"init=/tmp/x\"", 0o644))
	must(t, run(cur, snapOf(old), archive()), "snap.file_modified:/etc/default/grub", model.SevBackdoor)
}

func TestJudgeRootsEverydayFilesAreQuiet(t *testing.T) {
	old := clean()
	old.Files = append(old.Files, file("/root/.bash_history", "ls", 0o600), file("/root/.ssh/known_hosts", "a", 0o644), file("/root/.viminfo", "v", 0o600))
	cur := clone(old)
	setFile(cur, file("/root/.bash_history", "ls\ncd", 0o600))
	setFile(cur, file("/root/.ssh/known_hosts", "a\nb", 0o644))
	setFile(cur, file("/root/.lesshst", "l", 0o600))
	cur.Files = slices.DeleteFunc(cur.Files, func(e model.FileEntry) bool { return e.Path == "/root/.viminfo" })
	r := run(cur, snapOf(old), nil)
	absent(t, r, "snap.file_modified:/root/.bash_history")
	absent(t, r, "snap.file_modified:/root/.ssh/known_hosts")
	absent(t, r, "snap.file_added:/root/.lesshst")
	// A wiped history or editor state is still listed.
	must(t, r, "snap.file_removed:/root/.viminfo", model.SevNote)

	// root's key file and SSH configuration stay persistence locations.
	cur.Files = append(cur.Files, file("/root/.ssh/rc", "evil", 0o755))
	must(t, run(cur, snapOf(old), nil), "snap.file_added:/root/.ssh/rc", model.SevBackdoor)
}

func TestJudgeConffileReplacedByUpgradeIsExplained(t *testing.T) {
	const p = "/etc/security/limits.conf"
	old := clean()
	lp := pkg("libpam-modules", "1.5.2-6", p)
	lp.Conffiles = map[string]string{p: "0123456789abcdef0123456789abcdef"}
	old.Packages.Installed = append(old.Packages.Installed, lp)
	old.Files = append(old.Files, file(p, "limits", 0o644))
	cur := clone(old)
	setVersion(cur, "libpam-modules", "1.5.2-6+deb12u1")
	setFile(cur, file(p, "limits, new default", 0o644))

	r := run(cur, snapOf(old), archive())
	absent(t, r, "snap.file_modified:"+p)
	if g := explained(r, "explained:libpam-modules"); g == nil || !hasEvidencePath(g, p) {
		t.Errorf("conffile replaced by the upgrade not explained: %+v", g)
	}
	// Edited away from the default: ranked as a persistence location.
	res := archive()
	res.Conffiles = []pkgverify.ConffileDiff{{Path: p, Package: "libpam-modules", Version: "1.5.2-6+deb12u1", Expected: h("default"), Actual: h("limits, new default")}}
	must(t, run(cur, snapOf(old), res), "snap.file_modified:"+p, model.SevBackdoor)
}

func cron(lines ...string) model.PersistFile {
	return model.PersistFile{Path: "/etc/cron.d/backup", Kind: model.PersistKindCron, Mode: 0o100644, SHA256: h(strings.Join(lines, "\n")), Lines: lines, MTime: changed}
}

func TestJudgePersistChanged(t *testing.T) {
	old := clean()
	old.Persist = []model.PersistFile{cron("0 3 * * * root /usr/local/bin/backup")}
	old.Files = append(old.Files, file("/etc/cron.d/backup", "0 3 * * * root /usr/local/bin/backup", 0o644))
	cur := clone(old)
	cur.Persist = []model.PersistFile{cron("0 3 * * * root /usr/local/bin/backup", "* * * * * root /tmp/.x")}
	setFile(cur, file("/etc/cron.d/backup", "0 3 * * * root /usr/local/bin/backup\n* * * * * root /tmp/.x", 0o644))

	r := run(cur, snapOf(old), nil)
	f := must(t, r, "snap.persist:/etc/cron.d/backup", model.SevBackdoor)
	if f.Evidence[0].After != cur.Persist[0].SHA256 {
		t.Errorf("first evidence must carry the file's new hash (the value an exception accepts): %+v", f.Evidence[0])
	}
	if !slices.ContainsFunc(f.Evidence, func(e model.Evidence) bool { return e.Line == 2 && e.After == "* * * * * root /tmp/.x" }) {
		t.Errorf("added line missing: %+v", f.Evidence)
	}
	if !strings.HasPrefix(f.Fix, evidenceCopy+"'/etc/cron.d/backup' /root/telltale-evidence/ && sed -i '2d' '/etc/cron.d/backup'") {
		t.Errorf("fix %q", f.Fix)
	}
	absent(t, r, "snap.file_modified:/etc/cron.d/backup")
}

func TestJudgePersistConffileUpgradeExplained(t *testing.T) {
	const p = "/etc/cron.daily/logrotate"
	lr := func(version, text string) (model.Package, model.PersistFile) {
		pk := pkg("logrotate", version, p, "/usr/sbin/logrotate")
		pk.Conffiles = map[string]string{p: "0123456789abcdef0123456789abcdef"}
		return pk, model.PersistFile{Path: p, Kind: model.PersistKindCron, Mode: 0o100755, SHA256: h(text), Lines: strings.Split(text, "\n"), MTime: changed}
	}
	old := clean()
	pk, pf := lr("3.21.0-1", "#!/bin/sh\nlogrotate /etc/logrotate.conf")
	old.Packages.Installed = append(old.Packages.Installed, pk)
	old.Persist = []model.PersistFile{pf}
	old.Files = append(old.Files, file(p, "#!/bin/sh\nlogrotate /etc/logrotate.conf", 0o755))

	upgraded := clone(old)
	pk2, pf2 := lr("3.21.0-2", "#!/bin/sh\nexec logrotate /etc/logrotate.conf")
	upgraded.Packages.Installed[len(upgraded.Packages.Installed)-1] = pk2
	upgraded.Persist = []model.PersistFile{pf2}
	nf := file(p, "#!/bin/sh\nexec logrotate /etc/logrotate.conf", 0o755)
	setFile(upgraded, nf)

	// The upgrade replaced the conffile and it matches the new default
	// (package verification reports nothing about it): explained.
	r := run(upgraded, snapOf(old), archive())
	absent(t, r, "snap.persist:"+p)
	absent(t, r, "snap.file_modified:"+p)
	if g := explained(r, "explained:logrotate"); g == nil || !hasEvidencePath(g, p) {
		t.Errorf("conffile update not explained: %+v", g)
	}

	// It differs from the package default: not explained by the upgrade.
	res := archive()
	res.Conffiles = []pkgverify.ConffileDiff{{Path: p, Package: "logrotate", Version: "3.21.0-2", Expected: h("default"), Actual: nf.SHA256}}
	must(t, run(upgraded, snapOf(old), res), "snap.persist:"+p, model.SevBackdoor)

	// Same change with no upgrade behind it.
	same := clone(upgraded)
	setVersion(same, "logrotate", "3.21.0-1")
	must(t, run(same, snapOf(old), archive()), "snap.persist:"+p, model.SevBackdoor)

	// Without package verification there is nothing to explain it with.
	must(t, run(upgraded, snapOf(old), nil), "snap.persist:"+p, model.SevBackdoor)
}

func TestJudgeNewPackageRaisedBy(t *testing.T) {
	cases := []struct {
		name  string
		files []model.FileEntry
		edit  func(c *model.Collection)
	}{
		{"caps", []model.FileEntry{func() model.FileEntry {
			e := file("/usr/bin/pinger", "p", 0o755)
			e.Caps = "0100000200200000"
			return e
		}()}, nil},
		{"module", []model.FileEntry{file("/lib/modules/6.1.0-25-amd64/updates/x.ko", "ko", 0o644)}, nil},
		{"pam", []model.FileEntry{file("/usr/lib/x86_64-linux-gnu/security/pam_x.so", "pam", 0o644)}, nil},
		{"unit", []model.FileEntry{file("/lib/systemd/system/xd.service", "[Service]", 0o644)}, func(c *model.Collection) {
			c.Persist = append(c.Persist, model.PersistFile{Path: "/etc/systemd/system/multi-user.target.wants/xd.service", Kind: model.PersistKindSystemdEnabled,
				Mode: 0o120777, SHA256: h("/lib/systemd/system/xd.service"), Lines: []string{"/lib/systemd/system/xd.service"}, MTime: changed})
		}},
		{"listener", []model.FileEntry{file("/usr/sbin/xd", "xd", 0o755)}, func(c *model.Collection) {
			c.Runtime.Processes = append(c.Runtime.Processes, model.Process{PID: 77, UID: 0, Exe: "/usr/sbin/xd"})
			c.Runtime.Sockets = append(c.Runtime.Sockets, model.Socket{Proto: "tcp", Local: "0.0.0.0:8080", Listening: true, PID: 77})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			old := clean()
			cur := clone(old)
			res := archive()
			var paths []string
			for _, e := range tc.files {
				cur.Files = append(cur.Files, e)
				paths = append(paths, e.Path)
				res.Verified = append(res.Verified, pkgverify.FileVerdict{Path: e.Path, Package: "xpkg", Version: "1", Expected: e.SHA256, Actual: e.SHA256, Source: "archive"})
			}
			cur.Packages.Installed = append(cur.Packages.Installed, pkg("xpkg", "1", paths...))
			if tc.edit != nil {
				tc.edit(cur)
			}
			r := run(cur, snapOf(old), res)
			f := must(t, r, "snap.pkg_installed:xpkg", model.SevBackdoor)
			if tc.name == "unit" {
				absent(t, r, "snap.persist:/etc/systemd/system/multi-user.target.wants/xd.service")
				if !hasEvidencePath(f, "/etc/systemd/system/multi-user.target.wants/xd.service") {
					t.Errorf("enable link not shown on the package finding: %+v", f.Evidence)
				}
			}
		})
	}
}

func TestJudgeSecurityPackageRemovedIsWeak(t *testing.T) {
	old := clean()
	old.Packages.Installed = append(old.Packages.Installed, pkg("fail2ban", "1.0.2-2"), pkg("jq", "1.6-2.1"))
	cur := clone(old)
	removePkg(cur, "fail2ban")
	removePkg(cur, "jq")
	r := run(cur, snapOf(old), nil)
	f := must(t, r, "snap.pkg_removed:fail2ban", model.SevWeak)
	if !strings.Contains(f.Fix, "apt-get install 'fail2ban'") {
		t.Errorf("fix %q", f.Fix)
	}
	must(t, r, "snap.pkg_removed:jq", model.SevNote)
}

// --- fixes, evidence and assembly ---

func TestJudgeCheckFixComesFromFixFor(t *testing.T) {
	c := clean()
	c.Accounts.Users = append(c.Accounts.Users, model.User{Name: "toor", UID: 0, Home: "/root", Shell: "/bin/bash",
		Password: model.PasswordState{Known: true, Set: true, Algo: "yescrypt", Digest: "d", LastChange: 20000}})
	it, _ := checklist.ByID("TT-ACCT-001")
	want := it.FixFor(c, ctx)
	if want == it.Fix {
		t.Fatalf("test needs an item whose machine-specific fix differs from the static one")
	}
	f := must(t, run(c, nil, nil), "check:TT-ACCT-001", model.SevWeak)
	if f.Fix != want {
		t.Errorf("fix %q, want %q", f.Fix, want)
	}
	if f.Evidence[0].After != "UID 0 besides root: toor" {
		t.Errorf("observed value not in evidence: %+v", f.Evidence[0])
	}
}

func TestJudgeFixQuotesAndRefusesControlCharacters(t *testing.T) {
	old := clean()
	cur := clone(old)
	cur.Files = append(cur.Files, file("/usr/local/bin/it's", "q", 0o755), file("/usr/local/bin/bad\nname", "n", 0o755))
	r := run(cur, snapOf(old), nil)
	q := must(t, r, "snap.file_added:/usr/local/bin/it's", model.SevBackdoor)
	if !strings.Contains(q.Fix, `rm -- '/usr/local/bin/it'\''s'`) {
		t.Errorf("fix %q", q.Fix)
	}
	n := must(t, r, "snap.file_added:/usr/local/bin/bad\nname", model.SevBackdoor)
	if strings.Contains(n.Fix, "rm") || strings.Contains(n.Fix, "\n") || !strings.Contains(n.Fix, "control") {
		t.Errorf("fix for a name with a newline: %q", n.Fix)
	}
}

func TestJudgeDuplicateKeysMergedKeepingHighest(t *testing.T) {
	j := newJudge(Input{Collection: clean()}, clean())
	j.add(&model.Finding{Key: "k", Severity: model.SevNote, Title: "low", Evidence: []model.Evidence{{Detail: "a"}}})
	j.add(&model.Finding{Key: "k", Severity: model.SevBackdoor, Title: "high", Evidence: []model.Evidence{{Detail: "b"}}})
	j.add(&model.Finding{Key: "k", Severity: model.SevWeak, Title: "mid", Evidence: []model.Evidence{{Detail: "a"}}})
	if len(j.findings) != 1 {
		t.Fatalf("%d findings", len(j.findings))
	}
	f := j.findings[0]
	if f.Severity != model.SevBackdoor || f.Title != "high" || len(f.Evidence) != 2 {
		t.Errorf("merged %+v", f)
	}
}

func TestJudgeSkippedListsCollectionAndCheckSkips(t *testing.T) {
	c := clean()
	c.Skipped = []model.Skip{{Check: "accounts", Reason: "/etc/shadow: permission denied"}}
	r := run(c, nil, nil)
	if !slices.Contains(r.Skipped, c.Skipped[0]) {
		t.Errorf("collection skip missing: %+v", r.Skipped)
	}
	if !slices.ContainsFunc(r.Skipped, func(s model.Skip) bool {
		return s.Check == "TT-SSH-001" && strings.Contains(s.Reason, "no sshd configuration")
	}) {
		t.Errorf("check skip missing: %+v", r.Skipped)
	}
	if r.Schema != model.ReportSchema || r.Host.Hostname != "web01" || !r.Time.Equal(now) {
		t.Errorf("header %+v %v %v", r.Host, r.Schema, r.Time)
	}
}
