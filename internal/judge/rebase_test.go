package judge

import (
	"slices"
	"strings"
	"testing"

	"github.com/donaldsteele/telltale/internal/checklist"
	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/pkgverify"
)

func rebaseRun(c *model.Collection, s *model.Snapshot, r *pkgverify.Result) (*model.Report, *Rebase) {
	if s != nil && s.Collection != nil {
		inventoried(s.Collection)
	}
	return JudgeRebase(Input{Collection: inventoried(c), Snapshot: s, Context: ctx, Pkg: r, Now: now})
}

// An upgrade the signed package explains rolls forward by itself: the
// package's record and the files shown with it.
func TestJudgeRebaseRoutineUpgrade(t *testing.T) {
	old := clean()
	cur := clone(old)
	setVersion(cur, "openssl", "3.0.15-1~deb12u1")
	nf := file("/usr/bin/openssl", "openssl 3.0.15", 0o755)
	nf.CTime = changed
	setFile(cur, nf)
	v := pkgverify.FileVerdict{Path: "/usr/bin/openssl", Package: "openssl", Version: "3.0.15-1~deb12u1", Expected: nf.SHA256, Actual: nf.SHA256, Source: "archive"}

	snap := snapOf(old)
	r, rb := rebaseRun(cur, snap, archive(v))
	if len(r.Findings) != 0 || explained(r, "explained:openssl") == nil {
		t.Fatalf("findings %v explained %v", keys(r), r.Explained)
	}
	if rb == nil || !slices.Equal(rb.Routine.Packages, []string{"openssl:amd64"}) || !slices.Equal(rb.Routine.Paths, []string{"/usr/bin/openssl"}) {
		t.Fatalf("routine %+v", rb)
	}
	if len(rb.Accept) != 0 {
		t.Errorf("nothing ranked, nothing to accept: %v", rb.Accept)
	}
	rolled := RollForward(snap, cur, checklist.Evaluate(cur, ctx), rb.Routine)
	r, rb = rebaseRun(cur, rolled, archive())
	if len(r.Findings) != 0 || len(r.Explained) != 0 {
		t.Errorf("after rolling forward: findings %v explained %v", keys(r), r.Explained)
	}
	if !rb.Routine.Empty() {
		t.Errorf("nothing left to roll: %+v", rb.Routine)
	}
	if snap.Collection.Packages.Installed[0].Version != "3.0.14-1~deb12u2" {
		t.Errorf("the old snapshot was changed in place")
	}
}

// An upgrade nothing confirmed is ranked, not routine: it rolls forward only
// when accepted, together with the files shown with it.
func TestJudgeRebaseAcceptScopes(t *testing.T) {
	old := clean()
	cur := clone(old)
	setVersion(cur, "openssl", "3.0.15-1~deb12u1")
	setFile(cur, file("/usr/bin/openssl", "openssl 3.0.15", 0o755))
	cur.Persist = append(cur.Persist, cron("* * * * * root /tmp/.x"))
	cur.Files = append(cur.Files, file("/etc/cron.d/backup", "* * * * * root /tmp/.x", 0o644))
	cur.Accounts.Users = append(cur.Accounts.Users, model.User{Name: "toor", UID: 0, GID: 0, Home: "/root", Shell: "/bin/bash"})

	snap := snapOf(old)
	r, rb := rebaseRun(cur, snap, nil)
	must(t, r, "snap.pkg_upgraded:openssl", model.SevNote)
	must(t, r, "snap.persist:/etc/cron.d/backup", model.SevBackdoor)
	must(t, r, "heur.uid0:toor", model.SevBackdoor)
	if !rb.Routine.Empty() {
		t.Errorf("nothing is routine: %+v", rb.Routine)
	}
	// Nothing confirmed the new version, so the changed program is a finding
	// of its own, accepted on its own.
	if up := rb.Accept["snap.pkg_upgraded:openssl"]; !slices.Equal(up.Packages, []string{"openssl:amd64"}) || len(up.Paths) != 0 {
		t.Errorf("accepting the upgrade: %+v", up)
	}
	if s := rb.Accept["snap.file_modified:/usr/bin/openssl"]; !slices.Equal(s.Paths, []string{"/usr/bin/openssl"}) {
		t.Errorf("accepting the program: %+v", s)
	}
	if s := rb.Accept["snap.persist:/etc/cron.d/backup"]; !slices.Equal(s.Paths, []string{"/etc/cron.d/backup"}) {
		t.Errorf("accepting the cron file: %+v", s)
	}
	if s := rb.Accept["snap.user_added:toor"]; !slices.Equal(s.Users, []string{"toor"}) {
		t.Errorf("accepting the account: %+v", s)
	}
	if _, ok := rb.Accept["heur.uid0:toor"]; ok {
		t.Errorf("a heuristic is not a change since the snapshot")
	}

	// Accepting the cron file rolls only it forward.
	rolled := RollForward(snap, cur, checklist.Evaluate(cur, ctx), rb.Accept["snap.persist:/etc/cron.d/backup"])
	r, _ = rebaseRun(cur, rolled, nil)
	absent(t, r, "snap.persist:/etc/cron.d/backup")
	must(t, r, "snap.pkg_upgraded:openssl", model.SevNote)
	must(t, r, "snap.user_added:toor", model.SevBackdoor)
}

// Two keys added to root's authorized_keys: the file rolls forward as a
// whole, so accepting one key accepts the other too. Each says so, and a
// package mismatch about a changed file is named with that file's change.
func TestJudgeRebaseAcceptedTogether(t *testing.T) {
	old := clean()
	old.Persist = []model.PersistFile{rootKeys(ownerKey)}
	cur := clone(old)
	cur.Persist = []model.PersistFile{rootKeys(ownerKey, evilKey, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAnotherKeyBlob other")}
	ls := file("/usr/bin/ls", "trojaned ls", 0o755)
	setFile(cur, ls)
	res := archive()
	res.Mismatch = []pkgverify.FileVerdict{{Path: "/usr/bin/ls", Package: "coreutils", Version: "9.1-1", Expected: h("ls 9.1"), Actual: ls.SHA256, Source: "archive"}}

	r, rb := rebaseRun(cur, snapOf(old), res)
	must(t, r, "pkg.mismatch:/usr/bin/ls", model.SevTampering)
	a, b := "snap.root_key:/root/.ssh/authorized_keys:2", "snap.root_key:/root/.ssh/authorized_keys:3"
	if s := rb.Accept[a]; !slices.Equal(s.Paths, []string{"/root/.ssh/authorized_keys"}) || !slices.Contains(s.With, b) {
		t.Errorf("%s: %+v", a, s)
	}
	if s := rb.Accept[b]; !slices.Contains(s.With, a) {
		t.Errorf("%s: %+v", b, s)
	}
	for k, s := range rb.Accept {
		if slices.Contains(s.Paths, "/usr/bin/ls") && !slices.Contains(s.With, "pkg.mismatch:/usr/bin/ls") {
			t.Errorf("%s rolls the trojaned file forward without naming the mismatch: %+v", k, s)
		}
	}
	if slices.Contains(rb.Routine.Paths, "/usr/bin/ls") {
		t.Errorf("the trojaned file rolls forward by itself: %+v", rb.Routine)
	}
	if _, ok := rb.Accept["pkg.mismatch:/usr/bin/ls"]; ok {
		t.Errorf("a mismatch is not a change since the snapshot")
	}
}

// Without a snapshot nothing rolls forward.
func TestJudgeRebaseNoSnapshot(t *testing.T) {
	if _, rb := rebaseRun(clean(), nil, nil); rb != nil {
		t.Errorf("rebase without a snapshot: %+v", rb)
	}
}

// A regressed checklist item rolls the snapshot's result forward.
func TestRollForwardChecks(t *testing.T) {
	old := clean()
	snap := snapOf(old)
	cur := clone(old)
	cur.Sysctl["kernel.randomize_va_space"] = "0"
	r, rb := rebaseRun(cur, snap, nil)
	must(t, r, "check:TT-KERN-001", model.SevTampering)
	s, ok := rb.Accept["check:TT-KERN-001"]
	if !ok || !slices.Equal(s.Checks, []string{"TT-KERN-001"}) {
		t.Fatalf("accept %+v", rb.Accept)
	}
	r, _ = rebaseRun(cur, RollForward(snap, cur, checklist.Evaluate(cur, ctx), s), nil)
	must(t, r, "check:TT-KERN-001", model.SevWeak)
}

// Exceptions kept outside the snapshot (the server's store) apply as the
// snapshot's own do, with or without a snapshot.
func TestInputExceptions(t *testing.T) {
	cur := clean()
	cur.Accounts.Users = append(cur.Accounts.Users, model.User{Name: "toor", UID: 0, GID: 0, Home: "/root", Shell: "/bin/bash"})
	r := run(cur, nil, nil)
	f := must(t, r, "heur.uid0:toor", model.SevBackdoor)
	exc := model.Exception{FindingKey: f.Key, AcceptedValue: ExceptionValue(f), At: now}
	r = Judge(Input{Collection: inventoried(cur), Context: ctx, Now: now, Exceptions: []model.Exception{exc}})
	absent(t, r, "heur.uid0:toor")
	if len(r.Exceptions) != 1 || r.Exceptions[0].FindingKey != f.Key {
		t.Errorf("exceptions in force %+v", r.Exceptions)
	}
	r = Judge(Input{Collection: inventoried(cur), Snapshot: snapOf(cur), Context: ctx, Now: now, Exceptions: []model.Exception{exc}})
	if len(r.Exceptions) != 1 {
		t.Errorf("with a snapshot: exceptions in force %+v", r.Exceptions)
	}
}

func TestAddFindingsRanks(t *testing.T) {
	r := run(clean(), nil, nil)
	if r.ExitCode != 0 {
		t.Fatalf("clean exit %d: %v", r.ExitCode, keys(r))
	}
	AddFindings(r, model.Finding{Key: "z.note", Severity: model.SevNote}, model.Finding{Key: "a.tamper", Severity: model.SevTampering})
	if r.ExitCode != 2 || r.Findings[0].Key != "a.tamper" || r.Findings[len(r.Findings)-1].Key != "z.note" {
		t.Errorf("exit %d order %v", r.ExitCode, keys(r))
	}
}

// A library cache rebuilt from verified package files rolls forward with
// its list, so the next rebuild is judged against the list as it is now.
func TestJudgeRebaseLinkerCache(t *testing.T) {
	const cache, ssl, zlib = "/etc/ld.so.cache", "/usr/lib/x86_64-linux-gnu/libssl.so.3", "/usr/lib/x86_64-linux-gnu/libz.so.1"
	old := clean()
	old.Files = append(old.Files, file(cache, "cache 1", 0o644), file(ssl, "libssl", 0o644))
	old.Packages.Installed = append(old.Packages.Installed, pkg("libssl3", "3.0.14-1~deb12u2", ssl))
	old.LinkerCache = []string{ssl}
	cur := clone(old)
	setFile(cur, file(cache, "cache 2", 0o644))
	lib := file(zlib, "libz", 0o644)
	cur.Files = append(cur.Files, lib)
	cur.Packages.Installed = append(cur.Packages.Installed, pkg("zlib1g", "1:1.2.13.dfsg-1", zlib))
	cur.LinkerCache = []string{ssl, zlib}
	v := pkgverify.FileVerdict{Path: zlib, Package: "zlib1g", Version: "1:1.2.13.dfsg-1", Expected: lib.SHA256, Actual: lib.SHA256, Source: "archive"}

	snap := snapOf(old)
	r, rb := rebaseRun(cur, snap, archive(v))
	if explained(r, "rebuilt:"+cache) == nil {
		t.Fatalf("cache rebuild not explained: findings %v", keys(r))
	}
	if !slices.Contains(rb.Routine.Paths, cache) || !rb.Routine.LinkerCache {
		t.Fatalf("routine %+v", rb.Routine)
	}
	rolled := RollForward(snap, cur, checklist.Evaluate(cur, ctx), rb.Routine)
	if !slices.Equal(rolled.Collection.LinkerCache, cur.LinkerCache) {
		t.Errorf("cache list %v", rolled.Collection.LinkerCache)
	}
}

const sslNew = "3.0.15-1~deb12u1"

// upgradedSSL is clean() with openssl:amd64 upgraded and its program
// verified, the routine case.
func upgradedSSL() (*model.Collection, pkgverify.FileVerdict) {
	cur := clean()
	setVersion(cur, "openssl", sslNew)
	nf := file("/usr/bin/openssl", "openssl 3.0.15", 0o755)
	setFile(cur, nf)
	return cur, pkgverify.FileVerdict{Path: "/usr/bin/openssl", Package: "openssl", Version: sslNew, Expected: nf.SHA256, Actual: nf.SHA256, Source: "archive"}
}

// Probe A: next to a confirmed upgrade of openssl:amd64, openssl:i386 is
// installed with a setuid program. Only amd64 rolls forward; the i386
// install stays a backdoor sign on the next visit too.
func TestJudgeRebaseOtherArchInstallStays(t *testing.T) {
	old := clean()
	cur, v := upgradedSSL()
	helper := file("/usr/lib/i386-linux-gnu/openssl/helper", "helper", 0o4755)
	cur.Files = append(cur.Files, helper)
	i386 := pkg("openssl", sslNew, helper.Path)
	i386.Arch = "i386"
	cur.Packages.Installed = append(cur.Packages.Installed, i386)
	vi := pkgverify.FileVerdict{Path: helper.Path, Package: "openssl", Version: sslNew, Expected: helper.SHA256, Actual: helper.SHA256, Source: "archive"}

	snap := snapOf(old)
	r, rb := rebaseRun(cur, snap, archive(v, vi))
	must(t, r, "snap.pkg_installed:openssl:i386", model.SevBackdoor)
	if !slices.Equal(rb.Routine.Packages, []string{"openssl:amd64"}) || slices.Contains(rb.Routine.Paths, helper.Path) {
		t.Fatalf("routine %+v", rb.Routine)
	}
	rolled := RollForward(snap, cur, checklist.Evaluate(cur, ctx), rb.Routine)
	if n := len(slices.DeleteFunc(slices.Clone(rolled.Collection.Packages.Installed), func(p model.Package) bool { return p.Name != "openssl" })); n != 1 {
		t.Fatalf("%d openssl entries in the snapshot", n)
	}
	r, _ = rebaseRun(cur, rolled, archive(vi))
	var raised bool
	for _, f := range r.Findings {
		if strings.HasPrefix(f.Key, "snap.pkg_installed:openssl") && f.Severity == model.SevBackdoor {
			raised = true
		}
	}
	if !raised {
		t.Errorf("visit 2 lost the i386 install with a setuid program: %v", keys(r))
	}
}

// Probe B: openssl:i386 claims a version nothing confirmed while
// openssl:amd64 has a confirmed upgrade. The i386 record does not roll; the
// next visit judges it.
func TestJudgeRebaseOtherArchVersionStays(t *testing.T) {
	old := clean()
	lib := file("/usr/lib/i386-linux-gnu/libssl.so.3", "libssl i386", 0o644)
	old.Files = append(old.Files, lib)
	i386 := pkg("openssl", "3.0.14-1~deb12u2", lib.Path)
	i386.Arch = "i386"
	old.Packages.Installed = append(old.Packages.Installed, i386)
	cur, v := upgradedSSL()
	cur.Files = append(cur.Files, lib)
	fake := i386
	fake.Version = "3.0.99-fake"
	cur.Packages.Installed = append(cur.Packages.Installed, fake)

	snap := snapOf(old)
	_, rb := rebaseRun(cur, snap, archive(v))
	if !slices.Equal(rb.Routine.Packages, []string{"openssl:amd64"}) {
		t.Fatalf("routine %+v", rb.Routine)
	}
	rolled := RollForward(snap, cur, checklist.Evaluate(cur, ctx), rb.Routine)
	for _, p := range rolled.Collection.Packages.Installed {
		if p.Name == "openssl" && p.Arch == "i386" && p.Version != "3.0.14-1~deb12u2" {
			t.Fatalf("the unconfirmed i386 version rolled in: %s", p.Version)
		}
	}
	r, _ := rebaseRun(cur, rolled, archive())
	if find(r, "snap.pkg_version_only:openssl") == nil && find(r, "snap.pkg_upgraded:openssl") == nil {
		t.Errorf("visit 2 does not report the i386 version: %v", keys(r))
	}
}

// Probe C: the archive is unreachable, openssl moves to a version nobody
// could check, a data file changes and a package directory appears. The
// explained group survives (an outage contradicts nothing), but nothing
// rolls forward: once the archive is back, the version is a backdoor sign.
func TestJudgeRebaseUncheckedVersionDoesNotRoll(t *testing.T) {
	old := clean()
	old.Files = append(old.Files, model.FileEntry{Path: "/usr/lib/ssl", Type: "dir", Mode: 0o40755, MTime: taken, CTime: taken})
	old.Packages.Installed[0].Files = append(old.Packages.Installed[0].Files, "/usr/lib/ssl", "/usr/lib/ssl/certs")
	cur := clone(old)
	setVersion(cur, "openssl", "3.0.99-fake")
	setFile(cur, file("/usr/share/doc/openssl/README", "readme 2", 0o644))
	cur.Files = append(cur.Files, model.FileEntry{Path: "/usr/lib/ssl/certs", Type: "dir", Mode: 0o40755, MTime: changed, CTime: changed})
	down := archive()
	down.Unverifiable = []pkgverify.FileVerdict{{Path: "/usr/share/doc/openssl/README", Package: "openssl", Version: "3.0.99-fake", Reason: "no route to host", Kind: pkgverify.KindUnreachable}}

	snap := snapOf(old)
	r, rb := rebaseRun(cur, snap, down)
	if explained(r, "explained:openssl") == nil {
		t.Fatalf("fixture: the group did not survive the outage: findings %v", keys(r))
	}
	if !rb.Routine.Empty() {
		t.Fatalf("an unchecked version rolls forward: %+v", rb.Routine)
	}
	back := archive()
	back.Unverifiable = []pkgverify.FileVerdict{{Path: "/usr/share/doc/openssl/README", Package: "openssl", Version: "3.0.99-fake", Reason: pkgverify.ReasonNotOfficial, Kind: pkgverify.KindNotFound}}
	r, _ = rebaseRun(cur, RollForward(snap, cur, checklist.Evaluate(cur, ctx), rb.Routine), back)
	must(t, r, "snap.pkg_upgraded:openssl", model.SevBackdoor)
}

// Probe D: a newer kernel entry with no files, nothing confirmed: explained
// as routine kernel update, but it does not roll forward.
func TestJudgeRebaseUnconfirmedKernelDoesNotRoll(t *testing.T) {
	old := clean()
	old.Packages.Installed = append(old.Packages.Installed, pkg("linux-image-6.1.0-25-amd64", "6.1.106-3"))
	cur := clone(old)
	cur.Packages.Installed = append(cur.Packages.Installed, pkg("linux-image-6.1.0-27-amd64", "6.1.115-1"))
	r, rb := rebaseRun(cur, snapOf(old), archive())
	if explained(r, "explained:linux-image-6.1.0-27-amd64") == nil {
		t.Fatalf("fixture: kernel not explained: %v", keys(r))
	}
	if !rb.Routine.Empty() {
		t.Errorf("an unconfirmed kernel rolls forward: %+v", rb.Routine)
	}
}

// Accepting a second architecture's install rolls that architecture's
// record and files forward; the next visit no longer reports it.
func TestJudgeRebaseAcceptOtherArchInstall(t *testing.T) {
	old := clean()
	cur, v := upgradedSSL()
	helper := file("/usr/lib/i386-linux-gnu/openssl/helper", "helper", 0o4755)
	cur.Files = append(cur.Files, helper)
	i386 := pkg("openssl", sslNew, helper.Path)
	i386.Arch = "i386"
	cur.Packages.Installed = append(cur.Packages.Installed, i386)
	vi := pkgverify.FileVerdict{Path: helper.Path, Package: "openssl", Version: sslNew, Expected: helper.SHA256, Actual: helper.SHA256, Source: "archive"}

	snap := snapOf(old)
	_, rb := rebaseRun(cur, snap, archive(v, vi))
	s, ok := rb.Accept["snap.pkg_installed:openssl:i386"]
	if !ok || !slices.Equal(s.Packages, []string{"openssl:i386"}) || !slices.Contains(s.Paths, helper.Path) {
		t.Fatalf("accept %+v", s)
	}
	snap = RollForward(snap, cur, checklist.Evaluate(cur, ctx), rb.Routine)
	snap = RollForward(snap, cur, checklist.Evaluate(cur, ctx), s)
	r, _ := rebaseRun(cur, snap, archive())
	for _, f := range r.Findings {
		if strings.HasPrefix(f.Key, "snap.") {
			t.Errorf("after accepting: %s", f.Key)
		}
	}
}

// The grouped note on unverifiable files accepts exactly the files it
// shows: another single file is another value.
func TestUnverifiableNoteValueNamesTheFiles(t *testing.T) {
	value := func(p string) string {
		c := clean()
		c.Files = append(c.Files, file(p, p, 0o644))
		res := archive()
		res.Unverifiable = []pkgverify.FileVerdict{{Path: p, Package: "localpkg", Reason: pkgverify.ReasonNotOfficial}}
		return ExceptionValue(must(t, run(c, nil, res), "pkg.unverifiable", model.SevNote))
	}
	if a, b := value("/usr/share/a"), value("/usr/share/b"); a == b {
		t.Errorf("two different files give the same value %q", a)
	}
}

func TestPackagesIncomplete(t *testing.T) {
	if r := run(clean(), nil, archive()); PackagesIncomplete(r) {
		t.Errorf("a full verification reported incomplete: %v", r.CouldNotRuleOut)
	}
	if r := run(clean(), nil, nil); !PackagesIncomplete(r) {
		t.Errorf("no verification: %v", r.CouldNotRuleOut)
	}
	stopped := archive()
	stopped.Unverifiable = []pkgverify.FileVerdict{{Path: "/usr/bin/ls", Package: "coreutils", Version: "9.1-1", Reason: "deadline", Kind: pkgverify.KindStopped}}
	if r := run(clean(), nil, stopped); !PackagesIncomplete(r) {
		t.Errorf("stopped: %v", r.CouldNotRuleOut)
	}
	down := archive()
	down.Unverifiable = []pkgverify.FileVerdict{{Path: "/usr/bin/openssl", Package: "openssl", Version: "3.0.14-1~deb12u2", Reason: "no route to host", Kind: pkgverify.KindUnreachable}}
	if r := run(clean(), snapOf(clean()), down); !PackagesIncomplete(r) {
		t.Errorf("unreachable: %v", r.CouldNotRuleOut)
	}
}

// A checklist item that failed in the snapshot too is a weak setting, not a
// change since the snapshot: accepting it would change nothing, so it is not
// offered, and the web UI does not count it as a change. The same holds once
// an accepted regression has rolled forward.
func TestStandingChecklistFailureIsNotAChange(t *testing.T) {
	old := clean()
	old.Sysctl["kernel.randomize_va_space"] = "0"
	snap := snapOf(old)
	r, rb := rebaseRun(clone(old), snap, nil)
	must(t, r, "check:TT-KERN-001", model.SevWeak)
	if s, ok := rb.Accept["check:TT-KERN-001"]; ok {
		t.Errorf("a weak setting the snapshot already had is offered as a change: %+v", s)
	}

	cur := clean()
	snap = snapOf(clone(cur))
	cur.Sysctl["kernel.randomize_va_space"] = "0"
	r, rb = rebaseRun(cur, snap, nil)
	must(t, r, "check:TT-KERN-001", model.SevTampering)
	r, rb = rebaseRun(cur, RollForward(snap, cur, checklist.Evaluate(cur, ctx), rb.Accept["check:TT-KERN-001"]), nil)
	must(t, r, "check:TT-KERN-001", model.SevWeak)
	if s, ok := rb.Accept["check:TT-KERN-001"]; ok {
		t.Errorf("after the regression was accepted, the weak setting is offered again: %+v", s)
	}
}
