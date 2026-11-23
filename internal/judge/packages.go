package judge

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/pkgverify"
)

// sourceWords says where an expected hash came from, for evidence.
func sourceWords(src string) string {
	switch src {
	case pkgverify.SourceArchive:
		return "the distribution's signed archive"
	case pkgverify.SourceSnapshot:
		return "snapshot.debian.org's file API (SHA-1 over HTTPS, lower trust than a signed index)"
	case pkgverify.SourceLaunchpad:
		return "Launchpad over HTTPS (lower trust than a signed index)"
	case pkgverify.SourceRefs:
		return "a reference bundle, checked with the built-in archive keys"
	case pkgverify.SourceOfflineLocal:
		return OfflineReference
	case pkgverify.SourceThirdParty:
		return "a third-party repository's signed index (owner-supplied key)"
	case "":
		return "an unnamed source"
	}
	return src
}

// isKernelModule: a module file below /lib/modules (either merged-/usr
// spelling), compressed or not.
func isKernelModule(p string) bool {
	if !strings.HasPrefix(p, "/lib/modules/") && !strings.HasPrefix(p, "/usr/lib/modules/") {
		return false
	}
	b := p[strings.LastIndexByte(p, '/')+1:]
	return strings.HasSuffix(b, ".ko") || strings.Contains(b, ".ko.")
}

// isPAMModule: a shared object in a PAM module directory (/lib/security,
// /lib/<triplet>/security and their /usr spellings).
func isPAMModule(p string) bool {
	if !strings.HasSuffix(p, ".so") {
		return false
	}
	rest, ok := strings.CutPrefix(p, "/usr")
	if !ok {
		rest = p
	}
	rest, ok = strings.CutPrefix(rest, "/lib/")
	if !ok {
		return false
	}
	seg := strings.Split(rest, "/")
	return (len(seg) == 2 && seg[0] == "security") || (len(seg) == 3 && seg[1] == "security")
}

// specialCategory names the kinds of file that are a backdoor sign when they
// cannot be verified: setuid/setgid programs, kernel modules, PAM modules
// and boot files. "" for anything else.
//
// The kind is told from the path dpkg installs the file at. listed holds
// dpkg's spellings when p is where the file really is, behind a package
// directory that is a link now (pkgverify.FileVerdict.Listed): a PAM module
// moved to /srv is still a PAM module.
func (j *judge) specialCategory(p string, listed ...string) string {
	if e := j.files[p]; e != nil && e.Type == "file" && e.Mode&0o6000 != 0 {
		return "setuid/setgid program"
	}
	for _, q := range append([]string{p}, listed...) {
		switch {
		case isKernelModule(q):
			return "kernel module"
		case isPAMModule(q):
			return "PAM module"
		case strings.HasPrefix(q, "/boot/"):
			return "boot file"
		}
	}
	return ""
}

func (j *judge) exists(p string) bool { return j.files[p] != nil }

// packages maps the package verification result onto findings, explained
// groups, the report's references and its limits.
func (j *judge) packages() {
	r := j.in.Pkg
	if r == nil {
		j.couldNot = append(j.couldNot, noPkgLimit)
		return
	}
	for _, list := range [][]pkgverify.FileVerdict{r.Verified, r.Mismatch, r.Unverifiable, r.Suspicious} {
		for _, v := range list {
			j.reported[v.Path] = true
		}
	}
	for _, d := range r.Conffiles {
		j.reported[d.Path] = true
	}

	lower := map[string]int{}
	for _, v := range r.Verified {
		if _, ok := j.verified[v.Path]; !ok {
			j.verified[v.Path] = v
		}
		if p := j.pkgs[v.Package]; p != nil && (v.Version == "" || v.Version == p.Version) {
			// Any file that matches the signed package of the version
			// installed now confirms that version, a maintainer script too.
			j.confirmed[v.Package] = true
		}
		if v.Source == pkgverify.SourceSnapshot || v.Source == pkgverify.SourceLaunchpad {
			lower[v.Source]++
		}
		if v.Kind == pkgverify.KindModeLessPermissive {
			j.add(j.modeRelaxed(v))
		}
	}
	for _, v := range r.Mismatch {
		j.pkgPath[v.Path] = j.add(j.mismatch(v))
	}
	for _, v := range r.Suspicious {
		j.pkgPath[v.Path] = j.add(j.suspicious(v))
	}
	j.unverifiable(r.Unverifiable)
	if r.ClockSkew != nil {
		j.add(clockSkew(*r.ClockSkew))
	}
	if j.notRun != "" {
		j.couldNot = append(j.couldNot, j.notRun)
	}
	if n := len(j.stopped); n > 0 {
		j.couldNot = append(j.couldNot, fmt.Sprintf("verification stopped before %d %s checked", n, plural(n, "package was", "packages were")))
	}
	if len(j.budget) > 0 {
		j.add(&model.Finding{
			Key: "pkg.budget_exceeded", ID: "TT-PKG-008", Source: srcPackage, Severity: model.SevNote,
			Title: "Package verification stopped at one of its limits",
			Why: "The machine lists more packages than telltale checks in one scan, or more versions missing from the archive than it looks up (" + strings.Join(j.budget, "; ") +
				"). The files it did not get to are reported as not verified, and setuid programs, modules and boot files among them as backdoor signs. A machine with that many packages is itself unusual.",
			Evidence: []model.Evidence{{After: strings.Join(j.budget, "; "), Detail: "limit reached"}},
		})
	}
	j.conffiles(r.Conffiles)
	if n := lower[pkgverify.SourceSnapshot] + lower[pkgverify.SourceLaunchpad]; n > 0 {
		j.add(lowerTrust(lower, n))
	}

	var sig []string
	for _, e := range r.Errors {
		switch {
		case e == pkgverify.OfflineWarning:
			// Said by the reference and the limits below.
		case strings.Contains(strings.ToUpper(e), "BAD SIGNATURE") || strings.HasPrefix(e, "HASH MISMATCH"):
			sig = append(sig, e)
		default:
			j.skipped = append(j.skipped, model.Skip{Check: "packages", Reason: e})
		}
	}
	if len(sig) > 0 {
		j.add(indexSignature(sig))
		j.couldNot = append(j.couldNot, sig...)
	}

	switch {
	case r.Mode == pkgverify.ModeOfflineLocal:
		j.compared = append(j.compared, OfflineReference)
		j.couldNot = append(j.couldNot, offlineLimit)
	case !j.pkgUsed():
		j.couldNot = append(j.couldNot, "changed system files (no package reference could be used; see the skipped checks)")
	case r.Mode == pkgverify.ModeRefs:
		j.compared = append(j.compared, "reference bundle")
	default:
		j.compared = append(j.compared, distroPackages(j.c.Host.OSID))
	}
	for _, s := range r.SourcesUsed {
		if strings.HasSuffix(s, "(owner-supplied key)") {
			j.compared = append(j.compared, "third-party packages (owner-supplied keys)")
			break
		}
	}
	if n := len(r.Unverifiable); n > 0 {
		j.couldNot = append(j.couldNot, fmt.Sprintf("changes to %d package %s that could not be verified", n, plural(n, "file", "files")))
	}
}

// pkgUsed reports whether the verification had a package reference at all:
// it read a source, or reached a verdict that needs one.
func (j *judge) pkgUsed() bool {
	r := j.in.Pkg
	return len(r.SourcesUsed) > 0 || len(r.Verified) > 0 || len(r.Mismatch) > 0 || len(r.Suspicious) > 0
}

func distroPackages(osID string) string {
	switch osID {
	case "debian":
		return "Debian packages"
	case "ubuntu":
		return "Ubuntu packages"
	}
	return "distribution packages"
}

func (j *judge) mismatch(v pkgverify.FileVerdict) *model.Finding {
	title := fmt.Sprintf("%s does not match the signed %s package", v.Path, v.Package)
	why := "This file differs from the copy in the distribution's package for the version installed (" + strings.TrimSpace(v.Package+" "+v.Version) + "). " +
		"A routine update would match the package; replacing system programs and libraries is how rootkits and backdoors hide."
	if v.Kind == pkgverify.KindModeAddsPrivilege {
		title = fmt.Sprintf("%s has privileges its signed %s package does not give it", v.Path, v.Package)
		why = "The file's content matches the package, but its mode adds privilege the package does not set (" + v.Reason +
			"). A setuid bit or a writable system file added after installation is a classic way back to root."
	}
	if v.Source == pkgverify.SourceOfflineLocal {
		title = fmt.Sprintf("%s differs from the machine's own package checksums for %s", v.Path, v.Package)
		why = "This file differs from the checksum the machine's own package database records for it (" + strings.TrimSpace(v.Package+" "+v.Version) + "). " +
			"A routine update would update both; replacing system programs and libraries is how rootkits and backdoors hide. Root can edit those checksums, so a match would prove less than this mismatch does."
	}
	fix := fixReinstall(v.Path, v.Package, j.exists(v.Path))
	if maintainerScript(v.Path) && j.exists(v.Path) {
		title = fmt.Sprintf("The maintainer script %s does not match the signed %s package", v.Path, v.Package)
		why = "dpkg runs this script as root the next time the package is upgraded, reconfigured, removed or purged, and it is not the script of the signed package (" +
			strings.TrimSpace(v.Package+" "+v.Version) + "): " + v.Reason + ". A line planted here is a way back in that waits for routine maintenance."
		fix = fixScript(v.Path, v.Package, j.pkgs[v.Package] != nil)
	}
	return &model.Finding{
		Key: "pkg.mismatch:" + v.Path, ID: "TT-PKG-001", Source: srcPackage, Severity: model.SevTampering,
		Title: title, Why: why,
		Fix: fix,
		Evidence: []model.Evidence{{Path: v.Path, Before: v.Expected, After: v.Actual,
			Detail: v.Reason + "; expected value from " + sourceWords(v.Source), When: j.whenFor(v.Path)}},
		Refs: []string{"T1554"},
	}
}

func (j *judge) suspicious(v pkgverify.FileVerdict) *model.Finding {
	var fix string
	switch {
	case v.Kind == pkgverify.KindStatOverride:
		fix = command([]string{v.Path, v.Package}, func(q []string) string {
			return keep(q[0]) + " && dpkg-statoverride --remove -- " + q[0] + " && apt-get install --reinstall -- " + q[1] + "   # only if you did not add the override yourself"
		})
	case v.Kind == pkgverify.KindDiversion:
		fix = fixKeepOnly(v.Path, "then compare it with the package's own copy; dpkg-divert --list shows the diversion")
	default:
		fix = fixReinstall(v.Path, v.Package, j.exists(v.Path))
	}
	return &model.Finding{
		Key: "pkg.suspicious:" + v.Path, ID: "TT-PKG-002", Source: srcPackage, Severity: model.SevBackdoor,
		Title: fmt.Sprintf("Only this machine's own package data explains %s", v.Path),
		Why: "This file is not cleanly verified: " + v.Reason + ". The only explanation is data on this machine that root can edit (dpkg diversions or statoverrides), " +
			"which is how a replaced or privileged program can be kept in place.",
		Fix:      fix,
		Evidence: []model.Evidence{{Path: v.Path, Before: v.Expected, After: v.Actual, Detail: v.Reason, When: j.whenFor(v.Path)}},
		Refs:     []string{"T1574", "T1548.001"},
	}
}

func (j *judge) modeRelaxed(v pkgverify.FileVerdict) *model.Finding {
	return &model.Finding{
		Key: "pkg.mode_relaxed:" + v.Path, ID: "TT-PKG-004", Source: srcPackage, Severity: model.SevNote,
		Title: fmt.Sprintf("%s has stricter permissions than its package gives it", v.Path),
		Why:   "The file matches " + j.refWords() + ", but its mode is less permissive than the package sets. That is usually deliberate hardening; it is listed so that nothing about package files goes unsaid.",
		Fix: command([]string{v.Package}, func(q []string) string {
			return "# nothing to do if you tightened it on purpose; apt-get install --reinstall -- " + q[0] + " restores the package's mode"
		}),
		Evidence: []model.Evidence{{Path: v.Path, After: v.Reason, Detail: "content matches " + v.Package + " " + v.Version + " from " + sourceWords(v.Source)}},
	}
}

// unverifiable groups files that could not be checked into one note, except
// the kinds of file rootkits replace, which are a backdoor sign each.
func (j *judge) unverifiable(vs []pkgverify.FileVerdict) {
	type bucket struct {
		reason string
		paths  []string
	}
	byReason := map[string]*bucket{}
	n := 0
	for _, v := range vs {
		j.unverReason[v.Path], j.unverKind[v.Path] = v.Reason, v.Kind
		owner := v.Package
		if owner == "" {
			owner = j.owned[v.Path]
		}
		cat := j.specialCategory(v.Path, v.Listed...)
		class := j.classify(v.Kind)
		switch {
		case v.Kind == pkgverify.KindBudget && !slices.Contains(j.budget, v.Reason):
			j.budget = append(j.budget, v.Reason)
		case v.Kind == pkgverify.KindRelease:
			j.notRun = "package verification did not run: /etc/os-release says " + strings.TrimSpace(j.c.Host.OSID+" "+j.c.Host.OSVersionID)
		case v.Kind == pkgverify.KindHostArch:
			j.notRun = "package verification did not run: " + v.Reason
		case class == classStopped:
			j.stopped[owner] = true
		case class == classUnchecked && owner != "":
			if _, ok := j.unreachable[owner]; !ok {
				j.unreachable[owner] = v
			}
		}
		if class == classHostLimit {
			continue // stated once; nothing about this file was checked
		}
		// A special file goes into the one note on unchecked files only when
		// the host's own indexes could not be used, so a network failure does
		// not raise one backdoor sign per module or setuid program; what a
		// deadline left is a backdoor sign for a package that changed, and
		// anything else is a backdoor sign.
		if cat != "" && class == classUnchecked {
			j.uncheckedSpecial[v.Path] = true
			j.uncheckedFiles = append(j.uncheckedFiles, model.Evidence{Path: v.Path, After: v.Actual,
				Detail: strings.TrimSpace(v.Package+" "+v.Version) + ": could not be checked: " + v.Reason, When: j.whenFor(v.Path)})
			continue
		}
		if cat != "" && (class == classNotFound || (class == classStopped && j.pkgChanged(owner))) {
			j.pkgPath[v.Path] = j.add(&model.Finding{
				Key: "pkg.unverifiable:" + v.Path, ID: "TT-PKG-003", Source: srcPackage, Severity: model.SevBackdoor,
				Title: fmt.Sprintf("%s (a %s) could not be verified against its package", v.Path, cat),
				Why: "Setuid/setgid programs, kernel modules, PAM modules and boot files run with the machine's full trust, and they are what rootkits replace. " +
					"This one could not be checked: " + v.Reason + ".",
				Fix:      fixKeepOnly(v.Path, "then verify it: run telltale fetch-refs on a machine with network access and scan again with --refs DIR (or --keys DIR for a third-party repository)"),
				Evidence: []model.Evidence{{Path: v.Path, After: v.Actual, Detail: strings.TrimSpace(v.Package+" "+v.Version) + ": " + v.Reason, When: j.whenFor(v.Path)}},
				Refs:     []string{"T1554"},
			})
			continue
		}
		j.unverified[v.Path] = true
		n++
		b := byReason[v.Reason]
		if b == nil {
			b = &bucket{reason: v.Reason}
			byReason[v.Reason] = b
		}
		b.paths = append(b.paths, v.Path)
	}
	if n == 0 {
		return
	}
	var bs []*bucket
	for _, b := range byReason {
		bs = append(bs, b)
	}
	sort.Slice(bs, func(a, b int) bool {
		if len(bs[a].paths) != len(bs[b].paths) {
			return len(bs[a].paths) > len(bs[b].paths)
		}
		return bs[a].reason < bs[b].reason
	})
	f := &model.Finding{
		Key: "pkg.unverifiable", ID: "TT-PKG-003", Source: srcPackage, Severity: model.SevNote,
		Title: fmt.Sprintf("%d package %s could not be verified", n, plural(n, "file", "files")),
		Why: "These files belong to packages telltale could not check against a trusted copy, so a change to them would go unnoticed. " +
			"Setuid programs, kernel modules, PAM modules and boot files are reported on their own, or with the files that could not be checked at all.",
		Fix:      "Run telltale fetch-refs on a machine with network access and scan again with --refs DIR; pass third-party repository keys with --keys DIR.",
		Evidence: []model.Evidence{{After: fmt.Sprintf("%d %s", n, plural(n, "file", "files")), Detail: "grouped by reason below"}},
	}
	for _, b := range bs {
		ex := b.paths
		if len(ex) > 3 {
			ex = ex[:3]
		}
		c := len(b.paths)
		f.Evidence = append(f.Evidence, model.Evidence{Detail: fmt.Sprintf("%d %s: %s (e.g. %s)", c, plural(c, "file", "files"), b.reason, strings.Join(ex, ", "))})
	}
	j.add(f)
}

// clockSkew notes that the clock of the machine that ran package
// verification is provably wrong: behind the archive's newest signed date,
// or past the validity of an index that archive still serves. The clock decided
// nothing in the verification.
func clockSkew(s pkgverify.ClockSkew) *model.Finding {
	d, dir := s.Clock.Sub(s.Signed), "ahead of"
	if d < 0 {
		d, dir = -d, "behind"
	}
	days := int((d + 12*time.Hour) / (24 * time.Hour))
	by := fmt.Sprintf("%d %s %s", days, plural(days, "day", "days"), dir)
	const layout = "2006-01-02 15:04 UTC"
	title := "The machine's clock is out of date: the clock is " + by + " the newest signed index"
	why := "The clock of the machine that ran package verification said " + s.Clock.UTC().Format(layout) + ", while the newest index the archive signed is dated " + s.Signed.UTC().Format(layout) + ". "
	if dir == "ahead of" {
		title = "The machine's clock, or the archive mirror's index, is out of date: the clock is " + by + " the newest signed index"
		why += "Either the clock is wrong, or the mirror that answered served an old index (a mirror that stopped updating, or one replaying old files, looks the same from here). A clock cannot be right when it is past the date until which a signed index is valid. "
	} else {
		why += "The clock is wrong: a clock cannot be right when it is behind what the archive has already signed. "
	}
	why += "Package verification took its time from the signed indexes, so the clock decided nothing there; but root can set the clock, and a wrong one breaks certificate checks, log times and scheduled jobs."
	return &model.Finding{
		Key: "pkg.clock_skew", ID: "TT-PKG-009", Source: srcPackage, Severity: model.SevNote,
		Title:    title,
		Why:      why,
		Fix:      "timedatectl set-ntp true   # or set the clock by hand with: date -u -s 'YYYY-MM-DD HH:MM:SS'",
		Evidence: []model.Evidence{{After: "clock " + by + " the signed date", Detail: "clock " + s.Clock.UTC().Format(layout) + "; newest signed index " + s.Signed.UTC().Format(layout)}},
		Refs:     []string{"T1070.006"},
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// conffiles lists configuration files that differ from their package's
// default quietly, grouped by package: they are expected to be edited, and
// the checklist judges what they set.
func (j *judge) conffiles(ds []pkgverify.ConffileDiff) {
	for _, d := range ds {
		key := "pkg.conffiles:" + d.Package
		g := j.groups[key]
		if g == nil {
			g = &model.Finding{
				Key: key, ID: "TT-EXPL-002", Source: srcPackage, Severity: model.SevExplained,
				Why: "Configuration files are expected to be edited. They are not compared as package files; the checklist judges the settings in them.",
			}
			j.groups[key] = g
		}
		detail := "differs from the default in " + d.Package + " " + d.Version
		if d.Note != "" {
			detail = d.Note
		}
		j.attach(g, model.Evidence{Path: d.Path, Before: d.Expected, After: d.Actual, Detail: detail}, maxExplainedEvidence)
		n := len(g.Evidence) + j.omitted[g]
		g.Title = fmt.Sprintf("%d configuration %s of %s differ from the package defaults", n, plural(n, "file", "files"), d.Package)
	}
}

func lowerTrust(counts map[string]int, n int) *model.Finding {
	var parts []string
	if c := counts[pkgverify.SourceSnapshot]; c > 0 {
		parts = append(parts, fmt.Sprintf("%d from snapshot.debian.org's file API (SHA-1 over HTTPS)", c))
	}
	if c := counts[pkgverify.SourceLaunchpad]; c > 0 {
		parts = append(parts, fmt.Sprintf("%d from Launchpad over HTTPS", c))
	}
	return &model.Finding{
		Key: "pkg.lower_trust", ID: "TT-PKG-006", Source: srcPackage, Severity: model.SevNote,
		Title: fmt.Sprintf("%d %s verified against lower-trust sources", n, plural(n, "file was", "files were")),
		Why: "These package versions are no longer in the signed archive, so their expected hashes came from a service over HTTPS rather than a signed index. " +
			"A match is still good evidence, but weaker than the signed chain.",
		Evidence: []model.Evidence{{After: fmt.Sprintf("%d %s", n, plural(n, "file", "files")), Detail: strings.Join(parts, "; ")}},
	}
}

func indexSignature(errs []string) *model.Finding {
	f := &model.Finding{
		Key: "pkg.index_signature", ID: "TT-PKG-005", Source: srcPackage, Severity: model.SevNote,
		Title: "A package index FAILED its signature check: files that depend on it were not verified",
		Why: "telltale checks the archive's signed index with keys built into it. A bad signature or hash means the index was tampered with or intercepted on the way, " +
			"or telltale's built-in keys are out of date. Either way nothing that depended on it was verified.",
		Fix: "Scan again from another network, or build a reference bundle with telltale fetch-refs on a trusted machine and scan with --refs DIR; update telltale if its keys are out of date.",
	}
	for _, e := range errs {
		f.Evidence = append(f.Evidence, model.Evidence{Detail: e})
	}
	return f
}

// packageDirLinks reports each directory dpkg lists that is a symbolic link
// now (model.Packages.DirLinks). dpkg unpacks a package into real
// directories; a link in the place of one means every file the package lists
// below it is really somewhere else. An admin moving /opt to another disk
// does that, and so does someone who wants a package's names to cover other
// files. The collector records what is behind such a link, and package
// verification compares it with the package where it is; this finding says
// that the directory itself is not what the package installed.
//
// It is a note when the link leads to an ordinary place on the machine and
// every file listed below it has an entry where it really is. It is a
// backdoor sign when the link leads into a temporary, user-writable or
// hidden place or nowhere the inventory can follow, and when a listed file
// below it has no entry: then nobody looked at what the package's name leads
// to. The machine's file lists do not bound that: root can delete a line
// from one. A file the signed package installs below the directory, with no
// entry where the link leads (pkgverify.Result.MovedUnseen), counts the same
// whether or not a list still names it. The links merged /usr consists of
// are left out.
func (j *judge) packageDirLinks() {
	phys := model.NewPhysicalResolver(j.files)
	var signed []pkgverify.MovedFile
	if j.in.Pkg != nil {
		signed = j.in.Pkg.MovedUnseen
	}
	for _, l := range j.c.Packages.DirLinks(j.files) {
		d, pkgName, to := l.Dir, l.Package, l.To
		f := &model.Finding{
			Key: "pkg.dir_now_link:" + d, ID: "TT-PKG-010", Source: srcPackage, Severity: model.SevNote,
			Title: fmt.Sprintf("%s, a directory of package %s, is now a link to %s", d, pkgName, to),
			Why: "dpkg unpacked this package into a real directory here; a symbolic link is in its place now, so every file the package lists below it is really somewhere else. " +
				"Moving a directory to another disk and leaving a link looks like this. It is also a way to put other files under a package's names, " +
				"so the files the link leads to are compared with the package where they are, and none of them counts as the package's own just for being there.",
			Fix: command([]string{d}, func(q []string) string {
				return "ls -ld -- " + q[0] + " && readlink -f -- " + q[0] + "   # nothing to do if you moved this directory yourself"
			}),
			Evidence: []model.Evidence{{Path: d, After: "symlink -> " + l.Target, Detail: "listed as a directory by package " + pkgName + "; leads to " + to, When: j.whenFor(l.At)}},
			Refs:     []string{"T1574"},
		}
		// Listed files below the link that have no entry where they are.
		var unseen []string
		// Files the signed packages install below it, listed or not.
		var unlisted []pkgverify.MovedFile
		if to != "" {
			at := map[string]bool{}
			for _, p := range l.Below {
				q, ok := phys.Path(p)
				if ok {
					at[q] = true
				}
				if !ok || j.files[q] == nil {
					unseen = append(unseen, p)
				}
			}
			for _, m := range signed {
				if strings.HasPrefix(m.At, to+"/") && !at[m.At] && j.files[m.At] == nil {
					at[m.At] = true
					unlisted = append(unlisted, m)
				}
			}
		}
		reason, tail := "", "Nobody keeps a package's files there: whatever the link leads to is what programs get when they ask for this package's files."
		switch {
		case to == "":
			reason = "it leads nowhere telltale could follow"
			f.Title = fmt.Sprintf("%s, a directory of package %s, is now a link that cannot be followed", d, pkgName)
			f.Evidence[0].Detail = "listed as a directory by package " + pkgName + "; where the link leads cannot be told"
		case underTemp(to) != "":
			reason = "it leads into " + underTemp(to)
		case hiddenPath(to):
			reason = "it leads into a hidden directory"
		case len(unseen)+len(unlisted) > 0:
			if len(unseen) > 0 {
				reason = fmt.Sprintf("%d of the %d files the package lists below it could not be checked where the link leads (they are missing there, or telltale could not look)", len(unseen), len(l.Below))
			}
			if len(unlisted) > 0 {
				if reason != "" {
					reason += ", and "
				}
				reason += fmt.Sprintf("%d %s the signed package installs below it %s not in the machine's file list any more and could not be checked where the link leads",
					len(unlisted), plural(len(unlisted), "file", "files"), plural(len(unlisted), "is", "are"))
			}
			tail = "What programs get when they ask for those files is unknown: they were not compared with the package."
			// The files no list names come first: a line deleted from a
			// file list is what hides a replaced file.
			for _, m := range unlisted {
				if len(f.Evidence) == maxEvidence {
					break
				}
				f.Evidence = append(f.Evidence, model.Evidence{Path: m.Path, Detail: "installed by the signed package " + m.Package + " " + m.Version + ", in no file list on the machine; nothing was recorded for it at " + m.At})
			}
			for _, p := range unseen {
				if len(f.Evidence) == maxEvidence {
					break
				}
				f.Evidence = append(f.Evidence, model.Evidence{Path: p, Detail: "listed by a package below " + d + "; nothing was found for it where the link leads"})
			}
		}
		if reason != "" {
			f.Severity = model.SevBackdoor
			f.Why = "dpkg unpacked this package into a real directory here; a symbolic link is in its place now, and " + reason + ". " + tail
			f.Fix = command([]string{d, pkgName}, func(q []string) string {
				return keep(q[0]) + " && ls -la -- " + q[0] + "/   # the link is saved; look at what it leads to. To put the package's directory back: rm -- " + q[0] + " && apt-get install --reinstall -- " + q[1]
			})
		}
		j.add(f)
	}
}

// tempPlaces are trees any user can write to: the world-writable temporary
// directories, each user's runtime directory and the lock directory.
var tempPlaces = []string{"/tmp", "/dev/shm", "/var/tmp", "/run/user", "/run/lock"}

// underTemp names the temporary or user-writable tree p is in, or "".
func underTemp(p string) string {
	for _, d := range tempPlaces {
		if p == d || strings.HasPrefix(p, d+"/") {
			return d
		}
	}
	return ""
}

// hiddenPath reports whether a component of p starts with a dot.
func hiddenPath(p string) bool {
	for _, comp := range strings.Split(p, "/") {
		if strings.HasPrefix(comp, ".") {
			return true
		}
	}
	return false
}
