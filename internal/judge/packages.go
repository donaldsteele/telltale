package judge

import (
	"fmt"
	"sort"
	"strings"

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
func (j *judge) specialCategory(p string) string {
	if e := j.files[p]; e != nil && e.Type == "file" && e.Mode&0o6000 != 0 {
		return "setuid/setgid program"
	}
	switch {
	case isKernelModule(p):
		return "kernel module"
	case isPAMModule(p):
		return "PAM module"
	case strings.HasPrefix(p, "/boot/"):
		return "boot file"
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
		if v.Source == pkgverify.SourceSnapshot || v.Source == pkgverify.SourceLaunchpad {
			lower[v.Source]++
		}
		if strings.HasPrefix(v.Reason, "mode differs (less permissive)") {
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
	why := "This file differs from the copy in the distribution's package for the version installed (" + v.Package + " " + v.Version + "). " +
		"A routine update would match the package; replacing system programs and libraries is how rootkits and backdoors hide."
	if strings.HasPrefix(v.Reason, "mode differs") {
		title = fmt.Sprintf("%s has privileges its signed %s package does not give it", v.Path, v.Package)
		why = "The file's content matches the package, but its mode adds privilege the package does not set (" + v.Reason +
			"). A setuid bit or a writable system file added after installation is a classic way back to root."
	}
	if v.Source == pkgverify.SourceOfflineLocal {
		why += " The expected value comes from the machine's own package checksums, which root can edit."
	}
	return &model.Finding{
		Key: "pkg.mismatch:" + v.Path, ID: "TT-PKG-001", Source: srcPackage, Severity: model.SevTampering,
		Title: title, Why: why,
		Fix: fixReinstall(v.Path, v.Package, j.exists(v.Path)),
		Evidence: []model.Evidence{{Path: v.Path, Before: v.Expected, After: v.Actual,
			Detail: v.Reason + "; expected value from " + sourceWords(v.Source), When: j.whenFor(v.Path)}},
		Refs: []string{"T1554"},
	}
}

func (j *judge) suspicious(v pkgverify.FileVerdict) *model.Finding {
	var fix string
	switch {
	case strings.Contains(v.Reason, "statoverride"):
		fix = command([]string{v.Path, v.Package}, func(q []string) string {
			return keep(q[0]) + " && dpkg-statoverride --remove " + q[0] + " && apt-get install --reinstall " + q[1] + "   # only if you did not add the override yourself"
		})
	case strings.Contains(v.Reason, "diverted by"):
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
		Why:   "The file matches the signed package, but its mode is less permissive than the package sets. That is usually deliberate hardening; it is listed so that nothing about package files goes unsaid.",
		Fix: command([]string{v.Package}, func(q []string) string {
			return "# nothing to do if you tightened it on purpose; apt-get install --reinstall " + q[0] + " restores the package's mode"
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
		if cat := j.specialCategory(v.Path); cat != "" {
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
			"None of them is a setuid program, kernel module, PAM module or boot file.",
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
