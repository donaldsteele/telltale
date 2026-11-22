package judge

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/donaldsteele/telltale/internal/diff"
	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/pkgverify"
)

// Which package changes are routine:
//   - an upgrade: explained;
//   - a new kernel package of a flavour already installed, newer than every
//     kernel package of that flavour in the snapshot (linux-image-<newer>-
//     <flavour> and its companions): explained; removing an older one once a
//     newer one of its flavour is installed: explained;
//   - any other new package: a note, raised to a backdoor sign if it brings a
//     setuid/setgid program, a file capability, a kernel module, a PAM
//     module, an enabled systemd unit, or a program that listens on a new
//     socket;
//   - a downgrade: a backdoor sign;
//   - removal of a security package: a weak setting; other removals: a note.

// securityPackages are the packages whose removal weakens the machine.
var securityPackages = map[string]bool{"ufw": true, "nftables": true, "iptables": true, "auditd": true, "fail2ban": true, "apparmor": true}

// kernelRe matches a kernel package and its companions:
// linux-<kind>-<abi>-<flavour>, where kind is image, image-unsigned,
// modules, modules-extra, headers, tools, cloud-tools, or Ubuntu's
// modules-/objects-/signatures-nvidia-<driver>[-server][-open].
// Ubuntu's linux-headers-<abi>, linux-tools-<abi> and
// linux-cloud-tools-<abi> have no flavour.
var kernelRe = regexp.MustCompile(`^linux-(image|image-unsigned|modules|modules-extra|headers|tools|cloud-tools|(?:modules|objects|signatures)-nvidia-[0-9]+(?:-(?:server|open))*)-([0-9][0-9.]*-[0-9][0-9.]*)(?:-([a-z][a-z0-9+.-]*))?$`)

type kernelPkg struct{ kind, flavour string }

func parseKernel(name string) (kernelPkg, bool) {
	m := kernelRe.FindStringSubmatch(name)
	if m == nil {
		return kernelPkg{}, false
	}
	return kernelPkg{kind: m[1], flavour: m[3]}, true
}

// sameFlavour: same flavour; flavourless headers only match their own kind.
func (k kernelPkg) sameFlavour(o kernelPkg) bool {
	return k.flavour == o.flavour && (k.flavour != "" || k.kind == o.kind)
}

// newerKernel reports whether a newly installed package is a kernel package
// of a flavour the snapshot had, newer than all of that flavour's packages
// there.
func (j *judge) newerKernel(name, version string) bool {
	k, ok := parseKernel(name)
	if !ok {
		return false
	}
	seen := false
	for _, p := range j.old.Packages.Installed {
		o, ok := parseKernel(p.Name)
		if !ok || !k.sameFlavour(o) {
			continue
		}
		seen = true
		if diff.CompareVersions(version, p.Version) <= 0 {
			return false
		}
	}
	return seen
}

// olderKernel reports whether a removed package is a kernel package older
// than one of its flavour that is installed now.
func (j *judge) olderKernel(name, version string) bool {
	k, ok := parseKernel(name)
	if !ok {
		return false
	}
	for _, p := range j.c.Packages.Installed {
		if o, ok := parseKernel(p.Name); ok && k.sameFlavour(o) && diff.CompareVersions(p.Version, version) > 0 {
			return true
		}
	}
	return false
}

// pkgChanged reports whether the package's version changed (or it came or
// went) since the snapshot.
func (j *judge) pkgChanged(name string) bool {
	_, ok := j.pkgChange[name]
	return name != "" && ok
}

// group returns the explained group of a package, creating it.
func (j *judge) group(name string) *model.Finding {
	key := "explained:" + name
	g := j.groups[key]
	if g == nil {
		g = &model.Finding{Key: key, ID: "TT-EXPL-001", Source: srcPackage, Severity: model.SevExplained}
		j.groups[key] = g
	}
	return g
}

// explain adds evidence to a package's explained group.
func (j *judge) explain(name string, e model.Evidence) {
	j.touch(name, e.Path)
	j.attach(j.group(name), e, maxExplainedEvidence)
}

// foldIntoPackage shows a change as part of its package's change: on the
// package's finding when that is ranked, else in its explained group. sev
// is what the change would rank as on its own; an exception never drops a
// finding together with evidence more serious than the finding itself.
func (j *judge) foldIntoPackage(name string, e model.Evidence, sev model.Severity) {
	j.touch(name, e.Path)
	if f := j.pkgFinding[name]; f != nil {
		j.attach(f, e, maxEvidence)
		if sev > j.foldedMax[f] {
			j.foldedMax[f] = sev
		}
		return
	}
	j.explain(name, e)
}

// refWords names what package files are compared with in this scan.
func (j *judge) refWords() string {
	if j.in.Pkg != nil && j.in.Pkg.Mode == pkgverify.ModeOfflineLocal {
		return OfflineReference
	}
	return "the distribution's signed package"
}

func (j *judge) packageChange(ch diff.Change) {
	pc := ch.Pkg
	if pc == nil {
		return
	}
	name := pc.Name
	switch ch.Kind {
	case diff.PkgUpgraded:
		// The version change comes first: it is the group's value.
		g := j.group(name)
		g.Evidence = append([]model.Evidence{{Before: pc.Old, After: pc.New, Detail: "upgraded", When: j.listWhen(name)}}, g.Evidence...)
	case diff.PkgDowngraded:
		j.pkgFinding[name] = j.add(&model.Finding{
			Key: "snap.pkg_downgraded:" + name, ID: "TT-SNAP-007", Source: srcSnapshot, Severity: model.SevBackdoor,
			Title: fmt.Sprintf("%s was downgraded from %s to %s since the snapshot", name, pc.Old, pc.New),
			Why: "An older version can bring back security holes that have been fixed, a known way back in. " +
				"Updates never downgrade a package by themselves; someone asked for the older version.",
			Fix:      fixDowngrade(name, pc.Old),
			Evidence: []model.Evidence{{Before: pc.Old, After: pc.New, Detail: "downgraded", When: j.listWhen(name)}},
			Refs:     []string{"T1562.010"},
		})
	case diff.PkgInstalled:
		if j.newerKernel(name, pc.New) {
			j.explain(name, model.Evidence{After: pc.New, Detail: "installed: a newer kernel package of a flavour already installed", When: j.listWhen(name)})
			return
		}
		j.installed(name, pc.New)
	case diff.PkgRemoved:
		switch {
		case securityPackages[name]:
			j.pkgFinding[name] = j.add(&model.Finding{
				Key: "snap.pkg_removed:" + name, ID: "TT-SNAP-008", Source: srcSnapshot, Severity: model.SevWeak,
				Title:    fmt.Sprintf("Security package %s was removed since the snapshot", name),
				Why:      "Firewalls, audit logging, intrusion blocking and AppArmor are what an attacker turns off first so that they can come and go unseen.",
				Fix:      fixInstall(name),
				Evidence: []model.Evidence{{Before: pc.Old, After: "removed", Detail: "removed since the snapshot"}},
				Refs:     []string{"T1562.001"},
			})
		case j.olderKernel(name, pc.Old):
			j.explain(name, model.Evidence{Before: pc.Old, After: "removed", Detail: "removed: an older kernel; a newer one of its flavour is installed"})
		default:
			j.pkgFinding[name] = j.add(&model.Finding{
				Key: "snap.pkg_removed:" + name, ID: "TT-SNAP-009", Source: srcSnapshot, Severity: model.SevNote,
				Title:    fmt.Sprintf("%s was removed since the snapshot", name),
				Why:      "Listed so that every package change is accounted for; removing a package is rarely how an attacker gets in.",
				Fix:      command([]string{name}, func(q []string) string { return "# if you did not remove it: apt-get install -- " + q[0] }),
				Evidence: []model.Evidence{{Before: pc.Old, After: "removed", Detail: "removed since the snapshot"}},
			})
		}
	}
}

// listWhen dates a package change by when dpkg last wrote its file list.
func (j *judge) listWhen(name string) *time.Time {
	p := j.pkgs[name]
	if p == nil {
		return nil
	}
	for _, n := range []string{p.Name + ".list", p.Name + ":" + p.Arch + ".list"} {
		if w := j.whenFor("/var/lib/dpkg/info/" + n); w != nil {
			return w
		}
	}
	return nil
}

// installed ranks a newly installed package that is not routine.
func (j *judge) installed(name, version string) {
	f, reasons := j.installFinding(j.pkgs[name], name, version)
	// What raised the package is part of the value an exception accepts.
	j.pkgReasons[name] = append(j.pkgReasons[name], reasons...)
	j.pkgFinding[name] = j.add(f)
}

// installedExtra ranks a package installed for another architecture while
// the same name also changed: it is judged as an install of its own.
func (j *judge) installedExtra(ch diff.Change) {
	var p *model.Package
	for i := range j.c.Packages.Installed {
		if q := &j.c.Packages.Installed[i]; q.Name == ch.Pkg.Name && q.Arch == ch.Pkg.Arch {
			p = q
		}
	}
	name := ch.Pkg.Name + ":" + ch.Pkg.Arch
	f, reasons := j.installFinding(p, ch.Pkg.Name, ch.Pkg.New)
	f.Key = "snap.pkg_installed:" + name
	f.Title = strings.Replace(f.Title, "New package "+ch.Pkg.Name+" ", "New package "+name+" ", 1)
	var files []string
	if p != nil {
		files = p.Files
	}
	sort.Strings(reasons)
	f.Evidence[0].After = strings.Join(append([]string{ch.Pkg.New}, reasons...), "; ") + "; files " + j.contentDigest(append([]string(nil), files...))
	j.add(f)
}

// installFinding builds the finding for a newly installed package p (its
// dpkg entry; nil if it has none): a note, or a backdoor sign with what
// raised it. reasons summarise what raised it.
func (j *judge) installFinding(p *model.Package, name, version string) (*model.Finding, []string) {
	var raised []model.Evidence
	if p != nil {
		for _, f := range p.Files {
			e := j.files[f]
			if e == nil {
				if a := usrAlias(f); a != "" {
					e = j.files[a]
				}
			}
			if e != nil && e.Type == "file" {
				if e.Mode&0o6000 != 0 {
					raised = append(raised, model.Evidence{Path: f, Detail: fmt.Sprintf("setuid/setgid program (mode %04o)", e.Mode&0o7777)})
				}
				if e.Caps != "" {
					raised = append(raised, model.Evidence{Path: f, Detail: "file capability " + e.Caps})
				}
			}
			switch {
			case isKernelModule(f):
				raised = append(raised, model.Evidence{Path: f, Detail: "kernel module"})
			case isPAMModule(f):
				raised = append(raised, model.Evidence{Path: f, Detail: "PAM module"})
			case isUnitFile(f):
				if link := j.enabledLink(f); link != "" {
					raised = append(raised, model.Evidence{Path: f, Detail: "systemd unit enabled by " + link})
				}
			}
		}
	}
	for _, l := range j.listeners {
		if l.After != "" && j.owned[l.After] == name {
			raised = append(raised, model.Evidence{Path: l.After, After: l.Subject, Detail: "listens on a new socket"})
		}
	}
	f := &model.Finding{
		Key: "snap.pkg_installed:" + name, ID: "TT-SNAP-006", Source: srcSnapshot, Severity: model.SevNote,
		Title:    fmt.Sprintf("New package %s %s since the snapshot", name, version),
		Why:      "A package installed since the machine was known to be clean. It brings nothing that runs with special rights or listens on the network; listed so that every change is accounted for.",
		Fix:      fixPurge(name),
		Evidence: []model.Evidence{{After: version, Detail: "installed since the snapshot", When: j.listWhen(name)}},
		Refs:     []string{"T1072"},
	}
	if len(raised) > 0 {
		f.Severity = model.SevBackdoor
		f.Title = fmt.Sprintf("New package %s %s since the snapshot, with %s", name, version, raised[0].Detail)
		f.Why = "A package installed since the machine was known to be clean that adds something that runs with special rights or reaches the network: " +
			"a setuid/setgid program, a file capability, a kernel module, a PAM module, an enabled service or a listening program. " +
			"Installing a package is an easy way to plant a backdoor that looks legitimate."
		f.Evidence = append(f.Evidence, raised...)
	}
	var reasons []string
	for _, r := range raised {
		reasons = append(reasons, strings.TrimSpace(r.Detail+" "+r.Path))
	}
	return f, reasons
}

// changedNames lists the packages that changed, those still installed first
// (by name), then the removed ones.
func (j *judge) changedNames() []string {
	var in, out []string
	for n, ch := range j.pkgChange {
		if ch.Kind == diff.PkgRemoved {
			out = append(out, n)
		} else {
			in = append(in, n)
		}
	}
	sort.Strings(in)
	sort.Strings(out)
	return append(in, out...)
}

// changedPackage is the first changed package (in changedNames order) for
// which ok (see rebuilderOK) and match hold, or "".
func (j *judge) changedPackage(ok, match func(name string) bool) string {
	for _, n := range j.changedNames() {
		if ok(n) && match(n) {
			return n
		}
	}
	return ""
}

// ships reports whether the package lists a file below prefix, now or in
// the snapshot.
func (j *judge) ships(name, prefix string) bool {
	for _, c := range []*model.Collection{j.c, j.old} {
		if c == nil {
			continue
		}
		for _, p := range c.Packages.Installed {
			if p.Name != name {
				continue
			}
			for _, f := range p.Files {
				if strings.HasPrefix(f, prefix) || strings.HasPrefix(usrAlias(f), prefix) {
					return true
				}
			}
		}
	}
	return false
}

// rebuilderOK reports whether a package change can explain a rebuilt boot
// file: a removal, or a new version that something confirmed (one of its
// files matched it). A version bump typed into dpkg status explains
// nothing.
func (j *judge) rebuilderOK(name string) bool {
	return j.pkgChange[name].Kind == diff.PkgRemoved || j.confirmed[name]
}

// couldNotCheck reports whether a package changed and nothing could say
// whether its new version is genuine, because the host's own indexes could
// not be used (a real outage): not confirmed, but not contradicted either.
func (j *judge) couldNotCheck(name string) bool {
	_, down := j.unreachable[name]
	return down && j.pkgChanged(name) && !j.confirmed[name]
}

// broughtScripts reports whether a package change brings new maintainer
// scripts: an install or an upgrade (a downgrade is ranked on its own, a
// removal leaves the scripts as they were).
func (j *judge) broughtScripts(name string) bool {
	k := j.pkgChange[name].Kind
	return k == diff.PkgUpgraded || k == diff.PkgInstalled
}

// anyChange accepts every changed package, confirmed or not.
func (j *judge) anyChange(string) bool { return true }

// changeConfirmed reports whether a package change may carry its links,
// directories and removed files quietly: a removal, a version one of whose
// files matched the signed package, or a change an outage left unchecked
// (which goes into the note on unchecked files). A version nothing
// confirmed explains none of its files.
func (j *judge) changeConfirmed(name string) bool {
	return j.rebuilderOK(name) || j.couldNotCheck(name)
}

// foldWithChange shows a link, directory or removed file as part of its
// package's change. When nothing confirmed that change, it stops being an
// explained one: it becomes a finding that lists them.
func (j *judge) foldWithChange(name string, e model.Evidence) {
	if !j.changeConfirmed(name) {
		j.unconfirmed[name] = true
	}
	j.foldIntoPackage(name, e, model.SevNote)
}

// kernelPackageFor is the changed kernel package of a kernel release for
// which ok holds, or "".
func (j *judge) kernelPackageFor(release string, ok func(name string) bool) string {
	for _, name := range []string{"linux-image-" + release, "linux-image-unsigned-" + release, "linux-modules-" + release, "linux-modules-extra-" + release} {
		if j.pkgChanged(name) && ok(name) {
			return name
		}
	}
	return ""
}

func isGrub(name string) bool {
	return strings.HasPrefix(name, "grub") || strings.HasPrefix(name, "shim")
}

// rebuiltBy names the changed package that rebuilds a generated boot file
// or module index, or "": an initramfs only for its own kernel, initramfs-
// tools or a package with initramfs hooks or scripts; the boot menu for
// GRUB, shim or a kernel image; GRUB's modules, fonts and EFI binaries only
// for GRUB or shim; a module index for its kernel, a package with modules
// for that kernel, or DKMS. ok chooses among the changed packages: the
// confirmed ones (rebuilderOK) explain the file.
func (j *judge) rebuiltBy(p string, ok func(name string) bool) string {
	switch {
	case p == "/boot/initrd.img" || p == "/boot/initrd.img.old" || p == "/boot/vmlinuz" || p == "/boot/vmlinuz.old":
		return j.changedPackage(ok, func(n string) bool { return strings.HasPrefix(n, "linux-image") })
	case strings.HasPrefix(p, "/boot/initrd.img-"):
		if k := j.kernelPackageFor(strings.TrimPrefix(p, "/boot/initrd.img-"), ok); k != "" {
			return k
		}
		return j.changedPackage(ok, func(n string) bool {
			return strings.HasPrefix(n, "initramfs-tools") || j.ships(n, "/usr/share/initramfs-tools/") ||
				strings.HasPrefix(n, "linux-firmware") || strings.HasPrefix(n, "firmware-") || n == "intel-microcode" || n == "amd64-microcode"
		})
	case p == "/boot/grub/grub.cfg" || p == "/boot/grub/grubenv":
		return j.changedPackage(ok, func(n string) bool { return isGrub(n) || strings.HasPrefix(n, "linux-image") })
	case strings.HasPrefix(p, "/boot/grub/") || strings.HasPrefix(p, "/boot/efi/"):
		return j.changedPackage(ok, isGrub)
	}
	release := moduleRelease(p)
	if release == "" {
		return ""
	}
	if k := j.kernelPackageFor(release, ok); k != "" {
		return k
	}
	return j.changedPackage(ok, func(n string) bool {
		return strings.Contains(n, "dkms") || j.ships(n, "/lib/modules/"+release+"/") || j.ships(n, "/usr/lib/modules/"+release+"/")
	})
}

// moduleRelease is the kernel release of a depmod output
// (/lib/modules/<release>/modules.*), or "".
func moduleRelease(p string) string {
	for _, pre := range []string{"/lib/modules/", "/usr/lib/modules/"} {
		if rest, ok := strings.CutPrefix(p, pre); ok {
			if seg := strings.Split(rest, "/"); len(seg) == 2 && strings.HasPrefix(seg[1], "modules.") {
				return seg[0]
			}
		}
	}
	return ""
}

// finishPackages settles package changes once every file change is placed.
// An upgrade, or a routine kernel change, is explained only when the files
// it changed matched the package: programs whose version no trusted source
// has make it a backdoor sign, programs that could not be checked at all
// put it in one note with every other such package, other unconfirmed files
// make it a note. A ranked package change gains its unverified programs,
// and a new package's value names everything that raised it.
func (j *judge) finishPackages() {
	var unchecked []string
	for _, name := range j.changedNames() {
		ch := j.pkgChange[name]
		unver := j.unverIn[name]
		g := j.groups["explained:"+name]
		f := j.pkgFinding[name]
		switch {
		case f == nil && g != nil && ch.Kind != diff.PkgRemoved && len(unver) > 0:
			f = j.unexplain(name, ch, g, unver)
		case len(unver) == 0 && len(j.unchecked[name]) > 0:
			unchecked = append(unchecked, name)
			if f == nil && g != nil {
				delete(j.groups, g.Key) // not explained: nothing checked it
			}
		case f == nil && g != nil && ch.Kind != diff.PkgRemoved && j.unconfirmed[name]:
			f = j.unexplain(name, ch, g, nil)
		case f == nil && g != nil && ch.Kind == diff.PkgUpgraded && !j.confirmed[name] && !j.filesChanged(name):
			f = j.versionOnly(name, ch, g)
		case f != nil && len(unver) > 0:
			for _, e := range unver {
				j.attach(f, e, maxEvidence)
			}
			if f.Severity < model.SevBackdoor && ch.Pkg != nil {
				f.Severity = model.SevBackdoor
				f.Title = fmt.Sprintf("New package %s %s since the snapshot, with %d %s %s", name, ch.Pkg.New, len(unver), plural(len(unver), "file", "files"), j.unconfirmedFiles())
				f.Why = j.unverifiedWhy(unver)
			}
		}
		if f != nil && len(unver) > 0 {
			for _, e := range j.unchecked[name] {
				j.attach(f, e, maxEvidence)
			}
		}
		if f != nil && ch.Kind == diff.PkgInstalled && ch.Pkg != nil && len(f.Evidence) > 0 {
			reasons := append([]string(nil), j.pkgReasons[name]...)
			if len(unver) > 0 {
				var ps []string
				for _, e := range unver {
					ps = append(ps, e.Path)
				}
				sort.Strings(ps)
				reasons = append(reasons, "not confirmed by a trusted source: "+strings.Join(ps, ", "))
			}
			sort.Strings(reasons)
			f.Evidence[0].After = strings.Join(append([]string{ch.Pkg.New}, reasons...), "; ")
		}
		// Package findings accept exactly the files they showed: the value names
		// a digest of every (path, content) pair, so other content at the
		// same version is a finding again.
		if f != nil && len(f.Evidence) > 0 && (strings.HasPrefix(f.Key, "snap.pkg_upgraded:") || strings.HasPrefix(f.Key, "snap.pkg_installed:") || strings.HasPrefix(f.Key, "snap.pkg_downgraded:") || strings.HasPrefix(f.Key, "snap.pkg_version_only:")) {
			f.Evidence[0].After += "; files " + j.pkgDigest(name, ch.Kind == diff.PkgInstalled)
		}
	}
	j.uncheckedPkgs = unchecked
}

// offline reports whether package files were compared with the machine's
// own checksums only.
func (j *judge) offline() bool {
	return j.in.Pkg != nil && j.in.Pkg.Mode == pkgverify.ModeOfflineLocal
}

// unconfirmedVersion words why a package's new version is unconfirmed.
func (j *judge) unconfirmedVersion() string {
	if j.notRun != "" {
		return "nothing confirmed, because package verification did not run"
	}
	return "no trusted source confirmed"
}

// unconfirmedFiles words why a package's changed files are unconfirmed.
func (j *judge) unconfirmedFiles() string {
	if j.notRun != "" {
		return "not checked because package verification did not run"
	}
	return "no trusted source confirmed"
}

func (j *judge) unverifiedWhy(unver []model.Evidence) string {
	if j.notRun != "" {
		return "Nothing confirmed the programs this package change brought, because " + j.notRun + ". /etc/os-release, which names the release, is a file root can edit, " +
			"so a change that could not be checked counts as unexplained."
	}
	why := "Verification ran, and no trusted source (the signed archive, its snapshots or a reference bundle) has the version of the programs this package change brought"
	if len(unver) > 0 && unver[0].Detail != "" {
		why += " (" + unver[0].Detail + ")"
	}
	return why + ". A package \"update\" from an unofficial source is a way to slip in replaced programs, so they count as unexplained."
}

// uncheckedNote lists, in one note, the package files that could not be
// checked because a package source could not be read or used: the changed
// programs of packages that changed since the snapshot, and setuid
// programs, kernel modules, PAM modules and boot files, with or without a
// snapshot. Not being able to check is not evidence of tampering, so a
// network failure must not raise a backdoor sign per file or package; the
// reasons go into what the report could not rule out.
func (j *judge) uncheckedNote() {
	var items []model.Evidence
	var ids, reasons, paths []string
	listed := map[string]bool{}
	unreachable := true
	add := func(e model.Evidence) {
		items = append(items, e)
		if e.Path == "" || listed[e.Path] {
			return
		}
		listed[e.Path] = true
		paths = append(paths, e.Path)
		if r := j.unverReason[e.Path]; r != "" && !slices.Contains(reasons, r) {
			reasons = append(reasons, r)
		}
		if j.unverKind[e.Path] != pkgverify.KindUnreachable {
			unreachable = false
		}
	}
	for _, name := range j.uncheckedPkgs {
		ch := j.pkgChange[name]
		ev := model.Evidence{Detail: name + ": " + strings.TrimPrefix(ch.Kind, "pkg_"), When: j.listWhen(name)}
		if ch.Pkg != nil {
			ev.Before, ev.After = ch.Pkg.Old, ch.Pkg.New
			ids = append(ids, strings.TrimSpace(name+" "+ch.Pkg.New))
		}
		items = append(items, ev)
		for _, e := range j.unchecked[name] {
			add(e)
		}
	}
	for _, e := range j.uncheckedFiles {
		if !listed[e.Path] {
			add(e)
		}
	}
	n := len(paths)
	if n == 0 {
		return
	}
	files := fmt.Sprintf("%d package %s", n, plural(n, "file", "files"))
	f := &model.Finding{
		Key: "pkg.unchecked_changes", ID: "TT-PKG-007", Source: srcPackage, Severity: model.SevNote,
		Title: files + " could not be checked against a trusted source",
		Fix:   "Scan again when the package archive can be reached, or run telltale fetch-refs on a machine with network access and scan with --refs DIR.",
	}
	if unreachable {
		f.Title = files + " could not be checked because the package archive could not be reached"
	}
	sort.Strings(reasons)
	shown, more := reasons, ""
	if len(shown) > 3 {
		shown, more = shown[:3], fmt.Sprintf("; and %d more", len(reasons)-3)
	}
	f.Why = "These programs, modules and boot files could not be checked: " + strings.Join(shown, "; ") + more +
		". That is not evidence of tampering, but they stay unverified until a scan can use the package archive or a reference bundle."
	if len(ids) > 0 {
		f.Why += fmt.Sprintf(" %d of the packages they belong to changed since the snapshot.", len(ids))
	}
	// The value an exception accepts names every changed package and
	// version, and every file with its content.
	f.Evidence = []model.Evidence{{After: strings.Join(append(ids, "files "+j.contentDigest(paths)), "; "), Detail: files + " that could not be checked"}}
	for _, e := range items {
		j.attach(f, e, maxEvidence)
	}
	j.add(f)
	j.couldNot = append(j.couldNot, fmt.Sprintf("changes to %s that could not be checked (%s%s)", files, strings.Join(shown, "; "), more))
}

// unexplain turns an explained package change into a finding.
func (j *judge) unexplain(name string, ch diff.Change, g *model.Finding, unver []model.Evidence) *model.Finding {
	delete(j.groups, g.Key)
	pc := ch.Pkg
	f := &model.Finding{Key: "snap.pkg_upgraded:" + name, ID: "TT-SNAP-012", Source: srcSnapshot, Severity: model.SevNote, Refs: []string{"T1554"}}
	installed := ch.Kind == diff.PkgInstalled
	if installed {
		f.Key, f.ID = "snap.pkg_installed:"+name, "TT-SNAP-006"
	}
	for _, e := range g.Evidence {
		j.attach(f, e, maxEvidence)
	}
	if len(unver) > 0 {
		n := len(unver)
		f.Severity = model.SevBackdoor
		f.Why = j.unverifiedWhy(unver)
		if installed {
			f.Title = fmt.Sprintf("New package %s %s since the snapshot, with %d %s %s", name, pc.New, n, plural(n, "file", "files"), j.unconfirmedFiles())
			f.Fix = fixPurge(name)
		} else {
			f.Title = fmt.Sprintf("%s changed from %s to %s, a version %s; %d %s changed", name, pc.Old, pc.New, j.unconfirmedVersion(), n, plural(n, "file", "files"))
			f.Fix = fixDowngrade(name, pc.Old)
		}
		for _, e := range unver {
			j.attach(f, e, maxEvidence)
		}
	} else {
		f.Why = "The package change itself may be routine, but nothing confirmed the version installed now, or files it changed did not match it. " +
			"A version that nothing confirmed explains none of the changes made with it: they are listed here or as their own findings."
		f.Fix = command([]string{name}, func(q []string) string {
			return "apt-get install --reinstall -- " + q[0] + "   # puts the package's own files back"
		})
		switch {
		case installed:
			f.Title = fmt.Sprintf("New package %s %s since the snapshot; not all of its files match the package", name, pc.New)
		case !j.confirmed[name]:
			f.Title = fmt.Sprintf("%s changed from %s to %s, but nothing confirmed the new version", name, pc.Old, pc.New)
		default:
			f.Title = fmt.Sprintf("%s upgraded from %s to %s, but not all of the files it changed match the package", name, pc.Old, pc.New)
		}
	}
	f = j.add(f)
	j.pkgFinding[name] = f
	return f
}

var unitSuffixes = []string{".service", ".socket", ".timer", ".path"}

func isUnitFile(p string) bool {
	if !strings.Contains(p, "/systemd/system/") && !strings.Contains(p, "/systemd/user/") {
		return false
	}
	for _, s := range unitSuffixes {
		if strings.HasSuffix(p, s) {
			return true
		}
	}
	return false
}

// enabledLink returns the systemd enable link that points at the unit file
// u, or "".
func (j *judge) enabledLink(u string) string {
	alias := usrAlias(u)
	for _, p := range j.c.Persist {
		if p.Kind != model.PersistKindSystemdEnabled || len(p.Lines) == 0 {
			continue
		}
		t := linkTarget(p.Path, p.Lines[0])
		if t == u || (alias != "" && t == alias) || path.Base(p.Path) == path.Base(u) {
			return p.Path
		}
	}
	return ""
}

func linkTarget(link, target string) string {
	target = strings.TrimSpace(target)
	if !path.IsAbs(target) {
		target = path.Join(path.Dir(link), target)
	}
	return path.Clean(target)
}

var mergedDirs = []string{"bin", "sbin", "lib", "lib32", "lib64", "libx32"}

// usrAlias is the other spelling of p on merged-/usr systems, or "".
func usrAlias(p string) string {
	for _, d := range mergedDirs {
		if strings.HasPrefix(p, "/"+d+"/") {
			return "/usr" + p
		}
		if strings.HasPrefix(p, "/usr/"+d+"/") {
			return strings.TrimPrefix(p, "/usr")
		}
	}
	return ""
}

// accountDBs are the account databases whose content the account comparison
// shows line by line (without password data). A content change is left to
// that comparison only when it found a change belonging to the file; every
// other edit (a duplicate line, a field it does not compare) is ranked.
// gshadow, subuid and subgid are not compared there, so they are always
// ranked.
var accountDBs = map[string]bool{"/etc/passwd": true, "/etc/shadow": true, "/etc/group": true}

// accountFileWhy explains files whose meaning is not obvious from their place.
var accountFileWhy = map[string]string{
	"/etc/gshadow": "This file holds group passwords and group administrators; a password or administrator added here lets an account join privileged groups such as sudo.",
	"/etc/subuid":  "This file gives accounts ranges of user ids for their containers. A range that includes id 0 maps a user's container root to the real root of this machine.",
	"/etc/subgid":  "This file gives accounts ranges of group ids for their containers. A range that includes id 0 maps a user's containers to the real root group of this machine.",
}

// generatedFile: files that update-initramfs, update-grub, grub-install,
// the kernel's install scripts and depmod rebuild when packages change.
// They belong to no package, so they cannot be verified.
func generatedFile(p string) bool {
	switch p {
	case "/boot/initrd.img", "/boot/initrd.img.old", "/boot/vmlinuz", "/boot/vmlinuz.old":
		return true
	}
	return strings.HasPrefix(p, "/boot/initrd.img-") || strings.HasPrefix(p, "/boot/grub/") || strings.HasPrefix(p, "/boot/efi/") || moduleRelease(p) != ""
}

// dpkgInfoPackage is the package a file of dpkg's own database belongs to,
// e.g. /var/lib/dpkg/info/libc6:amd64.list -> libc6.
func dpkgInfoPackage(p string) string {
	rest, ok := strings.CutPrefix(p, "/var/lib/dpkg/info/")
	if !ok || strings.Contains(rest, "/") {
		return ""
	}
	i := strings.LastIndexByte(rest, '.')
	if i <= 0 {
		return ""
	}
	name, _, _ := strings.Cut(rest[:i], ":")
	return name
}

// persistExact and persistPrefixes are persistence locations beyond the
// collected persistence files: places whose files run code or decide who
// gets in.
var (
	persistExact = map[string]bool{"/etc/passwd": true, "/etc/shadow": true, "/etc/group": true, "/etc/gshadow": true, "/etc/subuid": true, "/etc/subgid": true,
		"/etc/ld.so.preload": true, "/etc/rc.local": true, "/etc/environment": true, "/etc/bash.bashrc": true, "/etc/crontab": true}
	persistPrefixes = []string{
		"/etc/sudoers", "/etc/ssh/", "/etc/cron.", "/var/spool/cron/", "/etc/systemd/", "/lib/systemd/", "/usr/lib/systemd/", "/etc/init.d/",
		"/etc/profile", "/etc/ld.so.conf", "/etc/pam.d/", "/etc/security/", "/etc/modules", "/etc/modprobe.d/", "/lib/modprobe.d/",
		"/usr/lib/modprobe.d/", "/etc/update-motd.d/", "/etc/hosts", "/etc/resolv.conf", "/etc/nsswitch.conf",
		"/etc/default/grub", "/etc/grub.d/", "/etc/initramfs-tools/",
		"/root/.ssh/authorized_keys", "/root/.ssh/rc", "/root/.ssh/environment", "/root/.ssh/config",
		"/root/.bashrc", "/root/.profile", "/root/.bash_profile",
	}
)

// volatileRootFiles change whenever root uses the machine (shell and tool
// history, editor state, hosts seen over SSH). Their appearing or changing
// is not reported; their disappearing is, since wiping history hides tracks.
var volatileRootFiles = map[string]bool{
	"/root/.bash_history": true, "/root/.lesshst": true, "/root/.viminfo": true, "/root/.wget-hsts": true,
	"/root/.python_history": true, "/root/.mysql_history": true, "/root/.psql_history": true, "/root/.sqlite_history": true,
	"/root/.ssh/known_hosts": true, "/root/.ssh/known_hosts.old": true,
}

// volatileRootFile: one of those, or a directory or plain data file in
// root's cache. Programs and libraries in the cache are still reported.
func volatileRootFile(p string, e *model.FileEntry) bool {
	if volatileRootFiles[p] {
		return true
	}
	if !strings.HasPrefix(p, "/root/.cache/") {
		return false
	}
	return e.Type == "dir" || (e.Type == "file" && !pkgverify.InScope(p, e.Mode))
}

// finishGroups gives each package's explained group its title, now that
// all of its evidence is in.
func (j *judge) finishGroups() {
	for key, g := range j.groups {
		name, ok := strings.CutPrefix(key, "explained:")
		if !ok {
			continue
		}
		files := j.omitted[g]
		var change *model.Evidence
		for i := range g.Evidence {
			e := &g.Evidence[i]
			if e.Path != "" {
				files++
			} else if change == nil {
				change = e
			}
		}
		fileWords := fmt.Sprintf("%d %s", files, plural(files, "file", "files"))
		switch {
		case change != nil && change.Detail == "upgraded":
			g.Title = fmt.Sprintf("%s upgraded from %s to %s", name, change.Before, change.After)
			g.Why = "An upgrade to a newer version is routine. Changed files that match " + j.refWords() + " for the new version are shown here, not ranked."
		case change != nil && change.Before == "":
			g.Title = fmt.Sprintf("%s %s installed (a newer kernel of a flavour already installed)", name, change.After)
			g.Why = "Installing a newer kernel of the flavour already in use is how kernel updates arrive, so it is routine."
		case change != nil:
			g.Title = fmt.Sprintf("%s %s removed (a newer kernel of its flavour is installed)", name, change.Before)
			g.Why = "Removing an old kernel once a newer one of the same flavour is installed is routine clean-up."
		default:
			g.Title = fmt.Sprintf("%s of %s match %s", fileWords, name, j.refWords())
			g.Why = "These files changed since the snapshot, but they match " + j.refWords() + " for the version installed now, so the package put them there (for example a reinstall)."
			continue
		}
		if files > 0 {
			g.Title += "; " + fileWords + " changed with it"
		}
	}
}

func (j *judge) isPersistLocation(p string) bool {
	if j.persist[p] != nil || j.oldPersist[p] != nil || persistExact[p] {
		return true
	}
	for _, pre := range persistPrefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

// touch records a path shown with a package's change.
func (j *judge) touch(name, p string) {
	if name == "" || p == "" {
		return
	}
	if j.touched[name] == nil {
		j.touched[name] = map[string]bool{}
	}
	j.touched[name][p] = true
}

// pkgDigest is a digest of the paths shown with a package's change (and,
// for a new package, every file it lists) with their current content.
func (j *judge) pkgDigest(name string, listed bool) string {
	var paths []string
	for p := range j.touched[name] {
		paths = append(paths, p)
	}
	if p := j.pkgs[name]; listed && p != nil {
		paths = append(paths, p.Files...)
	}
	return j.contentDigest(paths)
}

// contentDigest hashes the sorted, distinct (path, content) pairs of paths:
// a file's SHA-256, a persistence file's, or what the path is now.
func (j *judge) contentDigest(paths []string) string {
	sort.Strings(paths)
	h := sha256.New()
	prev := ""
	for i, p := range paths {
		if i > 0 && p == prev {
			continue
		}
		prev = p
		content := "absent"
		switch e, pf := j.files[p], j.persist[p]; {
		case e != nil && e.SHA256 != "":
			content = e.SHA256
		case e != nil:
			content = e.Type + " " + e.Target
		case pf != nil:
			content = pf.SHA256
		}
		fmt.Fprintf(h, "%s\x00%s\n", p, content)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// filesChanged reports whether any file the package owns (beyond dpkg's own
// records of it) is shown with its change.
func (j *judge) filesChanged(name string) bool {
	for p := range j.touched[name] {
		if !strings.HasPrefix(p, "/var/lib/dpkg/info/") {
			return true
		}
	}
	return false
}

// versionOnly turns an upgrade that changed no files, and whose new version
// nothing confirmed, into a note: only dpkg's record of the version moved.
func (j *judge) versionOnly(name string, ch diff.Change, g *model.Finding) *model.Finding {
	delete(j.groups, g.Key)
	f := &model.Finding{
		Key: "snap.pkg_version_only:" + name, ID: "TT-SNAP-013", Source: srcSnapshot, Severity: model.SevNote,
		Title: fmt.Sprintf("The recorded version of %s changed from %s to %s, but no files changed and the new version could not be confirmed", name, ch.Pkg.Old, ch.Pkg.New),
		Why: "dpkg's record says this package was upgraded, but none of its files changed and nothing confirmed the new version. A version typed into dpkg status changes nothing by itself, " +
			"but it can make other changes look like part of an update.",
		Fix: command([]string{name}, func(q []string) string {
			return "apt-get install --reinstall -- " + q[0] + "   # puts the package's own files and record back; /var/log/dpkg.log shows whether dpkg made the upgrade"
		}),
	}
	for _, e := range g.Evidence {
		j.attach(f, e, maxEvidence)
	}
	f = j.add(f)
	j.pkgFinding[name] = f
	return f
}
