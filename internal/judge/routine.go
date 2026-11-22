package judge

import (
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/donaldsteele/telltale/internal/diff"
	"github.com/donaldsteele/telltale/internal/model"
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

// kernelRe matches linux-(image|modules|modules-extra|headers)-<abi>-<flavour>.
// Ubuntu's linux-headers-<abi> has no flavour.
var kernelRe = regexp.MustCompile(`^linux-(image|modules|modules-extra|headers)-([0-9][0-9.]*-[0-9][0-9.]*)(?:-([a-z][a-z0-9+.-]*))?$`)

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
	j.attach(j.group(name), e, maxExplainedEvidence)
}

// foldIntoPackage shows a file change as part of its package's change: on
// the package's finding when the change is ranked, else in its explained
// group.
func (j *judge) foldIntoPackage(name string, e model.Evidence) {
	if f := j.pkgFinding[name]; f != nil {
		j.attach(f, e, maxEvidence)
		return
	}
	j.explain(name, e)
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
				Fix:      command([]string{name}, func(q []string) string { return "# if you did not remove it: apt-get install " + q[0] }),
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
	var reasons []model.Evidence
	if p := j.pkgs[name]; p != nil {
		for _, f := range p.Files {
			e := j.files[f]
			if e == nil {
				if a := usrAlias(f); a != "" {
					e = j.files[a]
				}
			}
			if e != nil && e.Type == "file" {
				if e.Mode&0o6000 != 0 {
					reasons = append(reasons, model.Evidence{Path: f, Detail: fmt.Sprintf("setuid/setgid program (mode %04o)", e.Mode&0o7777)})
				}
				if e.Caps != "" {
					reasons = append(reasons, model.Evidence{Path: f, Detail: "file capability " + e.Caps})
				}
			}
			switch {
			case isKernelModule(f):
				reasons = append(reasons, model.Evidence{Path: f, Detail: "kernel module"})
			case isPAMModule(f):
				reasons = append(reasons, model.Evidence{Path: f, Detail: "PAM module"})
			case isUnitFile(f):
				if link := j.enabledLink(f); link != "" {
					reasons = append(reasons, model.Evidence{Path: f, Detail: "systemd unit enabled by " + link})
				}
			}
		}
	}
	for _, l := range j.listeners {
		if l.After != "" && j.owned[l.After] == name {
			reasons = append(reasons, model.Evidence{Path: l.After, After: l.Subject, Detail: "listens on a new socket"})
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
	if len(reasons) > 0 {
		f.Severity = model.SevBackdoor
		f.Title = fmt.Sprintf("New package %s %s since the snapshot, with %s", name, version, reasons[0].Detail)
		f.Why = "A package installed since the machine was known to be clean that adds something that runs with special rights or reaches the network: " +
			"a setuid/setgid program, a file capability, a kernel module, a PAM module, an enabled service or a listening program. " +
			"Installing a package is an easy way to plant a backdoor that looks legitimate."
		f.Evidence = append(f.Evidence, reasons...)
	}
	j.pkgFinding[name] = j.add(f)
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

// accountFiles hold the account databases. Their content changes are listed
// one account or group at a time from the account comparison, which never
// shows password hashes.
var accountFiles = map[string]bool{}

func init() {
	for _, f := range []string{"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/subuid", "/etc/subgid"} {
		accountFiles[f] = true
		accountFiles[f+"-"] = true
	}
}

// generatedFile: files that update-initramfs, update-grub, grub-install and
// depmod rebuild when packages change. They belong to no package, so they
// cannot be verified.
func generatedFile(p string) bool {
	if strings.HasPrefix(p, "/boot/initrd.img") || strings.HasPrefix(p, "/boot/grub/") || strings.HasPrefix(p, "/boot/efi/") {
		return true
	}
	for _, pre := range []string{"/lib/modules/", "/usr/lib/modules/"} {
		if rest, ok := strings.CutPrefix(p, pre); ok {
			seg := strings.Split(rest, "/")
			return len(seg) == 2 && strings.HasPrefix(seg[1], "modules.")
		}
	}
	return false
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
	persistExact    = map[string]bool{"/etc/passwd": true, "/etc/shadow": true, "/etc/group": true, "/etc/gshadow": true, "/etc/ld.so.preload": true, "/etc/rc.local": true, "/etc/environment": true, "/etc/bash.bashrc": true, "/etc/crontab": true}
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

func volatileRootFile(p string) bool {
	return volatileRootFiles[p] || strings.HasPrefix(p, "/root/.cache/")
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
			g.Why = "An upgrade to a newer version is routine. Changed files that match the distribution's signed package for the new version are shown here, not ranked."
		case change != nil && change.Before == "":
			g.Title = fmt.Sprintf("%s %s installed (a newer kernel of a flavour already installed)", name, change.After)
			g.Why = "Installing a newer kernel of the flavour already in use is how kernel updates arrive, so it is routine."
		case change != nil:
			g.Title = fmt.Sprintf("%s %s removed (a newer kernel of its flavour is installed)", name, change.Before)
			g.Why = "Removing an old kernel once a newer one of the same flavour is installed is routine clean-up."
		default:
			g.Title = fmt.Sprintf("%s match the signed %s package", fileWords, name)
			g.Why = "These files changed since the snapshot, but they match the distribution's signed package installed now, so the package put them there (for example a reinstall)."
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
