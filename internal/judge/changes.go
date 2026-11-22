package judge

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/donaldsteele/telltale/internal/diff"
	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/pkgverify"
)

// index records what the other rules depend on: which packages changed,
// the new listeners, and which account databases the account comparison
// explains.
func (j *judge) index(chs []diff.Change) {
	for _, ch := range chs {
		switch ch.Kind {
		case diff.PkgUpgraded, diff.PkgDowngraded, diff.PkgInstalled, diff.PkgRemoved:
			// An architecture edited in dpkg status shows as an install and a
			// removal of the same name: the package installed now counts.
			if ch.Pkg == nil {
				continue
			}
			if prev, ok := j.pkgChange[ch.Pkg.Name]; !ok || prev.Kind == diff.PkgRemoved {
				j.pkgChange[ch.Pkg.Name] = ch
			}
		case diff.ListenerAdded:
			j.listeners = append(j.listeners, ch)
		case diff.UserAdded, diff.UserRemoved:
			j.acctChanged["/etc/passwd"], j.acctChanged["/etc/shadow"] = true, true
		case diff.UserChanged:
			if o, n := findUser(j.old, ch.Subject), findUser(j.c, ch.Subject); o != nil && n != nil {
				if o.UID != n.UID || o.GID != n.GID || o.Shell != n.Shell || o.Home != n.Home {
					j.acctChanged["/etc/passwd"] = true
				}
				if o.Password.Digest != n.Password.Digest || o.Password.Locked != n.Password.Locked || o.Password.Set != n.Password.Set {
					j.acctChanged["/etc/shadow"] = true
				}
			}
		case diff.GroupChanged:
			j.acctChanged["/etc/group"] = true
			o, n := findGroup(j.old, ch.Subject), findGroup(j.c, ch.Subject)
			if shadowChanged(o, n) {
				j.acctChanged["/etc/gshadow"] = true
			}
			if pw, added, admins := groupGains(o, n); pw || ((j.privileged(o) || j.privileged(n)) && (len(added) > 0 || admins)) {
				j.gshadowRisk = true
			}
		}
	}
}

// shadowChanged reports whether the group comparison saw a gshadow change
// for this group: a group added or removed with its gshadow entry, or a
// different entry where both scans read gshadow.
func shadowChanged(o, n *model.Group) bool {
	switch {
	case o == nil:
		return n != nil && n.Shadow != nil
	case n == nil:
		return o.Shadow != nil
	case o.Shadow == nil || n.Shadow == nil:
		return false
	}
	return o.Shadow.PasswordSet != n.Shadow.PasswordSet || sortedJoin(o.Shadow.Admins) != sortedJoin(n.Shadow.Admins) ||
		sortedJoin(o.Shadow.Members) != sortedJoin(n.Shadow.Members)
}

// groupGains lists what a group change gives: a group password where there
// was none, members added (in /etc/group or gshadow) and new
// administrators.
func groupGains(o, n *model.Group) (password bool, added []string, admins bool) {
	if n == nil {
		return false, nil, false
	}
	var oldM []string
	var oldS *model.GroupShadow
	if o != nil {
		oldM, oldS = append([]string(nil), o.Members...), o.Shadow
	}
	cur := append([]string(nil), n.Members...)
	// gshadow counts only for a new group or when both scans read it.
	if n.Shadow != nil && (o == nil || oldS != nil) {
		password = n.Shadow.PasswordSet && (oldS == nil || !oldS.PasswordSet)
		for _, a := range n.Shadow.Admins {
			if oldS == nil || !slices.Contains(oldS.Admins, a) {
				admins = true
			}
		}
		cur = append(cur, n.Shadow.Members...)
		if oldS != nil {
			oldM = append(oldM, oldS.Members...)
		}
	}
	for _, m := range cur {
		if !slices.Contains(oldM, m) && !slices.Contains(added, m) {
			added = append(added, m)
		}
	}
	slices.Sort(added)
	return password, added, admins
}

func sortedJoin(ss []string) string {
	m := append([]string(nil), ss...)
	slices.Sort(m)
	return strings.Join(m, ",")
}

// changes ranks every difference from the snapshot (index has run).
func (j *judge) changes(chs []diff.Change) {
	for _, ch := range chs {
		switch ch.Kind {
		case diff.PkgUpgraded, diff.PkgDowngraded, diff.PkgInstalled, diff.PkgRemoved:
			if ch.Pkg != nil && j.pkgChange[ch.Pkg.Name].Kind == ch.Kind {
				j.packageChange(ch)
			}
		}
	}
	for _, ch := range chs {
		if ch.Kind == diff.PersistChanged {
			j.persistChange(ch)
		}
	}
	for _, ch := range chs {
		switch ch.Kind {
		case diff.FileAdded, diff.FileModified, diff.FileRemoved:
			j.fileChange(ch)
		}
	}
	for _, ch := range chs {
		switch ch.Kind {
		case diff.UserAdded:
			j.userAdded(ch)
		case diff.UserRemoved:
			j.add(&model.Finding{
				Key: "snap.user_removed:" + ch.Subject, ID: "TT-SNAP-004", Source: srcSnapshot, Severity: model.SevNote,
				Title:    fmt.Sprintf("Account %q was removed since the snapshot", ch.Subject),
				Why:      "Listed so that every account change is accounted for. Removing an account is rarely how an attacker gets in, but it can remove a record of who logged in.",
				Fix:      "Restore the account from a backup of /etc/passwd and /etc/shadow if you did not remove it.",
				Evidence: []model.Evidence{{Path: "/etc/passwd", Before: ch.Before, After: "removed", Detail: "removed since the snapshot"}},
			})
		case diff.UserChanged:
			j.userChanged(ch)
		case diff.GroupChanged:
			j.groupChanged(ch)
		case diff.ModuleAdded:
			j.moduleAdded(ch)
		case diff.ListenerAdded:
			j.listenerAdded(ch)
		case diff.CheckRegressed:
			j.regressed(ch.CheckID, ch.Before, nil)
		}
	}
}

// --- files ---

// sameMeta reports whether two entries differ in at most content.
func sameMeta(a, b *model.FileEntry) bool {
	return a.Type == b.Type && a.Target == b.Target && a.Mode&0o7777 == b.Mode&0o7777 && a.UID == b.UID && a.GID == b.GID &&
		a.Flags == b.Flags && a.Caps == b.Caps && a.Err == b.Err
}

// metaOnly reports whether only mode and owner changed.
func metaOnly(a, b *model.FileEntry) bool {
	return a.Type == b.Type && a.Target == b.Target && a.SHA256 == b.SHA256 && a.Size == b.Size &&
		a.Flags == b.Flags && a.Caps == b.Caps && a.Err == b.Err
}

// verifiedNow reports whether a verified verdict covers the file as it is
// now, for the package installed now.
func (j *judge) verifiedNow(v pkgverify.FileVerdict, e *model.FileEntry) bool {
	if e == nil || e.Type != "file" {
		return false
	}
	if v.Actual != e.SHA256 && !strings.HasPrefix(v.Actual, "md5:") { // offline mode compares MD5 at verification time
		return false
	}
	p := j.pkgs[v.Package]
	return p != nil && (v.Version == "" || v.Version == p.Version)
}

// File change categories, which decide severity and wording.
const (
	catNote = iota
	catPersist
	catSecurity
	catGenerated
	catLink
	catLoosened
	catAccount
	catHandedOff
)

// handedOff reports whether a root-owned directory now belongs to another
// account, which can then add or replace what is inside it.
func handedOff(old, cur *model.FileEntry) bool {
	return old != nil && cur != nil && old.Type == "dir" && cur.Type == "dir" && old.UID == 0 && cur.UID != 0
}

// accountNote says why a content-only change of an account database is a
// note, or "": passwd or shadow content in which the account comparison
// found no change to ids, shells, homes or passwords (ageing, comments, a
// line it skips; duplicate names are their own finding); gshadow content
// that the group comparison shows group by group, giving no group a
// password and no privileged group a member or administrator.
func (j *judge) accountNote(p string, old, cur *model.FileEntry) string {
	if old == nil || cur == nil || !sameMeta(old, cur) {
		return ""
	}
	switch {
	case (p == "/etc/passwd" || p == "/etc/shadow") && !j.acctChanged[p] && !j.acctDirty[p]:
		return "The account comparison found no change to user ids, groups, shells, home directories or passwords in this file, so this is most likely an ageing (chage) or comment (GECOS) change. Duplicate account names are reported on their own."
	case p == "/etc/gshadow" && j.acctChanged[p] && !j.gshadowRisk && !j.acctDirty[p] && !j.acctDirty["/etc/group"]:
		return "The group comparison shows each change in this file (shown above as group changes); none gives a group a password or a privileged group a new member or administrator."
	}
	return ""
}

// newlyWritable reports whether a directory became writable by its group or
// by everyone: write bits added, or a new world-writable directory without
// the sticky bit.
func newlyWritable(old, cur *model.FileEntry) bool {
	if cur == nil || cur.Type != "dir" {
		return false
	}
	if old == nil || old.Type != "dir" {
		return cur.Mode&0o002 != 0 && cur.Mode&0o1000 == 0
	}
	return (cur.Mode&^old.Mode)&0o022 != 0
}

// systemDirs are where a system program's link may point.
var systemDirs = []string{"/usr", "/lib", "/lib32", "/lib64", "/libx32", "/bin", "/sbin", "/etc", "/boot", "/run/systemd"}

// badLink says why a symbolic link now points somewhere it should not, or
// "": into a temporary or hidden place (whenever it changed), or, when it
// was pointed somewhere new, out of the system directories.
func badLink(p string, old, cur *model.FileEntry) string {
	if cur == nil || cur.Type != "symlink" {
		return ""
	}
	t := linkTarget(p, cur.Target)
	for _, d := range []string{"/tmp", "/dev/shm", "/var/tmp"} {
		if t == d || strings.HasPrefix(t, d+"/") {
			return "it points into " + d
		}
	}
	for _, comp := range strings.Split(t, "/") {
		if strings.HasPrefix(comp, ".") {
			return "it points into a hidden directory"
		}
	}
	if old != nil && (old.Type != "symlink" || old.Target != cur.Target) &&
		!slices.ContainsFunc(systemDirs, func(d string) bool { return t == d || strings.HasPrefix(t, d+"/") }) {
		return "it was pointed outside the system directories"
	}
	return ""
}

func (j *judge) fileChange(ch diff.Change) {
	p := ch.Subject
	cur, old := j.files[p], j.oldFiles[p]
	e := cur
	if e == nil {
		e = old
	}
	if e == nil {
		return
	}
	if cur != nil && old != nil && sameMeta(old, cur) {
		// A directory whose only change is its size: entries came or went,
		// and those are listed themselves.
		if cur.Type == "dir" {
			return
		}
		// An account database whose change the account comparison shows,
		// without password data.
		if accountDBs[p] && j.acctChanged[p] && !j.acctDirty[p] {
			return
		}
	}
	if volatileRootFile(p, e) && ch.Kind != diff.FileRemoved {
		return
	}
	ev := model.Evidence{Path: p, Before: fullHash(ch.Before, old), After: fullHash(ch.After, cur), Detail: changeWord(ch.Kind), When: j.changeWhen(cur)}
	owner := j.owned[p]
	if owner == "" {
		owner = j.oldOwned[p]
	}

	// A persistence file: its persistence change carries it.
	if f, ok := j.persistDone[p]; ok {
		if f != nil {
			j.attach(f, ev, maxEvidence)
		}
		return
	}
	// A package verification finding is about this file already.
	if f := j.pkgPath[p]; f != nil {
		ev.Detail += " since the snapshot"
		j.attach(f, ev, maxEvidence)
		if j.pkgChanged(owner) {
			if strings.HasPrefix(f.Key, "pkg.unverifiable:") {
				j.unverifiedProgram(owner, p, ev)
			} else {
				j.unconfirmed[owner] = true
			}
		}
		return
	}

	linkWhy := badLink(p, old, cur)
	accountWhy := j.accountNote(p, old, cur)
	cat := catNote
	switch {
	case linkWhy != "":
		cat = catLink
	case newlyWritable(old, cur):
		cat = catLoosened
	case handedOff(old, cur):
		cat = catHandedOff
	case accountWhy != "":
		cat = catAccount
	case j.placed(ch, e, old, cur, owner, ev):
		return
	case generatedFile(p):
		cat = catGenerated
	case j.isPersistLocation(p):
		cat = catPersist
	case e.Type == "file" && pkgverify.InScope(p, e.Mode):
		cat = catSecurity
	}
	if e.Type == "file" && j.pkgChanged(owner) {
		j.unconfirmed[owner] = true
	}

	sev := model.SevBackdoor
	why := ""
	var refs []string
	fix := j.fileFix(ch, old, cur, owner)
	switch cat {
	case catNote:
		sev = model.SevNote
		why = "No package update explains this change. It is probably routine (a locally installed program, a generated file, an edited setting) but it is listed so that nothing is hidden."
	case catAccount:
		sev = model.SevNote
		why = accountWhy
		refs = []string{"T1098"}
	case catPersist:
		why = "This is a place attackers use to get back in or to run code again, and no package update explains the change."
		if w := accountFileWhy[p]; w != "" {
			why = w + " It changed since the snapshot in a way the account comparison does not explain."
		}
		refs = []string{"T1546"}
	case catSecurity:
		why = "Programs, libraries, PAM modules, kernel modules and boot files run with the machine's full trust. A change that no package update explains is what a backdoored system file looks like."
		refs = []string{"T1554"}
	case catGenerated:
		why = "This boot file or module index is rebuilt only when the packages that build it change (a kernel, GRUB, initramfs-tools or a package with initramfs hooks), and none of them changed since the snapshot. " +
			"Boot-time backdoors hide in the initramfs, the boot loader and its modules."
		refs = []string{"T1542"}
		if cur != nil {
			fix = fixKeepOnly(p, "then rebuild it from the installed packages: update-initramfs -u -k all for an initramfs, update-grub for the boot menu, grub-install for GRUB's modules, depmod -a for module indexes (check /etc/initramfs-tools and /etc/grub.d first)")
		}
	case catLink:
		why = fmt.Sprintf("This link now points to %s: %s. A program or file replaced by a link runs or reads whatever sits at the other end, so it no longer matters what the package installed here.",
			linkTarget(p, cur.Target), linkWhy)
		refs = []string{"T1574"}
	case catHandedOff:
		why = fmt.Sprintf("This system directory now belongs to user id %d instead of root, so that account can add or replace the programs and settings inside it.", cur.UID)
		refs = []string{"T1222.002"}
	case catLoosened:
		why = fmt.Sprintf("This directory is now writable by its group or by everyone (mode %04o), so they can add or replace the programs and settings inside it.", cur.Mode&0o7777)
		refs = []string{"T1222.002"}
		if old == nil {
			fix = command([]string{p}, func(q []string) string { return "chmod go-w " + q[0] + "   # unless it must be shared on purpose" })
		}
	}
	j.add(&model.Finding{
		Key: "snap." + ch.Kind + ":" + p, ID: "TT-SNAP-001", Source: srcSnapshot, Severity: sev,
		Title: fileTitle(ch.Kind, e.Type, p), Why: why,
		Fix:      fix,
		Evidence: []model.Evidence{ev},
		Refs:     refs,
	})
}

// placed shows a file change as part of what explains it, and reports
// whether it did: the signed package installed now, the package change that
// rebuilt or listed it, or a conffile default.
func (j *judge) placed(ch diff.Change, e, old, cur *model.FileEntry, owner string, ev model.Evidence) bool {
	p := ch.Subject
	// It matches the package installed now. The machine's own checksums
	// count only after a package change: a different file at the same
	// version cannot have come from an update.
	if v, ok := j.verified[p]; ok && j.verifiedNow(v, cur) && (v.Source != pkgverify.SourceOfflineLocal || j.pkgChanged(v.Package)) {
		ev.Detail = "matches " + strings.TrimSpace(v.Package+" "+v.Version) + " from " + sourceWords(v.Source)
		j.foldIntoPackage(v.Package, ev, model.SevExplained)
		return true
	}
	if generatedFile(p) {
		name := j.rebuiltBy(p)
		if name == "" {
			return false
		}
		ev.Detail += "; rebuilt by " + name
		j.foldIntoPackage(name, ev, model.SevNote)
		return true
	}
	switch {
	case e.Type == "dir" && j.pkgChanged(owner) && (old == nil || cur == nil || sameMeta(old, cur)):
		j.foldIntoPackage(owner, ev, model.SevNote)
		return true
	case e.Type == "symlink" && j.pkgChanged(owner):
		j.foldIntoPackage(owner, ev, model.SevNote)
		return true
	case ch.Kind == diff.FileRemoved && j.owned[p] == "" && j.pkgChanged(j.oldOwned[p]):
		ev.Detail = "removed with the package change"
		j.foldIntoPackage(j.oldOwned[p], ev, model.SevNote)
		return true
	case j.pkgChanged(dpkgInfoPackage(p)):
		ev.Detail = "dpkg's record of the package"
		j.foldIntoPackage(dpkgInfoPackage(p), ev, model.SevNote)
		return true
	case (j.unverified[p] || j.uncheckedSpecial[p]) && j.pkgChanged(owner) && j.classify(j.unverKind[p]) != classScanLimit:
		// A version no trusted source confirmed explains none of its
		// files: every one goes on the package's change, which it makes
		// a backdoor sign. When a source could not be used, programs go
		// into the note on unchecked files and the rest is counted in
		// the grouped note.
		if j.classify(j.unverKind[p]) == classNotFound || (e.Type == "file" && pkgverify.InScope(p, e.Mode)) {
			j.unverifiedProgram(owner, p, ev)
		}
		return true
	}
	// A conffile the package change replaced with the new default: package
	// verification checked it and said nothing.
	if name := conffileOwner(j.c.Packages.Installed, p); cur != nil && name != "" && j.unreported(p) {
		switch j.pkgChange[name].Kind {
		case diff.PkgUpgraded:
			ev.Detail += "; the package's default configuration"
			j.explain(name, ev)
			return true
		case diff.PkgInstalled:
			ev.Detail += "; the package's default configuration"
			j.foldIntoPackage(name, ev, model.SevExplained)
			return true
		}
	}
	return false
}

// unverifiedProgram records a changed program of a changed package that no
// trusted source confirmed: found in none (a backdoor sign for the package)
// or not checked at all because a source could not be used (one note for
// every such package).
func (j *judge) unverifiedProgram(pkg, p string, ev model.Evidence) {
	r := j.unverReason[p]
	j.touch(pkg, p)
	if j.classify(j.unverKind[p]) == classNotFound {
		ev.Detail = "changed; no trusted source confirmed this version: " + r
		j.unverIn[pkg] = append(j.unverIn[pkg], ev)
		return
	}
	ev.Detail = "changed; could not be checked"
	if r != "" {
		ev.Detail += ": " + r
	}
	j.unchecked[pkg] = append(j.unchecked[pkg], ev)
}

// Classes of unverifiable verdict, by what the judge does with them.
type verdictClass int

const (
	// classNotFound: no trusted source confirmed the version, or the kind
	// comes from data root can write (a version string, an architecture,
	// a package count, a file size). Treated as a version no trusted source
	// has: a backdoor sign.
	classNotFound verdictClass = iota
	// classUnchecked: a package source could not be read or used (the
	// network, a signature, the reference bundle). One note for all.
	classUnchecked
	// classScanLimit: package verification could not run for this scan at
	// all; files are judged as if it had not run.
	classScanLimit
)

// classify sorts an unverifiable verdict by its pkgverify kind. Only the
// network kinds count as "could not check"; Ubuntu Pro does too, but only
// on an Ubuntu host with an ESM source configured. A verdict without a kind
// is read cautiously, as not found.
func (j *judge) classify(kind string) verdictClass {
	switch kind {
	case pkgverify.KindUnreachable, pkgverify.KindBadSignature, pkgverify.KindNotInBundle:
		return classUnchecked
	case pkgverify.KindPro:
		if j.esmHost() {
			return classUnchecked
		}
	case pkgverify.KindScanLimit:
		return classScanLimit
	}
	return classNotFound
}

// esmHost reports whether the machine is Ubuntu with an ESM source, the
// only place Pro package versions are expected.
func (j *judge) esmHost() bool {
	if j.c.Host.OSID != "ubuntu" {
		return false
	}
	for _, s := range j.c.Packages.Sources {
		for _, u := range s.URIs {
			if strings.Contains(u, "esm.ubuntu.com") {
				return true
			}
		}
	}
	return false
}

// fullHash puts the entry's whole hash in place of the shortened one diff
// shows. An exception accepts this text, so a later file only needs to
// share a hash prefix to slip past it otherwise.
func fullHash(s string, e *model.FileEntry) string {
	if e == nil || len(e.SHA256) <= 12 {
		return s
	}
	return strings.Replace(s, e.SHA256[:12]+"…", e.SHA256, 1)
}

// changeWhen dates a file change by the file as it is now.
func (j *judge) changeWhen(cur *model.FileEntry) *time.Time {
	if cur == nil {
		return nil
	}
	return j.whenFor(cur.Path)
}

func changeWord(kind string) string {
	switch kind {
	case diff.FileAdded:
		return "added"
	case diff.FileRemoved:
		return "removed"
	}
	return "changed"
}

func fileTitle(kind, typ, p string) string {
	switch kind {
	case diff.FileAdded:
		what := "file"
		switch typ {
		case "dir":
			what = "directory"
		case "symlink":
			what = "symbolic link"
		}
		return "New " + what + " since the snapshot: " + p
	case diff.FileRemoved:
		return p + " was removed since the snapshot"
	}
	return p + " changed since the snapshot"
}

func (j *judge) fileFix(ch diff.Change, old, cur *model.FileEntry, owner string) string {
	p := ch.Subject
	if old != nil && cur != nil && metaOnly(old, cur) && (old.Mode&0o7777 != cur.Mode&0o7777 || old.UID != cur.UID || old.GID != cur.GID) {
		return fixRestoreMeta(p, old.Mode, old.Mode&0o7777 != cur.Mode&0o7777, old.UID, int64(old.GID), old.UID != cur.UID || old.GID != cur.GID)
	}
	if owner != "" && j.pkgs[owner] != nil {
		return fixReinstall(p, owner, cur != nil)
	}
	switch {
	case ch.Kind == diff.FileAdded && cur != nil:
		return fixRemove(p, cur.Type == "dir")
	case cur != nil:
		return fixKeepOnly(p, "then restore it from a backup; telltale keeps no copy of file contents")
	}
	return "Restore the file from a backup if you did not remove it."
}

// --- persistence locations ---

type persistKind struct {
	label, why string
	refs       []string
}

var persistKinds = map[string]persistKind{
	model.PersistKindSudoers:        {"sudo rules", "sudo rules decide who can become root; one added line can give an account root without a password.", []string{"T1548.003"}},
	model.PersistKindSSHD:           {"SSH server configuration", "The SSH server configuration decides who may log in and how; attackers turn root or password login back on, or add a Match block for themselves.", []string{"T1098.004", "T1021.004"}},
	model.PersistKindSSHClient:      {"SSH client configuration", "SSH client settings can run commands (ProxyCommand, LocalCommand) whenever someone connects out from this machine.", []string{"T1546"}},
	model.PersistKindAuthorizedKeys: {"SSH authorized keys", "Each key listed here lets its holder log in as this account without a password.", []string{"T1098.004"}},
	model.PersistKindCron:           {"scheduled job", "cron runs these commands on a schedule, often as root; a planted line is a classic way back in.", []string{"T1053.003"}},
	model.PersistKindAt:             {"at job", "at runs this job once at a set time, as the account that queued it.", []string{"T1053.002"}},
	model.PersistKindSystemdUnit:    {"systemd unit", "systemd starts these services at boot or on a timer, as root unless told otherwise.", []string{"T1543.002"}},
	model.PersistKindSystemdEnabled: {"systemd enable link", "These links decide which services start at boot.", []string{"T1543.002"}},
	model.PersistKindRC:             {"start-up script", "Start-up scripts run as root at boot.", []string{"T1037.004"}},
	model.PersistKindProfile:        {"shell start-up file", "Every login shell runs these lines; they can start a program or set PATH or LD_PRELOAD for everyone.", []string{"T1546.004"}},
	model.PersistKindShellRC:        {"shell start-up file", "This account's shell runs these lines at every login.", []string{"T1546.004"}},
	model.PersistKindLDPreload:      {"preload list", "Libraries listed here load into every program; rootkits use it to hide files, processes and connections.", []string{"T1574.006"}},
	model.PersistKindLDConf:         {"library search path", "These files decide where programs find shared libraries; a directory added here can substitute a library.", []string{"T1574.006"}},
	model.PersistKindPAM:            {"PAM configuration", "PAM decides how logins are checked; one changed line can accept any password or record every password typed.", []string{"T1556.003"}},
	model.PersistKindHosts:          {"hosts file", "The hosts file overrides DNS; it can send update or login traffic to a machine an attacker controls.", nil},
	model.PersistKindResolver:       {"name resolution settings", "These settings decide which DNS servers answer and in what order; an attacker's resolver can redirect any name.", nil},
	model.PersistKindModulesLoad:    {"boot-time kernel module list", "Kernel modules named here load at every boot.", []string{"T1547.006"}},
	model.PersistKindModprobe:       {"kernel module options", "modprobe settings can run a command (an install line) whenever a module loads.", []string{"T1547.006"}},
}

func kindInfo(kind string) persistKind {
	if k, ok := persistKinds[kind]; ok {
		return k
	}
	return persistKind{label: "persistence file", why: "Files here decide what runs on the machine or who can get in."}
}

// describePersist is the value of a persistence file for the change
// evidence: its full hash, plus mode and owner when those changed. The full
// hash is what an exception accepts, so any later edit shows again.
func describePersist(pf *model.PersistFile, withMeta bool) string {
	if pf == nil {
		return "absent"
	}
	if withMeta {
		return fmt.Sprintf("sha256 %s mode %04o owner %d", pf.SHA256, pf.Mode&0o7777, pf.UID)
	}
	return pf.SHA256
}

// conffileOwner is the installed package that lists p as a conffile.
func conffileOwner(pkgs []model.Package, p string) string {
	alias := usrAlias(p)
	for _, pk := range pkgs {
		if _, ok := pk.Conffiles[p]; ok {
			return pk.Name
		}
		if _, ok := pk.Conffiles[alias]; ok && alias != "" {
			return pk.Name
		}
	}
	return ""
}

// unreported reports whether package verification ran and said nothing
// about p. With a snapshot, the scan asks it to check exactly the changed
// package-owned files, and it is silent only about a conffile that equals
// its package's default.
func (j *judge) unreported(p string) bool {
	if j.in.Pkg == nil || j.reported[p] {
		return false
	}
	a := usrAlias(p)
	return a == "" || !j.reported[a]
}

// persistExplained names the package that explains a changed persistence
// file: its content matches the signed package installed now, or it is a
// conffile that an upgrade replaced with the new default.
func (j *judge) persistExplained(p string, cur *model.PersistFile) string {
	if cur == nil {
		return ""
	}
	if v, ok := j.verified[p]; ok && j.verifiedNow(v, j.files[p]) && (v.Source != pkgverify.SourceOfflineLocal || j.pkgChanged(v.Package)) {
		return v.Package
	}
	if name := conffileOwner(j.c.Packages.Installed, p); name != "" && j.pkgChange[name].Kind == diff.PkgUpgraded && j.unreported(p) {
		return name
	}
	return ""
}

// persistOfPackageChange names the newly installed or removed package that
// a new or vanished persistence file belongs to: a new package's enable link
// or default conffile, or a file that left with its package. sev is what
// the change would rank as on its own.
func (j *judge) persistOfPackageChange(p string, cur, old *model.PersistFile) (string, model.Severity) {
	switch {
	case old == nil && cur != nil:
		if cur.Kind == model.PersistKindSystemdEnabled && len(cur.Lines) > 0 {
			if name := j.owned[linkTarget(p, cur.Lines[0])]; name != "" && j.pkgChange[name].Kind == diff.PkgInstalled {
				return name, model.SevBackdoor // it also raises the package
			}
		}
		if name := conffileOwner(j.c.Packages.Installed, p); name != "" && j.pkgChange[name].Kind == diff.PkgInstalled && j.unreported(p) {
			return name, model.SevExplained
		}
	case cur == nil && old != nil:
		name := j.oldOwned[p]
		if name == "" {
			name = conffileOwner(j.old.Packages.Installed, p)
		}
		if k := j.pkgChange[name].Kind; name != "" && j.owned[p] == "" && (k == diff.PkgRemoved || k == diff.PkgUpgraded) {
			return name, model.SevNote
		}
	}
	return "", 0
}

// linkView reads a persistence file that is a symbolic link: Lines[0] is
// the link's target and the rest is the target's content, so content line
// n is diff line n+1, and edits go to the target (sed -i on the link would
// replace it with a plain file).
type linkView struct {
	link   bool
	target string // the resolved target; "" when unknown
}

func linkViewOf(p string, cur, old *model.PersistFile) linkView {
	isLink := func(pf *model.PersistFile) bool { return pf != nil && pf.Mode&0o170000 == 0o120000 }
	v := linkView{link: isLink(cur) || (cur == nil && isLink(old))}
	if v.link && cur != nil && len(cur.Lines) > 0 && !strings.HasPrefix(cur.Lines[0], "<redacted") {
		v.target = linkTarget(p, cur.Lines[0])
	}
	return v
}

// isTarget reports whether a line change is the link's target changing.
func (v linkView) isTarget(lc diff.LineChange) bool { return v.link && lc.Line == 1 }

// line is the content line number of a diff line.
func (v linkView) line(n int) int {
	if v.link {
		return n - 1
	}
	return n
}

// deleteLines removes content lines, from the target of a link.
func (v linkView) deleteLines(p string, lines []int, note string) string {
	if v.link {
		return fixDeleteLinesIn(p, v.target, lines, note)
	}
	return fixDeleteLines(p, lines, note)
}

func (j *judge) persistChange(ch diff.Change) {
	p := ch.Subject
	cur, old := j.persist[p], j.oldPersist[p]
	kind := ""
	switch {
	case cur != nil:
		kind = cur.Kind
	case old != nil:
		kind = old.Kind
	}
	meta := cur != nil && old != nil && (cur.Mode&0o7777 != old.Mode&0o7777 || cur.UID != old.UID)
	lv := linkViewOf(p, cur, old)
	summary := func(lines []diff.LineChange) model.Evidence {
		adds, dels := 0, 0
		first := 0
		retarget := false
		for _, lc := range lines {
			if lv.isTarget(lc) {
				retarget = true
				continue
			}
			if first == 0 {
				first = lv.line(lc.Line)
			}
			if lc.Op == "add" {
				adds++
			} else {
				dels++
			}
		}
		var parts []string
		switch {
		case old == nil:
			parts = append(parts, "new file")
		case cur == nil:
			parts = append(parts, "file removed")
		case retarget:
			parts = append(parts, "link target changed")
		}
		if adds > 0 {
			parts = append(parts, fmt.Sprintf("%d %s added", adds, plural(adds, "line", "lines")))
		}
		if dels > 0 {
			parts = append(parts, fmt.Sprintf("%d %s removed", dels, plural(dels, "line", "lines")))
		}
		if meta {
			parts = append(parts, "mode or owner changed")
		}
		return model.Evidence{Path: p, Line: first, Before: describePersist(old, meta), After: describePersist(cur, meta),
			Detail: strings.Join(parts, ", "), When: j.whenFor(p)}
	}

	if !meta {
		if name := j.persistExplained(p, cur); name != "" {
			ev := summary(ch.Lines)
			ev.Detail = strings.TrimPrefix(ev.Detail+"; the package's own version", "; ")
			j.explain(name, ev)
			j.persistDone[p] = nil
			return
		}
		if name, sev := j.persistOfPackageChange(p, cur, old); name != "" {
			j.foldIntoPackage(name, summary(ch.Lines), sev)
			j.persistDone[p] = j.pkgFinding[name]
			return
		}
	}

	lines := ch.Lines
	if kind == model.PersistKindAuthorizedKeys && j.rootKeyFile(p) {
		lines = j.newRootKeys(p, ch, old, lv)
		if len(lines) == 0 && !meta {
			if _, ok := j.persistDone[p]; !ok {
				j.persistDone[p] = nil // only the telltale server's key, blank lines or comments
			}
			return
		}
	}
	info := kindInfo(kind)
	var title string
	switch {
	case old == nil:
		title = fmt.Sprintf("New %s since the snapshot: %s", info.label, p)
	case cur == nil:
		title = fmt.Sprintf("%s removed since the snapshot: %s", capitalize(info.label), p)
	default:
		title = fmt.Sprintf("%s changed since the snapshot: %s", capitalize(info.label), p)
	}
	f := j.add(&model.Finding{
		Key: "snap.persist:" + p, ID: "TT-SNAP-002", Source: srcSnapshot, Severity: model.SevBackdoor,
		Title: title,
		Why:   info.why + " It changed since the machine was known to be clean, and no package update explains it.",
		Fix:   persistFix(p, cur, old, lines, meta, lv),
		Refs:  info.refs,
		// The summary first: its After is the file's full hash.
		Evidence: []model.Evidence{summary(lines)},
	})
	for _, lc := range lines {
		e := model.Evidence{Path: p, Line: lv.line(lc.Line), Before: lc.Old, After: lc.New, Detail: "line added"}
		switch {
		case lv.isTarget(lc):
			e.Line, e.Detail = 0, "link target"
		case lc.Op != "add":
			e.Detail = "line removed"
		}
		j.attach(f, e, maxEvidence)
	}
	j.persistDone[p] = f
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func persistFix(p string, cur, old *model.PersistFile, lines []diff.LineChange, meta bool, lv linkView) string {
	switch {
	case cur == nil:
		return "Restore the file from a backup if you did not remove it (the snapshot's lines are shown above)."
	case old == nil:
		return command([]string{p}, func(q []string) string {
			return keep(q[0]) + " && rm -- " + q[0] + "   # only if you did not create it; after removing a systemd unit run systemctl daemon-reload"
		})
	case meta && len(lines) == 0:
		return fixRestoreMeta(p, old.Mode, old.Mode&0o7777 != cur.Mode&0o7777, old.UID, -1, old.UID != cur.UID)
	}
	var added []int
	for _, lc := range lines {
		if lc.Op != "add" || lv.isTarget(lc) {
			added = nil
			break
		}
		added = append(added, lv.line(lc.Line))
	}
	if !meta && len(added) > 0 {
		return lv.deleteLines(p, added, "removes the added lines shown above")
	}
	return fixKeepOnly(p, "then edit it back to the snapshot's lines shown above")
}

// --- SSH keys for root ---

// rootKeyFile reports whether p is an authorized_keys file in the home of an
// account with user id 0.
func (j *judge) rootKeyFile(p string) bool {
	homes := []string{"/root"}
	for _, u := range j.c.Accounts.Users {
		if u.UID == 0 && u.Home != "" && u.Home != "/" && !strings.HasPrefix(u.Name, "+") && !strings.HasPrefix(u.Name, "-") {
			homes = append(homes, strings.TrimSuffix(u.Home, "/"))
		}
	}
	return slices.ContainsFunc(homes, func(h string) bool { return strings.HasPrefix(p, h+"/") })
}

// newRootKeys reports each key added for root (other than the telltale
// server's) as its own backdoor sign and returns the line changes left
// over: removed keys, edited key lines and anything that is not a key.
func (j *judge) newRootKeys(p string, ch diff.Change, old *model.PersistFile, lv linkView) []diff.LineChange {
	server, _ := keyBlob(j.ctx.ServerKeyLine)
	had := map[string]bool{}
	if old != nil {
		for _, l := range old.Lines {
			if b, _ := keyBlob(strings.TrimSpace(l)); b != "" {
				had[b] = true
			}
		}
	}
	var rest []diff.LineChange
	for _, lc := range ch.Lines {
		if lv.isTarget(lc) {
			rest = append(rest, lc) // the link now points at another file
			continue
		}
		text := lc.New
		if lc.Op != "add" {
			text = lc.Old
		}
		s := strings.TrimSpace(text)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		blob, _ := keyBlob(s)
		if server != "" && blob == server {
			continue // the telltale server's own key: expected on every visit
		}
		if lc.Op == "add" && blob != "" && !had[blob] {
			n := lv.line(lc.Line)
			j.persistDone[p] = j.add(&model.Finding{
				Key: fmt.Sprintf("snap.root_key:%s:%d", p, n), ID: "TT-SNAP-003", Source: srcSnapshot, Severity: model.SevBackdoor,
				Title: fmt.Sprintf("New SSH key for root, not in the snapshot: %s line %d", p, n),
				Why: "Whoever holds the matching private key can now log in as root without a password. Planting a key is the most common way attackers keep root access. " +
					"It is not the telltale server's key.",
				Fix:      lv.deleteLines(p, []int{n}, "only if you do not recognise the key; if you remove several lines from this file, start with the highest line number"),
				Evidence: []model.Evidence{{Path: p, Line: n, After: s, Detail: "key added since the snapshot", When: j.whenFor(p)}},
				Refs:     []string{"T1098.004"},
			})
			continue
		}
		rest = append(rest, lc)
	}
	return rest
}

// splitFields splits an authorized_keys line on unquoted blanks; inside
// double quotes a backslash escapes a quote, as in sshd's option parser.
func splitFields(line string) []string {
	var toks []string
	var cur strings.Builder
	inQ := false
	for i := 0; i < len(line); i++ {
		ch := line[i]
		switch {
		case inQ && ch == '\\' && i+1 < len(line) && line[i+1] == '"':
			cur.WriteString(`\"`)
			i++
		case ch == '"':
			inQ = !inQ
			cur.WriteByte(ch)
		case (ch == ' ' || ch == '\t') && !inQ:
			if cur.Len() > 0 {
				toks = append(toks, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(ch)
		}
	}
	if cur.Len() > 0 {
		toks = append(toks, cur.String())
	}
	return toks
}

// keyBlob returns "type base64" of the public key in an authorized_keys
// line, and the options before it.
func keyBlob(line string) (blob, opts string) {
	toks := splitFields(line)
	for i, t := range toks {
		if (strings.HasPrefix(t, "ssh-") || strings.HasPrefix(t, "ecdsa-") || strings.HasPrefix(t, "sk-")) && i+1 < len(toks) {
			return t + " " + toks[i+1], strings.Join(toks[:i], " ")
		}
	}
	return "", strings.Join(toks, " ")
}

// --- accounts ---

func findUser(c *model.Collection, name string) *model.User {
	for i := range c.Accounts.Users {
		if c.Accounts.Users[i].Name == name {
			return &c.Accounts.Users[i]
		}
	}
	return nil
}

func findGroup(c *model.Collection, name string) *model.Group {
	for i := range c.Accounts.Groups {
		if c.Accounts.Groups[i].Name == name {
			return &c.Accounts.Groups[i]
		}
	}
	return nil
}

func (j *judge) userAdded(ch diff.Change) {
	name := ch.Subject
	u := findUser(j.c, name)
	uid0 := u != nil && u.UID == 0
	f := &model.Finding{
		Key: "snap.user_added:" + name, ID: "TT-SNAP-004", Source: srcSnapshot, Severity: model.SevNote,
		Title:    fmt.Sprintf("New account %q since the snapshot", name),
		Why:      "An account added since the machine was known to be clean. Check that you, or a package you installed, created it.",
		Fix:      fixUserAdded(name, false),
		Evidence: []model.Evidence{{Path: "/etc/passwd", After: ch.After, Detail: "added since the snapshot", When: j.whenFor("/etc/passwd")}},
		Refs:     []string{"T1136.001"},
	}
	if uid0 {
		f.Severity = model.SevBackdoor
		f.Title = fmt.Sprintf("New account %q with user id 0 (root powers), not in the snapshot", name)
		f.Why = "Only root should have user id 0. A new account with id 0 is a second root login under another name, a classic hidden way back in."
		f.Fix = fixUserAdded(name, true)
	}
	j.add(f)
}

func (j *judge) userChanged(ch diff.Change) {
	name := ch.Subject
	old, cur := findUser(j.old, name), findUser(j.c, name)
	file := "/etc/passwd"
	if old != nil && cur != nil && old.UID == cur.UID && old.GID == cur.GID && old.Shell == cur.Shell && old.Home == cur.Home {
		file = "/etc/shadow"
	}
	f := &model.Finding{
		Key: "snap.user_changed:" + name, ID: "TT-SNAP-004", Source: srcSnapshot, Severity: model.SevNote,
		Title:    fmt.Sprintf("Account %q changed since the snapshot", name),
		Why:      "An account's settings changed since the machine was known to be clean (shown without any password data). Check that the change was yours.",
		Fix:      fixUserChanged(name, old, cur),
		Evidence: []model.Evidence{{Path: file, Before: ch.Before, After: ch.After, Detail: "changed since the snapshot", When: j.whenFor(file)}},
		Refs:     []string{"T1098"},
	}
	if cur != nil && cur.UID == 0 && (old == nil || old.UID != 0) {
		f.Severity = model.SevBackdoor
		f.Title = fmt.Sprintf("Account %q was given user id 0 (root powers) since the snapshot", name)
		f.Why = "Only root should have user id 0. Giving an existing account id 0 makes it a second root login under another name, a classic hidden way back in."
	}
	j.add(f)
}

// privilegedGroups make their members root, or let them read logs,
// secrets or raw devices, or write /usr/local (staff), without any
// password changing.
var privilegedGroups = map[string]bool{"root": true, "sudo": true, "wheel": true, "admin": true, "adm": true, "shadow": true,
	"disk": true, "docker": true, "lxd": true, "libvirt": true, "staff": true}

func (j *judge) groupChanged(ch diff.Change) {
	name := ch.Subject
	o, n := findGroup(j.old, name), findGroup(j.c, name)
	password, added, admins := groupGains(o, n)
	f := &model.Finding{
		Key: "snap.group:" + name, ID: "TT-SNAP-005", Source: srcSnapshot, Severity: model.SevNote,
		Title:    fmt.Sprintf("Group %q changed since the snapshot", name),
		Why:      "Group membership decides who can read logs, use devices or run privileged tools; listed so that every account change is accounted for.",
		Evidence: []model.Evidence{{Path: "/etc/group", Before: ch.Before, After: ch.After, Detail: "changed since the snapshot", When: j.whenFor("/etc/group")}},
		Refs:     []string{"T1098"},
	}
	if len(added) > 0 || password || admins {
		f.Fix = fixGroupChange(name, added, password, admins)
	}
	switch {
	case password:
		f.Severity = model.SevBackdoor
		f.Title = fmt.Sprintf("Group %q was given a password since the snapshot", name)
		f.Why = "Anyone who knows a group's password can join it with newgrp, without being a member. Group passwords are almost never used, so a new one is a quiet way back into the group's rights."
	case (j.privileged(o) || j.privileged(n)) && admins:
		f.Severity = model.SevBackdoor
		f.Title = fmt.Sprintf("The %q group has a new administrator since the snapshot", name)
		f.Why = "A group administrator can add anyone to the group. For this group that means root, or access to secrets or raw disks, without any password changing."
	case (j.privileged(o) || j.privileged(n)) && len(added) > 0:
		f.Severity = model.SevBackdoor
		f.Title = fmt.Sprintf("%s added to the %q group since the snapshot", strings.Join(added, ", "), name)
		f.Why = "Members of this group can become root, or read logs, secrets or raw disks, without any password changing. Adding an account to it is a quiet way to keep root access."
	}
	j.add(f)
}

// --- running state ---

func (j *judge) moduleAdded(ch diff.Change) {
	name, file := ch.Subject, ch.After
	owner := ""
	if file != "" {
		owner = j.owned[file]
	}
	f := &model.Finding{
		Key: "snap.module:" + name, ID: "TT-SNAP-010", Source: srcSnapshot, Severity: model.SevBackdoor,
		Title: fmt.Sprintf("Kernel module %q was loaded since the snapshot and comes from no package", name),
		Why:   "Kernel modules run with full control of the machine, and a module no package installed is how kernel rootkits load. It may also be a driver you built yourself.",
		Fix:   fixModule(name, file),
		Refs:  []string{"T1547.006"},
	}
	detail := "loaded since the snapshot; no module file found under /lib/modules"
	if file != "" {
		detail = "loaded since the snapshot; the file belongs to no package"
	}
	if owner != "" {
		f.Severity = model.SevNote
		f.Title = fmt.Sprintf("Kernel module %q (package %s) was loaded since the snapshot", name, owner)
		f.Why = "A module from an installed package was loaded since the snapshot. That is usually routine (new hardware, a service that needs it); listed so that every change is accounted for."
		detail = "loaded since the snapshot; from package " + owner
	}
	// The value an exception accepts names the file and its owner, so the
	// same module name loaded from another file is a finding again.
	from := "no module file found under /lib/modules"
	if file != "" {
		from = file + " (no package)"
		if owner != "" {
			from = file + " (package " + owner + ")"
		}
	}
	f.Evidence = []model.Evidence{{Path: file, After: name + " from " + from, Detail: detail}}
	j.add(f)
}

// listenKey is the change subject diff gives a listener, e.g.
// "tcp6 [::]:22".
func listenKey(s model.Socket) string {
	proto := strings.TrimSuffix(s.Proto, "6")
	if strings.HasPrefix(s.Local, "[") || strings.HasSuffix(s.Proto, "6") {
		proto += "6"
	}
	return proto + " " + s.Local
}

// suspiciousExe says why a program's location is suspicious, or "".
func suspiciousExe(exe string, proc *model.Process) string {
	if proc != nil && proc.ExeDeleted {
		return "its program file was deleted after it started"
	}
	for _, d := range []string{"/tmp/", "/dev/shm/", "/var/tmp/"} {
		if strings.HasPrefix(exe, d) {
			return "it runs from " + strings.TrimSuffix(d, "/")
		}
	}
	for _, comp := range strings.Split(exe, "/") {
		if strings.HasPrefix(comp, ".") && comp != "." && comp != ".." {
			return "its path has a hidden directory"
		}
	}
	return ""
}

func (j *judge) listenerAdded(ch diff.Change) {
	exe := ch.After
	pid := 0
	for _, s := range j.c.Runtime.Sockets {
		if s.Listening && listenKey(s) == ch.Subject {
			pid = s.PID
			break
		}
	}
	var proc *model.Process
	for i := range j.c.Runtime.Processes {
		if pid > 0 && j.c.Runtime.Processes[i].PID == pid {
			proc = &j.c.Runtime.Processes[i]
		}
	}
	owner := ""
	if exe != "" {
		owner = j.owned[exe]
	}
	reason := suspiciousExe(exe, proc)
	f := &model.Finding{
		Key: "snap.listener:" + strings.Replace(ch.Subject, " ", ":", 1), ID: "TT-SNAP-011", Source: srcSnapshot, Severity: model.SevNote,
		Fix:  "ss -lntup   # shows which program owns the socket",
		Refs: []string{"T1571"},
	}
	if pid > 0 {
		f.Fix = fixProcess(pid)
	}
	var detail string
	switch {
	case exe == "":
		f.Title = fmt.Sprintf("New listening socket %s since the snapshot", ch.Subject)
		f.Why = "A socket started listening since the snapshot, but telltale could not see which program owns it (a scan without root cannot see other accounts' processes)."
		detail = "owning program not visible"
	case reason != "" || owner == "":
		f.Severity = model.SevBackdoor
		f.Title = fmt.Sprintf("New listening socket %s since the snapshot, served by %s", ch.Subject, exe)
		f.Why = "A program that belongs to no package, or runs from a temporary or hidden place, started listening for connections since the snapshot. That is what a bind shell or backdoor service looks like."
		detail = fmt.Sprintf("pid %d; belongs to no package", pid)
		if owner != "" {
			detail = fmt.Sprintf("pid %d; package %s", pid, owner)
		}
		if reason != "" {
			detail += "; " + reason
		}
	default:
		f.Title = fmt.Sprintf("New listening socket %s since the snapshot (%s)", ch.Subject, exe)
		f.Why = "A service started listening since the snapshot. Its program belongs to package " + owner + "; check that you meant to run it and to expose it."
		detail = fmt.Sprintf("pid %d; package %s", pid, owner)
	}
	// The value an exception accepts names the program, its package and
	// anything suspicious about it, so another program on the same socket
	// is a finding again.
	by := "a program telltale could not see"
	switch {
	case exe != "" && owner != "":
		by = exe + " (package " + owner + ")"
	case exe != "":
		by = exe + " (no package)"
	}
	if reason != "" {
		by += "; " + reason
	}
	f.Evidence = []model.Evidence{{Path: exe, After: ch.Subject + " served by " + by, Detail: detail}}
	j.add(f)
}
