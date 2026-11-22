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

// changes ranks every difference from the snapshot. Package changes and new
// listeners are indexed first, since they decide how file, persistence and
// package-install changes rank.
func (j *judge) changes(chs []diff.Change) {
	for _, ch := range chs {
		switch ch.Kind {
		case diff.PkgUpgraded, diff.PkgDowngraded, diff.PkgInstalled, diff.PkgRemoved:
			if ch.Pkg != nil {
				j.pkgChange[ch.Pkg.Name] = ch
			}
		case diff.ListenerAdded:
			j.listeners = append(j.listeners, ch)
		}
	}
	for _, ch := range chs {
		switch ch.Kind {
		case diff.PkgUpgraded, diff.PkgDowngraded, diff.PkgInstalled, diff.PkgRemoved:
			j.packageChange(ch)
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
)

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
		// Account databases: the account comparison lists each change,
		// without password data. Directories: a size change only means
		// entries came or went, and those are listed themselves.
		if accountFiles[p] || cur.Type == "dir" {
			return
		}
	}
	if volatileRootFile(p) && ch.Kind != diff.FileRemoved {
		return
	}
	ev := model.Evidence{Path: p, Before: ch.Before, After: ch.After, Detail: changeWord(ch.Kind), When: j.changeWhen(cur)}

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
		return
	}
	// It matches the signed package installed now: shown with that
	// package's change, or explained by it.
	if v, ok := j.verified[p]; ok && j.verifiedNow(v, cur) {
		ev.Detail = "matches " + v.Package + " " + v.Version + " from " + sourceWords(v.Source)
		j.foldIntoPackage(v.Package, ev)
		return
	}
	// Rebuilt for a kernel package that came or went.
	if k := j.kernelPackageFor(p); k != "" {
		ev.Detail += "; rebuilt for " + k
		j.foldIntoPackage(k, ev)
		return
	}
	// Part of a package that changed: a directory or link it lists, a file
	// that left with it, or dpkg's own record of it.
	owner := j.owned[p]
	if owner == "" {
		owner = j.oldOwned[p]
	}
	switch {
	case e.Type != "file" && j.pkgChanged(owner):
		j.foldIntoPackage(owner, ev)
		return
	case ch.Kind == diff.FileRemoved && j.owned[p] == "" && j.pkgChanged(j.oldOwned[p]):
		ev.Detail = "removed with the package change"
		j.foldIntoPackage(j.oldOwned[p], ev)
		return
	case j.pkgChanged(dpkgInfoPackage(p)):
		ev.Detail = "dpkg's record of the package"
		j.foldIntoPackage(dpkgInfoPackage(p), ev)
		return
	case j.unverified[p] && j.pkgChanged(owner):
		return // counted in the grouped note on unverifiable files
	}
	// A conffile the package change replaced with the new default:
	// package verification checked it and said nothing.
	if name := conffileOwner(j.c.Packages.Installed, p); cur != nil && name != "" && j.unreported(p) {
		switch j.pkgChange[name].Kind {
		case diff.PkgUpgraded:
			ev.Detail += "; the package's default configuration"
			j.explain(name, ev)
			return
		case diff.PkgInstalled:
			ev.Detail += "; the package's default configuration"
			j.foldIntoPackage(name, ev)
			return
		}
	}

	cat := catNote
	switch {
	case generatedFile(p):
		cat = catGenerated
	case j.isPersistLocation(p):
		cat = catPersist
	case e.Type == "file" && pkgverify.InScope(p, e.Mode):
		cat = catSecurity
	}
	sev := model.SevNote
	why := "No package update explains this change. It is probably routine (a locally installed program, a generated file, an edited setting) but it is listed so that nothing is hidden."
	var refs []string
	switch cat {
	case catPersist:
		sev = model.SevBackdoor
		why = "This is a place attackers use to get back in or to run code again, and no package update explains the change."
		refs = []string{"T1546"}
	case catSecurity:
		sev = model.SevBackdoor
		why = "Programs, libraries, PAM modules, kernel modules and boot files run with the machine's full trust. A change that no package update explains is what a backdoored system file looks like."
		refs = []string{"T1554"}
	case catGenerated:
		if len(j.pkgChange) > 0 {
			why = "update-initramfs, update-grub, grub-install and depmod rebuild this file when packages change, and packages did change since the snapshot, so this is probably routine. " +
				"It belongs to no package and cannot be checked against one; if nothing you updated would rebuild it, investigate."
		} else {
			sev = model.SevBackdoor
			why = "This boot file or module index is rebuilt only when packages change, and no package changed since the snapshot. Boot-time backdoors hide in the initramfs and the boot loader."
		}
		refs = []string{"T1542"}
	}
	fix := j.fileFix(ch, old, cur, owner)
	if cat == catGenerated && cur != nil {
		fix = fixKeepOnly(p, "then rebuild it from the installed packages: update-initramfs -u -k all for an initramfs, update-grub for the boot menu, depmod -a for module indexes (check /etc/initramfs-tools and /etc/grub.d first)")
	}
	j.add(&model.Finding{
		Key: "snap." + ch.Kind + ":" + p, ID: "TT-SNAP-001", Source: srcSnapshot, Severity: sev,
		Title: fileTitle(ch.Kind, e.Type, p), Why: why,
		Fix:      fix,
		Evidence: []model.Evidence{ev},
		Refs:     refs,
	})
}

// kernelPackageFor names the kernel package, changed since the snapshot,
// that a generated initramfs or module index belongs to (by its kernel
// release in the path), or "".
func (j *judge) kernelPackageFor(p string) string {
	release := ""
	if r, ok := strings.CutPrefix(p, "/boot/initrd.img-"); ok {
		release = r
	} else if generatedFile(p) {
		for _, pre := range []string{"/lib/modules/", "/usr/lib/modules/"} {
			if r, ok := strings.CutPrefix(p, pre); ok {
				release, _, _ = strings.Cut(r, "/")
			}
		}
	}
	if release == "" {
		return ""
	}
	for _, name := range []string{"linux-image-" + release, "linux-modules-" + release, "linux-image-unsigned-" + release} {
		if j.pkgChanged(name) {
			return name
		}
	}
	return ""
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
	if v, ok := j.verified[p]; ok && j.verifiedNow(v, j.files[p]) {
		return v.Package
	}
	if name := conffileOwner(j.c.Packages.Installed, p); name != "" && j.pkgChange[name].Kind == diff.PkgUpgraded && j.unreported(p) {
		return name
	}
	return ""
}

// persistOfPackageChange names the newly installed or removed package that
// a new or vanished persistence file belongs to: a new package's enable link
// or default conffile, or a file that left with its package.
func (j *judge) persistOfPackageChange(p string, cur, old *model.PersistFile) string {
	switch {
	case old == nil && cur != nil:
		if cur.Kind == model.PersistKindSystemdEnabled && len(cur.Lines) > 0 {
			if name := j.owned[linkTarget(p, cur.Lines[0])]; name != "" && j.pkgChange[name].Kind == diff.PkgInstalled {
				return name
			}
		}
		if name := conffileOwner(j.c.Packages.Installed, p); name != "" && j.pkgChange[name].Kind == diff.PkgInstalled && j.unreported(p) {
			return name
		}
	case cur == nil && old != nil:
		name := j.oldOwned[p]
		if name == "" {
			name = conffileOwner(j.old.Packages.Installed, p)
		}
		if k := j.pkgChange[name].Kind; name != "" && j.owned[p] == "" && (k == diff.PkgRemoved || k == diff.PkgUpgraded) {
			return name
		}
	}
	return ""
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
	summary := func(lines []diff.LineChange) model.Evidence {
		adds, dels := 0, 0
		first := 0
		for _, lc := range lines {
			if first == 0 {
				first = lc.Line
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
		if name := j.persistOfPackageChange(p, cur, old); name != "" {
			j.foldIntoPackage(name, summary(ch.Lines))
			j.persistDone[p] = j.pkgFinding[name]
			return
		}
	}

	lines := ch.Lines
	if kind == model.PersistKindAuthorizedKeys && j.rootKeyFile(p) {
		lines = j.newRootKeys(p, ch, old)
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
		Fix:   persistFix(p, cur, old, lines, meta),
		Refs:  info.refs,
		// The summary first: its After is the file's full hash.
		Evidence: []model.Evidence{summary(lines)},
	})
	for _, lc := range lines {
		e := model.Evidence{Path: p, Line: lc.Line, Before: lc.Old, After: lc.New, Detail: "line added"}
		if lc.Op != "add" {
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

func persistFix(p string, cur, old *model.PersistFile, lines []diff.LineChange, meta bool) string {
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
		if lc.Op != "add" {
			added = nil
			break
		}
		added = append(added, lc.Line)
	}
	// sed -i would replace a symlink with a plain file.
	if !meta && len(added) > 0 && cur.Mode&0o170000 != 0o120000 {
		return fixDeleteLines(p, added, "removes the added lines shown above")
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
func (j *judge) newRootKeys(p string, ch diff.Change, old *model.PersistFile) []diff.LineChange {
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
			j.persistDone[p] = j.add(&model.Finding{
				Key: fmt.Sprintf("snap.root_key:%s:%d", p, lc.Line), ID: "TT-SNAP-003", Source: srcSnapshot, Severity: model.SevBackdoor,
				Title: fmt.Sprintf("New SSH key for root, not in the snapshot: %s line %d", p, lc.Line),
				Why: "Whoever holds the matching private key can now log in as root without a password. Planting a key is the most common way attackers keep root access. " +
					"It is not the telltale server's key.",
				Fix:      fixDeleteLines(p, []int{lc.Line}, "only if you do not recognise the key; if you remove several lines from this file, start with the highest line number"),
				Evidence: []model.Evidence{{Path: p, Line: lc.Line, After: s, Detail: "key added since the snapshot", When: j.whenFor(p)}},
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

// privilegedGroups make their members root, or let them read secrets or
// raw devices, without any password changing.
var privilegedGroups = map[string]bool{"root": true, "sudo": true, "wheel": true, "admin": true, "shadow": true, "disk": true, "docker": true, "lxd": true}

func (j *judge) groupChanged(ch diff.Change) {
	name := ch.Subject
	var oldM, curM []string
	if g := findGroup(j.old, name); g != nil {
		oldM = g.Members
	}
	if g := findGroup(j.c, name); g != nil {
		curM = g.Members
	}
	var added []string
	for _, m := range curM {
		if !slices.Contains(oldM, m) && !slices.Contains(added, m) {
			added = append(added, m)
		}
	}
	slices.Sort(added)
	f := &model.Finding{
		Key: "snap.group:" + name, ID: "TT-SNAP-005", Source: srcSnapshot, Severity: model.SevNote,
		Title:    fmt.Sprintf("Group %q changed since the snapshot", name),
		Why:      "Group membership decides who can read logs, use devices or run privileged tools; listed so that every account change is accounted for.",
		Evidence: []model.Evidence{{Path: "/etc/group", Before: ch.Before, After: ch.After, Detail: "changed since the snapshot", When: j.whenFor("/etc/group")}},
		Refs:     []string{"T1098"},
	}
	if len(added) > 0 {
		f.Fix = fixGroupMembers(name, added)
		if privilegedGroups[name] {
			f.Severity = model.SevBackdoor
			f.Title = fmt.Sprintf("%s added to the %q group since the snapshot", strings.Join(added, ", "), name)
			f.Why = "Members of this group can become root, or read secrets or raw disks, without any password changing. Adding an account to it is a quiet way to keep root access."
		}
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
	f.Evidence = []model.Evidence{{Path: file, After: name, Detail: detail}}
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
	f.Evidence = []model.Evidence{{Path: exe, After: ch.Subject, Detail: detail}}
	j.add(f)
}
