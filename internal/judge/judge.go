// Package judge turns what telltale collected into its report. It compares
// the machine with its known-good snapshot, runs the hardening checklist and
// the checks that are suspicious on any machine, folds in the package
// verification result, and ranks every finding with why it matters, its
// evidence and the command that would fix it. It also says what it compared
// against and what it could not rule out. It changes nothing: fix commands
// are text for a person to run.
package judge

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/donaldsteele/telltale/internal/checklist"
	"github.com/donaldsteele/telltale/internal/diff"
	"github.com/donaldsteele/telltale/internal/heuristics"
	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/pkgverify"
)

// Input is everything one judgement needs.
type Input struct {
	Collection *model.Collection
	// Snapshot is the known-good baseline; nil means there is none.
	Snapshot *model.Snapshot
	Context  model.ScanContext
	// Pkg is the package verification result; nil means it did not run.
	Pkg *pkgverify.Result
	Now time.Time
}

// Fixed report wording.
const (
	// KernelLimit is in every report: no on-machine check can rule it out.
	KernelLimit = "kernel-level rootkits (any on-machine check can be fooled)"
	// OfflineReference names the reference of an offline-local scan.
	OfflineReference  = "the machine's own package checksums (root can edit these)"
	noSnapshotLimit   = "changes made since the machine was last known to be clean (no snapshot to compare against)"
	noPkgLimit        = "changed system files (package verification did not run)"
	sharedKernelLimit = "kernel modules (this machine is a container on its host's kernel; scan the host)"
	offlineLimit      = "system files changed together with the machine's own package checksums (offline mode trusts them)"
	nonRootLimit      = "checks that need root were skipped (see Skipped); a scan as root is needed for a full answer"
	nothingCollected  = "anything at all: nothing was collected from the machine"
	checkKeyPrefix    = "check:"
)

type judge struct {
	in  Input
	c   *model.Collection
	old *model.Collection // the snapshot's collection; nil without a usable snapshot
	ctx model.ScanContext

	owned, oldOwned map[string]string
	files, oldFiles map[string]*model.FileEntry
	persist         map[string]*model.PersistFile
	oldPersist      map[string]*model.PersistFile
	pkgs            map[string]*model.Package

	findings []*model.Finding
	byKey    map[string]*model.Finding
	groups   map[string]*model.Finding // explained items by key
	omitted  map[*model.Finding]int

	skipped  []model.Skip
	couldNot []string
	compared []string

	// From package verification.
	verified    map[string]pkgverify.FileVerdict
	pkgPath     map[string]*model.Finding // path -> the package finding about it
	unverified  map[string]bool           // grouped unverifiable paths
	unverReason map[string]string         // every unverifiable path -> why
	unverKind   map[string]string         // every unverifiable path -> pkgverify Kind*
	// Special files that could not be checked (a source could not be used),
	// for the one note on unchecked files instead of a backdoor sign each.
	uncheckedSpecial map[string]bool
	uncheckedFiles   []model.Evidence
	uncheckedPkgs    []string        // changed packages whose programs could not be checked
	reported         map[string]bool // every path package verification named

	// From the snapshot comparison.
	pkgChange   map[string]diff.Change      // package name -> its change
	pkgFinding  map[string]*model.Finding   // package name -> finding about its change
	pkgReasons  map[string][]string         // new package -> what raised it
	unverIn     map[string][]model.Evidence // changed package -> its programs found in no trusted source
	unchecked   map[string][]model.Evidence // changed package -> its programs that could not be checked
	gshadowRisk bool                        // a group change gives a group a password or a privileged group a member or admin
	unconfirmed map[string]bool             // changed package -> a changed file of it was not confirmed
	listeners   []diff.Change
	persistDone map[string]*model.Finding  // persistence path -> its finding (nil: explained)
	acctChanged map[string]bool            // account database -> the account comparison found a change in it
	acctDirty   map[string]bool            // account database -> it holds a duplicate name or a line glibc rejects
	touched     map[string]map[string]bool // changed package -> paths shown with its change
	privGID     map[int]bool               // ids of privileged groups on either side
	budget      []string                   // reasons package verification stopped at a limit
	notRun      string                     // why package verification did not run at all
	stopped     map[string]bool            // packages a deadline left unchecked
	confirmed   map[string]bool            // packages one of whose files matched the version installed now
	residual    map[string][]string        // packages removed but not purged -> the versions dpkg records
	// unreachable holds, per package, a verdict saying the host's own
	// indexes could not be used, so nothing about the package was checked.
	unreachable   map[string]pkgverify.FileVerdict
	extraInstalls []diff.Change // a second architecture of a package that also changed
	foldedMax     map[*model.Finding]model.Severity
}

func newJudge(in Input, c *model.Collection) *judge {
	j := &judge{
		in: in, c: c, ctx: in.Context,
		byKey: map[string]*model.Finding{}, groups: map[string]*model.Finding{}, omitted: map[*model.Finding]int{},
		verified: map[string]pkgverify.FileVerdict{}, pkgPath: map[string]*model.Finding{},
		unverified: map[string]bool{}, unverReason: map[string]string{}, unverKind: map[string]string{}, uncheckedSpecial: map[string]bool{}, reported: map[string]bool{},
		pkgChange: map[string]diff.Change{}, pkgFinding: map[string]*model.Finding{}, persistDone: map[string]*model.Finding{},
		pkgReasons: map[string][]string{}, unverIn: map[string][]model.Evidence{}, unchecked: map[string][]model.Evidence{}, unconfirmed: map[string]bool{},
		acctChanged: map[string]bool{}, foldedMax: map[*model.Finding]model.Severity{},
		acctDirty: map[string]bool{}, touched: map[string]map[string]bool{}, privGID: map[int]bool{},
		stopped: map[string]bool{}, confirmed: map[string]bool{},
		residual: map[string][]string{}, unreachable: map[string]pkgverify.FileVerdict{},
	}
	for _, p := range c.Packages.Residual {
		j.residual[p.Name] = append(j.residual[p.Name], p.Version)
	}
	if in.Snapshot != nil && in.Snapshot.Collection != nil {
		j.old = in.Snapshot.Collection
	}
	j.owned, j.files, j.persist, j.pkgs = indexCollection(c)
	if j.old != nil {
		j.oldOwned, j.oldFiles, j.oldPersist, _ = indexCollection(j.old)
	} else {
		j.oldOwned, j.oldFiles, j.oldPersist = map[string]string{}, map[string]*model.FileEntry{}, map[string]*model.PersistFile{}
	}
	for _, col := range []*model.Collection{c, j.old} {
		if col == nil {
			continue
		}
		for _, g := range col.Accounts.Groups {
			if privilegedGroups[g.Name] {
				j.privGID[g.GID] = true
			}
		}
	}
	for _, e := range append(append([]string(nil), c.Accounts.Duplicates...), c.Accounts.Malformed...) {
		if file, _, ok := strings.Cut(e, ":"); ok {
			j.acctDirty[file] = true
		}
	}
	seen := map[string]bool{}
	for _, u := range c.Accounts.Users {
		if seen[u.Name] {
			j.acctDirty["/etc/passwd"] = true
		}
		seen[u.Name] = true
	}
	seenG := map[string]bool{}
	for _, g := range c.Accounts.Groups {
		if seenG[g.Name] {
			j.acctDirty["/etc/group"] = true
		}
		seenG[g.Name] = true
	}
	return j
}

// privileged reports whether a group makes its members root (or lets them
// read secrets, logs or raw devices, or write /usr/local): by its name, or
// by sharing the id of such a group on this machine.
func (j *judge) privileged(g *model.Group) bool {
	return g != nil && (privilegedGroups[g.Name] || j.privGID[g.GID])
}

func indexCollection(c *model.Collection) (map[string]string, map[string]*model.FileEntry, map[string]*model.PersistFile, map[string]*model.Package) {
	files := make(map[string]*model.FileEntry, len(c.Files))
	for i := range c.Files {
		if _, ok := files[c.Files[i].Path]; !ok {
			files[c.Files[i].Path] = &c.Files[i]
		}
	}
	persist := make(map[string]*model.PersistFile, len(c.Persist))
	for i := range c.Persist {
		if _, ok := persist[c.Persist[i].Path]; !ok {
			persist[c.Persist[i].Path] = &c.Persist[i]
		}
	}
	pkgs := make(map[string]*model.Package, len(c.Packages.Installed))
	for i := range c.Packages.Installed {
		if _, ok := pkgs[c.Packages.Installed[i].Name]; !ok {
			pkgs[c.Packages.Installed[i].Name] = &c.Packages.Installed[i]
		}
	}
	return c.Packages.Owners(), files, persist, pkgs
}

// Judge combines the snapshot comparison, the checklist, the heuristics and
// the package verification result into one ranked report.
func Judge(in Input) *model.Report {
	c := in.Collection
	if c == nil {
		c = &model.Collection{}
	}
	j := newJudge(in, c)
	checks := checklist.Evaluate(c, in.Context)
	j.checklist(checks)
	// Package and account changes are indexed first: how package
	// verification results rank depends on which packages changed.
	var chs []diff.Change
	if j.old != nil {
		chs = diff.Compare(in.Snapshot, c, checks)
		j.index(chs)
	}
	j.packages()
	if j.old != nil {
		j.changes(chs)
		j.finishPackages()
	} else if in.Snapshot != nil {
		j.skipped = append(j.skipped, model.Skip{Check: "snapshot", Reason: "the snapshot holds no collected data, so nothing was compared with it"})
	}
	j.uncheckedNote()
	j.accountAnomalies()
	j.heuristics()
	j.fillWhen()
	j.finishGroups()
	applied := j.exceptions()
	return j.report(checks, applied)
}

// checklist turns failing items into weak settings and skipped items into
// skips.
func (j *judge) checklist(checks []model.CheckResult) {
	for _, r := range checks {
		if r.Skipped != "" {
			j.skipped = append(j.skipped, model.Skip{Check: r.ID, Reason: r.Skipped})
			continue
		}
		if r.Pass {
			continue
		}
		it, ok := checklist.ByID(r.ID)
		if !ok {
			continue
		}
		j.add(&model.Finding{
			Key: checkKeyPrefix + it.ID, ID: it.ID, Source: srcChecklist, Severity: model.SevWeak,
			Title: "Not met: " + it.Title,
			Why:   it.Why,
			Fix:   it.FixFor(j.c, j.ctx),
			// After carries the observed value: it is what an exception
			// accepts and what a later scan compares it with.
			Evidence: []model.Evidence{{After: r.Observed, Detail: "checklist item " + it.ID}},
			Refs:     it.Refs,
		})
	}
}

// regressed raises a checklist finding to tampering: the item held in the
// baseline (the snapshot, or the value an exception accepted) and fails now
// with another value.
func (j *judge) regressed(id, before string, accepted *model.Exception) {
	f := j.byKey[checkKeyPrefix+id]
	it, ok := checklist.ByID(id)
	if f == nil || !ok {
		return
	}
	f.Severity = model.SevTampering
	if accepted == nil {
		day := j.in.Snapshot.Taken.UTC().Format("2006-01-02")
		f.Title = "No longer met since the snapshot of " + day + ": " + it.Title
		f.Why = it.Why + " It held in the known-good snapshot and fails now, so the setting was changed since: attackers loosen settings like this to keep a way back in."
		f.Evidence[0].Detail = "checklist item " + id + ": held in the snapshot of " + day + ", fails now"
	} else {
		day := accepted.At.UTC().Format("2006-01-02")
		f.Title = "Changed from the value accepted on " + day + ": " + it.Title
		f.Why = it.Why + " You accepted this item's earlier value as an exception; it has changed since, so it counts as a regression from the accepted value: attackers loosen settings like this to keep a way back in."
		f.Evidence[0].Detail = "checklist item " + id + ": the exception accepted on " + day + " covers only the value before"
	}
	f.Evidence[0].Before = before
}

func (j *judge) heuristics() {
	for _, f := range heuristics.Run(j.c, j.ctx, j.owned) {
		// With a snapshot, new root keys are ranked from the comparison
		// instead (keys already there were accepted with the snapshot).
		if j.old != nil && strings.HasPrefix(f.Key, "heur.root_key:") {
			continue
		}
		if strings.HasPrefix(f.Key, "heur.crossview:") {
			f.Source = srcCrossview
		}
		f := f
		if strings.HasPrefix(f.Key, "heur.persist_link_pkg:") {
			j.rankPackageLink(&f)
		}
		j.add(&f)
	}
}

// accountAnomalies flags what the collector found in the account databases
// beyond the accounts themselves: a name on more than one line (programs
// disagree about which line counts, so a second line can hide another
// password or identity behind a familiar name) and lines glibc rejects.
// A collection that still lists duplicate users is checked too.
func (j *judge) accountAnomalies() {
	dup := func(entry string, ev []model.Evidence) {
		file, name := splitEntry(entry)
		j.add(&model.Finding{
			Key: "acct.duplicate:" + entry, ID: "TT-JUDGE-001", Source: srcHeuristic, Severity: model.SevBackdoor,
			Title: fmt.Sprintf("%q appears on more than one line of %s", name, file),
			Why: "Lookups by name use the first line, while other programs (group membership, some tools) read every line. " +
				"A second line for a familiar name is a way to hide another password, user id or group membership behind it.",
			Fix:      fixKeepOnly(file, "then remove the extra line with vipw -s, vigr or vigr -s as fits the file"),
			Evidence: ev,
			Refs:     []string{"T1136.001", "T1098"},
		})
	}
	for _, e := range j.c.Accounts.Duplicates {
		file, _ := splitEntry(e)
		dup(e, []model.Evidence{{Path: file, After: e, Detail: "name on more than one line", When: j.whenFor(file)}})
	}
	byName := map[string][]model.User{}
	var order []string
	for _, u := range j.c.Accounts.Users {
		if u.Name == "" || strings.HasPrefix(u.Name, "+") || strings.HasPrefix(u.Name, "-") {
			continue
		}
		if _, ok := byName[u.Name]; !ok {
			order = append(order, u.Name)
		}
		byName[u.Name] = append(byName[u.Name], u)
	}
	for _, name := range order {
		us := byName[name]
		if len(us) < 2 || slices.Contains(j.c.Accounts.Duplicates, "/etc/passwd:"+name) {
			continue
		}
		var ev []model.Evidence
		for _, u := range us {
			ev = append(ev, model.Evidence{Path: "/etc/passwd", After: fmt.Sprintf("uid %d gid %d shell %s home %s", u.UID, u.GID, u.Shell, u.Home), Detail: "line for " + name})
		}
		dup("/etc/passwd:"+name, ev)
	}
	groups := map[string][]model.Group{}
	var gorder []string
	for _, g := range j.c.Accounts.Groups {
		if _, ok := groups[g.Name]; !ok {
			gorder = append(gorder, g.Name)
		}
		groups[g.Name] = append(groups[g.Name], g)
	}
	for _, name := range gorder {
		gs := groups[name]
		if len(gs) < 2 || slices.Contains(j.c.Accounts.Duplicates, "/etc/group:"+name) {
			continue
		}
		var ev []model.Evidence
		for _, g := range gs {
			ev = append(ev, model.Evidence{Path: "/etc/group", After: fmt.Sprintf("gid %d members %s", g.GID, strings.Join(g.Members, ",")), Detail: "line for " + name})
		}
		dup("/etc/group:"+name, ev)
	}
	for _, e := range j.c.Accounts.Malformed {
		file, rest := splitEntry(e)
		line, note, _ := strings.Cut(rest, " ")
		n, _ := strconv.Atoi(line)
		// A line glibc cannot parse is skipped by it. A line with an empty
		// name parses, and glibc uses it.
		title := fmt.Sprintf("Line %s of %s is not a valid entry", line, file)
		why := "glibc skips this line, but other programs that read the file may not. A line written so that tools disagree about it is a way to hide an account or a password."
		detail := "rejected by glibc's parser"
		if note != "" {
			title = fmt.Sprintf("Line %s of %s is an entry with no name %s", line, file, note)
			why, detail = emptyNameWhy(file), "an entry with no name, which glibc uses"
		}
		j.add(&model.Finding{
			Key: "acct.malformed:" + e, ID: "TT-JUDGE-002", Source: srcHeuristic, Severity: model.SevBackdoor,
			Title:    title,
			Why:      why + " Its content is not shown, since it may hold a password hash.",
			Fix:      fixKeepOnly(file, "then look at line "+line+" and remove or correct it with vipw -s, vigr or vigr -s as fits the file"),
			Evidence: []model.Evidence{{Path: file, Line: n, After: e, Detail: detail, When: j.whenFor(file)}},
			Refs:     []string{"T1136.001"},
		})
	}
}

// emptyNameWhy says what glibc does with a line whose name is empty, which
// it accepts in every account database.
func emptyNameWhy(file string) string {
	const hidden = " Tools that list or look up accounts by name show nothing unusual, so the line is a way to hide one."
	switch file {
	case "/etc/passwd":
		return "glibc uses this line: a lookup by user id (getpwuid) returns it, so its user id belongs to an account with no name, with this line's group, home directory and shell." + hidden
	case "/etc/group":
		return "glibc uses this line: group memberships are collected from every line (initgroups), so the accounts it lists are members of its group id at their next login, and a lookup by group id (getgrgid) returns it." + hidden
	case "/etc/shadow":
		return "glibc uses this line: it is the password entry of an account with an empty name, such as an /etc/passwd line with no name." + hidden
	}
	return "glibc uses this line: it is the entry of a group with an empty name, such as an /etc/group line with no name." + hidden
}

// splitEntry splits "<file>:<name or line>"; the files have no colon.
func splitEntry(e string) (string, string) {
	file, rest, _ := strings.Cut(e, ":")
	return file, rest
}

// whenFor is when the file at p last changed: its inode change time (which,
// unlike the modification time, cannot be set back with touch), else its
// modification time.
func (j *judge) whenFor(p string) *time.Time {
	if e := j.files[p]; e != nil {
		for _, t := range []time.Time{e.CTime, e.MTime} {
			if !t.IsZero() {
				t := t
				return &t
			}
		}
	}
	if pf := j.persist[p]; pf != nil && !pf.MTime.IsZero() {
		t := pf.MTime
		return &t
	}
	return nil
}

// fillWhen dates evidence that names a collected file but carries no time.
func (j *judge) fillWhen() {
	for _, f := range j.findings {
		for i := range f.Evidence {
			if e := &f.Evidence[i]; e.When == nil && e.Path != "" {
				e.When = j.whenFor(e.Path)
			}
		}
	}
}

// currentValue is what an exception is compared with. It mirrors what
// telltale accept records: the first evidence's After, else the title.
func currentValue(f *model.Finding) string {
	if len(f.Evidence) > 0 && f.Evidence[0].After != "" {
		return f.Evidence[0].After
	}
	return f.Title
}

// exceptions drops findings whose current value the owner accepted and
// returns the exceptions that did so. A finding whose value differs from the
// accepted one stays; a checklist item is then judged by the regression
// rule against the accepted value.
func (j *judge) exceptions() []model.Exception {
	if j.in.Snapshot == nil || len(j.in.Snapshot.Exceptions) == 0 {
		return nil
	}
	all := j.in.Snapshot.Exceptions
	byKey := map[string][]int{}
	for i, e := range all {
		byKey[e.FindingKey] = append(byKey[e.FindingKey], i)
	}
	used := map[int]bool{}
	match := func(f *model.Finding) bool {
		idx := byKey[f.Key]
		if len(idx) == 0 {
			return false
		}
		val := currentValue(f)
		for _, i := range idx {
			if all[i].AcceptedValue == val {
				used[i] = true
				if j.foldedMax[f] > f.Severity {
					// Something folded into this finding would rank higher on
					// its own; the exception did not accept that.
					f.Evidence = append(f.Evidence, model.Evidence{Detail: "kept although an exception covers this finding: it now includes a change more serious than the one accepted"})
					return false
				}
				return true
			}
		}
		latest := all[idx[0]]
		for _, i := range idx[1:] {
			if all[i].At.After(latest.At) {
				latest = all[i]
			}
		}
		if id, ok := strings.CutPrefix(f.Key, checkKeyPrefix); ok {
			j.regressed(id, latest.AcceptedValue, &latest)
		} else {
			f.Evidence = append(f.Evidence, model.Evidence{Before: latest.AcceptedValue, After: val,
				Detail: "differs from the value accepted as an exception on " + latest.At.UTC().Format("2006-01-02")})
		}
		return false
	}
	kept := j.findings[:0]
	for _, f := range j.findings {
		if match(f) {
			delete(j.byKey, f.Key)
			continue
		}
		kept = append(kept, f)
	}
	j.findings = kept
	for k, g := range j.groups {
		if match(g) {
			delete(j.groups, k)
		}
	}
	var applied []model.Exception
	for i, e := range all {
		if used[i] {
			applied = append(applied, e)
		}
	}
	return applied
}

func (j *judge) report(checks []model.CheckResult, applied []model.Exception) *model.Report {
	t := j.in.Now
	if t.IsZero() {
		t = j.c.Time
	}
	r := &model.Report{
		Schema: model.ReportSchema, Host: j.c.Host, Time: t,
		Findings: []model.Finding{}, Explained: []model.Finding{}, Exceptions: applied,
	}
	finish := func(f *model.Finding) model.Finding {
		out := *f
		if n := j.omitted[f]; n > 0 {
			out.Evidence = append(append([]model.Evidence(nil), f.Evidence...), model.Evidence{Detail: fmt.Sprintf("and %d more", n)})
		}
		return out
	}
	for _, f := range j.findings {
		r.Findings = append(r.Findings, finish(f))
	}
	sortFindings(r.Findings)
	for _, g := range j.groups {
		r.Explained = append(r.Explained, finish(g))
	}
	sortFindings(r.Explained)

	if j.old != nil {
		r.ComparedAgainst = append(r.ComparedAgainst, "snapshot of "+j.in.Snapshot.Taken.UTC().Format("2006-01-02"))
	}
	r.ComparedAgainst = append(r.ComparedAgainst, j.compared...)
	judged := 0
	for _, c := range checks {
		if c.Skipped == "" {
			judged++
		}
	}
	r.ComparedAgainst = append(r.ComparedAgainst, fmt.Sprintf("checklist (%d items)", judged))

	r.CouldNotRuleOut = append(r.CouldNotRuleOut, KernelLimit)
	switch {
	case j.in.Collection == nil:
		r.CouldNotRuleOut = append(r.CouldNotRuleOut, nothingCollected)
	case !j.c.AsRoot:
		r.CouldNotRuleOut = append(r.CouldNotRuleOut, nonRootLimit)
	}
	if j.in.Collection != nil && j.c.Runtime.SharedKernel {
		r.CouldNotRuleOut = append(r.CouldNotRuleOut, sharedKernelLimit)
	}
	if j.old == nil {
		r.CouldNotRuleOut = append(r.CouldNotRuleOut, noSnapshotLimit)
	}
	r.CouldNotRuleOut = append(r.CouldNotRuleOut, j.couldNot...)

	r.Skipped = append(append(r.Skipped, j.c.Skipped...), j.skipped...)
	r.ExitCode = exitCode(r.Findings)
	return r
}

// rankPackageLink ranks a startup link into a package-owned file outside the
// system directories (R68b). With no trusted source for the file, root could
// have overwritten it, so the note stands only when the file is verified, or
// matches the md5 the machine's own dpkg database holds for it. The escalated
// finding takes the backdoor key of a plain link, so an exception accepted
// for the note never covers it. A mismatch
// against a trusted source is also reported by package verification itself.
func (j *judge) rankPackageLink(f *model.Finding) {
	link := strings.TrimPrefix(f.Key, "heur.persist_link_pkg:")
	pf := j.persist[link]
	if pf == nil {
		return
	}
	// The same resolution the note was made with.
	target, ok := heuristics.LinkFile(j.files, *pf)
	if !ok {
		return
	}
	const localOnly = " The file was checked only against the machine's own checksums, which root can edit."
	if r := j.in.Pkg; r != nil {
		for _, v := range r.Mismatch {
			if v.Path == target {
				f.Severity, f.Key = model.SevBackdoor, "heur.persist_link:"+link
				f.Why = "The startup entry runs a package-owned file that no longer matches its package (see the tampering finding for it). " + f.Why
				return
			}
		}
		if v, ok := j.verified[target]; ok {
			if v.Source == pkgverify.SourceOfflineLocal {
				f.Why += localOnly
			}
			return
		}
	}
	// No trusted verdict: the machine's own md5 for the file decides.
	var want, got string
	if p := j.pkgs[j.owned[target]]; p != nil {
		want = strings.ToLower(p.LocalMD5[target])
	}
	if e := j.files[target]; e != nil {
		got = strings.ToLower(e.MD5)
	}
	if want == "" || got == "" || want != got {
		f.Severity, f.Key = model.SevBackdoor, "heur.persist_link:"+link
		f.Why = "The startup entry runs a package-owned file outside the system directories that no trusted source could check, and the machine's own checksum for it is missing or does not match the file: it may have been overwritten. " + f.Why
		return
	}
	f.Why += localOnly
}
