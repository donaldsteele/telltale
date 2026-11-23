package judge

import (
	"slices"
	"sort"
	"strings"

	"github.com/donaldsteele/telltale/internal/diff"
	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/pkgverify"
)

// Rebase says how a machine's snapshot can roll forward after a judgement:
// server mode's re-baselining. Only the judge knows which changes it
// explained and which findings stand for which changes, so it says so here.
type Rebase struct {
	// Routine is what the report shows only as explained by package
	// changes this scan confirmed: a removal, or a new version a file of
	// the changed architecture's package matched from a trusted source.
	// It holds those packages' records (that architecture only) and the
	// files shown with them, except files any finding (an excepted one
	// included) is about and files only another architecture of the same
	// name lists. A change nothing confirmed (an outage left it unchecked,
	// or it has no files) is left out whole, to be judged again at the
	// next visit. Routine rolls forward on every visit.
	Routine Scope
	// Accept maps the key of each finding in the report that is about a
	// change since the snapshot to what accepting it rolls forward. A
	// finding that is not (a heuristic, a package mismatch, a checklist
	// item judged without a baseline) is absent: it can only be accepted as
	// an exception.
	Accept map[string]Scope
}

// Scope names parts of a collection the way diff compares them.
type Scope struct {
	Paths     []string `json:"paths,omitempty"`     // file and persistence entries
	Packages  []string `json:"packages,omitempty"`  // installed packages, as "name:arch"
	Users     []string `json:"users,omitempty"`     // accounts
	Groups    []string `json:"groups,omitempty"`    // groups
	Modules   []string `json:"modules,omitempty"`   // loaded kernel modules
	Listeners []string `json:"listeners,omitempty"` // listening sockets, as diff names them ("tcp 0.0.0.0:22")
	Checks    []string `json:"checks,omitempty"`    // checklist item IDs
	// LinkerCache is the list of files the dynamic linker's cache sends
	// programs to (Collection.LinkerCache). It goes with the cache file:
	// the next rebuild is judged against it.
	LinkerCache bool `json:"linker_cache,omitempty"`
	// Cmdline is the kernel command line the machine booted with
	// (Runtime.Cmdline); Firewall the summary of the live firewall rules
	// (Collection.Firewall).
	Cmdline  bool `json:"cmdline,omitempty"`
	Firewall bool `json:"firewall,omitempty"`
	// With lists the other findings in the report about the same things
	// that depend on the snapshot: rolling this scope forward would make
	// them go away too (a file no longer changed is no longer verified
	// against its package), so they are accepted together or not at all.
	With []string `json:"with,omitempty"`
}

// Empty reports whether s names nothing to roll forward.
func (s Scope) Empty() bool {
	return len(s.Paths)+len(s.Packages)+len(s.Users)+len(s.Groups)+len(s.Modules)+len(s.Listeners)+len(s.Checks) == 0 && !s.LinkerCache && !s.Cmdline && !s.Firewall
}

// Merge adds o's parts to s (not With).
func (s *Scope) Merge(o Scope) {
	s.Paths = append(s.Paths, o.Paths...)
	s.Packages = append(s.Packages, o.Packages...)
	s.Users = append(s.Users, o.Users...)
	s.Groups = append(s.Groups, o.Groups...)
	s.Modules = append(s.Modules, o.Modules...)
	s.Listeners = append(s.Listeners, o.Listeners...)
	s.Checks = append(s.Checks, o.Checks...)
	s.LinkerCache = s.LinkerCache || o.LinkerCache
	s.Cmdline = s.Cmdline || o.Cmdline
	s.Firewall = s.Firewall || o.Firewall
}

// addPath adds a path, and the linker cache's list with the cache file.
func (s *Scope) addPath(p string) {
	s.Paths = append(s.Paths, p)
	if p == linkerCachePath {
		s.LinkerCache = true
	}
}

// subjects lists the parts a scope names, one string each.
func (s Scope) subjects() []string {
	var out []string
	for _, l := range []struct {
		kind string
		vals []string
	}{{"path:", s.Paths}, {"pkg:", s.Packages}, {"user:", s.Users}, {"group:", s.Groups}, {"module:", s.Modules}, {"listener:", s.Listeners}, {"check:", s.Checks}} {
		for _, v := range l.vals {
			out = append(out, l.kind+v)
		}
	}
	if s.Cmdline {
		out = append(out, "cmdline:")
	}
	if s.Firewall {
		out = append(out, "firewall:")
	}
	return out
}

// RollForward returns a copy of snap in which the parts s names are as they
// are in cur (and curChecks, cur's checklist results): taken from cur, or
// gone when cur has none. Everything else stays as the snapshot had it.
// snap itself is not changed.
func RollForward(snap *model.Snapshot, cur *model.Collection, curChecks []model.CheckResult, s Scope) *model.Snapshot {
	out := *snap
	if snap.Collection == nil || cur == nil {
		return &out
	}
	set := func(vals []string) map[string]bool {
		m := make(map[string]bool, len(vals))
		for _, v := range vals {
			m[v] = true
		}
		return m
	}
	paths, pkgs, users, groups := set(s.Paths), set(s.Packages), set(s.Users), set(s.Groups)
	mods, listeners, checks := set(s.Modules), set(s.Listeners), set(s.Checks)
	oc := *snap.Collection
	oc.Files = replaceIn(oc.Files, cur.Files, func(e model.FileEntry) bool { return paths[e.Path] })
	oc.Persist = replaceIn(oc.Persist, cur.Persist, func(p model.PersistFile) bool { return paths[p.Path] })
	oc.Accounts.Users = replaceIn(oc.Accounts.Users, cur.Accounts.Users, func(u model.User) bool { return users[u.Name] })
	oc.Accounts.Groups = replaceIn(oc.Accounts.Groups, cur.Accounts.Groups, func(g model.Group) bool { return groups[g.Name] })
	oc.Packages.Installed = replaceIn(oc.Packages.Installed, cur.Packages.Installed, func(p model.Package) bool { return pkgs[pkgKey(p.Name, p.Arch)] })
	oc.Runtime.Modules = replaceIn(oc.Runtime.Modules, cur.Runtime.Modules, func(m model.KernelModule) bool { return mods[m.Name] })
	oc.Runtime.Sockets = replaceIn(oc.Runtime.Sockets, cur.Runtime.Sockets, func(k model.Socket) bool { return k.Listening && listeners[listenKey(k)] })
	if s.LinkerCache {
		oc.LinkerCache = slices.Clone(cur.LinkerCache)
	}
	if s.Cmdline {
		oc.Runtime.Cmdline = cur.Runtime.Cmdline
	}
	if s.Firewall {
		oc.Firewall = cur.Firewall
	}
	out.Collection = &oc
	out.Checks = replaceIn(snap.Checks, curChecks, func(r model.CheckResult) bool { return checks[r.ID] })
	return &out
}

// replaceIn returns old without the entries in names, followed by cur's
// entries in names, in their order. old is not changed.
func replaceIn[T any](old, cur []T, in func(T) bool) []T {
	out := make([]T, 0, len(old))
	for _, e := range old {
		if !in(e) {
			out = append(out, e)
		}
	}
	for _, e := range cur {
		if in(e) {
			out = append(out, e)
		}
	}
	return out
}

// ExceptionValue is the value an exception for f accepts: what a later
// judgement compares the finding with (the first evidence's After, else the
// title), as telltale accept records it.
func ExceptionValue(f *model.Finding) string { return currentValue(f) }

// AddFindings adds findings made outside the judgement (server mode's notes
// about the visit itself) to r, ranks them with the rest and sets the exit
// code again.
func AddFindings(r *model.Report, fs ...model.Finding) {
	r.Findings = append(r.Findings, fs...)
	sortFindings(r.Findings)
	r.ExitCode = exitCode(r.Findings)
}

// heldBack lists the paths the findings are about (before exceptions drop
// any): the path a key names, every evidence path, and every file a ranked
// package change, an unchecked change or an unverifiable file stands for.
// None of them rolls forward by itself.
func (j *judge) heldBack() map[string]bool {
	held := map[string]bool{}
	for _, f := range j.findings {
		for _, s := range j.subjectsOf(f) {
			if p, ok := strings.CutPrefix(s, "path:"); ok {
				held[p] = true
			}
		}
	}
	for name, f := range j.pkgFinding {
		if f != nil {
			for p := range j.touched[name] {
				held[p] = true
			}
		}
	}
	for _, es := range j.unchecked {
		for _, e := range es {
			held[e.Path] = true
		}
	}
	for _, es := range j.unverIn {
		for _, e := range es {
			held[e.Path] = true
		}
	}
	for _, e := range j.uncheckedFiles {
		held[e.Path] = true
	}
	for p := range j.unverReason {
		held[p] = true
	}
	return held
}

// rebase works out the Rebase once the findings are final.
func (j *judge) rebase(held map[string]bool) *Rebase {
	if j.old == nil {
		return nil
	}
	rb := &Rebase{Accept: map[string]Scope{}}
	var names []string
	for key := range j.groups {
		if name, ok := strings.CutPrefix(key, "explained:"); ok && j.pkgFinding[name] == nil {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		if ch, ok := j.pkgChange[name]; ok {
			if ch.Pkg == nil || !j.routineOK(name) {
				continue // the whole group, files and all, is judged again
			}
			rb.Routine.Packages = append(rb.Routine.Packages, pkgKey(name, ch.Pkg.Arch))
		}
		other := j.otherArchPaths(name)
		for _, p := range sortedSet(j.touched[name]) {
			if !held[p] && !other[p] {
				rb.Routine.addPath(p)
			}
		}
	}
	// A file rebuilt from verified package files (the library cache).
	for key := range j.groups {
		if p, ok := strings.CutPrefix(key, "rebuilt:"); ok && !held[p] {
			rb.Routine.addPath(p)
		}
	}
	// Which snapshot-dependent findings are about what.
	about := map[string][]string{}
	for _, f := range j.findings {
		if dependsOnSnapshot(f.Key) {
			for _, s := range j.subjectsOf(f) {
				about[s] = append(about[s], f.Key)
			}
		}
	}
	for _, f := range j.findings {
		s, ok := j.acceptScope(f)
		if !ok {
			continue
		}
		with := map[string]bool{}
		for _, sub := range s.subjects() {
			for _, k := range about[sub] {
				if k != f.Key {
					with[k] = true
				}
			}
		}
		s.With = sortedSet(with)
		rb.Accept[f.Key] = s
	}
	return rb
}

// dependsOnSnapshot reports whether a finding with this key can go away
// when the snapshot rolls forward: a change since the snapshot, a regressed
// checklist item, or a package verification result (only changed files are
// verified when there is a snapshot).
func dependsOnSnapshot(key string) bool {
	return strings.HasPrefix(key, "snap.") || strings.HasPrefix(key, "pkg.") || strings.HasPrefix(key, checkKeyPrefix)
}

// acceptScope is what accepting f rolls forward, when f is about a change
// since the snapshot.
func (j *judge) acceptScope(f *model.Finding) (Scope, bool) {
	s, ok := j.changeScope(f)
	if slices.Contains(s.Paths, linkerCachePath) {
		s.LinkerCache = true
	}
	return s, ok
}

func (j *judge) changeScope(f *model.Finding) (Scope, bool) {
	kind, subj, _ := strings.Cut(f.Key, ":")
	switch kind {
	case "snap." + diff.FileAdded, "snap." + diff.FileRemoved, "snap." + diff.FileModified, "snap.persist":
		return Scope{Paths: []string{subj}}, true
	case "snap.root_key":
		// "snap.root_key:<path>:<line>": the key file rolls forward as a
		// whole, so every other finding about it is accepted with it.
		if i := strings.LastIndexByte(subj, ':'); i > 0 {
			return Scope{Paths: []string{subj[:i]}}, true
		}
	case "snap.user_added", "snap.user_changed", "snap.user_removed":
		return Scope{Users: []string{subj}}, true
	case "snap.group":
		return Scope{Groups: []string{subj}}, true
	case "snap.module":
		return Scope{Modules: []string{subj}}, true
	case "snap.cmdline":
		return Scope{Cmdline: true}, true
	case "snap.firewall":
		return Scope{Firewall: true}, true
	case "snap.listener":
		// The key spells diff's subject "tcp 0.0.0.0:22" as "tcp:0.0.0.0:22".
		return Scope{Listeners: []string{strings.Replace(subj, ":", " ", 1)}}, true
	case "snap.pkg_installed":
		// "snap.pkg_installed:<name>:<arch>" is another architecture of a
		// package that also changed (package names have no colon): its
		// record and every file it lists.
		if name, arch, ok := strings.Cut(subj, ":"); ok {
			s := Scope{Packages: []string{pkgKey(name, arch)}}
			for i := range j.c.Packages.Installed {
				if p := &j.c.Packages.Installed[i]; p.Name == name && p.Arch == arch {
					for _, f := range p.Files {
						s.addPath(f)
						if a := usrAlias(f); a != "" {
							s.addPath(a)
						}
					}
				}
			}
			s.Paths = sortedSet(toSet(s.Paths))
			return s, true
		}
		return j.packageScope(subj), true
	case "snap.pkg_upgraded", "snap.pkg_downgraded", "snap.pkg_removed", "snap.pkg_version_only":
		return j.packageScope(subj), true
	case strings.TrimSuffix(checkKeyPrefix, ":"):
		return Scope{Checks: []string{subj}}, true
	case "pkg.unchecked_changes":
		var s Scope
		for _, name := range j.uncheckedPkgs {
			s.Merge(j.packageScope(name))
		}
		s.Paths = append(s.Paths, j.uncheckedPaths()...)
		s.Paths = sortedSet(toSet(s.Paths))
		return s, true
	}
	return Scope{}, false
}

// packageScope is the record of the package change the judge looked at (its
// architecture only) and every path shown with it, except those only
// another architecture of the name lists.
func (j *judge) packageScope(name string) Scope {
	var s Scope
	if ch, ok := j.pkgChange[name]; ok && ch.Pkg != nil {
		s.Packages = []string{pkgKey(name, ch.Pkg.Arch)}
	}
	other := j.otherArchPaths(name)
	for _, p := range sortedSet(j.touched[name]) {
		if !other[p] {
			s.addPath(p)
		}
	}
	return s
}

// pkgKey names an installed package by name and architecture, as dpkg
// tells them apart.
func pkgKey(name, arch string) string { return name + ":" + arch }

// routineOK reports whether a package change may roll forward without the
// owner: a removal, or a new version this scan verified, meaning a file the
// changed architecture's package lists matched that version from a trusted
// source as the file is now. A change an outage left unchecked does not
// count (it contradicts nothing, but confirms nothing either), nor does a
// version with no file to show for it.
func (j *judge) routineOK(name string) bool {
	ch := j.pkgChange[name]
	if ch.Pkg == nil {
		return false
	}
	if ch.Kind == diff.PkgRemoved {
		return true
	}
	if j.in.Pkg == nil || !j.rebuilderOK(name) {
		return false
	}
	p := j.entry(name, ch.Pkg.Arch)
	if p == nil || p.Arch != ch.Pkg.Arch || p.Version != ch.Pkg.New {
		return false
	}
	listed := map[string]bool{}
	for _, f := range p.Files {
		listed[f] = true
		if a := usrAlias(f); a != "" {
			listed[a] = true
		}
	}
	for _, v := range j.in.Pkg.Verified {
		if v.Package != name || v.Version != ch.Pkg.New || v.Source == "" || v.Source == pkgverify.SourceOfflineLocal {
			continue
		}
		if e := j.files[v.Path]; e == nil || e.Type != "file" || e.SHA256 != v.Actual {
			continue
		}
		if listed[v.Path] || (j.literal[v.Path] != "" && listed[j.literal[v.Path]]) {
			return true
		}
	}
	return false
}

// otherArchPaths lists the paths that another architecture of name lists,
// now or in the snapshot, and the architecture whose change the judge
// looked at does not. They belong to a change of their own.
func (j *judge) otherArchPaths(name string) map[string]bool {
	ch, ok := j.pkgChange[name]
	if !ok || ch.Pkg == nil {
		return nil
	}
	mine, theirs := map[string]bool{}, map[string]bool{}
	for _, c := range []*model.Collection{j.c, j.old} {
		if c == nil {
			continue
		}
		for _, p := range c.Packages.Installed {
			if p.Name != name {
				continue
			}
			dst := theirs
			if p.Arch == ch.Pkg.Arch {
				dst = mine
			}
			for _, f := range p.Files {
				dst[f] = true
				if a := usrAlias(f); a != "" {
					dst[a] = true
				}
			}
		}
	}
	for p := range mine {
		delete(theirs, p)
	}
	return theirs
}

// uncheckedPaths are the files the note on unchecked changes stands for.
func (j *judge) uncheckedPaths() []string {
	var out []string
	for _, name := range j.uncheckedPkgs {
		for _, e := range j.unchecked[name] {
			out = append(out, e.Path)
		}
	}
	for _, e := range j.uncheckedFiles {
		out = append(out, e.Path)
	}
	return out
}

// subjectsOf lists what f is about: its scope when it is a change since the
// snapshot, the path its key names, its evidence paths, and for grouped
// package notes every file they stand for.
func (j *judge) subjectsOf(f *model.Finding) []string {
	var out []string
	if s, ok := j.acceptScope(f); ok {
		out = s.subjects()
	}
	if _, subj, ok := strings.Cut(f.Key, ":"); ok && strings.HasPrefix(subj, "/") {
		out = append(out, "path:"+subj)
	}
	for _, e := range f.Evidence {
		if e.Path != "" {
			out = append(out, "path:"+e.Path)
		}
	}
	if f.Key == "pkg.unverifiable" {
		for p := range j.unverified {
			out = append(out, "path:"+p)
		}
	}
	return out
}

func toSet(vals []string) map[string]bool {
	m := make(map[string]bool, len(vals))
	for _, v := range vals {
		if v != "" {
			m[v] = true
		}
	}
	return m
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		if k != "" {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}
