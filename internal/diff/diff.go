// Package diff compares a machine's current collection with its known-good
// snapshot and lists every difference as a typed Change. It does not judge
// them; ranking and explaining package updates is the judge's job.
package diff

import (
	"fmt"
	"sort"
	"strings"

	"github.com/donaldsteele/telltale/internal/model"
)

// Change kinds.
const (
	FileAdded       = "file_added"
	FileRemoved     = "file_removed"
	FileModified    = "file_modified"
	PersistChanged  = "persist_changed"
	UserAdded       = "user_added"
	UserRemoved     = "user_removed"
	UserChanged     = "user_changed"
	GroupChanged    = "group_changed"
	PkgUpgraded     = "pkg_upgraded"
	PkgDowngraded   = "pkg_downgraded"
	PkgInstalled    = "pkg_installed"
	PkgRemoved      = "pkg_removed"
	ModuleAdded     = "module_added"
	ListenerAdded   = "listener_added"
	CheckRegressed  = "check_regressed"
	CheckFixed      = "check_fixed"
	absent          = "absent"
	passwordChanged = "password changed"
)

var kindOrder = map[string]int{}

func init() {
	for i, k := range []string{FileAdded, FileRemoved, FileModified, PersistChanged,
		UserAdded, UserRemoved, UserChanged, GroupChanged,
		PkgUpgraded, PkgDowngraded, PkgInstalled, PkgRemoved,
		ModuleAdded, ListenerAdded, CheckRegressed, CheckFixed} {
		kindOrder[k] = i
	}
}

// PkgChange carries the package behind a pkg_* change. Old is empty for an
// install and New is empty for a removal.
type PkgChange struct {
	Name string
	Arch string
	Old  string
	New  string
}

// Change is one difference between the snapshot and the current state.
type Change struct {
	Kind    string
	Subject string
	Before  string
	After   string
	Lines   []LineChange
	Pkg     *PkgChange
	CheckID string
}

// Compare lists every change from old to the current collection and checks,
// ordered by kind then subject.
func Compare(old *model.Snapshot, cur *model.Collection, curChecks []model.CheckResult) []Change {
	var out []Change
	var oc model.Collection
	if old != nil && old.Collection != nil {
		oc = *old.Collection
	}
	if cur == nil {
		cur = &model.Collection{}
	}
	out = append(out, compareFiles(oc.Files, cur.Files, append(append([]string{}, oc.SweepIncomplete...), cur.SweepIncomplete...))...)
	out = append(out, comparePersist(oc.Persist, cur.Persist)...)
	out = append(out, compareAccounts(oc.Accounts, cur.Accounts)...)
	out = append(out, comparePackages(oc.Packages.Installed, cur.Packages.Installed)...)
	out = append(out, compareRuntime(oc.Runtime, cur.Runtime)...)
	if old != nil {
		out = append(out, compareChecks(old.Checks, curChecks)...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if ki, kj := kindOrder[out[i].Kind], kindOrder[out[j].Kind]; ki != kj {
			return ki < kj
		}
		return out[i].Subject < out[j].Subject
	})
	return out
}

func short(h string) string {
	if h == "" {
		return "-"
	}
	if len(h) > 12 {
		h = h[:12] + "…"
	}
	return h
}

// summary joins the changed fields of a record, in order, with spaces.
type summary struct{ before, after []string }

func (s *summary) add(field, b, a string) {
	s.before = append(s.before, strings.TrimSpace(field+" "+b))
	s.after = append(s.after, strings.TrimSpace(field+" "+a))
}

func (s *summary) join() (string, string) {
	return strings.Join(s.before, " "), strings.Join(s.after, " ")
}

// underAny reports whether p is one of prefixes or below one.
func underAny(p string, prefixes []string) bool {
	for _, d := range prefixes {
		if p == d || strings.HasPrefix(p, strings.TrimRight(d, "/")+"/") {
			return true
		}
	}
	return false
}

// compareFiles compares two file inventories. incomplete holds the path
// prefixes where either sweep stopped early: an entry found by the sweep that
// exists on one side only, under such a prefix, may simply not have been looked
// at, so it is not reported.
func compareFiles(old, cur []model.FileEntry, incomplete []string) []Change {
	om := make(map[string]model.FileEntry, len(old))
	for _, f := range old {
		om[f.Path] = f
	}
	seen := make(map[string]bool, len(cur))
	var out []Change
	for _, n := range cur {
		seen[n.Path] = true
		o, ok := om[n.Path]
		if !ok && n.Supplementary {
			continue // exists only while something refers to it
		}
		if !ok {
			if n.Swept && underAny(n.Path, incomplete) {
				continue
			}
			out = append(out, Change{Kind: FileAdded, Subject: n.Path, After: describeFile(n)})
			continue
		}
		var s summary
		if n.Err != "" && o.Err == "" {
			s.add("err", "", n.Err)
		} else {
			if o.SHA256 != n.SHA256 {
				s.add("sha256", short(o.SHA256), short(n.SHA256))
			}
			if o.Size != n.Size {
				s.add("size", fmt.Sprint(o.Size), fmt.Sprint(n.Size))
			}
			if o.Mode&07777 != n.Mode&07777 {
				s.add("mode", fmt.Sprintf("%04o", o.Mode&07777), fmt.Sprintf("%04o", n.Mode&07777))
			}
			if o.UID != n.UID || o.GID != n.GID {
				s.add("owner", fmt.Sprintf("%d:%d", o.UID, o.GID), fmt.Sprintf("%d:%d", n.UID, n.GID))
			}
			if o.Flags != n.Flags {
				s.add("flags", fmt.Sprintf("%#x", o.Flags), fmt.Sprintf("%#x", n.Flags))
			}
			if o.Caps != n.Caps {
				s.add("caps", orNone(o.Caps), orNone(n.Caps))
			}
			if o.Type != n.Type || o.Target != n.Target {
				s.add("type", typeTarget(o), typeTarget(n))
			}
			if o.Err != n.Err {
				s.add("err", o.Err, n.Err)
			}
		}
		if len(s.before) > 0 {
			b, a := s.join()
			out = append(out, Change{Kind: FileModified, Subject: n.Path, Before: b, After: a})
		}
	}
	for _, o := range old {
		if !seen[o.Path] && !o.Supplementary && !(o.Swept && underAny(o.Path, incomplete)) {
			out = append(out, Change{Kind: FileRemoved, Subject: o.Path, Before: describeFile(o)})
		}
	}
	return out
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func typeTarget(f model.FileEntry) string {
	if f.Target != "" {
		return f.Type + " -> " + f.Target
	}
	return f.Type
}

func describeFile(f model.FileEntry) string {
	return fmt.Sprintf("%s mode %04o owner %d:%d sha256 %s", typeTarget(f), f.Mode&07777, f.UID, f.GID, short(f.SHA256))
}

func comparePersist(old, cur []model.PersistFile) []Change {
	om := make(map[string]model.PersistFile, len(old))
	for _, f := range old {
		om[f.Path] = f
	}
	seen := make(map[string]bool, len(cur))
	var out []Change
	for _, n := range cur {
		seen[n.Path] = true
		o, ok := om[n.Path]
		if !ok {
			out = append(out, Change{Kind: PersistChanged, Subject: n.Path, Before: absent,
				After: short(n.SHA256), Lines: diffLines(nil, n.Lines)})
			continue
		}
		lines := diffLines(o.Lines, n.Lines)
		var s summary
		if o.Mode&07777 != n.Mode&07777 {
			s.add("mode", fmt.Sprintf("%04o", o.Mode&07777), fmt.Sprintf("%04o", n.Mode&07777))
		}
		if o.UID != n.UID {
			s.add("owner", fmt.Sprint(o.UID), fmt.Sprint(n.UID))
		}
		contentChanged := len(lines) > 0 || o.SHA256 != n.SHA256
		switch {
		case len(s.before) > 0:
			if contentChanged {
				s.before = append([]string{"sha256 " + short(o.SHA256)}, s.before...)
				s.after = append([]string{"sha256 " + short(n.SHA256)}, s.after...)
			}
			b, a := s.join()
			out = append(out, Change{Kind: PersistChanged, Subject: n.Path, Before: b, After: a, Lines: lines})
		case contentChanged:
			out = append(out, Change{Kind: PersistChanged, Subject: n.Path, Before: o.SHA256, After: n.SHA256, Lines: lines})
		}
	}
	for _, o := range old {
		if !seen[o.Path] {
			out = append(out, Change{Kind: PersistChanged, Subject: o.Path, Before: short(o.SHA256),
				After: absent, Lines: diffLines(o.Lines, nil)})
		}
	}
	return out
}

func compareAccounts(old, cur model.Accounts) []Change {
	// The first entry for a name counts, as for glibc's lookups; later
	// duplicates are reported by the collector, not compared here.
	om := make(map[string]model.User, len(old.Users))
	for _, u := range old.Users {
		if _, dup := om[u.Name]; !dup {
			om[u.Name] = u
		}
	}
	seen := make(map[string]bool, len(cur.Users))
	var out []Change
	for _, n := range cur.Users {
		if seen[n.Name] {
			continue
		}
		seen[n.Name] = true
		o, ok := om[n.Name]
		if !ok {
			out = append(out, Change{Kind: UserAdded, Subject: n.Name,
				After: fmt.Sprintf("uid %d gid %d shell %s home %s", n.UID, n.GID, n.Shell, n.Home)})
			continue
		}
		var s summary
		if o.UID != n.UID {
			s.add("uid", fmt.Sprint(o.UID), fmt.Sprint(n.UID))
		}
		if o.GID != n.GID {
			s.add("gid", fmt.Sprint(o.GID), fmt.Sprint(n.GID))
		}
		if o.Shell != n.Shell {
			s.add("shell", o.Shell, n.Shell)
		}
		if o.Home != n.Home {
			s.add("home", o.Home, n.Home)
		}
		if o.Password.Digest != n.Password.Digest {
			s.before = append(s.before, "password")
			s.after = append(s.after, passwordChanged)
		}
		if o.Password.Locked != n.Password.Locked {
			s.add("locked", fmt.Sprint(o.Password.Locked), fmt.Sprint(n.Password.Locked))
		}
		if o.Password.Set != n.Password.Set {
			s.add("set", fmt.Sprint(o.Password.Set), fmt.Sprint(n.Password.Set))
		}
		if len(s.before) > 0 {
			b, a := s.join()
			out = append(out, Change{Kind: UserChanged, Subject: n.Name, Before: b, After: a})
		}
	}
	gone := map[string]bool{}
	for _, o := range old.Users {
		if !seen[o.Name] && !gone[o.Name] {
			gone[o.Name] = true
			out = append(out, Change{Kind: UserRemoved, Subject: o.Name,
				Before: fmt.Sprintf("uid %d gid %d shell %s home %s", o.UID, o.GID, o.Shell, o.Home)})
		}
	}
	return append(out, compareGroups(old.Groups, cur.Groups)...)
}

// describeGroup summarises a group. The gshadow part is included only when
// withShadow is set, which the comparison does only when both sides read
// gshadow, so a scan that could not read it does not show every group as
// changed.
func describeGroup(g model.Group, withShadow bool) string {
	s := fmt.Sprintf("gid %d members %s", g.GID, sortedJoin(g.Members))
	if withShadow && g.Shadow != nil {
		pw := "no password"
		if g.Shadow.PasswordSet {
			pw = "password set"
		}
		s += fmt.Sprintf(" gshadow %s admins %s members %s", pw, sortedJoin(g.Shadow.Admins), sortedJoin(g.Shadow.Members))
	}
	return s
}

func sortedJoin(ss []string) string {
	m := append([]string(nil), ss...)
	sort.Strings(m)
	return strings.Join(m, ",")
}

func compareGroups(old, cur []model.Group) []Change {
	om := make(map[string]model.Group, len(old))
	for _, g := range old {
		if _, dup := om[g.Name]; !dup {
			om[g.Name] = g
		}
	}
	seen := make(map[string]bool, len(cur))
	var out []Change
	for _, n := range cur {
		if seen[n.Name] {
			continue
		}
		seen[n.Name] = true
		o, ok := om[n.Name]
		if !ok {
			out = append(out, Change{Kind: GroupChanged, Subject: n.Name, Before: absent, After: describeGroup(n, true)})
			continue
		}
		both := o.Shadow != nil && n.Shadow != nil
		if b, a := describeGroup(o, both), describeGroup(n, both); b != a {
			out = append(out, Change{Kind: GroupChanged, Subject: n.Name, Before: b, After: a})
		}
	}
	gone := map[string]bool{}
	for _, o := range old {
		if !seen[o.Name] && !gone[o.Name] {
			gone[o.Name] = true
			out = append(out, Change{Kind: GroupChanged, Subject: o.Name, Before: describeGroup(o, true), After: absent})
		}
	}
	return out
}

func comparePackages(old, cur []model.Package) []Change {
	type key struct{ name, arch string }
	om := make(map[key]model.Package, len(old))
	for _, p := range old {
		om[key{p.Name, p.Arch}] = p
	}
	seen := make(map[key]bool, len(cur))
	var out []Change
	for _, n := range cur {
		k := key{n.Name, n.Arch}
		seen[k] = true
		o, ok := om[k]
		if !ok {
			out = append(out, Change{Kind: PkgInstalled, Subject: n.Name, After: n.Version,
				Pkg: &PkgChange{Name: n.Name, Arch: n.Arch, New: n.Version}})
			continue
		}
		c := CompareVersions(o.Version, n.Version)
		if c == 0 {
			continue
		}
		kind := PkgUpgraded
		if c > 0 {
			kind = PkgDowngraded
		}
		out = append(out, Change{Kind: kind, Subject: n.Name, Before: o.Version, After: n.Version,
			Pkg: &PkgChange{Name: n.Name, Arch: n.Arch, Old: o.Version, New: n.Version}})
	}
	for _, o := range old {
		if !seen[key{o.Name, o.Arch}] {
			out = append(out, Change{Kind: PkgRemoved, Subject: o.Name, Before: o.Version,
				Pkg: &PkgChange{Name: o.Name, Arch: o.Arch, Old: o.Version}})
		}
	}
	return out
}

// listenKey identifies a listener by protocol, family and local address;
// the key doubles as the change subject, e.g. "tcp6 [::]:22".
func listenKey(s model.Socket) string {
	proto := strings.TrimSuffix(s.Proto, "6")
	if strings.HasPrefix(s.Local, "[") || strings.HasSuffix(s.Proto, "6") {
		proto += "6"
	}
	return proto + " " + s.Local
}

func compareRuntime(old, cur model.Runtime) []Change {
	var out []Change
	had := make(map[string]bool)
	for _, s := range old.Sockets {
		if s.Listening {
			had[listenKey(s)] = true
		}
	}
	exe := make(map[int]string, len(cur.Processes))
	for _, p := range cur.Processes {
		exe[p.PID] = p.Exe
	}
	for _, s := range cur.Sockets {
		if !s.Listening {
			continue
		}
		k := listenKey(s)
		if had[k] {
			continue
		}
		had[k] = true
		out = append(out, Change{Kind: ListenerAdded, Subject: k, After: exe[s.PID]})
	}
	mods := make(map[string]bool, len(old.Modules))
	for _, m := range old.Modules {
		mods[m.Name] = true
	}
	for _, m := range cur.Modules {
		if !mods[m.Name] {
			mods[m.Name] = true
			out = append(out, Change{Kind: ModuleAdded, Subject: m.Name, After: m.File})
		}
	}
	return out
}

func compareChecks(old, cur []model.CheckResult) []Change {
	om := make(map[string]model.CheckResult, len(old))
	for _, c := range old {
		om[c.ID] = c
	}
	var out []Change
	for _, n := range cur {
		o, ok := om[n.ID]
		if !ok || o.Skipped != "" || n.Skipped != "" || o.Pass == n.Pass {
			continue
		}
		kind := CheckFixed
		if o.Pass {
			kind = CheckRegressed
		}
		out = append(out, Change{Kind: kind, Subject: n.ID, CheckID: n.ID, Before: o.Observed, After: n.Observed})
	}
	return out
}
