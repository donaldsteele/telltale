// Package checklist is telltale's hardening checklist. Each item judges one
// setting on a collected machine. Items follow the DISA STIG for Ubuntu where
// a rule applies (STIGs are public domain) and add telltale's own items for
// the settings attackers loosen to keep a way in.
//
// A failing item is a weak setting; an item that passed in the known-good
// snapshot and fails now is tampering. An item whose input was not collected
// is skipped with a reason, never guessed.
package checklist

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/donaldsteele/telltale/internal/escape"
	"github.com/donaldsteele/telltale/internal/model"
)

// Item is one checklist item.
//
// Fix is an exact shell command that fixes the setting on any machine;
// FixFor builds a narrower command from the values seen on one machine
// (the file and line that set an sshd keyword, the accounts or files
// involved). Check returns skip != "" when its input was not collected; pass
// and observed are then meaningless.
type Item struct {
	ID    string
	Title string
	Why   string
	Fix   string
	Refs  []string
	Check func(c *model.Collection, ctx model.ScanContext) (pass bool, observed string, skip string)

	fixFor func(c *model.Collection, ctx model.ScanContext) string
}

// FixFor returns the fix command for the machine in c: built from the
// observed values when the item knows how, otherwise Fix.
func (it Item) FixFor(c *model.Collection, ctx model.ScanContext) string {
	if it.fixFor != nil && c != nil {
		if f := it.fixFor(c, ctx); f != "" {
			return f
		}
	}
	return it.Fix
}

// Items returns every checklist item in report order, with its STIG
// references. The slice and its Refs are fresh copies.
func Items() []Item {
	out := make([]Item, len(items))
	for i, it := range items {
		it.Refs = append([]string(nil), stigRefs[it.ID]...)
		out[i] = it
	}
	return out
}

// ByID returns the item with the given ID.
func ByID(id string) (Item, bool) {
	for _, it := range Items() {
		if it.ID == id {
			return it, true
		}
	}
	return Item{}, false
}

// Evaluate runs every item on c, in Items order. A nil collection counts as
// one where nothing was collected.
func Evaluate(c *model.Collection, ctx model.ScanContext) []model.CheckResult {
	if c == nil {
		c = &model.Collection{}
	}
	out := make([]model.CheckResult, 0, len(items))
	for _, it := range items {
		pass, observed, skip := it.Check(c, ctx)
		if skip != "" {
			pass, observed = false, ""
		}
		out = append(out, model.CheckResult{ID: it.ID, Pass: pass, Observed: observed, Skipped: skip})
	}
	return out
}

// shellQuote returns s ready to paste into a POSIX shell command line.
func shellQuote(s string) string {
	if s != "" && strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_./:@%+=,-", r))
	}) < 0 {
		return s
	}
	return escape.ShellQuote(s)
}

func quoteAll(ss []string) string {
	q := make([]string, len(ss))
	for i, s := range ss {
		q[i] = shellQuote(s)
	}
	return strings.Join(q, " ")
}

// listCap joins up to n items and says how many more there are.
func listCap(ss []string, n int) string {
	if len(ss) <= n {
		return strings.Join(ss, ", ")
	}
	return fmt.Sprintf("%s (and %d more)", strings.Join(ss[:n], ", "), len(ss)-n)
}

// fileStat returns the inventory entry for p, following one symlink.
// reason is non-empty when there is no usable stat data.
func fileStat(c *model.Collection, p string) (model.FileEntry, string) {
	e, ok := findFile(c, p)
	if ok && e.Type == "symlink" {
		t := e.Target
		if !path.IsAbs(t) {
			t = path.Join(path.Dir(p), t)
		}
		if e, ok = findFile(c, path.Clean(t)); !ok {
			return e, p + " is a symlink to " + t + ", which is not in the file inventory"
		}
	}
	if !ok {
		return e, p + " is not in the file inventory"
	}
	if e.Mode == 0 {
		return e, "could not stat " + p + ": " + e.Err
	}
	return e, ""
}

func findFile(c *model.Collection, p string) (model.FileEntry, bool) {
	for _, e := range c.Files {
		if e.Path == p {
			return e, true
		}
	}
	return model.FileEntry{}, false
}

func userName(c *model.Collection, uid uint32) string {
	for _, u := range c.Accounts.Users {
		if u.UID == int(uid) && realAccount(u) {
			return u.Name
		}
	}
	return fmt.Sprint(uid)
}

func groupName(c *model.Collection, gid uint32) string {
	for _, g := range c.Accounts.Groups {
		if g.GID == int(gid) {
			return g.Name
		}
	}
	return fmt.Sprint(gid)
}

func groupID(c *model.Collection, name string) (uint32, bool) {
	for _, g := range c.Accounts.Groups {
		if g.Name == name {
			return uint32(g.GID), true
		}
	}
	return 0, false
}

// describeOwner is "mode 0640, owner root" plus ", group shadow" when
// withGroup is set.
func describeOwner(c *model.Collection, e model.FileEntry, withGroup bool) string {
	s := fmt.Sprintf("mode %04o, owner %s", e.Mode&0o7777, userName(c, e.UID))
	if withGroup {
		s += ", group " + groupName(c, e.GID)
	}
	return s
}

// realAccount excludes NIS compat lines ("+", "+name", "-name"), which are
// not local accounts.
func realAccount(u model.User) bool {
	return u.Name != "" && u.Name[0] != '+' && u.Name[0] != '-'
}

func accounts(c *model.Collection) []model.User {
	var out []model.User
	for _, u := range c.Accounts.Users {
		if realAccount(u) {
			out = append(out, u)
		}
	}
	return out
}

// shadowMissing explains why there is no password data, or returns "".
func shadowMissing(c *model.Collection) string {
	for _, s := range c.Skipped {
		if s.Check == "accounts" && strings.HasPrefix(s.Reason, "/etc/shadow") {
			return "could not read " + s.Reason
		}
	}
	us := accounts(c)
	if len(us) == 0 {
		return "no accounts collected"
	}
	for _, u := range us {
		if u.Password.Set || u.Password.Locked || u.Password.LastChange >= 0 {
			return ""
		}
	}
	return "no password data collected (/etc/shadow was not read)"
}

func sortedUnique(ss []string) []string {
	sort.Strings(ss)
	out := ss[:0]
	for i, s := range ss {
		if i == 0 || s != ss[i-1] {
			out = append(out, s)
		}
	}
	return out
}

// A NUL byte cannot be part of a shell word, so a value holding one gets no
// command: it is left out and named in a comment line instead.
func nulNote(s string) string {
	return "# " + escape.Terminal(s) + " contains a NUL byte and cannot be typed safely; inspect it by hand"
}

// splitNUL separates the values a shell can be given from those it cannot.
func splitNUL(vals []string) (kept, notes []string) {
	for _, v := range vals {
		if escape.Quotable(v) {
			kept = append(kept, v)
		} else {
			notes = append(notes, nulNote(v))
		}
	}
	return kept, notes
}

// joinNotes puts the comment lines after a command (or alone, when every
// value was left out).
func joinNotes(cmd string, notes []string) string {
	if len(notes) == 0 {
		return cmd
	}
	if cmd == "" {
		return strings.Join(notes, "\n")
	}
	return cmd + "\n" + strings.Join(notes, "\n")
}

// overPaths builds a command over a list of machine values; build gets them
// quoted and joined. Values with a NUL are left out.
func overPaths(vals []string, build func(quoted string) string) string {
	kept, notes := splitNUL(vals)
	cmd := ""
	if len(kept) > 0 {
		cmd = build(quoteAll(kept))
	}
	return joinNotes(cmd, notes)
}

// escapeAll joins names for a comment line: a name from the machine must not
// end the comment.
func escapeAll(ss []string) string {
	e := make([]string, len(ss))
	for i, s := range ss {
		e[i] = escape.Terminal(s)
	}
	return strings.Join(e, ", ")
}
