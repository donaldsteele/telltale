package collect

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/donaldsteele/telltale/internal/model"
)

const malloryUnits = "/home/mallory/.config/systemd/user"

func under(pf []model.PersistFile, dir string) (n, text int) {
	for _, f := range pf {
		if strings.HasPrefix(f.Path, dir+"/") {
			n++
			for _, l := range f.Lines {
				text += len(l) + 1
			}
		}
	}
	return n, text
}

func floodSkip(skips []model.Skip, dir string) bool {
	return slices.ContainsFunc(skips, func(s model.Skip) bool {
		return s.Check == persistCheck && strings.HasPrefix(s.Reason, dir+": stopped after ")
	})
}

// A user can fill their own unit directory. The walk stops at a fixed number
// of entries, and says so.
func TestPersistenceUserUnitDirEntryBudget(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < userDirMaxEntries+100; i++ {
		writeFile(t, root, fmt.Sprintf("%s/u%05d.service", malloryUnits, i), "[Service]\nExecStart=/bin/true\n")
	}
	writeFile(t, root, "home/mallory/.ssh/authorized_keys", "ssh-ed25519 AAAA mallory\n")
	res := PersistenceScan(root, mallory(), testKey)
	if n, _ := under(res.Files, malloryUnits); n > userDirMaxEntries || n < userDirMaxEntries-1 {
		t.Errorf("%d entries recorded from the flooded directory, want %d", n, userDirMaxEntries)
	}
	if !slices.Equal(res.Flooded, []string{malloryUnits}) {
		t.Errorf("Flooded = %v", res.Flooded)
	}
	if !floodSkip(res.Skips, malloryUnits) {
		t.Errorf("no skip for the flooded directory: %+v", res.Skips)
	}
	// The rest of the user's files are still read.
	if _, ok := findPersist(res.Files, "/home/mallory/.ssh/authorized_keys"); !ok {
		t.Errorf("authorized_keys lost behind the flood")
	}
}

// The reviewer's probe: thousands of files at the size limit. The text kept
// from one directory is bounded.
func TestPersistenceUserUnitDirTextBudget(t *testing.T) {
	root := t.TempDir()
	big := strings.Repeat(strings.Repeat("x", 99)+"\n", (200<<10)/100)
	for i := 0; i < 60; i++ { // 12 MiB
		writeFile(t, root, fmt.Sprintf("%s/u%03d.service", malloryUnits, i), big)
	}
	res := PersistenceScan(root, mallory(), testKey)
	if _, text := under(res.Files, malloryUnits); text > userDirMaxText+maxPersistBytes {
		t.Errorf("%d bytes of text kept from one user directory, limit %d", text, userDirMaxText)
	}
	if !slices.Contains(res.Flooded, malloryUnits) || !floodSkip(res.Skips, malloryUnits) {
		t.Errorf("Flooded = %v, skips %+v", res.Flooded, res.Skips)
	}
}

// All users together are bounded too, and the system's own units and every
// user's shell files and keys are read whatever the users did.
func TestPersistenceUsersTextBudget(t *testing.T) {
	old := usersMaxText
	usersMaxText = 1 << 20
	t.Cleanup(func() { usersMaxText = old })
	root := t.TempDir()
	big := strings.Repeat(strings.Repeat("x", 99)+"\n", (200<<10)/100)
	var users []model.User
	for u := 0; u < 4; u++ {
		home := fmt.Sprintf("/home/u%d", u)
		users = append(users, model.User{Name: fmt.Sprintf("u%d", u), UID: 5000 + u, Home: home})
		for i := 0; i < 3; i++ { // 600 KiB each user
			writeFile(t, root, fmt.Sprintf("%s/.config/systemd/user/s%d.service", home, i), big)
		}
		writeFile(t, root, home+"/.bashrc", "alias ll='ls -l'\n")
	}
	writeFile(t, root, "etc/systemd/system/real.service", "[Service]\nExecStart=/usr/bin/real\n")
	res := PersistenceScan(root, users, testKey)
	total := 0
	for _, u := range users {
		_, text := under(res.Files, u.Home+"/.config/systemd/user")
		total += text
		if f, ok := findPersist(res.Files, u.Home+"/.bashrc"); !ok || len(f.Lines) != 1 {
			t.Errorf("%s/.bashrc not read: %+v", u.Home, f)
		}
	}
	if total > usersMaxText+maxPersistBytes {
		t.Errorf("%d bytes of text kept from all users, limit %d", total, usersMaxText)
	}
	if len(res.Flooded) == 0 {
		t.Errorf("nothing reported as flooded")
	}
	if f, ok := findPersist(res.Files, "/etc/systemd/system/real.service"); !ok || len(f.Lines) != 2 {
		t.Errorf("system unit: %+v", f)
	}
}

// In a user's unit directory text is kept only for files systemd would read
// as units; anything else is recorded by hash.
func TestPersistenceUserUnitDirKeepsTextOnlyForUnits(t *testing.T) {
	root := t.TempDir()
	for _, n := range []string{"a.service", "a.timer", "a.socket", "a.path", "a.mount", "a.target", "a.service.d/override.conf"} {
		writeFile(t, root, malloryUnits+"/"+n, "[Unit]\nDescription=x\n")
	}
	writeFile(t, root, malloryUnits+"/notes.txt", "not a unit\n")
	writeFile(t, root, malloryUnits+"/a.service.d/readme", "not a drop-in\n")
	res := PersistenceScan(root, mallory(), testKey)
	for _, n := range []string{"a.service", "a.timer", "a.socket", "a.path", "a.mount", "a.target", "a.service.d/override.conf"} {
		if f, ok := findPersist(res.Files, malloryUnits+"/"+n); !ok || len(f.Lines) != 2 {
			t.Errorf("%s: %+v ok=%v", n, f, ok)
		}
	}
	for _, n := range []string{"notes.txt", "a.service.d/readme"} {
		f, ok := findPersist(res.Files, malloryUnits+"/"+n)
		if !ok || len(f.Lines) != 0 || f.SHA256 == "" {
			t.Errorf("%s: want hash and no text, got %+v ok=%v", n, f, ok)
		}
	}
	if len(res.Flooded) != 0 || len(res.Skips) != 0 {
		t.Errorf("flooded %v skips %+v", res.Flooded, res.Skips)
	}
}

// ~/.config/systemd -> /run makes ~/.config/systemd/user read as /run/user,
// every user's runtime directory. The user's own link is followed, but only
// into what that user could read: another user's runtime directory is not.
func TestPersistenceUserUnitDirBehindUserLink(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "run/user/1000/systemd/private.service", "[Service]\nExecStart=/bin/SECRETHASHVALUE\n")
	writeFile(t, root, "run/user/1000/token.service", "SECRETHASHVALUE\n")
	if err := os.Chmod(filepath.Join(root, "run/user/1000"), 0o700); err != nil {
		t.Fatal(err)
	}
	symlinkAt(t, root, "home/mallory/.config/systemd", "/run")
	ownedBy(t, malloryUID, filepath.Join(root, "home/mallory"), filepath.Join(root, "home/mallory/.config"), filepath.Join(root, "home/mallory/.config/systemd"))
	res := PersistenceScan(root, mallory(), testKey)
	leaked(t, res.Files, res.Skips, "SECRETHASHVALUE")
	for _, f := range res.Files {
		if strings.HasPrefix(f.Path, malloryUnits+"/1000/") {
			t.Errorf("read inside another user's closed directory: %+v", f)
		}
	}
}

// The reviewer's probe: one ln -s must not hide a user's unit. A user's own
// link on the way to that user's unit directory (~/.config kept in a
// dotfiles directory), or the unit directory itself being the user's link,
// is followed, and the unit is read like any other.
func TestPersistenceUserUnitBehindOwnLinkIsRead(t *testing.T) {
	for _, tc := range []struct{ name, link, target, unit string }{
		{"~/.config is a link", "home/mallory/.config", "dotfiles/config", "home/mallory/dotfiles/config/systemd/user/evil.service"},
		{"the unit directory is a link", "home/mallory/.config/systemd/user", "../../units", "home/mallory/units/evil.service"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, root, tc.unit, "[Service]\nExecStart=/tmp/.x\n")
			symlinkAt(t, root, tc.link, tc.target)
			owned := []string{filepath.Join(root, tc.link)}
			for d := filepath.Dir(filepath.Join(root, tc.unit)); d != filepath.Join(root, "home"); d = filepath.Dir(d) {
				owned = append(owned, d)
			}
			owned = append(owned, filepath.Join(root, tc.unit))
			for d := filepath.Dir(filepath.Join(root, tc.link)); d != filepath.Join(root, "home"); d = filepath.Dir(d) {
				owned = append(owned, d)
			}
			ownedBy(t, malloryUID, owned...)
			res := PersistenceScan(root, mallory(), testKey)
			f, ok := findPersist(res.Files, malloryUnits+"/evil.service")
			if !ok || len(f.Lines) != 2 || f.Lines[1] != "ExecStart=/tmp/.x" {
				t.Errorf("the unit behind the user's own link was not read: %+v ok=%v\nskips %+v", f, ok, res.Skips)
			}
			if len(res.Refused) != 0 {
				t.Errorf("refused %v", res.Refused)
			}
		})
	}
}

// A link that is not followed is never silent: the link is recorded as a
// persistence entry with its target, and named for a note in the report.
func TestPersistenceRefusedUnitLinkIsRecorded(t *testing.T) {
	// The user's own link into a directory of /etc the user cannot read.
	root := t.TempDir()
	writeFile(t, root, "etc/private/units/x.service", "[Service]\nExecStart=/bin/SECRETHASHVALUE\n")
	if err := os.Chmod(filepath.Join(root, "etc/private"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "home/mallory/.config/systemd"), 0o755); err != nil {
		t.Fatal(err)
	}
	symlinkAt(t, root, "home/mallory/.config/systemd/user", "/etc/private/units")
	ownedBy(t, malloryUID, filepath.Join(root, "home/mallory"), filepath.Join(root, "home/mallory/.config"), filepath.Join(root, "home/mallory/.config/systemd"), filepath.Join(root, "home/mallory/.config/systemd/user"))
	res := PersistenceScan(root, mallory(), testKey)
	leaked(t, res.Files, res.Skips, "SECRETHASHVALUE")
	f, ok := findPersist(res.Files, malloryUnits)
	if !ok || f.Kind != model.PersistKindSystemdUnit || len(f.Lines) != 1 || f.Lines[0] != "/etc/private/units" {
		t.Errorf("the refused link is not recorded: %+v ok=%v", f, ok)
	}
	if !slices.Contains(res.Refused, malloryUnits) {
		t.Errorf("Refused = %v", res.Refused)
	}
	if n, _ := under(res.Files, malloryUnits); n != 0 {
		t.Errorf("%d entries read behind the refused link", n)
	}

	// Another account's link on the way.
	root = t.TempDir()
	writeFile(t, root, "home/mallory/real/systemd/user/evil.service", "[Service]\nExecStart=/tmp/.x\n")
	symlinkAt(t, root, "home/mallory/.config", "real")
	ownedBy(t, malloryUID+1, filepath.Join(root, "home/mallory/.config"))
	res = PersistenceScan(root, mallory(), testKey)
	if f, ok := findPersist(res.Files, "/home/mallory/.config"); !ok || len(f.Lines) != 1 || f.Lines[0] != "real" {
		t.Errorf("another account's link is not recorded: %+v ok=%v", f, ok)
	}
	if !slices.Contains(res.Refused, "/home/mallory/.config") || !persistSkip(res.Skips, malloryUnits, skipUserLinkPath) {
		t.Errorf("Refused = %v, skips %+v", res.Refused, res.Skips)
	}
}

// A unit directory that is itself a link: walked where it leads when root
// made the link and it stays inside the system directories, else not walked,
// with a Skip.
func TestPersistenceLinkedUnitDirectory(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "usr/lib/systemd/alt/x.service", "[Service]\nExecStart=/usr/bin/x\n")
	symlinkAt(t, root, "etc/systemd/system", "/usr/lib/systemd/alt")
	res := PersistenceScan(root, nil, testKey)
	if f, ok := findPersist(res.Files, "/etc/systemd/system/x.service"); !ok || len(f.Lines) != 2 {
		t.Errorf("unit behind root's directory link into the system directories: %+v ok=%v (skips %+v)", f, ok, res.Skips)
	}

	root = t.TempDir()
	writeFile(t, root, "srv/units/x.service", "[Service]\nExecStart=/srv/x\n")
	symlinkAt(t, root, "etc/systemd/system", "/srv/units")
	res = PersistenceScan(root, nil, testKey)
	if _, ok := findPersist(res.Files, "/etc/systemd/system/x.service"); ok {
		t.Errorf("unit directory linked outside the system directories was walked")
	}
	if !persistSkip(res.Skips, "/etc/systemd/system", skipLinkedUnitDir) {
		t.Errorf("skips %+v", res.Skips)
	}

	root = t.TempDir()
	writeFile(t, root, "home/mallory/units/x.service", "[Service]\nExecStart=/bin/x\n")
	if err := os.MkdirAll(filepath.Join(root, "home/mallory/.config/systemd"), 0o755); err != nil {
		t.Fatal(err)
	}
	symlinkAt(t, root, "home/mallory/.config/systemd/user", "../../units")
	ownedBy(t, malloryUID+1, filepath.Join(root, "home/mallory/.config/systemd/user"))
	res = PersistenceScan(root, mallory(), testKey)
	if n, _ := under(res.Files, malloryUnits); n != 0 {
		t.Errorf("a unit directory linked by another account was walked")
	}
	if !persistSkip(res.Skips, malloryUnits, skipLinkedUnitDir) {
		t.Errorf("skips %+v", res.Skips)
	}
}
