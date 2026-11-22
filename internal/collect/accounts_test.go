package collect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/donaldsteele/telltale/internal/model"
)

var testKey = []byte("test-key")

func userByName(a model.Accounts, name string) (model.User, bool) {
	for _, u := range a.Users {
		if u.Name == name {
			return u, true
		}
	}
	return model.User{}, false
}

func TestAccountsShadowReduced(t *testing.T) {
	acc, _ := Accounts("testdata/root1", testKey)
	root, ok := userByName(acc, "root")
	if !ok {
		t.Fatal("no root user")
	}
	p := root.Password
	if !p.Set || p.Locked || p.Algo != "yescrypt" || !strings.HasPrefix(p.Digest, "h:") {
		t.Fatalf("root password = %+v", p)
	}
	if p.LastChange != 19800 || p.MaxDays != 99999 {
		t.Fatalf("ageing = %+v", p)
	}
	js, _ := json.Marshal(acc)
	for _, secret := range []string{"Qm1mWsSx0kQWm0g0Yq6Gn", "k4wZtNn1XJp0V7dEu5xo3b9m2Qe2uQe0Hn6jvuRLtq8", "hashhashhash", "lockedhashvalue"} {
		if strings.Contains(string(js), secret) {
			t.Fatalf("result contains %q", secret)
		}
	}
	alice, _ := userByName(acc, "alice")
	if alice.Password.Algo != "sha512" || alice.UID != 1000 || alice.Home != "/home/alice" || alice.Shell != "/bin/bash" {
		t.Fatalf("alice = %+v", alice)
	}
	if len(acc.Groups) != 5 {
		t.Fatalf("groups = %+v", acc.Groups)
	}
	for _, g := range acc.Groups {
		if g.Name == "staff" && (g.GID != 50 || len(g.Members) != 2 || g.Members[1] != "bob") {
			t.Fatalf("staff = %+v", g)
		}
	}
}

func TestAccountsLockedAndEmpty(t *testing.T) {
	acc, _ := Accounts("testdata/root1", testKey)
	bob, _ := userByName(acc, "bob")
	if !bob.Password.Locked || !bob.Password.Set || bob.Password.Algo != "yescrypt" {
		t.Fatalf("bob = %+v", bob.Password)
	}
	nobody, _ := userByName(acc, "nobody")
	if !nobody.Password.Locked || nobody.Password.Set || nobody.Password.Algo != "none" || nobody.Password.Digest != "" || nobody.Password.MaxDays != -1 {
		t.Fatalf("nobody = %+v", nobody.Password)
	}
	daemon, _ := userByName(acc, "daemon")
	if !daemon.Password.Locked || daemon.Password.Set {
		t.Fatalf("daemon = %+v", daemon.Password)
	}
	ben, _ := userByName(acc, "ben")
	if ben.Password.Set || ben.Password.Locked || ben.Password.Algo != "none" || ben.Password.Digest != "" {
		t.Fatalf("ben = %+v", ben.Password)
	}
}

func TestShadowAlgo(t *testing.T) {
	for in, want := range map[string]string{
		"$y$j9T$x": "yescrypt", "$6$s$h": "sha512", "$5$s$h": "sha256", "$1$s$h": "md5",
		"$2b$12$x": "bcrypt", "$2a$12$x": "bcrypt", "$2y$12$x": "bcrypt",
		"abJnggxhB/yWI": "des", "": "none", "*": "none", "!": "none", "!!": "none", "!$6$s$h": "sha512",
	} {
		if got := shadowAlgo(in); got != want {
			t.Errorf("shadowAlgo(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAccountsPasswdFieldWins(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	passwd := "alice::1000:1000::/home/alice:/bin/sh\nbob:$6$s$PASSWDHASH:1001:1001::/home/bob:/bin/sh\ncarol:x:1002:1002::/home/carol:/bin/sh\n"
	shadow := "alice:$6$salt$SHADOWHASH:19000:0:99999:7:::\ncarol:$6$salt$CAROLHASH:19000:0:99999:7:::\n"
	for n, c := range map[string]string{"passwd": passwd, "shadow": shadow, "group": ""} {
		if err := os.WriteFile(filepath.Join(root, "etc", n), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	acc, _ := Accounts(root, testKey)
	alice, _ := userByName(acc, "alice")
	bob, _ := userByName(acc, "bob")
	carol, _ := userByName(acc, "carol")
	if alice.Password.Set || alice.Password.Algo != "none" {
		t.Errorf("alice = %+v", alice.Password)
	}
	if !bob.Password.Set || bob.Password.Algo != "sha512" {
		t.Errorf("bob = %+v", bob.Password)
	}
	if !carol.Password.Set || carol.Password.LastChange != 19000 {
		t.Errorf("carol = %+v", carol.Password)
	}
	js, _ := json.Marshal(acc)
	if strings.Contains(string(js), "PASSWDHASH") {
		t.Error("hash leaked")
	}
}

func TestAccountsPasswordKnown(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	passwd := "empty::1000:1000::/h:/bin/sh\nx1:x:1001:1001::/h:/bin/sh\nx2:x:1002:1002::/h:/bin/sh\n"
	shadow := "x2:!:19000:0:99999:7:::\n"
	for n, c := range map[string]string{"passwd": passwd, "shadow": shadow, "group": ""} {
		if err := os.WriteFile(filepath.Join(root, "etc", n), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	acc, _ := Accounts(root, testKey)
	for name, want := range map[string]bool{"empty": true, "x1": false, "x2": true} {
		u, _ := userByName(acc, name)
		if u.Password.Known != want {
			t.Errorf("%s Known = %v, want %v", name, u.Password.Known, want)
		}
	}
}

func groupByName(a model.Accounts, name string) (model.Group, bool) {
	for _, g := range a.Groups {
		if g.Name == name {
			return g, true
		}
	}
	return model.Group{}, false
}

func TestAccountsGShadowReduced(t *testing.T) {
	acc, _ := Accounts("testdata/root1", testKey)
	staff, _ := groupByName(acc, "staff")
	if staff.Shadow == nil || !staff.Shadow.PasswordSet || len(staff.Shadow.Admins) != 1 || staff.Shadow.Admins[0] != "bob" || len(staff.Shadow.Members) != 2 {
		t.Fatalf("staff shadow = %+v", staff.Shadow)
	}
	sudo, _ := groupByName(acc, "sudo")
	if sudo.Shadow == nil || sudo.Shadow.PasswordSet || len(sudo.Shadow.Members) != 1 {
		t.Fatalf("sudo shadow = %+v", sudo.Shadow)
	}
	// A group with no gshadow line has no group password.
	bob, _ := groupByName(acc, "bob")
	if bob.Shadow == nil || bob.Shadow.PasswordSet {
		t.Fatalf("bob shadow = %+v", bob.Shadow)
	}
	js, _ := json.Marshal(acc)
	if strings.Contains(string(js), "groupsecrethash") {
		t.Fatalf("group password hash kept")
	}

	// Without a readable gshadow, groups carry no shadow data.
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "etc/group"), []byte("sudo:x:27:alice\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	acc, _ = Accounts(dir, testKey)
	if g, _ := groupByName(acc, "sudo"); g.Shadow != nil {
		t.Fatalf("shadow without gshadow: %+v", g.Shadow)
	}
}

// accountsRoot writes the four account files into a fresh root.
func accountsRoot(t *testing.T, passwd, shadow, group, gshadow string) string {
	t.Helper()
	d := t.TempDir()
	if err := os.MkdirAll(filepath.Join(d, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"passwd": passwd, "shadow": shadow, "group": group, "gshadow": gshadow} {
		if err := os.WriteFile(filepath.Join(d, "etc", name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

// The account files are read the way glibc's files backend reads them
// (checked against getent): the first line for a name counts, short lines
// are accepted as glibc accepts them, and every duplicate name and rejected
// line is recorded.
func TestAccountsReadLikeGlibc(t *testing.T) {
	pw := "root:x:0:0:root:/root:/bin/bash\n"
	before, _ := Accounts(accountsRoot(t, pw, "root:$y$orig:20000:0:99999:7:::\n", "sudo:x:27:alice\n", "sudo:!::alice\n"), testKey)
	after, _ := Accounts(accountsRoot(t,
		pw+"toor:x:0:0\n  spaced:x:1001:1001::/home/spaced:/bin/sh\nbad:x:notanumber:0:::\nshort:x:5\n# comment\n\n",
		"root:$6$attacker:20000:0:99999:7:::\nroot:$y$orig:20000:0:99999:7:::\nnoage:$y$x\n",
		"sudo:x:27:alice\nsudo:x:27:eve\nnogid:x\n",
		"sudo:$6$grouphash\n"), testKey)

	// shadow: the prepended line is the one glibc uses.
	root, _ := userByName(after, "root")
	if b, _ := userByName(before, "root"); root.Password.Digest == b.Password.Digest {
		t.Errorf("root's password read from the last shadow line, not the first")
	}
	// passwd: a 4-field line is a real account with uid 0.
	if toor, ok := userByName(after, "toor"); !ok || toor.UID != 0 || toor.Shell != "" {
		t.Errorf("toor = %+v (found %v)", toor, ok)
	}
	// Leading blanks are skipped, as glibc does.
	if _, ok := userByName(after, "spaced"); !ok {
		t.Errorf("leading blanks not skipped")
	}
	// group: the first sudo line counts; the duplicate is recorded.
	sudo, _ := groupByName(after, "sudo")
	if len(sudo.Members) != 1 || sudo.Members[0] != "alice" {
		t.Errorf("sudo members = %v", sudo.Members)
	}
	// gshadow: a 2-field line gives sudo a group password.
	if sudo.Shadow == nil || !sudo.Shadow.PasswordSet {
		t.Errorf("sudo gshadow = %+v", sudo.Shadow)
	}
	for _, want := range []string{"/etc/shadow:root", "/etc/group:sudo"} {
		if !slices.Contains(after.Duplicates, want) {
			t.Errorf("duplicates %v lack %q", after.Duplicates, want)
		}
	}
	for _, want := range []string{"/etc/passwd:4", "/etc/passwd:5", "/etc/shadow:3", "/etc/group:3"} {
		if !slices.Contains(after.Malformed, want) {
			t.Errorf("malformed %v lack %q", after.Malformed, want)
		}
	}
	js, _ := json.Marshal(after)
	for _, secret := range []string{"attacker", "grouphash", "orig"} {
		if strings.Contains(string(js), secret) {
			t.Errorf("result contains %q", secret)
		}
	}
	if len(before.Duplicates) != 0 || len(before.Malformed) != 0 {
		t.Errorf("clean files: duplicates %v malformed %v", before.Duplicates, before.Malformed)
	}
}

// Empty-name lines are used by glibc (getpwuid(0) returns an empty-name uid
// 0 line placed first; initgroups honours ":x:27:eve"), so they are
// reported as malformed with what they claim. Lines whose ids are above
// 4294967295 ("-1" too, read as unsigned long) are dropped by glibc, so a
// later line for the same name counts; they are dropped here too and reported.
func TestAccountsEmptyNamesAndOutOfRangeIDs(t *testing.T) {
	acc, _ := Accounts(accountsRoot(t,
		":x:0:0::/tmp/x:/tmp/x/sh\nroot:x:0:0:root:/root:/bin/bash\nalice:x:4294968296:1000::/home/alice:/bin/bash\nalice:x:0:0::/home/alice:/bin/bash\nbig:x:4294967295:0::/:/bin/sh\nneg:x:-1:0::/:/bin/sh\n",
		":$6$x:20000:0:99999:7:::\nroot:$y$r:20000:0:99999:7:::\n",
		"root:x:0:\nsudo:x:27:alice\n:x:27:eve\n",
		"sudo:!::alice\n:$6$grouphash::eve\n"), testKey)
	for _, want := range []string{
		"/etc/passwd:1 (empty name, uid 0)",
		"/etc/passwd:3",
		"/etc/passwd:6",
		"/etc/shadow:1 (empty name)",
		"/etc/group:3 (empty name, gid 27, members eve)",
		"/etc/gshadow:2 (empty name)",
	} {
		if !slices.Contains(acc.Malformed, want) {
			t.Errorf("malformed %q lack %q", acc.Malformed, want)
		}
	}
	if alice, ok := userByName(acc, "alice"); !ok || alice.UID != 0 {
		t.Errorf("alice = %+v (glibc resolves alice to uid 0)", alice)
	}
	if _, ok := userByName(acc, "neg"); ok {
		t.Errorf("neg kept although glibc drops its line")
	}
	// glibc keeps an id of 4294967295: only values above it are refused.
	if big, ok := userByName(acc, "big"); !ok || big.UID != 4294967295 || slices.Contains(acc.Malformed, "/etc/passwd:5") {
		t.Errorf("big = %+v (kept %v), malformed %q; glibc keeps uid 4294967295", big, ok, acc.Malformed)
	}
	js, _ := json.Marshal(acc)
	if strings.Contains(string(js), "grouphash") || strings.Contains(string(js), "$6$x") {
		t.Errorf("a hash was kept")
	}
}

// The lines and the expected reading come from glibc 2.41's fgetpwent and
// fgetgrent: an id is refused only above 4294967295 (which "-1" and
// "-4294967295" are, read as unsigned long).
func TestAccountsIDBoundaryMatchesGlibc(t *testing.T) {
	acc, _ := Accounts(accountsRoot(t,
		"alice:x:4294967295:0::/home/alice:/bin/bash\nalice:x:0:0::/home/alice:/bin/bash\npg:x:7:4294967295::/:/bin/sh\n"+
			"max:x:4294967294:0::/:/bin/sh\nplus:x:+5:0::/:/bin/sh\nws:x: 7:0::/:/bin/sh\nover:x:4294967296:0::/:/bin/sh\n"+
			"neg:x:-1:0::/:/bin/sh\nneg2:x:-4294967295:0::/:/bin/sh\ngbig:x:5:4294967296::/:/bin/sh\n",
		"",
		"root:x:0:\ngmax:x:4294967295:dave\nbigg:x:4294967296:bob\nnegg:x:-1:bob\nokg:x:4294967294:carl\n",
		""), testKey)
	for name, uid := range map[string]int{"alice": 4294967295, "pg": 7, "max": 4294967294, "plus": 5, "ws": 7} {
		if u, ok := userByName(acc, name); !ok || u.UID != uid {
			t.Errorf("%s = %+v (kept %v), want uid %d", name, u, ok, uid)
		}
	}
	if pg, _ := userByName(acc, "pg"); pg.GID != 4294967295 {
		t.Errorf("pg gid = %d, want 4294967295", pg.GID)
	}
	for _, name := range []string{"over", "neg", "neg2", "gbig"} {
		if _, ok := userByName(acc, name); ok {
			t.Errorf("%s kept although glibc drops its line", name)
		}
	}
	if !slices.Contains(acc.Duplicates, "/etc/passwd:alice") {
		t.Errorf("duplicates %q lack the second alice line", acc.Duplicates)
	}
	groups := map[string]int{}
	for _, g := range acc.Groups {
		groups[g.Name] = g.GID
	}
	if len(groups) != 3 || groups["gmax"] != 4294967295 || groups["okg"] != 4294967294 {
		t.Errorf("groups = %v, want root, gmax (4294967295) and okg", groups)
	}
	want := []string{"/etc/passwd:7", "/etc/passwd:8", "/etc/passwd:9", "/etc/passwd:10", "/etc/group:3", "/etc/group:4"}
	if !slices.Equal(acc.Malformed, want) {
		t.Errorf("malformed = %q, want %q", acc.Malformed, want)
	}
}
