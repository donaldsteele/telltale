package collect

import (
	"encoding/json"
	"os"
	"path/filepath"
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
