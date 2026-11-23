package collect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/donaldsteele/telltale/internal/model"
	"golang.org/x/sys/unix"
)

const (
	malloryUID = 4242
	shadowLine = "root:$6$salt$SECRETHASHVALUE:19000:0:99999:7:::"
)

// ownedBy makes the collector see the given paths (not followed) as owned by
// uid for the rest of the test. Everything else keeps its real owner, the
// account running the test, which stands in for root.
func ownedBy(t *testing.T, uid uint32, paths ...string) {
	t.Helper()
	type id struct{ dev, ino uint64 }
	fake := map[id]bool{}
	for _, p := range paths {
		var st unix.Stat_t
		if err := unix.Lstat(p, &st); err != nil {
			t.Fatal(err)
		}
		fake[id{uint64(st.Dev), st.Ino}] = true
	}
	prev := ownerOf
	ownerOf = func(st *unix.Stat_t) uint32 {
		if fake[id{uint64(st.Dev), st.Ino}] {
			return uid
		}
		return prev(st)
	}
	t.Cleanup(func() { ownerOf = prev })
}

func rootOnly(t *testing.T, root, mp, content string) {
	t.Helper()
	writeFile(t, root, mp, content)
	if err := os.Chmod(filepath.Join(root, mp), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mallory() []model.User {
	return []model.User{{Name: "mallory", UID: malloryUID, Home: "/home/mallory"}}
}

// leaked fails the test when the secret is anywhere in what was collected.
func leaked(t *testing.T, pf []model.PersistFile, skips []model.Skip, secret string) {
	t.Helper()
	js, _ := json.Marshal(struct {
		P []model.PersistFile
		S []model.Skip
	}{pf, skips})
	if strings.Contains(string(js), secret) {
		t.Errorf("the secret was collected: %s", js)
	}
}

func persistSkip(skips []model.Skip, mp, reason string) bool {
	for _, s := range skips {
		if s.Check == persistCheck && s.Reason == mp+": "+reason {
			return true
		}
	}
	return false
}

// A user's link, read by a root scan, must not copy a file the user cannot
// read into the collection. Each case is one way to aim the link.
func TestPersistenceUserLinkDoesNotLeakRootFiles(t *testing.T) {
	for _, tc := range []struct {
		name   string
		link   string // the per-user path that is a link
		target string
		setup  func(t *testing.T, root string) []string // extra paths mallory owns
		reason string
	}{
		{name: "through a directory link of the user's", link: "home/mallory/.bashrc", target: "d/shadow",
			setup: func(t *testing.T, root string) []string {
				symlinkAt(t, root, "home/mallory/d", "/etc")
				return []string{"home/mallory/d"}
			}, reason: skipUserLinkTarget},
		{name: "a backup of shadow", link: "home/mallory/.bashrc", target: "/etc/shadow-", reason: skipSecretTarget},
		{name: "a root-only file with an ordinary name", link: "home/mallory/.bashrc", target: "/etc/app/credentials", reason: skipUnreadable},
		{name: "inside the user's unit directory", link: "home/mallory/.config/systemd/user/x.service", target: "/etc/app/credentials", reason: skipUnreadable},
		{name: "a world-readable file in a closed directory", link: "home/mallory/.profile", target: "/root/notes", reason: skipUnreadable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			rootOnly(t, root, "etc/shadow", shadowLine+"\n")
			rootOnly(t, root, "etc/shadow-", shadowLine+"\n")
			rootOnly(t, root, "etc/app/credentials", shadowLine+"\n")
			writeFile(t, root, "root/notes", shadowLine+"\n")
			if err := os.Chmod(filepath.Join(root, "root"), 0o700); err != nil {
				t.Fatal(err)
			}
			symlinkAt(t, root, tc.link, tc.target)
			owned := []string{filepath.Join(root, tc.link), filepath.Join(root, "home/mallory")}
			if tc.setup != nil {
				for _, p := range tc.setup(t, root) {
					owned = append(owned, filepath.Join(root, p))
				}
			}
			ownedBy(t, malloryUID, owned...)

			pf, skips := Persistence(root, mallory(), testKey)
			leaked(t, pf, skips, "SECRETHASHVALUE")
			f, ok := findPersist(pf, "/"+tc.link)
			if !ok || len(f.Lines) != 1 || f.Lines[0] != tc.target || f.Mode&unix.S_IFMT != unix.S_IFLNK {
				t.Errorf("the link itself must stay recorded with its target only: %+v ok=%v", f, ok)
			}
			if !persistSkip(skips, "/"+tc.link, tc.reason) {
				t.Errorf("no skip %q for the link: %+v", tc.reason, skips)
			}
		})
	}
}

// The real /proc: a link through /proc/<pid>/root reaches the same file by
// another name.
func TestPersistenceUserLinkThroughProc(t *testing.T) {
	if _, err := os.Stat("/proc/self/root"); err != nil {
		t.Skip("no /proc here")
	}
	home := t.TempDir()
	if err := os.Chmod(home, 0o755); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte(shadowLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(home, ".bashrc")
	if err := os.Symlink("/proc/self/root"+secret, link); err != nil {
		t.Fatal(err)
	}
	// The link is the test account's own, so only the rule about kernel
	// filesystems stands in the way.
	c := &collector{key: testKey, seen: map[string]bool{}}
	c.file(link, model.PersistKindShellRC)
	leaked(t, c.out, c.skips, "SECRETHASHVALUE")
	if f, ok := findPersist(c.out, link); !ok || len(f.Lines) != 1 {
		t.Errorf("link = %+v ok=%v", f, ok)
	}
	if !persistSkip(c.skips, link, "target: "+errKernelFS.Error()) {
		t.Errorf("skips %+v", c.skips)
	}
}

// What the link's owner can read anyway is still read: the user's own file,
// and a world-readable one.
func TestPersistenceUserLinkToReadableFileIsRead(t *testing.T) {
	root := t.TempDir()
	rootOnly(t, root, "home/mallory/dotfiles/bashrc", "alias ll='ls -l'\n")
	symlinkAt(t, root, "home/mallory/.bashrc", "dotfiles/bashrc")
	writeFile(t, root, "etc/skel/.profile", "umask 022\n")
	symlinkAt(t, root, "home/mallory/.profile", "/etc/skel/.profile")
	ownedBy(t, malloryUID, filepath.Join(root, "home/mallory"), filepath.Join(root, "home/mallory/dotfiles"),
		filepath.Join(root, "home/mallory/dotfiles/bashrc"), filepath.Join(root, "home/mallory/.bashrc"), filepath.Join(root, "home/mallory/.profile"))
	pf, skips := Persistence(root, mallory(), testKey)
	if f, ok := findPersist(pf, "/home/mallory/.bashrc"); !ok || len(f.Lines) != 2 || f.Lines[1] != "alias ll='ls -l'" {
		t.Errorf("own file behind the link not read: %+v", f)
	}
	if f, ok := findPersist(pf, "/home/mallory/.profile"); !ok || len(f.Lines) != 2 || f.Lines[1] != "umask 022" {
		t.Errorf("world-readable file behind the link not read: %+v", f)
	}
	if len(skips) != 0 {
		t.Errorf("skips %+v", skips)
	}
}

// A user's own directory link on the way to the user's own file is followed
// when it leads to files the user could read (~/.ssh kept in a dotfiles
// directory), so the keys there stay visible.
func TestPersistenceUserDirectoryLinkToOwnFiles(t *testing.T) {
	root := t.TempDir()
	rootOnly(t, root, "home/mallory/dot/ssh/authorized_keys", "ssh-ed25519 AAAA mallory@laptop\n")
	symlinkAt(t, root, "home/mallory/.ssh", "dot/ssh")
	ownedBy(t, malloryUID, filepath.Join(root, "home/mallory"), filepath.Join(root, "home/mallory/.ssh"),
		filepath.Join(root, "home/mallory/dot"), filepath.Join(root, "home/mallory/dot/ssh"), filepath.Join(root, "home/mallory/dot/ssh/authorized_keys"))
	pf, skips := Persistence(root, mallory(), testKey)
	if f, ok := findPersist(pf, "/home/mallory/.ssh/authorized_keys"); !ok || len(f.Lines) != 1 || f.Lines[0] != "ssh-ed25519 AAAA mallory@laptop" {
		t.Errorf("keys behind the user's own directory link: %+v ok=%v", f, ok)
	}
	if len(skips) != 0 {
		t.Errorf("skips %+v", skips)
	}

	// Another account's directory link on the way is never followed.
	ownedBy(t, malloryUID+1, filepath.Join(root, "home/mallory/.ssh"))
	pf, skips = Persistence(root, mallory(), testKey)
	if _, ok := findPersist(pf, "/home/mallory/.ssh/authorized_keys"); ok {
		t.Errorf("file behind another account's directory link was recorded")
	}
	if !persistSkip(skips, "/home/mallory/.ssh/authorized_keys", skipUserLinkPath) {
		t.Errorf("skips %+v", skips)
	}
}

// A user's directory link that leads to files the user cannot read is not
// read through; the link is recorded, so it is still seen and compared.
func TestPersistenceUserDirectoryLinkNotFollowed(t *testing.T) {
	root := t.TempDir()
	rootOnly(t, root, "root/.ssh/authorized_keys", "ssh-ed25519 AAAA rootsecretkey\n")
	symlinkAt(t, root, "home/mallory/.ssh", "/root/.ssh")
	ownedBy(t, malloryUID, filepath.Join(root, "home/mallory"), filepath.Join(root, "home/mallory/.ssh"))
	pf, skips := Persistence(root, mallory(), testKey)
	leaked(t, pf, skips, "rootsecretkey")
	if _, ok := findPersist(pf, "/home/mallory/.ssh/authorized_keys"); ok {
		t.Errorf("file behind the user's directory link was recorded")
	}
	f, ok := findPersist(pf, "/home/mallory/.ssh")
	if !ok || f.Kind != model.PersistKindAuthorizedKeys || len(f.Lines) != 1 || f.Lines[0] != "/root/.ssh" || f.Mode&unix.S_IFMT != unix.S_IFLNK {
		t.Errorf("the directory link is not recorded: %+v ok=%v", f, ok)
	}
	if !persistSkip(skips, "/home/mallory/.ssh/authorized_keys", skipOwnLinkPath) {
		t.Errorf("skips %+v", skips)
	}
}

// ln /etc/shadow ~/.bashrc, on a machine without protected_hardlinks.
func TestPersistenceUserHardLinkToRootFile(t *testing.T) {
	root := t.TempDir()
	rootOnly(t, root, "etc/shadow", shadowLine+"\n")
	if err := os.MkdirAll(filepath.Join(root, "home/mallory"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(root, "etc/shadow"), filepath.Join(root, "home/mallory/.bashrc")); err != nil {
		t.Fatal(err)
	}
	ownedBy(t, malloryUID, filepath.Join(root, "home/mallory"))
	pf, skips := Persistence(root, mallory(), testKey)
	leaked(t, pf, skips, "SECRETHASHVALUE")
	f, ok := findPersist(pf, "/home/mallory/.bashrc")
	if !ok || len(f.Lines) != 0 || f.SHA256 != "" {
		t.Errorf("hard link to a root-only file: %+v ok=%v", f, ok)
	}
	if !persistSkip(skips, "/home/mallory/.bashrc", skipHardLink) {
		t.Errorf("skips %+v", skips)
	}
	// A file with one name that root left in the home is read as before.
	rootOnly(t, root, "home/mallory/.profile", "umask 077\n")
	pf, _ = Persistence(root, mallory(), testKey)
	if f, ok := findPersist(pf, "/home/mallory/.profile"); !ok || len(f.Lines) != 1 {
		t.Errorf("root's own file in the home: %+v", f)
	}
}

func TestSecretTargetNames(t *testing.T) {
	for _, p := range []string{"/etc/shadow", "/etc/gshadow", "/etc/shadow-", "/etc/gshadow-", "/etc/passwd-", "/etc/group-",
		"/etc/shadow~", "/etc/shadow.bak", "/etc/shadow.old", "/etc/gshadow.bak", "/etc/passwd.old", "/etc/group~", "/etc/security/opasswd", "/etc/ssh/ssh_host_ed25519_key"} {
		if !secretTarget(p) {
			t.Errorf("%s is not treated as secret", p)
		}
	}
	for _, p := range []string{"/etc/passwd", "/etc/group", "/etc/shadow.d/x", "/etc/ssh/ssh_host_ed25519_key.pub", "/etc/hosts", "/home/u/shadow-"} {
		if secretTarget(p) {
			t.Errorf("%s is treated as secret", p)
		}
	}
}

// A private key anywhere in the target, not only on its first line.
func TestPersistenceLinkToPrivateKeyBelowTheFirstLine(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "srv/bundle.pem", "# service certificate and key\n-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n  -----BEGIN OPENSSH PRIVATE KEY-----\nKEYMATERIALVALUE\n-----END OPENSSH PRIVATE KEY-----\n")
	symlinkAt(t, root, "etc/cron.d/job", "/srv/bundle.pem")
	pf, skips := Persistence(root, nil, testKey)
	leaked(t, pf, skips, "KEYMATERIALVALUE")
	if f, ok := findPersist(pf, "/etc/cron.d/job"); !ok || len(f.Lines) != 1 {
		t.Errorf("link = %+v", f)
	}
	if !persistSkip(skips, "/etc/cron.d/job", skipSecretTarget) {
		t.Errorf("skips %+v", skips)
	}
}
