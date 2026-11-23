//go:build lab

package lab

import (
	"context"
	"crypto/rand"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/store"
	"github.com/donaldsteele/telltale/internal/visit"
	"github.com/donaldsteele/telltale/lab/labkit"
)

// The visit tests run server mode's visit from the host against a lab
// machine, as the server would. The machine is enrolled the way the owner
// enrols one: the server key line for root and the Match block are added
// through docker exec exactly as the enrolment snippets say, sshd is
// reloaded, and the host key's fingerprint is compared with the machine's
// own before it is pinned.

func TestVisitCleanMachine(t *testing.T) {
	onDistros(t, []string{"debian12"}, func(t *testing.T, distro string) {
		t.Run("clean", func(t *testing.T) {
			slot(t)
			m := labkit.Start(t, labkit.Build(t, distro, "clean"), labkit.Opts{})
			checkVisit(t, distro, m)
		})
	})
}

// TestVisitNoexecMachine visits the noexec machine with /run and /var/tmp
// mounted noexec as well (systemd mounts /run noexec, and hardened machines
// mount /var/tmp so), so the only candidate left for the collector is /root.
func TestVisitNoexecMachine(t *testing.T) {
	onDistros(t, []string{"debian12"}, func(t *testing.T, distro string) {
		t.Run("noexec", func(t *testing.T) {
			slot(t)
			m := labkit.Start(t, labkit.Build(t, distro, "noexec"), labkit.Opts{
				Tmpfs: []string{"/run:noexec,nosuid,nodev,mode=755", "/var/tmp:noexec,nosuid,nodev,mode=1777"},
			})
			for _, d := range []string{"/run", "/var/tmp", "/tmp"} {
				if opts := mustExec(t, m, "findmnt -no OPTIONS "+d); !strings.Contains(opts, "noexec") {
					t.Fatalf("%s is mounted %q, want noexec", d, strings.TrimSpace(opts))
				}
			}
			checkVisit(t, distro, m)
		})
	})
}

var tempDirRE = regexp.MustCompile(`^/(run|var/tmp|root|tmp)/telltale\.[A-Za-z0-9]{8}/`)

// checkVisit enrols the machine, visits it and checks what came back and
// what was left on the machine.
func checkVisit(t *testing.T, distro string, m *labkit.Machine) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	ip := m.IP()

	// The address the machine sees the server (this test) connect from.
	nc, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "22"), 10*time.Second)
	if err != nil {
		t.Fatalf("the host cannot reach sshd on %s at %s: %v", m.Name, ip, err)
	}
	serverAddr := nc.LocalAddr().(*net.TCPAddr).IP.String()
	nc.Close()

	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "server.db"), store.Unlock{KeyFile: filepath.Join(dir, "server.key")})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	signer, keyLine, err := visit.ServerKey(st)
	if err != nil {
		t.Fatal(err)
	}

	// Enrolment, in the owner's order: fetch the host key and compare its
	// fingerprint with the machine's own, pin it, then add the snippets on
	// the machine and reload sshd.
	key, fp, err := visit.FetchHostKey(ctx, ip)
	if err != nil {
		t.Fatalf("fetch the host key: %v", err)
	}
	if own := mustExec(t, m, "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub"); !strings.Contains(own, " "+fp+" ") {
		t.Fatalf("fetched host key %s, the machine's own ed25519 key is %s", fp, strings.TrimSpace(own))
	}
	id, err := st.AddMachine(store.Machine{Name: m.Hostname, Addr: ip, HostKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))})
	if err != nil {
		t.Fatal(err)
	}
	rec, err := st.Machine(id)
	if err != nil {
		t.Fatal(err)
	}
	authorizedKeys, match, err := visit.EnrolSnippets(serverAddr, keyLine)
	if err != nil {
		t.Fatalf("enrolment snippets: %v", err)
	}
	out, code := m.Exec(t, "sh", "-c", `exec 2>&1
set -e
umask 077
mkdir -p /root/.ssh
printf '%s\n' "$1" >> /root/.ssh/authorized_keys
printf '\n%s' "$2" >> /etc/ssh/sshd_config
/usr/sbin/sshd -t
kill -HUP "$(pgrep -o -x sshd)"`, "enrol", authorizedKeys, match)
	if code != 0 {
		t.Fatalf("enrolment on %s: exit %d:\n%s", m.Name, code, out)
	}
	waitFor(t, 30*time.Second, "sshd to let the server in as root", func() bool { return rootLogin(ip, signer, key) })

	binDir := t.TempDir()
	copyFile(t, binPath, filepath.Join(binDir, "telltale-linux-"+labkit.Arch))
	digest := make([]byte, 32)
	rand.Read(digest)
	sc := model.ScanContext{
		DigestKey:            digest,
		ServerAddr:           serverAddr,
		ServerKeyLine:        keyLine,
		ServerKeyFingerprint: ssh.FingerprintSHA256(signer.PublicKey()),
	}

	mustExec(t, m, "touch /lab/visit-marker")
	start := time.Now()
	c, err := visit.Visit(ctx, *rec, signer, sc, visit.Binaries{Dir: binDir})
	if err != nil {
		t.Fatalf("visit: %v", err)
	}
	t.Logf("visit took %v", time.Since(start).Round(time.Millisecond))

	if left := strings.TrimSpace(mustExec(t, m, "find /run /var/tmp /root /tmp -maxdepth 1 -name 'telltale.*'")); left != "" {
		t.Errorf("left on the machine:\n%s", left)
	}
	// Nothing but what any SSH login writes may have changed (R42: no
	// snapshot or cache on the machine; the collector's directory is gone).
	// pam_motd writes /run/motd.dynamic at every session start.
	changed := strings.Fields(mustExec(t, m, `find / \( -path /proc -o -path /sys -o -path /dev \) -prune -o ! -type d -newer /lab/visit-marker -print`))
	t.Logf("files changed during the visit: %q", changed)
	for _, p := range changed {
		switch p {
		case "/var/log/wtmp", "/var/log/btmp", "/var/log/lastlog", "/run/utmp", "/run/motd.dynamic":
		default:
			t.Errorf("the visit wrote %s on the machine", p)
		}
	}

	if !c.AsRoot {
		t.Error("the collection was not taken as root")
	}
	if want := wantOS[distro]; c.Host.OSID != want[0] || c.Host.OSVersionID != want[1] {
		t.Errorf("os = %s %s, want %v", c.Host.OSID, c.Host.OSVersionID, want)
	}
	if len(c.Files) < 4000 {
		t.Errorf("files = %d, want >= 4000", len(c.Files))
	}
	blob := strings.Join(strings.Fields(keyLine)[:2], " ")
	seen := false
	for _, p := range c.Persist {
		if p.Path == "/root/.ssh/authorized_keys" {
			for _, l := range p.Lines {
				seen = seen || strings.Contains(l, blob)
			}
		}
	}
	if !seen {
		t.Error("the collection does not show the server's key in root's authorized_keys")
	}
	for _, p := range c.Runtime.Processes {
		if tempDirRE.MatchString(p.Exe) {
			t.Errorf("the collector's own process is in the collection: pid %d %s", p.PID, p.Exe)
		}
	}
	// It checked the directory the visit made as its own and left out its
	// binary there, and the directory's own entry, which under /root would
	// be in the file inventory with a new name on every visit.
	if c.OwnDir == "" || c.OwnDir != c.VisitDir {
		t.Errorf("the collector left its binary out in %q; the visit made %q", c.OwnDir, c.VisitDir)
	}
	for _, f := range c.Files {
		if tempDirRE.MatchString(f.Path + "/") {
			t.Errorf("the collector's own directory is in the collection: %s", f.Path)
		}
	}
}

// rootLogin reports whether the server key logs in as root and runs a
// command.
func rootLogin(ip string, signer ssh.Signer, hostKey ssh.PublicKey) bool {
	cl, err := ssh.Dial("tcp", net.JoinHostPort(ip, "22"), &ssh.ClientConfig{
		User:              "root",
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback:   ssh.FixedHostKey(hostKey),
		HostKeyAlgorithms: []string{hostKey.Type()},
		Timeout:           5 * time.Second,
	})
	if err != nil {
		return false
	}
	defer cl.Close()
	s, err := cl.NewSession()
	if err != nil {
		return false
	}
	defer s.Close()
	return s.Run("true") == nil
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}
