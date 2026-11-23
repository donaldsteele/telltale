package visit

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/store"
)

// fakeMachine is an in-process SSH server standing in for an enrolled
// machine. It runs the visit's commands against a temporary directory (the
// remote path /run/x is <root>/run/x) instead of handing them to a shell:
// each command a visit may send is recognised exactly and emulated. Anything
// else fails with exit 127 and is recorded, so a test also sees that no
// other command went out.
type fakeMachine struct {
	t        *testing.T
	root     string
	addr     string
	client   ssh.Signer // the server's key, accepted for root
	hostKeys []ssh.Signer

	arch        string
	binary      []byte          // what an uploaded collector must hold to run
	noexec      map[string]bool // base directories where nothing may run
	mktempFails map[string]bool // base directories mktemp cannot write
	// mktempOut replaces mktemp's output when set; no directory is made.
	mktempOut  func(base string) string
	collect    func(c call) int
	collection *model.Collection

	mu       sync.Mutex
	cmds     []string
	unknown  []string
	auths    int
	conns    int
	open     []net.Conn
	contexts []model.ScanContext
}

// call is one run of the collector on the fake machine.
type call struct {
	ctx    context.Context // ends when the visit kills the command or closes its session
	stdin  []byte
	stdout io.Writer
	stderr io.Writer
	drop   func() // cuts the whole connection
}

func newSigner(t *testing.T, kind string) ssh.Signer {
	t.Helper()
	var key any
	var err error
	switch kind {
	case "ed25519":
		_, key, err = ed25519.GenerateKey(rand.Reader)
	case "ecdsa":
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	default:
		t.Fatalf("unknown key kind %q", kind)
	}
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// newFake starts a fake machine offering hostKeys (an ed25519 key when none
// is given) that lets the server's key in as root.
func newFake(t *testing.T, hostKeys ...ssh.Signer) *fakeMachine {
	t.Helper()
	if len(hostKeys) == 0 {
		hostKeys = []ssh.Signer{newSigner(t, "ed25519")}
	}
	f := &fakeMachine{
		t:        t,
		root:     t.TempDir(),
		client:   newSigner(t, "ed25519"),
		hostKeys: hostKeys,
		arch:     "x86_64",
		binary:   []byte("\x7fELF fake telltale collector\n"),
		collection: &model.Collection{
			Schema: model.CollectionSchema,
			Host:   model.Host{Hostname: "fake-machine", OSID: "debian", OSVersionID: "12"},
			AsRoot: true,
		},
	}
	f.collect = f.defaultCollect
	for _, d := range execDirs {
		if err := os.MkdirAll(f.local(d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			f.mu.Lock()
			f.auths++
			f.mu.Unlock()
			if meta.User() == "root" && bytes.Equal(key.Marshal(), f.client.PublicKey().Marshal()) {
				return nil, nil
			}
			return nil, errors.New("not authorised")
		},
	}
	for _, k := range hostKeys {
		cfg.AddHostKey(k)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.addr = l.Addr().String()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			nc, err := l.Accept()
			if err != nil {
				return
			}
			f.mu.Lock()
			f.conns++
			f.open = append(f.open, nc)
			f.mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				f.serve(nc, cfg)
			}()
		}
	}()
	t.Cleanup(func() {
		l.Close()
		f.mu.Lock()
		for _, c := range f.open {
			c.Close()
		}
		f.mu.Unlock()
		wg.Wait()
	})
	return f
}

func (f *fakeMachine) serve(nc net.Conn, cfg *ssh.ServerConfig) {
	defer nc.Close()
	_, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	var wg sync.WaitGroup
	for nch := range chans {
		if nch.ChannelType() != "session" {
			nch.Reject(ssh.UnknownChannelType, "sessions only")
			continue
		}
		ch, creqs, err := nch.Accept()
		if err != nil {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			f.session(ch, creqs, func() { nc.Close() })
		}()
	}
	wg.Wait()
}

func (f *fakeMachine) session(ch ssh.Channel, reqs <-chan *ssh.Request, drop func()) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	started := false
	for req := range reqs {
		switch req.Type {
		case "exec":
			var p struct{ Command string }
			if started || ssh.Unmarshal(req.Payload, &p) != nil {
				req.Reply(false, nil)
				continue
			}
			started = true
			req.Reply(true, nil)
			wg.Add(1)
			go func() {
				defer wg.Done()
				code := f.run(ctx, p.Command, ch, ch, ch.Stderr(), drop)
				ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(code)}))
				ch.Close()
			}()
		case "signal":
			cancel()
		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
	// The visit closed the session.
	cancel()
	wg.Wait()
}

const dirPat = `/(?:run|var/tmp|root|tmp)/telltale\.[A-Za-z0-9]{8}`

var (
	reMktemp  = regexp.MustCompile(`^mktemp -d (/run|/var/tmp|/root|/tmp)/telltale\.XXXXXXXX$`)
	reUpload  = regexp.MustCompile(`^cat > '(` + dirPat + `)/telltale' && chmod 0700 '(` + dirPat + `)/telltale'$`)
	reVersion = regexp.MustCompile(`^'(` + dirPat + `)/telltale' version$`)
	reCollect = regexp.MustCompile(`^'(` + dirPat + `)/telltale' collect --context-stdin --gzip$`)
	reRemove  = regexp.MustCompile(`^rm -rf '` + dirPat + `'(?: '` + dirPat + `')*$`)
	reDir     = regexp.MustCompile(dirPat)
)

func (f *fakeMachine) local(remote string) string {
	return filepath.Join(f.root, filepath.FromSlash(remote))
}

func randomSuffix() string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 8)
	rand.Read(b)
	for i := range b {
		b[i] = chars[int(b[i])%len(chars)]
	}
	return string(b)
}

// run emulates one command line and returns its exit status.
func (f *fakeMachine) run(ctx context.Context, cmd string, stdin io.Reader, stdout, stderr io.Writer, drop func()) int {
	f.mu.Lock()
	f.cmds = append(f.cmds, cmd)
	f.mu.Unlock()
	collector := func(d string) (int, bool) {
		data, err := os.ReadFile(f.local(d + "/telltale"))
		switch {
		case err != nil:
			fmt.Fprintf(stderr, "sh: 1: %s/telltale: not found\n", d)
			return 127, false
		case f.noexec[path.Dir(d)]:
			fmt.Fprintf(stderr, "sh: 1: %s/telltale: Permission denied\n", d)
			return 126, false
		case !bytes.Equal(data, f.binary):
			fmt.Fprintf(stderr, "sh: 1: %s/telltale: Exec format error\n", d)
			return 126, false
		}
		return 0, true
	}
	switch {
	case cmd == "uname -m":
		fmt.Fprintln(stdout, f.arch)
		return 0
	case reMktemp.MatchString(cmd):
		base := reMktemp.FindStringSubmatch(cmd)[1]
		if f.mktempOut != nil {
			fmt.Fprintln(stdout, f.mktempOut(base))
			return 0
		}
		if f.mktempFails[base] {
			fmt.Fprintf(stderr, "mktemp: failed to create directory via template '%s/telltale.XXXXXXXX': Read-only file system\n", base)
			return 1
		}
		d := base + "/telltale." + randomSuffix()
		if err := os.Mkdir(f.local(d), 0o700); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		fmt.Fprintln(stdout, d)
		return 0
	case reUpload.MatchString(cmd):
		m := reUpload.FindStringSubmatch(cmd)
		if m[1] != m[2] {
			break
		}
		data, err := io.ReadAll(stdin)
		if err == nil {
			err = os.WriteFile(f.local(m[1]+"/telltale"), data, 0o700)
		}
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	case reVersion.MatchString(cmd):
		if code, ok := collector(reVersion.FindStringSubmatch(cmd)[1]); !ok {
			return code
		}
		fmt.Fprintln(stdout, "telltale 1.2.3")
		return 0
	case reCollect.MatchString(cmd):
		if code, ok := collector(reCollect.FindStringSubmatch(cmd)[1]); !ok {
			return code
		}
		data, _ := io.ReadAll(stdin)
		return f.collect(call{ctx: ctx, stdin: data, stdout: stdout, stderr: stderr, drop: drop})
	case reRemove.MatchString(cmd):
		for _, d := range reDir.FindAllString(cmd, -1) {
			os.RemoveAll(f.local(d))
		}
		return 0
	}
	f.mu.Lock()
	f.unknown = append(f.unknown, cmd)
	f.mu.Unlock()
	fmt.Fprintln(stderr, "sh: 1: unknown command")
	return 127
}

// defaultCollect behaves like "telltale collect --context-stdin --gzip".
func (f *fakeMachine) defaultCollect(c call) int {
	var sc model.ScanContext
	dec := json.NewDecoder(bytes.NewReader(c.stdin))
	if err := dec.Decode(&sc); err != nil {
		fmt.Fprintf(c.stderr, "telltale collect: read scan context: %v\n", err)
		return 2
	}
	if _, err := dec.Token(); err != io.EOF {
		fmt.Fprintln(c.stderr, "telltale collect: trailing data after the scan context")
		return 2
	}
	if len(sc.DigestKey) < 16 {
		fmt.Fprintln(c.stderr, "telltale collect: digest key too short")
		return 2
	}
	f.mu.Lock()
	f.contexts = append(f.contexts, sc)
	f.mu.Unlock()
	zw := gzip.NewWriter(c.stdout)
	if err := json.NewEncoder(zw).Encode(f.collection); err != nil {
		return 1
	}
	if err := zw.Close(); err != nil {
		return 1
	}
	return 0
}

func (f *fakeMachine) machine() store.Machine {
	return store.Machine{ID: 1, Name: "fake", Addr: f.addr, HostKey: authorizedLine(f.hostKeys[0].PublicKey())}
}

// binaries writes the collector the fake machine runs as both
// architectures' binaries.
func (f *fakeMachine) binaries(t *testing.T) Binaries {
	t.Helper()
	dir := t.TempDir()
	for _, a := range []string{"amd64", "arm64"} {
		if err := os.WriteFile(filepath.Join(dir, "telltale-linux-"+a), f.binary, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return Binaries{Dir: dir}
}

// commands returns what the visit ran, with each temporary directory's
// random part replaced by "*" (mktemp's template stays as it is).
func (f *fakeMachine) commands() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.cmds))
	for i, c := range f.cmds {
		out[i] = reDir.ReplaceAllStringFunc(c, func(d string) string {
			if strings.HasSuffix(d, ".XXXXXXXX") {
				return d
			}
			return path.Dir(d) + "/telltale.*"
		})
	}
	return out
}

// leftovers lists everything on the fake machine but its base directories.
func (f *fakeMachine) leftovers(t *testing.T) []string {
	t.Helper()
	base := map[string]bool{"/": true, "/var": true}
	for _, d := range execDirs {
		base[d] = true
	}
	var out []string
	err := filepath.WalkDir(f.root, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(f.root, p)
		remote := "/" + filepath.ToSlash(rel)
		if rel == "." {
			remote = "/"
		}
		if !base[remote] {
			out = append(out, remote)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// check fails the test when the visit left anything on the machine or sent
// a command the fake machine does not know.
func (f *fakeMachine) check(t *testing.T) {
	t.Helper()
	if l := f.leftovers(t); len(l) > 0 {
		t.Errorf("left on the machine: %q", l)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.unknown) > 0 {
		t.Errorf("commands the visit may not send: %q", f.unknown)
	}
}

func testContext() model.ScanContext {
	return model.ScanContext{
		DigestKey:            bytes.Repeat([]byte{0x5a}, 32),
		ServerAddr:           "192.0.2.10",
		ServerKeyLine:        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFake telltale-server",
		ServerKeyFingerprint: "SHA256:fake",
	}
}

func testCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func noRawControl(t *testing.T, s string) {
	t.Helper()
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			t.Errorf("raw control byte %#x in %q", r, s)
			return
		}
	}
}

func TestEnrolSnippetsExactText(t *testing.T) {
	const line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExampleExample telltale-server"
	for _, addr := range []string{"192.0.2.7", "2001:db8::5"} {
		ak, match := EnrolSnippets(addr, line)
		if want := `from="` + addr + `" ` + line; ak != want {
			t.Errorf("authorized_keys line:\n got %q\nwant %q", ak, want)
		}
		if want := "Match Address " + addr + "\n    PermitRootLogin prohibit-password\n"; match != want {
			t.Errorf("sshd block:\n got %q\nwant %q", match, want)
		}
	}
}

func TestVisitRefusesChangedHostKey(t *testing.T) {
	f := newFake(t)
	other := newSigner(t, "ed25519")
	m := f.machine()
	m.HostKey = authorizedLine(other.PublicKey())
	c, err := Visit(testCtx(t), m, f.client, testContext(), f.binaries(t))
	if !errors.Is(err, ErrHostKeyChanged) {
		t.Fatalf("err = %v, want ErrHostKeyChanged", err)
	}
	if c != nil {
		t.Error("a collection came back from a machine with another host key")
	}
	for _, fp := range []string{ssh.FingerprintSHA256(other.PublicKey()), ssh.FingerprintSHA256(f.hostKeys[0].PublicKey())} {
		if !strings.Contains(err.Error(), fp) {
			t.Errorf("the error does not name %s: %v", fp, err)
		}
	}
	f.mu.Lock()
	auths, cmds := f.auths, len(f.cmds)
	f.mu.Unlock()
	if auths != 0 || cmds != 0 {
		t.Errorf("the server offered its key %d times and ran %d commands on a machine whose host key changed", auths, cmds)
	}
	f.check(t)

	t.Run("nothing pinned", func(t *testing.T) {
		f := newFake(t)
		m := f.machine()
		m.HostKey = ""
		_, err := Visit(testCtx(t), m, f.client, testContext(), f.binaries(t))
		if !errors.Is(err, ErrNoHostKey) {
			t.Fatalf("err = %v, want ErrNoHostKey", err)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.conns != 0 {
			t.Errorf("Visit connected %d times to a machine with no pinned host key: no trust on first use", f.conns)
		}
	})
}

func TestVisitFallsBackToNextExecDir(t *testing.T) {
	f := newFake(t)
	f.mktempFails = map[string]bool{"/run": true}
	f.noexec = map[string]bool{"/var/tmp": true}
	sc := testContext()
	c, err := Visit(testCtx(t), f.machine(), f.client, sc, f.binaries(t))
	if err != nil {
		t.Fatalf("Visit: %v", err)
	}
	if !reflect.DeepEqual(c, f.collection) {
		t.Errorf("collection = %+v, want %+v", c, f.collection)
	}
	want := []string{
		"uname -m",
		"mktemp -d /run/telltale.XXXXXXXX",
		"mktemp -d /var/tmp/telltale.XXXXXXXX",
		"cat > '/var/tmp/telltale.*/telltale' && chmod 0700 '/var/tmp/telltale.*/telltale'",
		"'/var/tmp/telltale.*/telltale' version",
		"rm -rf '/var/tmp/telltale.*'",
		"mktemp -d /root/telltale.XXXXXXXX",
		"cat > '/root/telltale.*/telltale' && chmod 0700 '/root/telltale.*/telltale'",
		"'/root/telltale.*/telltale' version",
		"'/root/telltale.*/telltale' collect --context-stdin --gzip",
		"rm -rf '/root/telltale.*'",
	}
	if got := f.commands(); !reflect.DeepEqual(got, want) {
		t.Errorf("commands:\n got %q\nwant %q", got, want)
	}
	f.mu.Lock()
	if len(f.contexts) != 1 || !reflect.DeepEqual(f.contexts[0], sc) {
		t.Errorf("scan context on the machine = %+v, want %+v", f.contexts, sc)
	}
	f.mu.Unlock()
	f.check(t)

	t.Run("none lets it run", func(t *testing.T) {
		f := newFake(t)
		f.noexec = map[string]bool{"/run": true, "/var/tmp": true, "/root": true, "/tmp": true}
		c, err := Visit(testCtx(t), f.machine(), f.client, testContext(), f.binaries(t))
		if !errors.Is(err, ErrNoExecDir) {
			t.Fatalf("err = %v, want ErrNoExecDir", err)
		}
		if c != nil {
			t.Error("a collection with no exec directory")
		}
		for _, d := range execDirs {
			if !strings.Contains(err.Error(), d+": ") {
				t.Errorf("the error does not say why %s failed: %v", d, err)
			}
		}
		if !strings.Contains(err.Error(), "Permission denied") {
			t.Errorf("the error does not carry the machine's reason: %v", err)
		}
		for _, cmd := range f.commands() {
			if strings.Contains(cmd, " collect ") {
				t.Errorf("collect ran with no exec directory: %q", cmd)
			}
		}
		f.check(t)
	})
}

func TestVisitCleansUpAfterFailure(t *testing.T) {
	endless := func(level int, prefix string, fill byte) func(c call) int {
		return func(c call) int {
			zw, _ := gzip.NewWriterLevel(c.stdout, level)
			if _, err := zw.Write([]byte(prefix)); err != nil {
				return 1
			}
			chunk := bytes.Repeat([]byte{fill}, 32<<10)
			for c.ctx.Err() == nil {
				if level == gzip.NoCompression {
					rand.Read(chunk)
					for i := range chunk {
						chunk[i] = 'a' + chunk[i]%26
					}
				}
				if _, err := zw.Write(chunk); err != nil {
					return 1
				}
			}
			return 137
		}
	}
	cases := []struct {
		name    string
		collect func(c call) int
		max     int64 // maxOutput for the case; 0 keeps the default
		timeout time.Duration
		want    []string
		is      error
	}{
		{
			name: "collector fails",
			collect: func(c call) int {
				fmt.Fprint(c.stderr, "telltale collect: cannot read /proc\x1b]0;owned\x07\n")
				return 2
			},
			want: []string{"exit status 2", `cannot read /proc\x1b]0;owned\x07`},
		},
		{
			name:    "output is not gzip",
			collect: func(c call) int { fmt.Fprint(c.stdout, "hello"); return 0 },
			want:    []string{"gzip"},
		},
		{
			name: "data after the collection",
			collect: func(c call) int {
				zw := gzip.NewWriter(c.stdout)
				fmt.Fprint(zw, `{"schema":1} {"schema":1}`)
				zw.Close()
				return 0
			},
			want: []string{"after the collection"},
		},
		{
			name:    "too much output",
			collect: endless(gzip.NoCompression, `{"host":{"hostname":"`, 'a'),
			max:     256 << 10,
			want:    []string{"more than 262144 bytes"},
		},
		{
			name:    "decompresses to too much",
			collect: endless(gzip.BestCompression, `{"host":{"hostname":"`, 'a'),
			max:     256 << 10,
			want:    []string{"more than 262144 bytes"},
		},
		{
			name:    "hangs past the deadline",
			collect: func(c call) int { <-c.ctx.Done(); return 137 },
			timeout: time.Second,
			is:      context.DeadlineExceeded,
		},
		{
			name:    "connection drops",
			collect: func(c call) int { c.drop(); return 1 },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.max > 0 {
				old := maxOutput
				maxOutput = tc.max
				t.Cleanup(func() { maxOutput = old })
			}
			f := newFake(t)
			f.collect = tc.collect
			ctx := testCtx(t)
			if tc.timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, tc.timeout)
				defer cancel()
			}
			start := time.Now()
			c, err := Visit(ctx, f.machine(), f.client, testContext(), f.binaries(t))
			if err == nil {
				t.Fatalf("Visit succeeded: %+v", c)
			}
			if c != nil {
				t.Error("a collection came back with an error")
			}
			if time.Since(start) > 20*time.Second {
				t.Errorf("Visit took %v", time.Since(start))
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q does not contain %q", err, w)
				}
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Errorf("err = %v, want %v", err, tc.is)
			}
			noRawControl(t, err.Error())
			cmds := f.commands()
			if len(cmds) == 0 || !strings.HasPrefix(cmds[len(cmds)-1], "rm -rf '/run/telltale.") {
				t.Errorf("the last command was not the clean-up: %q", cmds)
			}
			f.check(t)
		})
	}
}

func TestVisitRefusesOddTempDir(t *testing.T) {
	for _, out := range []string{
		"/tmp/telltale.ABCDEFGH", // a good name, but not where it was asked for
		"/run/telltale.ABCDEFGH; touch /pwned",
		"/run/../etc/telltale.ABCDEFGH",
		"/run/telltale.ABC",
		"/run/telltale.ABCDEFG\x1b",
		"Welcome to the machine\n/run/telltale.ABCDEFGH",
		"",
	} {
		t.Run(fmt.Sprintf("%q", out), func(t *testing.T) {
			f := newFake(t)
			f.mktempOut = func(string) string { return out }
			_, err := Visit(testCtx(t), f.machine(), f.client, testContext(), f.binaries(t))
			if err == nil || !strings.Contains(err.Error(), "mktemp") {
				t.Fatalf("err = %v, want a refusal of mktemp's output", err)
			}
			noRawControl(t, err.Error())
			want := []string{"uname -m", "mktemp -d /run/telltale.XXXXXXXX"}
			if got := f.commands(); !reflect.DeepEqual(got, want) {
				t.Errorf("commands after odd mktemp output:\n got %q\nwant %q", got, want)
			}
			f.check(t)
		})
	}
}

func TestVisitUsesThePinnedKeyType(t *testing.T) {
	ec, ed := newSigner(t, "ecdsa"), newSigner(t, "ed25519")
	f := newFake(t, ec, ed)
	for _, k := range []ssh.Signer{ec, ed} {
		m := f.machine()
		m.HostKey = authorizedLine(k.PublicKey())
		if _, err := Visit(testCtx(t), m, f.client, testContext(), f.binaries(t)); err != nil {
			t.Errorf("pinned %s: %v", k.PublicKey().Type(), err)
		}
	}
	f.check(t)
}

func TestVisitRefusesShortDigestKey(t *testing.T) {
	f := newFake(t)
	sc := testContext()
	sc.DigestKey = nil
	if _, err := Visit(testCtx(t), f.machine(), f.client, sc, f.binaries(t)); err == nil {
		t.Fatal("Visit ran without a digest key")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.conns != 0 {
		t.Errorf("Visit connected without a digest key to send")
	}
}

func TestFetchHostKey(t *testing.T) {
	ec, ed := newSigner(t, "ecdsa"), newSigner(t, "ed25519")
	f := newFake(t, ec, ed)
	key, fp, err := FetchHostKey(testCtx(t), f.addr)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key.Marshal(), ed.PublicKey().Marshal()) {
		t.Errorf("fetched a %s key, want the ed25519 one", key.Type())
	}
	if want := ssh.FingerprintSHA256(ed.PublicKey()); fp != want {
		t.Errorf("fingerprint = %q, want %q", fp, want)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.auths != 0 || len(f.cmds) != 0 {
		t.Errorf("fetching the host key offered the server's key %d times and ran %q", f.auths, f.cmds)
	}
}

// An empty address would become ":22", which is this host's own sshd.
func TestEmptyAddressRefused(t *testing.T) {
	f := newFake(t)
	m := f.machine()
	m.Addr = " "
	if _, err := Visit(testCtx(t), m, f.client, testContext(), f.binaries(t)); err == nil || !strings.Contains(err.Error(), "no address") {
		t.Errorf("Visit with no address: %v", err)
	}
	if _, _, err := FetchHostKey(testCtx(t), ""); err == nil || !strings.Contains(err.Error(), "no address") {
		t.Errorf("FetchHostKey with no address: %v", err)
	}
}

func TestWithPort(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.1":          "192.0.2.1:22",
		"192.0.2.1:2222":     "192.0.2.1:2222",
		"web01.lan":          "web01.lan:22",
		"2001:db8::1":        "[2001:db8::1]:22",
		"[2001:db8::1]:2222": "[2001:db8::1]:2222",
		"[2001:db8::1]":      "[2001:db8::1]:22",
	} {
		if got := withPort(in); got != want {
			t.Errorf("withPort(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestServerKeyPersistsAcrossOpen(t *testing.T) {
	dir := t.TempDir()
	db, keyFile := filepath.Join(dir, "server.db"), filepath.Join(dir, "server.key")
	open := func() *store.Store {
		st, err := store.Open(db, store.Unlock{KeyFile: keyFile})
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	st := open()
	s1, line1, err := ServerKey(st)
	if err != nil {
		t.Fatal(err)
	}
	if s1.PublicKey().Type() != ssh.KeyAlgoED25519 {
		t.Errorf("server key type %s, want ed25519", s1.PublicKey().Type())
	}
	again, lineAgain, err := ServerKey(st)
	if err != nil || lineAgain != line1 || !bytes.Equal(again.PublicKey().Marshal(), s1.PublicKey().Marshal()) {
		t.Fatalf("second ServerKey in the same store gave another key: %v", err)
	}
	st.Close()

	st = open()
	defer st.Close()
	s2, line2, err := ServerKey(st)
	if err != nil {
		t.Fatal(err)
	}
	if line2 != line1 {
		t.Errorf("key line after reopening:\n got %q\nwant %q", line2, line1)
	}
	// The private key itself came back, not only the public one.
	data := []byte("telltale server key check")
	sig, err := s2.Sign(rand.Reader, data)
	if err != nil {
		t.Fatal(err)
	}
	if err := s1.PublicKey().Verify(data, sig); err != nil {
		t.Errorf("the reopened key signs differently: %v", err)
	}
	pub, _, opts, rest, err := ssh.ParseAuthorizedKey([]byte(line1))
	if err != nil || len(opts) != 0 || len(rest) != 0 || !bytes.Equal(pub.Marshal(), s1.PublicKey().Marshal()) {
		t.Errorf("%q is not a plain authorized_keys line for the key (err %v, options %q)", line1, err, opts)
	}
	if strings.Contains(line1, "\n") {
		t.Errorf("key line %q holds a newline", line1)
	}
	if raw, err := st.SecretSetting("ssh_key"); err != nil || raw == nil {
		t.Errorf("no sealed ssh_key setting: %v", err)
	}
	b, err := os.ReadFile(db)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("PRIVATE KEY")) {
		t.Error("the private key is in the database in the clear")
	}
}

func TestBinariesFor(t *testing.T) {
	dir := t.TempDir()
	amd := filepath.Join(dir, "telltale-linux-amd64")
	if err := os.WriteFile(amd, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	b := Binaries{Dir: dir}
	if p, err := b.For("x86_64"); err != nil || p != amd {
		t.Errorf("For(x86_64) = %q, %v; want %q", p, err, amd)
	}
	if _, err := b.For("aarch64"); err == nil {
		t.Error("For(aarch64) found a binary that is not there")
	}
	if _, err := b.For("mips\x1b"); err == nil {
		t.Error("For(mips) found a binary")
	} else {
		noRawControl(t, err.Error())
	}

	own := map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[runtime.GOARCH]
	if own == "" || runtime.GOOS != "linux" {
		t.Skipf("no collector architecture for %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	exe, _ = filepath.EvalSymlinks(exe)
	if p, err := (Binaries{}).For(own); err != nil || p != exe {
		t.Errorf("Binaries{}.For(%s) = %q, %v; want the running executable %q", own, p, err, exe)
	}
	other := map[string]string{"x86_64": "aarch64", "aarch64": "x86_64"}[own]
	if p, err := (Binaries{}).For(other); err == nil {
		t.Errorf("Binaries{}.For(%s) = %q, want an error: nothing for that architecture sits next to the executable", other, p)
	}
}
