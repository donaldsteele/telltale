package visit

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/donaldsteele/telltale/internal/model"
	"golang.org/x/crypto/ssh"
)

func gz(t *testing.T, s string) *bytes.Reader {
	t.Helper()
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	zw.Write([]byte(s))
	zw.Close()
	return bytes.NewReader(b.Bytes())
}

// A machine can send a small collection that decodes to a very large one:
// millions of empty entries. The entries are counted on the raw text before
// anything is decoded, and a collection over a cap is refused.
func TestDecodeRefusesTooManyEntries(t *testing.T) {
	set(t, &maxEntries, entryCaps{Files: 100, Persist: 10, Processes: 20, Sockets: 20, Packages: 5, Other: 200, Strings: 300, MapMembers: 50, Depth: 12})
	rep := func(s string, n int) string { return strings.TrimSuffix(strings.Repeat(s+",", n), ",") }
	ok := `{"schema":1,"files":[` + rep(`{"path":"/a"}`, 100) + `],"persist":[{"path":"/p","lines":[` + rep(`"x"`, 250) + `]}],` +
		`"runtime":{"processes":[` + rep(`{}`, 20) + `],"sockets":[]},"packages":{"installed":[` + rep(`{"name":"a","files":["/f"],"local_md5":{"/f":"0"}}`, 5) + `]},"sysctl":{"a":"1"}}`
	var c model.Collection
	if err := decodeCollection(gz(t, ok), &c); err != nil || len(c.Files) != 100 || len(c.Packages.Installed) != 5 {
		t.Fatalf("at the caps: %v (%d files)", err, len(c.Files))
	}
	for name, doc := range map[string]string{
		"files":              `{"schema":1,"files":[` + rep(`{}`, 101) + `]}`,
		"persist":            `{"schema":1,"persist":[` + rep(`{}`, 11) + `]}`,
		"persist lines":      `{"schema":1,"persist":[{"lines":[` + rep(`""`, 301) + `]}]}`,
		"processes":          `{"schema":1,"runtime":{"processes":[` + rep(`{}`, 21) + `]}}`,
		"sockets":            `{"schema":1,"runtime":{"sockets":[` + rep(`{}`, 21) + `]}}`,
		"packages":           `{"schema":1,"packages":{"installed":[` + rep(`{}`, 6) + `]}}`,
		"package files":      `{"schema":1,"packages":{"installed":[{"files":[` + rep(`""`, 301) + `]}]}}`,
		"checksum map":       `{"schema":1,"packages":{"installed":[{"local_md5":{` + rep(`"":""`, 51) + `}}]}}`,
		"sysctl map":         `{"schema":1,"sysctl":{` + rep(`"":""`, 51) + `}}`,
		"users":              `{"schema":1,"accounts":{"users":[` + rep(`{}`, 201) + `]}}`,
		"an unknown array":   `{"schema":1,"junk":[` + rep(`[]`, 201) + `]}`,
		"nesting":            `{"schema":1,"junk":` + strings.Repeat("[", 40) + strings.Repeat("]", 40) + `}`,
		"entries split up":   `{"schema":1,"files":[` + rep(`{}`, 60) + `],"files":[` + rep(`{}`, 60) + `]}`,
		"an array for a map": `{"schema":1,"sysctl":[` + rep(`0`, 301) + `]}`,
	} {
		var c model.Collection
		err := decodeCollection(gz(t, doc), &c)
		if !errors.Is(err, ErrOversized) {
			t.Errorf("%s: err = %v, want ErrOversized", name, err)
		}
		if len(c.Files)+len(c.Persist)+len(c.Runtime.Processes)+len(c.Packages.Installed)+len(c.Sysctl) != 0 {
			t.Errorf("%s: decoded before it was refused", name)
		}
		if err != nil {
			noRawControl(t, err.Error())
		}
	}
}

// The default bound on what one visit may send.
func TestDefaultMaxCollectionIs64MiB(t *testing.T) {
	if DefaultMaxCollection != 64<<20 || maxOutput != DefaultMaxCollection {
		t.Errorf("default %d, in force %d", DefaultMaxCollection, maxOutput)
	}
}

// What the machine does wrong after it let the server in is told apart from
// a machine that cannot be reached or that drops the connection: the server
// ranks the first as a backdoor sign.
func TestVisitMarksACollectorThatMisbehaves(t *testing.T) {
	for name, tc := range map[string]struct {
		collect func(c call) int
		max     int64
		want    bool
	}{
		"killed":           {collect: func(c call) int { return 137 }, want: true},
		"not a collection": {collect: func(c call) int { fmt.Fprint(c.stdout, "hello"); return 0 }, want: true},
		"too much output":  {collect: func(c call) int { c.stdout.Write(bytes.Repeat([]byte("a"), 1<<20)); return 0 }, max: 64 << 10, want: true},
		"too many entries": {collect: func(c call) int {
			zw := gzip.NewWriter(c.stdout)
			fmt.Fprint(zw, `{"schema":1,"files":[`+strings.TrimSuffix(strings.Repeat("{},", 50), ",")+`]}`)
			zw.Close()
			return 0
		}, want: true},
		"connection drops": {collect: func(c call) int { c.drop(); return 1 }, want: false},
	} {
		t.Run(name, func(t *testing.T) {
			if tc.max > 0 {
				set(t, &maxOutput, tc.max)
			}
			caps := maxEntries
			caps.Files = 10
			set(t, &maxEntries, caps)
			f := newFake(t)
			f.collect = tc.collect
			_, err := Visit(testCtx(t), f.machine(), f.client, testContext(), f.binaries(t))
			if err == nil || errors.Is(err, ErrCollectorFailed) != tc.want {
				t.Errorf("err = %v; ErrCollectorFailed = %v, want %v", err, errors.Is(err, ErrCollectorFailed), tc.want)
			}
			if name == "too many entries" && !errors.Is(err, ErrOversized) {
				t.Errorf("err = %v, want ErrOversized", err)
			}
		})
	}
	// No directory to run from is the machine's configuration, not this.
	if errors.Is(fmt.Errorf("visit x: %w (all noexec)", ErrNoExecDir), ErrCollectorFailed) {
		t.Error("ErrNoExecDir counts as a misbehaving collector")
	}
}

// ErrLoginRefused means the SSH server rejected the server's key, nothing
// else: a login that times out or a connection that ends during it is a
// machine that could not be reached.
func TestLoginRefusedMeansAuthenticationFailedOnly(t *testing.T) {
	set(t, &dialTimeout, 2*time.Second)
	f := newFake(t)
	serve := func(onAuth func(nc net.Conn)) string {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { l.Close() })
		go func() {
			for {
				nc, err := l.Accept()
				if err != nil {
					return
				}
				cfg := &ssh.ServerConfig{PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
					onAuth(nc)
					return nil, errors.New("never reached a decision")
				}}
				for _, k := range f.hostKeys {
					cfg.AddHostKey(k)
				}
				go func() {
					ssh.NewServerConn(nc, cfg)
					nc.Close()
				}()
			}
		}()
		return l.Addr().String()
	}
	for name, onAuth := range map[string]func(net.Conn){
		"the connection ends during the login": func(nc net.Conn) { nc.Close() },
		"the login times out":                  func(net.Conn) { time.Sleep(4 * time.Second) },
	} {
		m := f.machine()
		m.Addr = serve(onAuth)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		_, err := Visit(ctx, m, f.client, testContext(), f.binaries(t))
		cancel()
		if err == nil || errors.Is(err, ErrLoginRefused) || errors.Is(err, ErrHostKeyChanged) {
			t.Errorf("%s: err = %v, want a failure that is not ErrLoginRefused", name, err)
		}
	}
	// The real thing is still marked.
	if _, err := Visit(testCtx(t), f.machine(), newSigner(t, "ed25519"), testContext(), f.binaries(t)); !errors.Is(err, ErrLoginRefused) {
		t.Errorf("a rejected key: %v", err)
	}
}

// The caller is told when a visit starts to read what the machine sent,
// before any of it is decoded: from then on the machine's data is in the
// server's memory.
func TestDecodeHookRunsBeforeTheCollectionIsRead(t *testing.T) {
	f := newFake(t)
	var order []string
	set(t, &decodeOutput, func(r io.Reader, c *model.Collection) error {
		order = append(order, "decode")
		return decodeCollection(r, c)
	})
	ctx := WithDecodeHook(testCtx(t), func() { order = append(order, "hook") })
	if _, err := Visit(ctx, f.machine(), f.client, testContext(), f.binaries(t)); err != nil {
		t.Fatal(err)
	}
	if len(order) != 2 || order[0] != "hook" || order[1] != "decode" {
		t.Errorf("order %v", order)
	}
	// A visit that never gets that far does not call it.
	called := false
	ctx = WithDecodeHook(testCtx(t), func() { called = true })
	Visit(ctx, f.machine(), newSigner(t, "ed25519"), testContext(), f.binaries(t))
	if called {
		t.Error("the hook ran for a visit that was refused at the login")
	}
}
