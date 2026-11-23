// Package visit is server mode's visit to an enrolled machine. The server
// logs in as root over SSH, accepting only the host key pinned at
// enrolment, copies a fresh collector binary into a temporary directory
// that allows execution, runs "telltale collect --context-stdin --gzip"
// with the scan context on stdin and reads the collection from stdout. The
// directory is removed on every path, failures included.
//
// The temporary binary is the only thing a visit writes to a machine: no
// snapshot and no cache is ever put there. Every remote command is built
// from fixed strings and mktemp's output, and that output is used only when
// it is exactly a directory of the expected form. Everything the machine
// prints that ends up in an error is escaped for the terminal.
//
// Enrolment is the other half: ServerKey makes the server's own key,
// EnrolSnippets gives the owner the lines to add on the machine, and
// FetchHostKey shows the host key's fingerprint for the owner to confirm.
package visit

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/donaldsteele/telltale/internal/escape"
	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/store"
)

var (
	// ErrHostKeyChanged means the machine offered a host key other than
	// the pinned one. Nothing was sent to it: the server did not log in.
	ErrHostKeyChanged = errors.New("the machine's host key is not the one pinned at enrolment")
	// ErrNoHostKey means the machine has no pinned host key yet. Visit
	// never trusts a key on first use; see FetchHostKey.
	ErrNoHostKey = errors.New("the machine has no pinned host key; confirm its fingerprint at enrolment first")
	// ErrNoExecDir means the collector could not run from a temporary
	// directory in any of /run, /var/tmp, /root and /tmp.
	ErrNoExecDir = errors.New("no temporary directory on the machine lets the collector run")
)

// execDirs are the places tried, in order, for the collector's temporary
// directory. /run comes first because it is a tmpfs, so even a directory
// a lost connection left behind is gone at the next boot; /tmp comes last
// because it is the one most often mounted noexec.
var execDirs = []string{"/run", "/var/tmp", "/root", "/tmp"}

// tempDirRE is the only form of mktemp output a visit uses in a command.
var tempDirRE = regexp.MustCompile(`^/(run|var/tmp|root|tmp)/telltale\.[A-Za-z0-9]{8}$`)

// Limits on each step. Every step also ends when the visit's context does.
// Variables, so tests can shorten them.
var (
	dialTimeout    = 30 * time.Second // connect, key exchange and login
	commandTimeout = time.Minute      // uname, mktemp, version
	uploadTimeout  = 10 * time.Minute // copying the collector
	collectTimeout = time.Hour        // the collection itself
	cleanupTimeout = time.Minute      // rm -rf of the directory
)

// maxOutput bounds the collector's stdout and the JSON it decompresses to.
// The store cannot hold a larger collection either.
var maxOutput int64 = 512 << 20

const (
	maxStderr      = 64 << 10 // the last 64 KiB of a command's stderr are kept for its error
	maxShortOutput = 4 << 10  // stdout of every command but collect
	minDigestKey   = 16       // what the collector accepts
)

var (
	// errSession marks a connection that can no longer run commands.
	errSession = errors.New("cannot run a command on the machine")
	// errOdd marks machine output a visit will not go on with.
	errOdd = errors.New("unexpected output")
	// errTooMuch marks output over its limit.
	errTooMuch = errors.New("too large")
)

// Visit logs into m as root with signer, runs a fresh collector there with
// sc on its stdin and returns the collection. It accepts only m.HostKey (an
// authorized_keys style line, as FetchHostKey's key is stored): a different
// key is ErrHostKeyChanged, an empty one ErrNoHostKey. bins supplies the
// collector for the architecture uname -m reports.
//
// The collector's temporary directory is removed before Visit returns,
// after a failure or a cancelled ctx too (the removal gets its own short
// time limit, and logs in again if the connection was lost). When even that
// fails, the error names the directory.
func Visit(ctx context.Context, m store.Machine, signer ssh.Signer, sc model.ScanContext, bins Binaries) (c *model.Collection, err error) {
	fail := func(err error) (*model.Collection, error) {
		return nil, fmt.Errorf("visit %s: %w", m.Name, err)
	}
	if len(sc.DigestKey) < minDigestKey {
		return fail(fmt.Errorf("the scan context's digest key is %d bytes, the collector needs at least %d", len(sc.DigestKey), minDigestKey))
	}
	pinned, err := pinnedKey(m.HostKey)
	if err != nil {
		return fail(err)
	}
	hostport, err := hostPort(m.Addr)
	if err != nil {
		return fail(err)
	}
	input, err := json.Marshal(sc)
	if err != nil {
		return fail(err)
	}
	cfg := &ssh.ClientConfig{
		User:              "root",
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyAlgorithms: algorithmsFor(pinned),
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
			if bytes.Equal(k.Marshal(), pinned.Marshal()) {
				return nil
			}
			return fmt.Errorf("%w: pinned %s, the machine offered %s", ErrHostKeyChanged, ssh.FingerprintSHA256(pinned), ssh.FingerprintSHA256(k))
		},
	}
	client, err := handshake(ctx, hostport, cfg)
	if err != nil {
		return fail(fmt.Errorf("log in to %s: %w", hostport, err))
	}
	r := &remote{client: client, relogin: func(ctx context.Context) (*ssh.Client, error) { return handshake(ctx, hostport, cfg) }}
	defer func() { r.client.Close() }()
	defer func() {
		if cerr := r.cleanup(ctx); cerr != nil {
			c, err = nil, errors.Join(err, fmt.Errorf("visit %s: %w", m.Name, cerr))
		}
	}()
	if c, err = r.visit(ctx, input, bins); err != nil {
		return fail(err)
	}
	return c, nil
}

// pinnedKey parses the stored host key.
func pinnedKey(line string) (ssh.PublicKey, error) {
	if strings.TrimSpace(line) == "" {
		return nil, ErrNoHostKey
	}
	k, _, opts, rest, err := ssh.ParseAuthorizedKey([]byte(line))
	if err == nil && (len(opts) > 0 || len(bytes.TrimSpace(rest)) > 0) {
		err = errors.New("it is not a single key without options")
	}
	if err != nil {
		return nil, fmt.Errorf("the pinned host key is unreadable: %w", err)
	}
	return k, nil
}

// algorithmsFor asks the machine for the pinned key's own algorithm, so a
// machine with several host keys shows the pinned one and not another.
func algorithmsFor(k ssh.PublicKey) []string {
	if k.Type() == ssh.KeyAlgoRSA {
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
	}
	return []string{k.Type()}
}

// remote is one visit's connection and the directories it made.
type remote struct {
	client  *ssh.Client
	relogin func(context.Context) (*ssh.Client, error)
	made    []string // temporary directories not yet removed
}

func (r *remote) visit(ctx context.Context, input []byte, bins Binaries) (*model.Collection, error) {
	var out []byte
	if err := r.run(ctx, "uname -m", "uname -m", commandTimeout, nil, maxShortOutput, keep(&out)); err != nil {
		return nil, err
	}
	bin, err := bins.For(strings.TrimSpace(string(out)))
	if err != nil {
		return nil, err
	}
	f, err := os.Open(bin)
	if err != nil {
		return nil, fmt.Errorf("open the collector: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("open the collector: %w", err)
	}
	d, err := r.execDir(ctx, io.NewSectionReader(f, 0, fi.Size()))
	if err != nil {
		return nil, err
	}
	var c model.Collection
	err = r.run(ctx, "collect", quote(d+"/telltale")+" collect --context-stdin --gzip", collectTimeout,
		bytes.NewReader(input), maxOutput, func(rd io.Reader) error { return decodeCollection(rd, &c) })
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// execDir makes a temporary directory in the first of execDirs where the
// collector, copied in, runs, and returns it with the collector inside.
func (r *remote) execDir(ctx context.Context, bin *io.SectionReader) (string, error) {
	var why []string
	for _, base := range execDirs {
		d, err := r.mktemp(ctx, base)
		if err == nil {
			if err = r.install(ctx, d, io.NewSectionReader(bin, 0, bin.Size())); err == nil {
				if err = r.check(ctx, d); err == nil {
					return d, nil
				}
			}
		}
		if ctx.Err() != nil || errors.Is(err, errSession) || errors.Is(err, errOdd) {
			return "", err
		}
		why = append(why, base+": "+err.Error())
		if d != "" {
			r.remove(ctx, d) // the deferred clean-up tries again if this fails
		}
	}
	return "", fmt.Errorf("%w (%s)", ErrNoExecDir, strings.Join(why, "; "))
}

// mktemp makes a directory of the visit's own in base and returns its name,
// which is used in later commands only after it matches tempDirRE.
func (r *remote) mktemp(ctx context.Context, base string) (string, error) {
	var out []byte
	err := r.run(ctx, "mktemp", "mktemp -d "+base+"/telltale.XXXXXXXX", commandTimeout, nil, maxShortOutput, keep(&out))
	if errors.Is(err, errTooMuch) {
		return "", fmt.Errorf("%w: %w", errOdd, err)
	}
	if err != nil {
		return "", err
	}
	d := strings.TrimSuffix(string(out), "\n")
	if !tempDirRE.MatchString(d) || !strings.HasPrefix(d, base+"/telltale.") {
		return "", fmt.Errorf("%w: mktemp in %s printed \"%s\", not a new directory there; nothing was run with it", errOdd, base, escape.Terminal(d))
	}
	r.made = append(r.made, d)
	return d, nil
}

// install copies the collector to d/telltale.
func (r *remote) install(ctx context.Context, d string, bin io.Reader) error {
	p := quote(d + "/telltale")
	return r.run(ctx, "copy the collector to "+d, "cat > "+p+" && chmod 0700 "+p, uploadTimeout, bin, maxShortOutput, nil)
}

// check runs d/telltale version: it fails where the directory is mounted
// noexec.
func (r *remote) check(ctx context.Context, d string) error {
	var out []byte
	if err := r.run(ctx, "run the collector in "+d, quote(d+"/telltale")+" version", commandTimeout, nil, maxShortOutput, keep(&out)); err != nil {
		return err
	}
	if !bytes.HasPrefix(out, []byte("telltale ")) {
		return fmt.Errorf("the collector in %s printed \"%s\", not its version", d, escape.Terminal(strings.TrimSpace(string(out))))
	}
	return nil
}

// remove deletes temporary directories. It is not stopped by the end of
// ctx: a visit that was cancelled still cleans up.
func (r *remote) remove(ctx context.Context, dirs ...string) error {
	quoted := make([]string, len(dirs))
	for i, d := range dirs {
		quoted[i] = quote(d)
	}
	err := r.run(context.WithoutCancel(ctx), "remove "+strings.Join(dirs, " "), "rm -rf "+strings.Join(quoted, " "),
		cleanupTimeout, nil, maxShortOutput, nil)
	if err == nil {
		r.made = slices.DeleteFunc(r.made, func(d string) bool { return slices.Contains(dirs, d) })
	}
	return err
}

// cleanup removes every directory the visit made and has not removed yet,
// logging in again when the connection was lost.
func (r *remote) cleanup(ctx context.Context) error {
	if len(r.made) == 0 {
		return nil
	}
	dirs := slices.Clone(r.made)
	err := r.remove(ctx, dirs...)
	if errors.Is(err, errSession) {
		c, lerr := r.relogin(context.WithoutCancel(ctx))
		if lerr == nil {
			r.client.Close()
			r.client = c
			err = r.remove(ctx, dirs...)
		} else {
			err = errors.Join(err, fmt.Errorf("log in again: %w", lerr))
		}
	}
	if err != nil {
		return fmt.Errorf("could not remove %s from the machine: %w", strings.Join(dirs, " "), err)
	}
	return nil
}

// run runs one command line in a new session. stdin, when not nil, is sent
// to it. Its stdout is read through a reader that fails past max bytes, by
// read when that is not nil; the rest is discarded. The command is killed
// when ctx ends, when limit passes or when its output is over max.
func (r *remote) run(ctx context.Context, what, line string, limit time.Duration, stdin io.Reader, max int64, read func(io.Reader) error) error {
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	start := time.Now()
	s, err := r.client.NewSession()
	if err != nil {
		return fmt.Errorf("%s: %w: %w", what, errSession, escaped{err})
	}
	defer s.Close()
	if stdin != nil {
		s.Stdin = stdin
	}
	errs := &tail{max: maxStderr}
	s.Stderr = errs
	stdout, err := s.StdoutPipe()
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	if err := s.Start(line); err != nil {
		return fmt.Errorf("%s: %w: %w", what, errSession, escaped{err})
	}
	type result struct{ read, wait error }
	done := make(chan result, 1)
	go func() {
		out := &capReader{r: stdout, max: max, what: "the output"}
		var rerr error
		if read != nil {
			rerr = read(out)
		}
		if !errors.Is(rerr, errTooMuch) {
			// Read the rest, still bounded, so the command can end and
			// its exit status can say why it failed.
			if _, err := io.Copy(io.Discard, out); err != nil && rerr == nil {
				rerr = err
			}
		}
		if errors.Is(rerr, errTooMuch) {
			s.Signal(ssh.SIGKILL)
			s.Close()
			done <- result{read: rerr}
			return
		}
		done <- result{read: rerr, wait: s.Wait()}
	}()
	select {
	case res := <-done:
		return outcome(what, res.read, res.wait, errs)
	case <-ctx.Done():
		s.Signal(ssh.SIGKILL)
		s.Close()
		return fmt.Errorf("%s: stopped after %v: %w%s", what, time.Since(start).Round(time.Millisecond), ctx.Err(), errs.suffix())
	}
}

// outcome turns how a command went into an error, or nil when it ran,
// exited 0 and its output was read.
func outcome(what string, rerr, werr error, errs *tail) error {
	var exit *ssh.ExitError
	var missing *ssh.ExitMissingError
	switch {
	case errors.As(werr, &exit):
		if sig := exit.Signal(); sig != "" {
			return fmt.Errorf("%s: killed by signal %s%s", what, escape.Terminal(sig), errs.suffix())
		}
		return fmt.Errorf("%s: exit status %d%s", what, exit.ExitStatus(), errs.suffix())
	case errors.As(werr, &missing):
		return fmt.Errorf("%s: the command or the connection ended without an exit status%s", what, errs.suffix())
	case rerr != nil:
		return fmt.Errorf("%s: %w%s", what, rerr, errs.suffix())
	case werr != nil:
		return fmt.Errorf("%s: %w%s", what, escaped{werr}, errs.suffix())
	}
	return nil
}

// decodeCollection reads one gzip-compressed collection and nothing after it.
func decodeCollection(r io.Reader, c *model.Collection) error {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("the output is not gzip: %w", err)
	}
	dec := json.NewDecoder(&capReader{r: zr, max: maxOutput, what: "the decompressed collection"})
	if err := dec.Decode(c); err != nil {
		return fmt.Errorf("the output is not a collection: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return errors.New("unexpected data after the collection")
		}
		return fmt.Errorf("after the collection: %w", err)
	}
	if c.Schema != model.CollectionSchema {
		return fmt.Errorf("the collection has schema %d, this server reads %d", c.Schema, model.CollectionSchema)
	}
	return nil
}

// keep returns a reader function that stores everything it reads in dst.
func keep(dst *[]byte) func(io.Reader) error {
	return func(r io.Reader) error {
		b, err := io.ReadAll(r)
		*dst = b
		return err
	}
}

// quote quotes a checked temporary path for the remote shell.
func quote(p string) string { return escape.ShellQuote(p) }

// capReader fails with errTooMuch once more than max bytes come through.
type capReader struct {
	r      io.Reader
	n, max int64
	what   string
}

func (c *capReader) Read(p []byte) (int, error) {
	if c.n >= c.max {
		var one [1]byte
		if n, err := c.r.Read(one[:]); n == 0 {
			return 0, err
		}
		return 0, fmt.Errorf("%s is %w: more than %d bytes", c.what, errTooMuch, c.max)
	}
	if rest := c.max - c.n; int64(len(p)) > rest {
		p = p[:rest]
	}
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// tail keeps the last max bytes written to it.
type tail struct {
	mu  sync.Mutex
	buf []byte
	max int
	cut bool
}

func (t *tail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := len(p)
	if len(p) > t.max {
		p, t.cut = p[len(p)-t.max:], true
	}
	if over := len(t.buf) + len(p) - t.max; over > 0 {
		t.buf, t.cut = append(t.buf[:0], t.buf[over:]...), true
	}
	t.buf = append(t.buf, p...)
	return n, nil
}

// suffix is ": " and the kept text, escaped for the terminal, or "".
func (t *tail) suffix() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := strings.TrimSpace(string(t.buf))
	if s == "" {
		return ""
	}
	if t.cut {
		s = "..." + s
	}
	return ": " + escape.Terminal(s)
}

// escaped is an error whose text may hold bytes from the machine (an SSH
// disconnect message, say). Its text is escaped for the terminal.
type escaped struct{ err error }

func (e escaped) Error() string { return escape.Terminal(e.err.Error()) }
func (e escaped) Unwrap() error { return e.err }
