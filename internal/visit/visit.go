// Package visit is server mode's visit to an enrolled machine. The server
// logs in as root over SSH, accepting only the host key pinned at
// enrolment, copies a fresh collector binary into a temporary directory
// that allows execution, runs "telltale collect --context-stdin --gzip"
// with the scan context on stdin and reads the collection from stdout. The
// directory is removed on every path, failures and a machine that stops
// answering included; when even that fails, the error is a
// *LeftOnMachineError naming what stayed behind.
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
	"sync/atomic"
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

// Limits on each step. Every step also ends when the visit's context does;
// the clean-up's steps do not (see remote.cleanup). Variables, so tests can
// shorten them.
var (
	dialTimeout    = 30 * time.Second // connect, key exchange and login
	commandTimeout = time.Minute      // uname, mktemp, version
	uploadTimeout  = 10 * time.Minute // copying the collector
	collectTimeout = time.Hour        // the collection itself
	cleanupTimeout = 30 * time.Second // each rm -rf of the directories
	// stopGrace is how long a step that is over may take to stop its
	// command before the whole connection is closed under it.
	stopGrace = 2 * time.Second
	// keepaliveInterval is how often a running step checks that the
	// machine still answers; keepaliveMisses unanswered checks in a row
	// close the connection.
	keepaliveInterval = 30 * time.Second
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
	// errStopped marks a step that ran out of time. Its connection may
	// have been closed under it.
	errStopped = errors.New("stopped")
	// errOdd marks machine output a visit will not go on with.
	errOdd = errors.New("unexpected output")
	// errTooMuch marks output over its limit.
	errTooMuch = errors.New("too large")
)

// LeftOnMachineError means the collector's temporary directories could not
// be removed from the machine: a telltale binary stays there, and the owner
// should be told. When the collection itself was read, Collection holds it,
// so the server can keep it. It is nil when the visit had failed anyway;
// Visit's error then carries that failure as well.
type LeftOnMachineError struct {
	Dirs       []string
	Collection *model.Collection
	Err        error // why the removal failed
}

func (e *LeftOnMachineError) Error() string {
	return fmt.Sprintf("could not remove %s from the machine: %v", strings.Join(e.Dirs, " "), e.Err)
}

func (e *LeftOnMachineError) Unwrap() error { return e.Err }

// Visit logs into m as root with signer, runs a fresh collector there with
// sc on its stdin and returns the collection. It accepts only m.HostKey (an
// authorized_keys style line, as FetchHostKey's key is stored): a different
// key is ErrHostKeyChanged, an empty one ErrNoHostKey. bins supplies the
// collector for the architecture uname -m reports.
//
// Every step has its own time limit and also ends with ctx. A machine that
// stops answering cannot hold a step past that: after stopGrace the
// connection is closed under it.
//
// The collector's temporary directory is removed before Visit returns,
// after a failure or a cancelled ctx too: the removal has time limits of its
// own, and logs in again when the connection was lost or the machine stopped
// answering on it. When even that fails, the error wraps a
// *LeftOnMachineError naming the directories (and holding the collection,
// if it was read), and the returned collection is nil.
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
		cerr := r.cleanup(ctx)
		if cerr == nil {
			return
		}
		var left *LeftOnMachineError
		if err == nil && errors.As(cerr, &left) {
			left.Collection = c
		}
		if err == nil {
			err = fmt.Errorf("visit %s: %w", m.Name, cerr)
		} else {
			err = fmt.Errorf("%w; and %w", err, cerr) // one line: no newline from errors.Join
		}
		c = nil
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

// algorithmsFor lists the pinned key's own algorithm first: SSH takes the
// client's preference, so a machine with several host keys shows the pinned
// one. The other algorithms follow, so that a machine (or a man in the
// middle) holding only another kind of key is ErrHostKeyChanged, not a bare
// failure to agree on an algorithm.
func algorithmsFor(k ssh.PublicKey) []string {
	algs := []string{k.Type()}
	if k.Type() == ssh.KeyAlgoRSA {
		algs = []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
	}
	for _, a := range fetchAlgorithms {
		if !slices.Contains(algs, a) {
			algs = append(algs, a)
		}
	}
	return algs
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
		bytes.NewReader(input), maxOutput, func(rd io.Reader) error { return decodeOutput(rd, &c) })
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
		if ctx.Err() != nil || errors.Is(err, errSession) || errors.Is(err, errStopped) || errors.Is(err, errOdd) {
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
		return "", fmt.Errorf("%w: %w; a directory mktemp may have made in %s is left on the machine", errOdd, err, base)
	}
	if errors.Is(err, errStopped) {
		// It may have run, and its directory is unknown.
		return "", fmt.Errorf("%w; a directory mktemp may have made in %s is left on the machine", err, base)
	}
	if err != nil {
		return "", err
	}
	d := strings.TrimSuffix(string(out), "\n")
	if !tempDirRE.MatchString(d) || !strings.HasPrefix(d, base+"/telltale.") {
		return "", fmt.Errorf("%w: mktemp in %s printed \"%s\", not a new directory there; nothing was run with it, and a directory mktemp may have made in %s is left on the machine",
			errOdd, base, escape.Terminal(d), base)
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

// remove deletes temporary directories.
func (r *remote) remove(ctx context.Context, dirs ...string) error {
	quoted := make([]string, len(dirs))
	for i, d := range dirs {
		quoted[i] = quote(d)
	}
	err := r.run(ctx, "remove "+strings.Join(dirs, " "), "rm -rf "+strings.Join(quoted, " "),
		cleanupTimeout, nil, maxShortOutput, nil)
	if err == nil {
		r.made = slices.DeleteFunc(r.made, func(d string) bool { return slices.Contains(dirs, d) })
	}
	return err
}

// cleanup removes every directory the visit made and has not removed yet.
// The end of ctx does not stop it (a cancelled visit still cleans up), but
// each of its steps has a limit of its own. When the connection is gone or
// the machine stopped answering on it, it logs in again once and retries.
// A failure is a *LeftOnMachineError.
func (r *remote) cleanup(ctx context.Context) error {
	if len(r.made) == 0 {
		return nil
	}
	ctx = context.WithoutCancel(ctx)
	dirs := slices.Clone(r.made)
	err := r.remove(ctx, dirs...)
	if errors.Is(err, errSession) || errors.Is(err, errStopped) {
		if c, lerr := r.relogin(ctx); lerr == nil {
			r.client.Close()
			r.client = c
			err = r.remove(ctx, dirs...)
		} else {
			err = fmt.Errorf("%w; log in again: %w", err, lerr)
		}
	}
	if err != nil {
		return &LeftOnMachineError{Dirs: dirs, Err: err}
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
	grace, every := stopGrace, keepaliveInterval // read once: goroutines below outlive the call
	errs := &tail{max: maxStderr}
	stopped := func() error {
		return fmt.Errorf("%s: %w after %v: %w%s", what, errStopped, time.Since(start).Round(time.Millisecond), ctx.Err(), errs.suffix())
	}
	var dead atomic.Bool // set when keepalives closed the connection
	lost := func(err error) error {
		if dead.Load() {
			return fmt.Errorf("%s: %w: the machine did not answer %d keepalives in a row", what, errSession, keepaliveMisses)
		}
		return err
	}
	// Opening a session, starting a command and even stopping one wait on
	// the machine, and one that stops answering would hold the step
	// forever. So once the step is over it has the grace to finish, then
	// the whole connection is closed under it.
	finished := make(chan struct{})
	defer close(finished)
	client := r.client
	defer context.AfterFunc(ctx, func() {
		t := time.NewTimer(grace)
		defer t.Stop()
		select {
		case <-finished:
		case <-t.C:
			client.Close()
		}
	})()
	go keepalive(client, finished, every, &dead)
	s, err := client.NewSession()
	if err != nil {
		if ctx.Err() != nil {
			return stopped()
		}
		return lost(fmt.Errorf("%s: %w: %w", what, errSession, escaped{err}))
	}
	defer s.Close()
	if stdin != nil {
		s.Stdin = stdin
	}
	s.Stderr = errs
	stdout, err := s.StdoutPipe()
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	if err := s.Start(line); err != nil {
		if ctx.Err() != nil {
			return stopped()
		}
		return lost(fmt.Errorf("%s: %w: %w", what, errSession, escaped{err}))
	}
	type result struct{ read, wait error }
	done := make(chan result, 1)
	waited := false // s.Wait was called; only the goroutine below uses it
	kill := func(rerr error) {
		s.Signal(ssh.SIGKILL)
		s.Close()
		if !waited {
			// Reap the session, so that none of its goroutines (stdin,
			// stderr, exit status) outlives the step: it has the grace,
			// then the connection is closed under it.
			w := make(chan struct{})
			go func() {
				s.Wait()
				close(w)
			}()
			t := time.NewTimer(grace)
			select {
			case <-w:
			case <-t.C:
				client.Close()
			}
			t.Stop()
		}
		select {
		case done <- result{read: rerr}:
		default:
		}
	}
	go func() {
		// A panic here would end the whole server, clean-up and all.
		defer func() {
			if p := recover(); p != nil {
				kill(fmt.Errorf("reading the output failed: %s", escape.Terminal(fmt.Sprint(p))))
			}
		}()
		out := &capReader{r: stdout, max: max, what: "the output"}
		var rerr error
		if read != nil {
			rerr = read(out)
		}
		tooMuch := errors.Is(rerr, errTooMuch)
		if !tooMuch {
			// Read the rest, still bounded, so the command can end and
			// its exit status can say why it failed.
			_, derr := io.Copy(io.Discard, out)
			tooMuch = errors.Is(derr, errTooMuch)
			if derr != nil && rerr == nil {
				rerr = derr
			}
		}
		if tooMuch {
			kill(rerr)
			return
		}
		waited = true
		done <- result{read: rerr, wait: s.Wait()}
	}()
	select {
	case res := <-done:
		if err := outcome(what, res.read, res.wait, errs); err != nil {
			return lost(err)
		}
		return nil
	case <-ctx.Done():
		s.Signal(ssh.SIGKILL)
		s.Close()
		// Wait for the goroutine above, which reaps the session; if the
		// machine does not end it, the guard closes the connection.
		<-done
		return stopped()
	}
}

// keepaliveMisses unanswered keepalives in a row close the connection.
const keepaliveMisses = 3

// keepalive sends a keepalive request every interval until stop is closed.
// A request that fails or gets no answer within the interval is a miss;
// after keepaliveMisses in a row it sets dead and closes the client, so a
// connection that died without a word is noticed within minutes, not at the
// end of a step's limit.
func keepalive(c *ssh.Client, stop <-chan struct{}, every time.Duration, dead *atomic.Bool) {
	tick := time.NewTicker(every)
	defer tick.Stop()
	misses := 0
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
		}
		reply := make(chan error, 1)
		go func() {
			_, _, err := c.SendRequest("keepalive@openssh.com", true, nil)
			reply <- err
		}()
		wait := time.NewTimer(every)
		select {
		case <-stop:
			wait.Stop()
			return
		case err := <-reply:
			if err != nil {
				misses++
			} else {
				misses = 0
			}
		case <-wait.C:
			misses++
		}
		wait.Stop()
		if misses >= keepaliveMisses {
			dead.Store(true)
			c.Close()
			return
		}
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

// decodeOutput is decodeCollection; tests replace it.
var decodeOutput = decodeCollection

// decodeCollection reads one gzip-compressed collection and nothing after
// it. Decoding errors can quote the machine's text (JSON errors name map
// keys and bad values as they came), so they are escaped.
func decodeCollection(r io.Reader, c *model.Collection) error {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("the output is not gzip: %w", escaped{err})
	}
	dec := json.NewDecoder(&capReader{r: zr, max: maxOutput, what: "the decompressed collection"})
	if err := dec.Decode(c); err != nil {
		return fmt.Errorf("the output is not a collection: %w", escaped{err})
	}
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return errors.New("unexpected data after the collection")
		}
		return fmt.Errorf("after the collection: %w", escaped{err})
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
