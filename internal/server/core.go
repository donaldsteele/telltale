// Package server is server mode's core: it visits enrolled machines on their
// schedules, judges each collection on the server (checklist, package
// verification against the server's own package cache, snapshot comparison),
// stores the reports, alerts on new and resolved findings, and keeps each
// machine's baseline: the snapshot taken when the owner marks the machine
// clean, rolled forward for package updates and for changes the owner
// accepts, and the owner's lasting exceptions.
//
// Nothing is written to a machine but the collector a visit copies there
// and removes again: no snapshot and no cache. The audit log, which is not
// encrypted, only ever gets fixed phrases and IDs, never anything a machine
// sent (names, file text, findings, error text).
package server

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"

	"github.com/donaldsteele/telltale/internal/checklist"
	"github.com/donaldsteele/telltale/internal/escape"
	"github.com/donaldsteele/telltale/internal/judge"
	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/pkgverify"
	"github.com/donaldsteele/telltale/internal/snapshot"
	"github.com/donaldsteele/telltale/internal/store"
	"github.com/donaldsteele/telltale/internal/visit"
)

// AlertSink sends alerts (bubbles, in production). newFindings are findings
// at the alert level that the owner has not been told about, or that rose
// in severity since; resolved are findings the owner was told about that
// are gone. Notify gets a context that ends after the alert_timeout
// setting; a call still running then is abandoned and the alert is sent
// again after the next visit. No lock is held and no visit slot is taken
// while it runs, but the machine counts as being visited until it returns.
type AlertSink interface {
	Notify(ctx context.Context, m store.Machine, newFindings, resolved []model.Finding) error
}

// Visitor collects a machine. SSHVisitor is the real one.
type Visitor interface {
	Visit(ctx context.Context, m store.Machine, signer ssh.Signer, sc model.ScanContext, bins visit.Binaries) (*model.Collection, error)
}

// LeftoverRemover is a Visitor that can also remove the temporary
// directories an earlier visit could not. Without it, leftovers stay
// recorded and reported.
type LeftoverRemover interface {
	RemoveLeftovers(ctx context.Context, m store.Machine, signer ssh.Signer, dirs []string) error
}

// SSHVisitor visits over SSH (visit.Visit) and removes leftovers
// (visit.RemoveLeftovers). A Core with no Visitor uses it.
type SSHVisitor struct{}

// Visit is visit.Visit.
func (SSHVisitor) Visit(ctx context.Context, m store.Machine, signer ssh.Signer, sc model.ScanContext, bins visit.Binaries) (*model.Collection, error) {
	return visit.Visit(ctx, m, signer, sc, bins)
}

// RemoveLeftovers is visit.RemoveLeftovers.
func (SSHVisitor) RemoveLeftovers(ctx context.Context, m store.Machine, signer ssh.Signer, dirs []string) error {
	return visit.RemoveLeftovers(ctx, m, signer, dirs)
}

// ErrVisitRunning means the machine is being visited: another visit and the
// owner's actions on its baseline wait until it is done.
var ErrVisitRunning = errors.New("a visit to this machine is running; try again when it is done")

// Settings the core reads. Durations are Go durations ("45m").
const (
	// SettingAlertLevel is "urgent" (tampering and backdoor signs, the
	// default) or "all" (every finding).
	SettingAlertLevel = "alert_level"
	// SettingVisitTimeout bounds each visit, package verification
	// included; 30 minutes when unset or unreadable.
	SettingVisitTimeout = "visit_timeout"
	// SettingAlertTimeout bounds each Notify; 60 seconds when unset or
	// unreadable.
	SettingAlertTimeout = "alert_timeout"
)

const (
	defaultVisitTimeout = 30 * time.Minute
	defaultAlertTimeout = time.Minute
	// maxVisits is how many visits run at once, across all machines.
	maxVisits = 4
	// failingAfter consecutive failed visits store a visit.failing report.
	failingAfter = 3
	// maxErrorText bounds the visit error kept for a machine.
	maxErrorText = 2000
	sourceVisit  = "visit"
	actorServer  = "server"
	actorOwner   = "owner"
)

// Finding keys of the core's own findings about visits. No judge key
// starts with "visit.", so a machine cannot fake one.
const (
	KeyHostKeyChanged = "visit.host_key_changed"
	KeyLeftOnMachine  = "visit.left_on_machine"
	KeyVisitFailing   = "visit.failing"
)

// Core is server mode's engine. Set the exported fields, then call Run (the
// scheduler) and the owner's actions from any goroutine.
//
// Memory: each visit can hold up to 512 MiB of collector output (visit's
// limit) plus the decoded collection, and up to four visits run at once, so
// plan on a few GiB for a server visiting large machines.
type Core struct {
	Store *store.Store
	// Bins supplies the collector binaries copied to machines.
	Bins visit.Binaries
	// CacheDir is the server's package cache, <data>/pkgcache. It is never
	// on a monitored machine.
	CacheDir string
	// Alerts receives new and resolved findings; nil sends none.
	Alerts AlertSink
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// Visitor collects machines; nil means SSHVisitor.
	Visitor Visitor
	// ServerAddr is the address machines see the server connect from, as
	// in the enrolment snippets. It goes to every scan, with the server's
	// key, so the server's own root key line and Match block are expected
	// on every visit, the first included. It must pass
	// visit.CheckServerAddr; while it does not, every visit fails and says
	// so.
	ServerAddr string
	// Verify is package verification; nil means pkgverify.Verify.
	Verify func(ctx context.Context, c *model.Collection, opt pkgverify.Options) *pkgverify.Result
	// Log is the server log (visit errors the scheduler sees, audit log
	// failures); nil means the standard logger.
	Log *log.Logger

	initOnce sync.Once
	slots    chan struct{}         // one per running visit
	keyMu    sync.Mutex            // digest key creation
	mu       sync.Mutex            // the maps below
	busy     map[int64]bool        // machines being visited
	locks    map[int64]*sync.Mutex // per machine: snapshot, reports, settings
	gen      map[int64]uint64      // per machine: bumped by every owner action
	// The schedule: when each machine is next due, the interval that was
	// worked out with, and the machines Run has started a visit for.
	due      map[int64]time.Time
	dueEvery map[int64]time.Duration
	queued   map[int64]bool
}

func (c *Core) init() {
	c.initOnce.Do(func() {
		c.slots = make(chan struct{}, maxVisits)
		c.busy = map[int64]bool{}
		c.locks = map[int64]*sync.Mutex{}
		c.gen = map[int64]uint64{}
		c.due = map[int64]time.Time{}
		c.dueEvery = map[int64]time.Duration{}
		c.queued = map[int64]bool{}
	})
}

func (c *Core) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Core) logf(format string, args ...any) {
	if c.Log != nil {
		c.Log.Printf(format, args...)
		return
	}
	log.Printf(format, args...)
}

func (c *Core) visitor() Visitor {
	if c.Visitor != nil {
		return c.Visitor
	}
	return SSHVisitor{}
}

func (c *Core) verify() func(context.Context, *model.Collection, pkgverify.Options) *pkgverify.Result {
	if c.Verify != nil {
		return c.Verify
	}
	return pkgverify.Verify
}

// lock locks the machine's stored state and returns the unlock.
func (c *Core) lock(id int64) func() {
	c.init()
	c.mu.Lock()
	l := c.locks[id]
	if l == nil {
		l = &sync.Mutex{}
		c.locks[id] = l
	}
	c.mu.Unlock()
	l.Lock()
	return l.Unlock
}

// claim marks the machine as being visited and returns its generation; it
// fails when a visit is running already.
func (c *Core) claim(id int64) (uint64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.busy[id] {
		return 0, false
	}
	c.busy[id] = true
	return c.gen[id], true
}

func (c *Core) unclaim(id int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.busy, id)
}

func (c *Core) generation(id int64) uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gen[id]
}

// bumpGeneration marks the machine's baseline as changed by the owner.
func (c *Core) bumpGeneration(id int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gen[id]++
}

// ownerAction starts one of the owner's actions on a machine's baseline: it
// locks the machine, refuses while a visit of it is running, and returns the
// function that ends the action. Ending it bumps the machine's generation,
// so a visit that started meanwhile does not save what it judged against
// the baseline as it was.
func (c *Core) ownerAction(id int64) (func(), error) {
	unlock := c.lock(id)
	c.mu.Lock()
	busy := c.busy[id]
	c.mu.Unlock()
	if busy {
		unlock()
		return nil, ErrVisitRunning
	}
	return func() {
		c.bumpGeneration(id)
		unlock()
	}, nil
}

// audit appends to the audit log. Only IDs and counts are ever formatted
// in: see the package comment. A failure is logged and returned.
func (c *Core) audit(actor, action, format string, args ...any) error {
	if err := c.Store.Audit(actor, action, fmt.Sprintf(format, args...)); err != nil {
		c.logf("telltale server: could not write \"%s\" to the audit log: %v", action, err)
		return fmt.Errorf("server: write the audit log: %w", err)
	}
	return nil
}

// Setting keys per machine.
func digestKeySetting(id int64) string { return "digest_key:" + strconv.FormatInt(id, 10) }
func leftoverSetting(id int64) string  { return "leftover:" + strconv.FormatInt(id, 10) }
func errorSetting(id int64) string     { return "visit_error:" + strconv.FormatInt(id, 10) }
func failuresSetting(id int64) string  { return "visit_failures:" + strconv.FormatInt(id, 10) }
func attemptSetting(id int64) string   { return "last_attempt:" + strconv.FormatInt(id, 10) }
func rebaseSetting(id int64) string    { return "rebase:" + strconv.FormatInt(id, 10) }
func alertSetting(id int64) string     { return "alert_state:" + strconv.FormatInt(id, 10) }

// outcome is what a visit leaves for VisitNow: the stored report, the
// error, and the alert still to send.
type outcome struct {
	rid   int64
	err   error
	alert *pendingAlert
}

// pendingAlert is a stored report not yet compared with what the owner was
// told.
type pendingAlert struct {
	m         store.Machine
	rep       *model.Report
	synthetic bool
	rid       int64
}

// VisitNow visits the machine, judges the collection on the server, stores
// the report and alerts. It returns the ID of any report it stored, and an
// error when the visit did not complete or the alert could not be sent:
//
//   - a changed host key stores a report with the tampering finding
//     visit.host_key_changed (the server did not log in);
//   - a visit that collected but could not remove its temporary directory
//     is judged as usual, with a note visit.left_on_machine; the next visit
//     removes the directory first;
//   - any other failure, a bad ServerAddr included, is recorded on the
//     machine (VisitError), and the third in a row stores a report with the
//     note visit.failing.
//
// At most four visits run at once and one per machine (ErrVisitRunning).
// The visit is bounded by the visit_timeout setting; the alert is sent
// after its slot is freed, bounded by alert_timeout. The machine's next
// scheduled visit moves to an interval from now.
func (c *Core) VisitNow(ctx context.Context, machineID int64) (int64, error) {
	c.init()
	select {
	case c.slots <- struct{}{}:
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	held := true
	release := func() {
		if held {
			<-c.slots
			held = false
		}
	}
	defer release()
	gen, ok := c.claim(machineID)
	if !ok {
		return 0, ErrVisitRunning
	}
	defer c.unclaim(machineID)
	vctx, cancel := context.WithTimeout(ctx, c.visitTimeout())
	out := c.visit(ctx, vctx, machineID, gen)
	cancel()
	release()
	err := out.err
	if out.alert != nil {
		if aerr := c.sendAlert(ctx, out.alert); aerr != nil {
			err = errors.Join(err, aerr)
		}
	}
	c.reschedule(machineID)
	return out.rid, err
}

func (c *Core) duration(key string, def time.Duration) time.Duration {
	v, _ := c.Store.Setting(key)
	if d, err := time.ParseDuration(v); err == nil && d > 0 {
		return d
	}
	return def
}

func (c *Core) visitTimeout() time.Duration {
	return c.duration(SettingVisitTimeout, defaultVisitTimeout)
}
func (c *Core) alertTimeout() time.Duration {
	return c.duration(SettingAlertTimeout, defaultAlertTimeout)
}

// scanContext is what every scan of the machine gets: its own digest key
// and the server's address and key.
func (c *Core) scanContext(id int64) (model.ScanContext, ssh.Signer, error) {
	addr, err := visit.CheckServerAddr(c.ServerAddr)
	if err != nil {
		return model.ScanContext{}, nil, fmt.Errorf("server: %w", err)
	}
	signer, line, err := visit.ServerKey(c.Store)
	if err != nil {
		return model.ScanContext{}, nil, err
	}
	key, err := c.digestKey(id)
	if err != nil {
		return model.ScanContext{}, nil, err
	}
	return model.ScanContext{
		DigestKey:            key,
		ServerAddr:           addr.String(),
		ServerKeyLine:        line,
		ServerKeyFingerprint: ssh.FingerprintSHA256(signer.PublicKey()),
	}, signer, nil
}

// digestKey returns the machine's own key for keyed digests (redacted
// values, shadow fields), made on first use: 32 random bytes, sealed in the
// store, never shared between machines. Every visit uses it, so digests
// compare across visits and with the snapshot.
func (c *Core) digestKey(id int64) ([]byte, error) {
	c.keyMu.Lock()
	defer c.keyMu.Unlock()
	k, err := c.Store.SecretSetting(digestKeySetting(id))
	if err != nil {
		return nil, fmt.Errorf("server: read the digest key of machine %d: %w", id, err)
	}
	if len(k) > 0 {
		return k, nil
	}
	k = make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	if err := c.Store.SetSecretSetting(digestKeySetting(id), k); err != nil {
		return nil, fmt.Errorf("server: store the digest key of machine %d: %w", id, err)
	}
	return k, nil
}

// visit is VisitNow once it may run: parent is the caller's context, ctx
// the one bounded by the visit timeout, gen the machine's generation when
// the visit claimed it.
func (c *Core) visit(parent, ctx context.Context, id int64, gen uint64) outcome {
	m, err := c.Store.Machine(id)
	if err != nil {
		return c.visitFailed(id, nil, err)
	}
	c.Store.SetSetting(attemptSetting(id), strconv.FormatInt(c.now().UnixNano(), 10))
	sc, signer, err := c.scanContext(id)
	if err != nil {
		return c.visitFailed(id, m, err)
	}
	c.removeLeftovers(ctx, *m, signer)
	col, verr := c.visitor().Visit(ctx, *m, signer, sc, c.Bins)
	var left *visit.LeftOnMachineError
	if verr != nil && errors.As(verr, &left) {
		if err := c.recordLeftovers(id, left.Dirs); err != nil {
			return outcome{err: err}
		}
	}
	switch {
	case verr == nil && col == nil:
		verr = errors.New("the visit returned no collection")
	case verr == nil:
	case errors.Is(verr, visit.ErrHostKeyChanged):
		return c.hostKeyChanged(m, verr)
	case left != nil && left.Collection != nil:
		col, verr = left.Collection, nil
	}
	if verr != nil {
		if parent.Err() != nil {
			// The server is stopping: not the machine's failure.
			return outcome{err: fmt.Errorf("server: visit to machine %d stopped: %w", id, parent.Err())}
		}
		return c.visitFailed(id, m, verr)
	}
	return c.judgeAndStore(parent, ctx, m, col, sc, gen)
}

// judgeAndStore judges a collection and stores the report: package
// verification on the server (only the changed package files when there is
// a snapshot, with the snapshot's repository keys), the judgement with the
// machine's exceptions, and the automatic roll-forward of the changes this
// scan confirmed. When an owner action changed the baseline after the visit
// started (gen), the report is stored but nothing rolls forward and nothing
// can be accepted from it.
func (c *Core) judgeAndStore(parent, ctx context.Context, m *store.Machine, col *model.Collection, sc model.ScanContext, gen uint64) outcome {
	snap, err := c.Store.Snapshot(m.ID)
	if err != nil {
		return outcome{err: err}
	}
	exc, err := c.Store.Exceptions(m.ID)
	if err != nil {
		return outcome{err: err}
	}
	checks := checklist.Evaluate(col, sc)
	opt := pkgverify.Options{CacheDir: c.CacheDir}
	judge.VerifyScope(&opt, snap, col)
	pkg := c.verify()(ctx, col, opt)
	if parent.Err() != nil {
		return outcome{err: fmt.Errorf("server: visit to machine %d stopped: %w", m.ID, parent.Err())}
	}
	rep, rb := judge.JudgeRebase(judge.Input{Collection: col, Snapshot: snap, Context: sc, Pkg: pkg, Now: c.now(), Exceptions: exc})

	unlock := c.lock(m.ID)
	defer unlock()
	if left, err := c.Leftovers(m.ID); err != nil {
		return outcome{err: err}
	} else if len(left) > 0 {
		judge.AddFindings(rep, leftOnMachine(left))
	}
	rid, err := c.Store.PutReport(m.ID, rep, col)
	if err != nil {
		return outcome{err: err}
	}
	fail := func(err error) outcome { return outcome{rid: rid, err: err} }
	st := rebaseState{ReportID: rid, Stale: c.generation(m.ID) != gen}
	if rb != nil && !st.Stale {
		st.Accept = rb.Accept
		// Changes this scan confirmed roll forward by themselves.
		if cur, err := c.Store.Snapshot(m.ID); err != nil {
			return fail(err)
		} else if cur != nil && !rb.Routine.Empty() {
			if err := c.Store.PutSnapshot(m.ID, judge.RollForward(cur, col, checks, rb.Routine)); err != nil {
				return fail(err)
			}
		}
	}
	if err := c.saveSecret(rebaseSetting(m.ID), st); err != nil {
		return fail(err)
	}
	if err := c.visitSucceeded(m.ID); err != nil {
		return fail(err)
	}
	return outcome{rid: rid, err: c.audit(actorServer, "visit", "machine %d report %d", m.ID, rid),
		alert: &pendingAlert{m: *m, rep: rep, rid: rid}}
}

// visitSucceeded resets the failure count and error and records the visit.
func (c *Core) visitSucceeded(id int64) error {
	if err := c.Store.SetSetting(failuresSetting(id), "0"); err != nil {
		return err
	}
	if err := c.Store.SetSecretSetting(errorSetting(id), []byte{}); err != nil {
		return err
	}
	// Read again just before writing: the owner may have edited the
	// machine during the visit.
	m, err := c.Store.Machine(id)
	if err != nil {
		return err
	}
	t := c.now().UTC()
	m.LastVisit = &t
	return c.Store.UpdateMachine(*m)
}

// visitFailed records a failed visit (m is nil when the machine could not
// be read); the third in a row stores a report.
func (c *Core) visitFailed(id int64, m *store.Machine, verr error) outcome {
	unlock := c.lock(id)
	defer unlock()
	fail := fmt.Errorf("server: visit to machine %d failed: %w", id, verr)
	if err := c.Store.SetSecretSetting(errorSetting(id), []byte(boundedText(verr.Error()))); err != nil {
		return outcome{err: errors.Join(fail, err)}
	}
	v, _ := c.Store.Setting(failuresSetting(id))
	n, _ := strconv.Atoi(v)
	n++
	if err := c.Store.SetSetting(failuresSetting(id), strconv.Itoa(n)); err != nil {
		return outcome{err: errors.Join(fail, err)}
	}
	if err := c.audit(actorServer, "visit failed", "machine %d", id); err != nil {
		fail = errors.Join(fail, err)
	}
	if n != failingAfter {
		return outcome{err: fail}
	}
	rep := c.syntheticReport(visitFailing(n))
	rid, err := c.Store.PutReport(id, rep, &model.Collection{})
	if err != nil {
		return outcome{err: errors.Join(fail, err)}
	}
	if err := c.audit(actorServer, "visits failing", "machine %d report %d", id, rid); err != nil {
		fail = errors.Join(fail, err)
	}
	mm := store.Machine{ID: id}
	if m != nil {
		mm = *m
	}
	return outcome{rid: rid, err: fail, alert: &pendingAlert{m: mm, rep: rep, synthetic: true, rid: rid}}
}

// hostKeyChanged stores the tampering report for a machine whose host key
// is not the pinned one. Nothing was sent to the machine.
func (c *Core) hostKeyChanged(m *store.Machine, verr error) outcome {
	unlock := c.lock(m.ID)
	defer unlock()
	fail := fmt.Errorf("server: visit to machine %d: %w", m.ID, verr)
	var hk *visit.HostKeyMismatchError
	errors.As(verr, &hk)
	rep := c.syntheticReport(hostKeyFinding(hk))
	rid, err := c.Store.PutReport(m.ID, rep, &model.Collection{})
	if err != nil {
		return outcome{err: errors.Join(fail, err)}
	}
	if err := c.Store.SetSecretSetting(errorSetting(m.ID), []byte(boundedText(verr.Error()))); err != nil {
		fail = errors.Join(fail, err)
	}
	if err := c.audit(actorServer, "host key changed", "machine %d report %d", m.ID, rid); err != nil {
		fail = errors.Join(fail, err)
	}
	return outcome{rid: rid, err: fail, alert: &pendingAlert{m: *m, rep: rep, synthetic: true, rid: rid}}
}

// syntheticReport is a report about the visit itself, with no collection.
func (c *Core) syntheticReport(f model.Finding) *model.Report {
	r := &model.Report{
		Schema:          model.ReportSchema,
		Time:            c.now(),
		CouldNotRuleOut: []string{judge.KernelLimit, "anything on the machine: the visit collected nothing"},
		Findings:        []model.Finding{},
		Explained:       []model.Finding{},
	}
	judge.AddFindings(r, f)
	return r
}

// synthetic reports whether r is a report about a visit that collected
// nothing.
func synthetic(r *model.Report) bool {
	return slices.ContainsFunc(r.Findings, func(f model.Finding) bool {
		return f.Key == KeyHostKeyChanged || f.Key == KeyVisitFailing
	})
}

func hostKeyFinding(hk *visit.HostKeyMismatchError) model.Finding {
	ev := model.Evidence{Detail: "the machine offered an SSH host key other than the one pinned at enrolment"}
	if hk != nil {
		ev.Before, ev.After = escape.Terminal(hk.Pinned), escape.Terminal(hk.Offered)
		ev.Detail = "SSH host key fingerprint: pinned at enrolment (before), offered now (after)"
	}
	return model.Finding{
		Key: KeyHostKeyChanged, ID: "TT-VISIT-001", Source: sourceVisit, Severity: model.SevTampering,
		Title: "The machine's SSH host key is not the one recorded at enrolment",
		Why: "The machine answered with a different SSH host key from the one pinned when it was enrolled. " +
			"Either something between the server and the machine is posing as it (a man-in-the-middle), or the machine was reinstalled or its host keys were regenerated. " +
			"The server did not log in, so nothing on the machine was checked.",
		Fix: "# Compare fingerprints: on the machine's console run ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub and compare its fingerprint with the one offered here.\n" +
			"# If the change is expected (a reinstall or new host keys), re-enrol the machine; if not, do not re-enrol and treat the machine and the network as under attack.",
		Evidence: []model.Evidence{ev},
		Refs:     []string{"T1557"},
	}
}

func visitFailing(n int) model.Finding {
	return model.Finding{
		Key: KeyVisitFailing, ID: "TT-VISIT-002", Source: sourceVisit, Severity: model.SevNote,
		Title: fmt.Sprintf("The last %d visits to the machine failed", n),
		Why: "Nothing on the machine has been checked since the last visit that worked. The machine may be down or unreachable, sshd may be stopped or reconfigured, " +
			"or the server's key line or Match block may have been removed; an attacker who wants to stay unseen might do that too.",
		Fix:      "# Check that the machine is up and reachable from the server, that sshd runs, and that the enrolment snippets are still in place; the machine page shows the last error.",
		Evidence: []model.Evidence{{After: "failing", Detail: fmt.Sprintf("%d visits in a row failed", n)}},
	}
}

func leftOnMachine(dirs []string) model.Finding {
	f := model.Finding{
		Key: KeyLeftOnMachine, ID: "TT-VISIT-003", Source: sourceVisit, Severity: model.SevNote,
		Title: "A telltale collector was left on the machine: " + escape.Terminal(strings.Join(dirs, " ")),
		Why: "A visit could not remove the temporary directory holding the collector it copied to the machine. " +
			"The collector only reads, and the server tries to remove the directory at the start of every visit, but it should not stay there.",
	}
	var quoted []string
	for _, d := range dirs {
		quoted = append(quoted, escape.ShellQuote(d))
		f.Evidence = append(f.Evidence, model.Evidence{Path: escape.Terminal(d), After: escape.Terminal(d), Detail: "left on the machine"})
	}
	f.Fix = "rm -rf -- " + strings.Join(quoted, " ")
	return f
}

// boundedText is s escaped for display and cut to maxErrorText bytes.
func boundedText(s string) string {
	s = escape.Terminal(s)
	if len(s) <= maxErrorText {
		return s
	}
	cut := maxErrorText
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}

// VisitError is the machine's last visit error, escaped and bounded, or ""
// when its last visit worked.
func (c *Core) VisitError(machineID int64) (string, error) {
	b, err := c.Store.SecretSetting(errorSetting(machineID))
	return string(b), err
}

// Leftovers lists the temporary directories visits could not remove from
// the machine.
func (c *Core) Leftovers(machineID int64) ([]string, error) {
	var dirs []string
	if err := c.loadSecret(leftoverSetting(machineID), &dirs); err != nil {
		return nil, err
	}
	return dirs, nil
}

// recordLeftovers adds directories to the machine's leftovers. Only those of
// the form a visit makes are kept: nothing else is ever put in a command.
func (c *Core) recordLeftovers(id int64, dirs []string) error {
	unlock := c.lock(id)
	defer unlock()
	have, err := c.Leftovers(id)
	if err != nil {
		return err
	}
	for _, d := range dirs {
		if visit.IsTempDir(d) && !slices.Contains(have, d) {
			have = append(have, d)
		}
	}
	slices.Sort(have)
	return c.saveSecret(leftoverSetting(id), have)
}

// removeLeftovers tries to remove what earlier visits left on the machine.
func (c *Core) removeLeftovers(ctx context.Context, m store.Machine, signer ssh.Signer) {
	dirs, err := c.Leftovers(m.ID)
	if err != nil || len(dirs) == 0 {
		return
	}
	rm, ok := c.visitor().(LeftoverRemover)
	if !ok {
		return
	}
	dirs = slices.DeleteFunc(dirs, func(d string) bool { return !visit.IsTempDir(d) })
	if err := rm.RemoveLeftovers(ctx, m, signer, dirs); err != nil {
		c.audit(actorServer, "leftovers not removed", "machine %d", m.ID) // logged on failure
		return
	}
	unlock := c.lock(m.ID)
	defer unlock()
	have, err := c.Leftovers(m.ID)
	if err != nil {
		return
	}
	have = slices.DeleteFunc(have, func(d string) bool { return slices.Contains(dirs, d) })
	if c.saveSecret(leftoverSetting(m.ID), have) == nil {
		c.audit(actorServer, "leftovers removed", "machine %d: %d directories", m.ID, len(dirs)) // logged on failure
	}
}

// rebaseState is what the machine's latest completed visit says about its
// baseline: the report, and what accepting each of its findings rolls
// forward. Stale means an owner action changed the baseline while the
// report was being made, so nothing can be accepted from it.
type rebaseState struct {
	ReportID int64                  `json:"report_id"`
	Stale    bool                   `json:"stale,omitempty"`
	Accept   map[string]judge.Scope `json:"accept,omitempty"`
}

// MarkClean takes the machine's snapshot from one of its reports: that
// report's collection, its checklist results and the machine's digest key.
// It replaces any snapshot the machine had.
//
// This is an owner action for the web UI only, called after the owner
// reviewed the report and confirmed that the machine is believed clean. It
// must never be exposed through MCP or any other automated interface. It
// returns ErrVisitRunning while the machine is being visited.
func (c *Core) MarkClean(ctx context.Context, machineID, reportID int64) error {
	done, err := c.ownerAction(machineID)
	if err != nil {
		return err
	}
	defer done()
	m, err := c.Store.Machine(machineID)
	if err != nil {
		return err
	}
	rep, col, err := c.ownReport(machineID, reportID)
	if err != nil {
		return err
	}
	if synthetic(rep) || col.Schema == 0 {
		return fmt.Errorf("server: report %d holds no collection; mark the machine clean from a completed visit", reportID)
	}
	sc, _, err := c.scanContext(machineID)
	if err != nil {
		return err
	}
	snap := snapshot.New(col, checklist.Evaluate(col, sc), sc.DigestKey)
	snap.Taken = c.now().UTC()
	if err := c.Store.PutSnapshot(machineID, snap); err != nil {
		return err
	}
	m.Clean = true
	if err := c.Store.UpdateMachine(*m); err != nil {
		return err
	}
	// What the latest report's findings would accept was worked out
	// against the old snapshot.
	var st rebaseState
	if err := c.loadSecret(rebaseSetting(machineID), &st); err != nil {
		return err
	}
	st.Accept = nil
	if err := c.saveSecret(rebaseSetting(machineID), st); err != nil {
		return err
	}
	return c.audit(actorOwner, "mark clean", "machine %d report %d", machineID, reportID)
}

// ownReport opens a report of the machine; another machine's is refused.
func (c *Core) ownReport(machineID, reportID int64) (*model.Report, *model.Collection, error) {
	metas, err := c.Store.Reports(machineID, 0)
	if err != nil {
		return nil, nil, err
	}
	if !slices.ContainsFunc(metas, func(m store.ReportMeta) bool { return m.ID == reportID }) {
		return nil, nil, fmt.Errorf("server: machine %d has no report %d", machineID, reportID)
	}
	return c.Store.Report(reportID)
}

// AcceptChanges re-baselines: the snapshot rolls forward for the changes
// the findings with these keys stand for, as the machine's latest report
// saw them. Only findings about changes since the snapshot can be accepted
// (anything else is an exception), and findings about the same things go
// together: accepting one new root key accepts the whole key file, so
// every finding about that file must be in keys. Changes a scan confirmed
// (package updates verified against the signed archive) need no accepting:
// they roll forward by themselves.
//
// This is an owner action for the web UI only. It must never be exposed
// through MCP or any other automated interface. It returns ErrVisitRunning
// while the machine is being visited.
func (c *Core) AcceptChanges(ctx context.Context, machineID, reportID int64, keys []string) error {
	if len(keys) == 0 {
		return errors.New("server: no changes to accept")
	}
	done, err := c.ownerAction(machineID)
	if err != nil {
		return err
	}
	defer done()
	snap, err := c.Store.Snapshot(machineID)
	if err != nil {
		return err
	}
	if snap == nil {
		return fmt.Errorf("server: machine %d has no snapshot yet; mark it clean first", machineID)
	}
	var st rebaseState
	if err := c.loadSecret(rebaseSetting(machineID), &st); err != nil {
		return err
	}
	if st.ReportID != reportID {
		return fmt.Errorf("server: changes are accepted from the machine's latest report (%d), not report %d", st.ReportID, reportID)
	}
	if st.Stale {
		return fmt.Errorf("server: the baseline changed while report %d was being made; accept changes from the next visit's report", reportID)
	}
	accepted := map[string]bool{}
	for _, k := range keys {
		accepted[k] = true
	}
	var scope judge.Scope
	for _, k := range keys {
		s, ok := st.Accept[k]
		if !ok {
			return fmt.Errorf("server: \"%s\" is not a change since the snapshot in report %d; accept it as an exception instead", escape.Terminal(k), reportID)
		}
		for _, w := range s.With {
			if accepted[w] {
				continue
			}
			if _, ok := st.Accept[w]; ok {
				return fmt.Errorf("server: accepting \"%s\" also accepts \"%s\"; accept them together", escape.Terminal(k), escape.Terminal(w))
			}
			return fmt.Errorf("server: accepting \"%s\" would also hide \"%s\", which is not a change since the snapshot; fix it or accept it as an exception first", escape.Terminal(k), escape.Terminal(w))
		}
		scope.Merge(s)
	}
	_, col, err := c.Store.Report(reportID)
	if err != nil {
		return err
	}
	sc, _, err := c.scanContext(machineID)
	if err != nil {
		return err
	}
	if err := c.Store.PutSnapshot(machineID, judge.RollForward(snap, col, checklist.Evaluate(col, sc), scope)); err != nil {
		return err
	}
	if err := c.forget(machineID, keys); err != nil {
		return err
	}
	return c.audit(actorOwner, "accept changes", "machine %d report %d: %d findings", machineID, reportID, len(keys))
}

// AddException accepts a finding of one of the machine's reports, the one
// the owner looked at, as a lasting exception: it records the finding's
// value in that report, and the finding is dropped from reports for as long
// as its value stays the same. Findings about the visit itself cannot be
// accepted.
//
// This is an owner action for the web UI only. It must never be exposed
// through MCP or any other automated interface. It returns ErrVisitRunning
// while the machine is being visited.
func (c *Core) AddException(ctx context.Context, machineID, reportID int64, key, note string) error {
	if strings.HasPrefix(key, sourceVisit+".") {
		return errors.New("server: findings about the visit itself cannot be accepted")
	}
	done, err := c.ownerAction(machineID)
	if err != nil {
		return err
	}
	defer done()
	rep, _, err := c.ownReport(machineID, reportID)
	if err != nil {
		return err
	}
	var found *model.Finding
	for _, list := range [][]model.Finding{rep.Findings, rep.Explained} {
		if i := slices.IndexFunc(list, func(f model.Finding) bool { return f.Key == key }); i >= 0 {
			found = &list[i]
			break
		}
	}
	if found == nil {
		return fmt.Errorf("server: no finding \"%s\" in report %d", escape.Terminal(key), reportID)
	}
	e := model.Exception{FindingKey: key, AcceptedValue: judge.ExceptionValue(found), Note: note, At: c.now().UTC()}
	if err := c.Store.AddException(machineID, e); err != nil {
		return err
	}
	if err := c.forget(machineID, []string{key}); err != nil {
		return err
	}
	return c.audit(actorOwner, "add exception", "machine %d report %d", machineID, reportID)
}

// alertState is what the owner has been told about a machine: the
// findings at the alert level from its latest completed visit, and the
// findings about failed visits since. A failed Notify leaves it as it was,
// so the next visit sends the alert again.
type alertState struct {
	Real      []model.Finding `json:"real,omitempty"`
	Synthetic []model.Finding `json:"synthetic,omitempty"`
}

func (c *Core) urgentOnly() bool {
	v, _ := c.Store.Setting(SettingAlertLevel)
	return v != "all"
}

// diffAlerts compares a report with what the owner was told. A finding is
// new when its key was not told about, or was at a lower severity (an
// escalation). A report about a visit that collected nothing (isSynthetic)
// resolves nothing; a completed visit resolves the findings it no longer
// has, except package findings when package verification did not run or
// finish (judge.PackagesIncomplete): those may only have gone unchecked, so
// they stay known.
func diffAlerts(st alertState, rep *model.Report, urgent, isSynthetic bool) (fresh, resolved []model.Finding, next alertState) {
	var cur []model.Finding
	for _, f := range rep.Findings {
		if !urgent || f.Severity >= model.SevBackdoor {
			cur = append(cur, f)
		}
	}
	told := func(fs []model.Finding) map[string]model.Severity {
		m := map[string]model.Severity{}
		for _, f := range fs {
			m[f.Key] = f.Severity
		}
		return m
	}
	if isSynthetic {
		was := told(st.Synthetic)
		next = alertState{Real: st.Real, Synthetic: slices.Clone(st.Synthetic)}
		for _, f := range cur {
			if sev, ok := was[f.Key]; ok && f.Severity <= sev {
				continue
			}
			fresh = append(fresh, f)
			next.Synthetic = slices.DeleteFunc(next.Synthetic, func(g model.Finding) bool { return g.Key == f.Key })
			next.Synthetic = append(next.Synthetic, f)
		}
		return fresh, nil, next
	}
	was, present := told(st.Real), told(rep.Findings)
	for _, f := range cur {
		if sev, ok := was[f.Key]; !ok || f.Severity > sev {
			fresh = append(fresh, f)
		}
	}
	next = alertState{Real: cur}
	unchecked := judge.PackagesIncomplete(rep)
	for _, f := range st.Real {
		if _, ok := present[f.Key]; ok {
			continue
		}
		if unchecked && strings.HasPrefix(f.Key, "pkg.") {
			next.Real = append(next.Real, f)
			continue
		}
		resolved = append(resolved, f)
	}
	// A visit that worked ends whatever was wrong with visiting.
	resolved = append(resolved, st.Synthetic...)
	return fresh, resolved, next
}

// sendAlert notifies what is new and resolved for a stored report and
// records what the owner was told. It holds no lock and no visit slot
// while Notify runs, and gives Notify alert_timeout.
func (c *Core) sendAlert(ctx context.Context, pa *pendingAlert) error {
	var st alertState
	if err := c.loadSecret(alertSetting(pa.m.ID), &st); err != nil {
		return err
	}
	fresh, resolved, next := diffAlerts(st, pa.rep, c.urgentOnly(), pa.synthetic)
	if len(fresh)+len(resolved) > 0 && c.Alerts != nil {
		if err := c.notify(ctx, pa.m, fresh, resolved); err != nil {
			c.audit(actorServer, "alert not sent", "machine %d report %d", pa.m.ID, pa.rid) // logged on failure
			return fmt.Errorf("server: report %d stored, but the alert was not sent: %w", pa.rid, err)
		}
	}
	unlock := c.lock(pa.m.ID)
	defer unlock()
	return c.saveSecret(alertSetting(pa.m.ID), next)
}

// notify calls the sink with alert_timeout. A sink that does not stop when
// its context ends is abandoned (its goroutine finishes whenever it does).
func (c *Core) notify(ctx context.Context, m store.Machine, fresh, resolved []model.Finding) error {
	ctx, cancel := context.WithTimeout(ctx, c.alertTimeout())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- c.Alerts.Notify(ctx, m, fresh, resolved) }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// forget drops accepted findings from what the owner was told, so their
// going away is not reported as resolved.
func (c *Core) forget(id int64, keys []string) error {
	var st alertState
	if err := c.loadSecret(alertSetting(id), &st); err != nil {
		return err
	}
	drop := func(f model.Finding) bool { return slices.Contains(keys, f.Key) }
	st.Real = slices.DeleteFunc(st.Real, drop)
	st.Synthetic = slices.DeleteFunc(st.Synthetic, drop)
	return c.saveSecret(alertSetting(id), st)
}

// loadSecret decodes a sealed JSON setting; an unset one leaves v alone.
func (c *Core) loadSecret(key string, v any) error {
	b, err := c.Store.SecretSetting(key)
	if err != nil || len(b) == 0 {
		return err
	}
	return json.Unmarshal(b, v)
}

// saveSecret stores v as a sealed JSON setting: these settings hold what
// machines sent (paths, findings), so they are never plain.
func (c *Core) saveSecret(key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return c.Store.SetSecretSetting(key, b)
}
