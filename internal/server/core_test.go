package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/donaldsteele/telltale/internal/alerts"
	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/pkgverify"
	"github.com/donaldsteele/telltale/internal/store"
	"github.com/donaldsteele/telltale/internal/visit"
)

const testServerAddr = "192.0.2.10"

var t0 = time.Date(2026, 11, 22, 9, 0, 0, 0, time.UTC)

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func fileEntry(p, content string) model.FileEntry {
	return model.FileEntry{Path: p, Type: "file", SHA256: sum(content), Mode: 0o100755, Size: int64(len(content)), MTime: t0, CTime: t0}
}

// base is a small machine with nothing alarming on it.
func base() *model.Collection {
	return &model.Collection{
		Schema: model.CollectionSchema,
		Host:   model.Host{Hostname: "web01", OSID: "debian", OSVersionID: "12", Arch: "amd64"},
		Time:   t0,
		AsRoot: true,
		Files:  []model.FileEntry{fileEntry("/usr/bin/ls", "ls 9.1")},
		Accounts: model.Accounts{
			Users: []model.User{{Name: "root", UID: 0, GID: 0, Home: "/root", Shell: "/bin/bash",
				Password: model.PasswordState{Known: true, Set: true, Algo: "yescrypt", Digest: "digest-root"}}},
			Groups: []model.Group{{Name: "root", GID: 0}},
		},
		Packages: model.Packages{Installed: []model.Package{{Name: "coreutils", Version: "9.1-1", Arch: "amd64",
			Status: "install ok installed", Files: []string{"/usr/bin/ls"}}}},
	}
}

// hidden adds a process the machine's ps does not show: a tampering finding.
func hidden(c *model.Collection) *model.Collection {
	c.CrossView = []model.CrossViewResult{{Tool: "ps", Ran: true, HiddenFromTool: []string{"pid 666 /tmp/.x"}}}
	return c
}

const crossKey = "heur.crossview:ps"

// uid0 adds a second account with user id 0: a backdoor sign.
func uid0(c *model.Collection) *model.Collection {
	c.Accounts.Users = append(c.Accounts.Users, model.User{Name: "toor", UID: 0, GID: 0, Home: "/root", Shell: "/bin/bash"})
	return c
}

// cronAdded adds a cron file: with a snapshot, a backdoor sign.
func cronAdded(c *model.Collection) *model.Collection {
	text := "* * * * * root /tmp/.x"
	c.Persist = append(c.Persist, model.PersistFile{Path: "/etc/cron.d/evil", Kind: model.PersistKindCron, Mode: 0o100644,
		SHA256: sum(text), Lines: []string{text}, MTime: t0})
	c.Files = append(c.Files, fileEntry("/etc/cron.d/evil", text))
	return c
}

const cronKey = "snap.persist:/etc/cron.d/evil"

type fakeVisitor struct {
	mu sync.Mutex
	// collect answers a visit; n counts this machine's visits from 1.
	collect   func(m store.Machine, n int) (*model.Collection, error)
	calls     map[int64]int
	contexts  map[int64][]model.ScanContext
	removed   [][]string
	removeErr error
	// gate, when set, holds every visit until it is closed or ctx ends.
	gate             chan struct{}
	running, maxSeen int
}

func newFakeVisitor() *fakeVisitor {
	return &fakeVisitor{
		collect:  func(store.Machine, int) (*model.Collection, error) { return base(), nil },
		calls:    map[int64]int{},
		contexts: map[int64][]model.ScanContext{},
	}
}

func (f *fakeVisitor) Visit(ctx context.Context, m store.Machine, signer ssh.Signer, sc model.ScanContext, _ visit.Binaries) (*model.Collection, error) {
	f.mu.Lock()
	f.calls[m.ID]++
	n := f.calls[m.ID]
	f.contexts[m.ID] = append(f.contexts[m.ID], sc)
	f.running++
	f.maxSeen = max(f.maxSeen, f.running)
	gate, collect := f.gate, f.collect
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.running--
		f.mu.Unlock()
	}()
	if signer == nil {
		return nil, errors.New("no signer")
	}
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return collect(m, n)
}

func (f *fakeVisitor) RemoveLeftovers(_ context.Context, _ store.Machine, _ ssh.Signer, dirs []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed = append(f.removed, slices.Clone(dirs))
	return f.removeErr
}

func (f *fakeVisitor) visits(id int64) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[id]
}

type alert struct {
	machine         int64
	fresh, resolved []string
}

type fakeAlerts struct {
	mu   sync.Mutex
	got  []alert
	fail error
	// block, when set, holds every Notify until it is closed, whatever
	// its context says: a sink that hangs.
	block chan struct{}
}

func keysOf(fs []model.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Key)
	}
	return out
}

func (a *fakeAlerts) Notify(_ context.Context, m store.Machine, fresh, resolved []model.Finding) error {
	a.mu.Lock()
	block := a.block
	a.mu.Unlock()
	if block != nil {
		<-block
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail != nil {
		return a.fail
	}
	a.got = append(a.got, alert{m.ID, keysOf(fresh), keysOf(resolved)})
	return nil
}

// retryingAlerts is a sink that keeps what it could not send (an
// AlertRetrier) and counts the core's kicks.
type retryingAlerts struct {
	fakeAlerts
	kicks atomic.Int32
}

func (a *retryingAlerts) Kick() { a.kicks.Add(1) }

// A sink that retries is asked to after every visit, also after one with
// nothing new to tell: the next visit is when pending alerts go out again.
func TestVisitKicksRetryingSink(t *testing.T) {
	fx := newFixture(t)
	ra := &retryingAlerts{}
	fx.core.Alerts = ra
	fx.vis.collect = func(store.Machine, int) (*model.Collection, error) { return hidden(base()), nil }
	fx.visitOK(t, fx.id)
	fx.visitOK(t, fx.id)
	if n := ra.kicks.Load(); n != 2 {
		t.Errorf("kicked %d times after two visits", n)
	}
	// A visit that fails still kicks.
	fx.vis.collect = func(store.Machine, int) (*model.Collection, error) { return nil, errors.New("no route") }
	fx.core.VisitNow(context.Background(), fx.id)
	if n := ra.kicks.Load(); n != 3 {
		t.Errorf("kicked %d times after a failed visit", n)
	}
}

// The alerts package reads the same alert_timeout setting for its retries.
func TestAlertTimeoutSettingShared(t *testing.T) {
	if alerts.SettingAlertTimeout != SettingAlertTimeout {
		t.Errorf("alerts reads %q, the core %q", alerts.SettingAlertTimeout, SettingAlertTimeout)
	}
	var _ AlertSink = (*alerts.Bubbles)(nil)
	var _ AlertRetrier = (*alerts.Bubbles)(nil)
}

func (a *fakeAlerts) all() []alert {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.got)
}

type verifyCall struct {
	opt pkgverify.Options
}

type fixture struct {
	core   *Core
	st     *store.Store
	vis    *fakeVisitor
	alerts *fakeAlerts
	id     int64 // the first machine

	mu       sync.Mutex
	verifies []verifyCall
	result   func(c *model.Collection) *pkgverify.Result
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "server.db"), store.Unlock{KeyFile: filepath.Join(dir, "server.key")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	fx := &fixture{st: st, vis: newFakeVisitor(), alerts: &fakeAlerts{}}
	fx.result = func(*model.Collection) *pkgverify.Result { return &pkgverify.Result{Mode: pkgverify.ModeArchive} }
	fx.core = &Core{
		Store:      st,
		CacheDir:   filepath.Join(dir, "pkgcache"),
		Alerts:     fx.alerts,
		Visitor:    fx.vis,
		ServerAddr: testServerAddr,
		Verify: func(_ context.Context, c *model.Collection, opt pkgverify.Options) *pkgverify.Result {
			fx.mu.Lock()
			fx.verifies = append(fx.verifies, verifyCall{opt})
			r := fx.result
			fx.mu.Unlock()
			return r(c)
		},
	}
	fx.id = fx.addMachine(t, "web01", "")
	return fx
}

func (fx *fixture) addMachine(t *testing.T, name, schedule string) int64 {
	t.Helper()
	id, err := fx.st.AddMachine(store.Machine{Name: name, Addr: "198.51.100.7", HostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHostKeyHostKeyHostKeyHostKeyHostKeyHostKeyHost", Schedule: schedule})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (fx *fixture) lastVerify(t *testing.T) pkgverify.Options {
	t.Helper()
	fx.mu.Lock()
	defer fx.mu.Unlock()
	if len(fx.verifies) == 0 {
		t.Fatal("package verification did not run")
	}
	return fx.verifies[len(fx.verifies)-1].opt
}

func (fx *fixture) visitOK(t *testing.T, id int64) (int64, *model.Report) {
	t.Helper()
	rid, err := fx.core.VisitNow(context.Background(), id)
	if err != nil {
		t.Fatalf("VisitNow: %v", err)
	}
	r, _, err := fx.st.Report(rid)
	if err != nil {
		t.Fatal(err)
	}
	return rid, r
}

func find(r *model.Report, key string) *model.Finding {
	for i := range r.Findings {
		if r.Findings[i].Key == key {
			return &r.Findings[i]
		}
	}
	return nil
}

func TestVisitNowStoresReport(t *testing.T) {
	fx := newFixture(t)
	fx.vis.collect = func(store.Machine, int) (*model.Collection, error) { return hidden(base()), nil }
	rid, r := fx.visitOK(t, fx.id)
	if rid <= 0 || r.Host.Hostname != "web01" || find(r, crossKey) == nil {
		t.Fatalf("report %d: %+v", rid, r)
	}
	metas, err := fx.st.Reports(fx.id, 0)
	if err != nil || len(metas) != 1 || metas[0].ID != rid || metas[0].ExitCode != 2 {
		t.Fatalf("stored reports %+v %v", metas, err)
	}
	m, _ := fx.st.Machine(fx.id)
	if m.LastVisit == nil {
		t.Error("last visit not recorded")
	}
	// The scan context names the server, so the checklist knows its own
	// key line and Match block on every visit, the first included.
	_, line, err := visit.ServerKey(fx.st)
	if err != nil {
		t.Fatal(err)
	}
	sc := fx.vis.contexts[fx.id][0]
	if sc.ServerAddr != testServerAddr || sc.ServerKeyLine != line || !strings.HasPrefix(sc.ServerKeyFingerprint, "SHA256:") || len(sc.DigestKey) != 32 {
		t.Errorf("scan context %+v", sc)
	}
	if opt := fx.lastVerify(t); opt.CacheDir != fx.core.CacheDir {
		t.Errorf("package cache %q, want the server's %q", opt.CacheDir, fx.core.CacheDir)
	}
	log, _ := fx.st.AuditLog(0)
	if len(log) == 0 || log[0].Action != "visit" || log[0].Detail != fmt.Sprintf("machine %d report %d", fx.id, rid) {
		t.Errorf("audit %+v", log)
	}
}

func TestVisitNowRefusesABadServerAddress(t *testing.T) {
	fx := newFixture(t)
	for _, a := range []string{"", "telltale.lan", "0.0.0.0", "192.0.2.0/24"} {
		fx.core.ServerAddr = a
		if _, err := fx.core.VisitNow(context.Background(), fx.id); err == nil {
			t.Errorf("server address %q: visited", a)
		}
	}
	if n := fx.vis.visits(fx.id); n != 0 {
		t.Errorf("%d visits without a usable server address", n)
	}
	// It is not silent: each try is a failed visit, recorded on the
	// machine, and the third in a row is reported.
	if msg, _ := fx.core.VisitError(fx.id); !strings.Contains(msg, "server address") {
		t.Errorf("recorded error %q", msg)
	}
	if metas, _ := fx.st.Reports(fx.id, 0); len(metas) != 1 {
		t.Errorf("reports %+v", metas)
	}
}

func TestFirstVisitDoesNotSnapshot(t *testing.T) {
	fx := newFixture(t)
	fx.visitOK(t, fx.id)
	if s, err := fx.st.Snapshot(fx.id); err != nil || s != nil {
		t.Fatalf("snapshot after a first visit: %v %v", s, err)
	}
	if m, _ := fx.st.Machine(fx.id); m.Clean {
		t.Error("machine marked clean by a visit")
	}
	if opt := fx.lastVerify(t); opt.OnlyPaths != nil {
		t.Errorf("no snapshot, yet verification was limited to %v", opt.OnlyPaths)
	}
}

func TestMarkCleanCreatesSnapshot(t *testing.T) {
	fx := newFixture(t)
	rid, _ := fx.visitOK(t, fx.id)
	if err := fx.core.MarkClean(context.Background(), fx.id, rid); err != nil {
		t.Fatal(err)
	}
	s, err := fx.st.Snapshot(fx.id)
	if err != nil || s == nil || s.Collection == nil || s.Collection.Host.Hostname != "web01" || len(s.Checks) == 0 {
		t.Fatalf("snapshot %+v %v", s, err)
	}
	key, _ := fx.st.SecretSetting(fmt.Sprintf("digest_key:%d", fx.id))
	if len(key) != 32 || !bytes.Equal(s.DigestKey, key) {
		t.Errorf("snapshot digest key %x, machine's %x", s.DigestKey, key)
	}
	if m, _ := fx.st.Machine(fx.id); !m.Clean {
		t.Error("machine not marked clean")
	}
	_, r := fx.visitOK(t, fx.id)
	if opt := fx.lastVerify(t); opt.OnlyPaths == nil || len(opt.OnlyPaths) != 0 {
		t.Errorf("with an unchanged snapshot: only %v", opt.OnlyPaths)
	}
	if len(r.ComparedAgainst) == 0 || !strings.HasPrefix(r.ComparedAgainst[0], "snapshot of ") {
		t.Errorf("compared against %v", r.ComparedAgainst)
	}

	// Another machine's report, and a report that holds no collection,
	// are refused.
	other := fx.addMachine(t, "files02", "")
	orid, _ := fx.visitOK(t, other)
	if err := fx.core.MarkClean(context.Background(), fx.id, orid); err == nil {
		t.Error("marked clean from another machine's report")
	}
	fx.vis.collect = func(store.Machine, int) (*model.Collection, error) {
		return nil, fmt.Errorf("log in: %w", &visit.HostKeyMismatchError{Pinned: "SHA256:a", Offered: "SHA256:b"})
	}
	hrid, _ := fx.core.VisitNow(context.Background(), other)
	if hrid == 0 {
		t.Fatal("no report for a changed host key")
	}
	if err := fx.core.MarkClean(context.Background(), other, hrid); err == nil {
		t.Error("marked clean from a report with no collection")
	}
}

func TestNewTamperingAlertsOnce(t *testing.T) {
	fx := newFixture(t)
	fx.vis.collect = func(store.Machine, int) (*model.Collection, error) { return hidden(base()), nil }
	fx.visitOK(t, fx.id)
	got := fx.alerts.all()
	if len(got) != 1 || got[0].machine != fx.id || !slices.Contains(got[0].fresh, crossKey) || len(got[0].resolved) != 0 {
		t.Fatalf("alerts after the first visit: %+v", got)
	}
	fx.visitOK(t, fx.id)
	if got := fx.alerts.all(); len(got) != 1 {
		t.Errorf("a second identical visit alerted again: %+v", got)
	}
}

// A failed alert is not lost: the next visit sends it.
func TestFailedAlertIsSentNextVisit(t *testing.T) {
	fx := newFixture(t)
	fx.vis.collect = func(store.Machine, int) (*model.Collection, error) { return hidden(base()), nil }
	fx.alerts.fail = errors.New("bubbles unreachable")
	rid, err := fx.core.VisitNow(context.Background(), fx.id)
	if rid == 0 || err == nil {
		t.Fatalf("report %d, err %v", rid, err)
	}
	fx.alerts.fail = nil
	fx.visitOK(t, fx.id)
	if got := fx.alerts.all(); len(got) != 1 || !slices.Contains(got[0].fresh, crossKey) {
		t.Errorf("alerts %+v", got)
	}
}

func TestResolvedFindingNotified(t *testing.T) {
	fx := newFixture(t)
	fx.vis.collect = func(_ store.Machine, n int) (*model.Collection, error) {
		if n == 1 {
			return hidden(base()), nil
		}
		return base(), nil
	}
	fx.visitOK(t, fx.id)
	fx.visitOK(t, fx.id)
	got := fx.alerts.all()
	if len(got) != 2 || len(got[1].fresh) != 0 || !slices.Equal(got[1].resolved, []string{crossKey}) {
		t.Fatalf("alerts %+v", got)
	}
}

func TestAlertLevelAll(t *testing.T) {
	fx := newFixture(t)
	fx.core.Visitor.(*fakeVisitor).collect = func(store.Machine, int) (*model.Collection, error) {
		c := base()
		c.Accounts.Users[0].Shell = "/bin/bash"
		c.Accounts.Users = append(c.Accounts.Users, model.User{Name: "daemon", UID: 1, GID: 1, Home: "/usr/sbin", Shell: "/bin/sh"})
		return c, nil
	}
	_, r := fx.visitOK(t, fx.id)
	var notes []string
	for _, f := range r.Findings {
		if f.Severity < model.SevBackdoor {
			notes = append(notes, f.Key)
		}
	}
	if len(notes) == 0 {
		t.Fatalf("fixture has no finding below a backdoor sign: %v", keysOf(r.Findings))
	}
	for _, a := range fx.alerts.all() {
		for _, k := range a.fresh {
			if slices.Contains(notes, k) {
				t.Errorf("urgent level alerted %s", k)
			}
		}
	}
	if err := fx.st.SetSetting("alert_level", "all"); err != nil {
		t.Fatal(err)
	}
	fx.visitOK(t, fx.id)
	got := fx.alerts.all()
	if len(got) == 0 || !slices.Contains(got[len(got)-1].fresh, notes[0]) {
		t.Errorf("level all did not alert %s: %+v", notes[0], got)
	}
}

func TestHostKeyChangedRaisesTampering(t *testing.T) {
	fx := newFixture(t)
	fx.vis.collect = func(store.Machine, int) (*model.Collection, error) {
		return nil, fmt.Errorf("visit web01: log in to x: %w", &visit.HostKeyMismatchError{Pinned: "SHA256:pinnedpinned", Offered: "SHA256:offeredoffered"})
	}
	rid, err := fx.core.VisitNow(context.Background(), fx.id)
	if !errors.Is(err, visit.ErrHostKeyChanged) || rid == 0 {
		t.Fatalf("report %d, err %v", rid, err)
	}
	r, _, err := fx.st.Report(rid)
	if err != nil {
		t.Fatal(err)
	}
	f := find(r, "visit.host_key_changed")
	if f == nil || f.Severity != model.SevTampering || r.ExitCode != 2 {
		t.Fatalf("report %+v", r)
	}
	if len(f.Evidence) == 0 || f.Evidence[0].Before != "SHA256:pinnedpinned" || f.Evidence[0].After != "SHA256:offeredoffered" {
		t.Errorf("evidence %+v", f.Evidence)
	}
	for _, w := range []string{"man-in-the-middle", "reinstalled"} {
		if !strings.Contains(f.Why, w) {
			t.Errorf("why %q does not mention %q", f.Why, w)
		}
	}
	if !strings.Contains(f.Fix, "fingerprint") || !strings.Contains(f.Fix, "re-enrol") {
		t.Errorf("fix %q", f.Fix)
	}
	got := fx.alerts.all()
	if len(got) != 1 || !slices.Equal(got[0].fresh, []string{"visit.host_key_changed"}) {
		t.Fatalf("alerts %+v", got)
	}
	// Still changed: stored again, not alerted again.
	if rid2, _ := fx.core.VisitNow(context.Background(), fx.id); rid2 == rid || rid2 == 0 {
		t.Errorf("second report %d", rid2)
	}
	if got := fx.alerts.all(); len(got) != 1 {
		t.Errorf("alerted twice: %+v", got)
	}
	// Re-enrolled: the next good visit says it is resolved.
	fx.vis.collect = func(store.Machine, int) (*model.Collection, error) { return base(), nil }
	fx.visitOK(t, fx.id)
	got = fx.alerts.all()
	if len(got) != 2 || !slices.Contains(got[1].resolved, "visit.host_key_changed") {
		t.Errorf("alerts %+v", got)
	}
}

func TestAcceptChangesRollsBaseline(t *testing.T) {
	fx := newFixture(t)
	rid, _ := fx.visitOK(t, fx.id)
	if err := fx.core.MarkClean(context.Background(), fx.id, rid); err != nil {
		t.Fatal(err)
	}
	fx.vis.collect = func(store.Machine, int) (*model.Collection, error) { return uid0(cronAdded(base())), nil }
	rid, r := fx.visitOK(t, fx.id)
	if f := find(r, cronKey); f == nil || f.Severity != model.SevBackdoor {
		t.Fatalf("no new cron file: %v", keysOf(r.Findings))
	}
	if got := fx.alerts.all(); len(got) != 1 || !slices.Contains(got[0].fresh, cronKey) {
		t.Fatalf("alerts %+v", got)
	}

	ctx := context.Background()
	for _, bad := range [][]string{nil, {"heur.uid0:toor"}, {"snap.persist:/etc/nothing"}} {
		if err := fx.core.AcceptChanges(ctx, fx.id, rid, bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if err := fx.core.AcceptChanges(ctx, fx.id, rid-1, []string{cronKey}); err == nil {
		t.Error("accepted from a report that is not the latest")
	}
	if err := fx.core.AcceptChanges(ctx, fx.id, rid, []string{cronKey}); err != nil {
		t.Fatal(err)
	}
	s, _ := fx.st.Snapshot(fx.id)
	if !slices.ContainsFunc(s.Collection.Persist, func(p model.PersistFile) bool { return p.Path == "/etc/cron.d/evil" }) {
		t.Fatal("the accepted cron file is not in the snapshot")
	}
	if slices.ContainsFunc(s.Collection.Accounts.Users, func(u model.User) bool { return u.Name == "toor" }) {
		t.Error("an account nobody accepted rolled into the snapshot")
	}
	_, r = fx.visitOK(t, fx.id)
	if find(r, cronKey) != nil || find(r, "snap.user_added:toor") == nil {
		t.Errorf("after accepting: %v", keysOf(r.Findings))
	}
	// Accepted is neither new nor "resolved".
	if got := fx.alerts.all(); len(got) != 1 {
		t.Errorf("alerts after accepting: %+v", got)
	}
}

// A package upgrade the signed package explains rolls forward on every visit
// without anyone accepting it.
func TestExplainedChangesRollForward(t *testing.T) {
	fx := newFixture(t)
	rid, _ := fx.visitOK(t, fx.id)
	if err := fx.core.MarkClean(context.Background(), fx.id, rid); err != nil {
		t.Fatal(err)
	}
	upgraded := func() *model.Collection {
		c := base()
		c.Packages.Installed[0].Version = "9.2-1"
		c.Files[0] = fileEntry("/usr/bin/ls", "ls 9.2")
		return c
	}
	fx.vis.collect = func(store.Machine, int) (*model.Collection, error) { return upgraded(), nil }
	fx.result = func(*model.Collection) *pkgverify.Result {
		return &pkgverify.Result{Mode: pkgverify.ModeArchive, SourcesUsed: []string{"https://deb.debian.org/debian bookworm"},
			Verified: []pkgverify.FileVerdict{{Path: "/usr/bin/ls", Package: "coreutils", Version: "9.2-1", Expected: sum("ls 9.2"), Actual: sum("ls 9.2"), Source: pkgverify.SourceArchive}}}
	}
	_, r := fx.visitOK(t, fx.id)
	if len(r.Explained) == 0 {
		t.Fatalf("upgrade not explained: findings %v", keysOf(r.Findings))
	}
	s, _ := fx.st.Snapshot(fx.id)
	if s.Collection.Packages.Installed[0].Version != "9.2-1" || s.Collection.Files[len(s.Collection.Files)-1].SHA256 != sum("ls 9.2") {
		t.Fatalf("snapshot did not roll forward: %+v", s.Collection.Packages.Installed)
	}
	_, r = fx.visitOK(t, fx.id)
	if len(r.Explained) != 0 || len(fx.lastVerify(t).OnlyPaths) != 0 {
		t.Errorf("the upgrade shows again: explained %v, verified %v", r.Explained, fx.lastVerify(t).OnlyPaths)
	}
}

func TestExceptionSuppressesAlert(t *testing.T) {
	fx := newFixture(t)
	fx.vis.collect = func(store.Machine, int) (*model.Collection, error) { return uid0(base()), nil }
	rid, _ := fx.visitOK(t, fx.id)
	if got := fx.alerts.all(); len(got) != 1 || !slices.Contains(got[0].fresh, "heur.uid0:toor") {
		t.Fatalf("alerts %+v", got)
	}
	ctx := context.Background()
	if err := fx.core.AddException(ctx, fx.id, rid, "heur.nothing", ""); err == nil {
		t.Error("exception for a finding the latest report does not have")
	}
	if err := fx.core.AddException(ctx, fx.id, rid, "heur.uid0:toor", "our rescue account"); err != nil {
		t.Fatal(err)
	}
	exc, _ := fx.st.Exceptions(fx.id)
	if len(exc) != 1 || exc[0].FindingKey != "heur.uid0:toor" || exc[0].AcceptedValue == "" || exc[0].Note != "our rescue account" {
		t.Fatalf("exceptions %+v", exc)
	}
	_, r := fx.visitOK(t, fx.id)
	if find(r, "heur.uid0:toor") != nil || len(r.Exceptions) != 1 {
		t.Errorf("report findings %v, exceptions in force %+v", keysOf(r.Findings), r.Exceptions)
	}
	if got := fx.alerts.all(); len(got) != 1 {
		t.Errorf("an accepted finding alerted (as new or resolved): %+v", got)
	}
}

func TestLeftOnMachineStoresReportAndCleansNextVisit(t *testing.T) {
	fx := newFixture(t)
	dir := "/run/telltale.AbCdEfGh"
	fx.vis.collect = func(_ store.Machine, n int) (*model.Collection, error) {
		if n == 1 {
			return nil, fmt.Errorf("visit web01: %w", &visit.LeftOnMachineError{
				Dirs: []string{dir, "/etc; rm -rf /", "/run/telltale.x\x1b[2J"}, Collection: base(), Err: errors.New("connection lost")})
		}
		return base(), nil
	}
	rid, err := fx.core.VisitNow(context.Background(), fx.id)
	if err != nil || rid == 0 {
		t.Fatalf("report %d, err %v", rid, err)
	}
	r, c, _ := fx.st.Report(rid)
	if c.Host.Hostname != "web01" {
		t.Errorf("the carried collection was not stored: %+v", c.Host)
	}
	f := find(r, "visit.left_on_machine")
	if f == nil || f.Severity != model.SevNote {
		t.Fatalf("no note: %v", keysOf(r.Findings))
	}
	text := fmt.Sprintf("%s %s %+v", f.Title, f.Fix, f.Evidence)
	if !strings.Contains(text, dir) || strings.Contains(text, "rm -rf /") || strings.Contains(text, "\x1b") {
		t.Errorf("note names %q", text)
	}
	if left, _ := fx.core.Leftovers(fx.id); !slices.Equal(left, []string{dir}) {
		t.Errorf("recorded leftovers %q", left)
	}

	// The next visit removes it first; it is no longer reported.
	_, r = fx.visitOK(t, fx.id)
	fx.vis.mu.Lock()
	removed := slices.Clone(fx.vis.removed)
	fx.vis.mu.Unlock()
	if len(removed) != 1 || !slices.Equal(removed[0], []string{dir}) {
		t.Errorf("removed %q", removed)
	}
	if find(r, "visit.left_on_machine") != nil {
		t.Error("still reported after removal")
	}
	if left, _ := fx.core.Leftovers(fx.id); len(left) != 0 {
		t.Errorf("still recorded %q", left)
	}

	// When removal fails, the note stays.
	fx.vis.collect = func(_ store.Machine, n int) (*model.Collection, error) {
		return nil, &visit.LeftOnMachineError{Dirs: []string{dir}, Collection: base(), Err: errors.New("x")}
	}
	fx.visitOK(t, fx.id)
	fx.vis.collect = func(store.Machine, int) (*model.Collection, error) { return base(), nil }
	fx.vis.removeErr = errors.New("unreachable")
	if _, r = fx.visitOK(t, fx.id); find(r, "visit.left_on_machine") == nil {
		t.Error("note dropped although the directory could not be removed")
	}
}

func TestThreeFailuresRaiseVisitFailing(t *testing.T) {
	fx := newFixture(t)
	if err := fx.st.SetSetting("alert_level", "all"); err != nil {
		t.Fatal(err)
	}
	fail := true
	fx.vis.collect = func(store.Machine, int) (*model.Collection, error) {
		if fail {
			return nil, errors.New("dial tcp 198.51.100.7:22: connect: connection refused \x1b[31mred")
		}
		return base(), nil
	}
	ctx := context.Background()
	for i := 1; i <= 2; i++ {
		if rid, err := fx.core.VisitNow(ctx, fx.id); rid != 0 || err == nil {
			t.Fatalf("failure %d: report %d, err %v", i, rid, err)
		}
	}
	if metas, _ := fx.st.Reports(fx.id, 0); len(metas) != 0 {
		t.Fatalf("reports after two failures: %+v", metas)
	}
	msg, _ := fx.core.VisitError(fx.id)
	if !strings.Contains(msg, "connection refused") || strings.Contains(msg, "\x1b") {
		t.Errorf("recorded error %q", msg)
	}
	rid, err := fx.core.VisitNow(ctx, fx.id)
	if rid == 0 || err == nil {
		t.Fatalf("third failure: report %d, err %v", rid, err)
	}
	r, _, _ := fx.st.Report(rid)
	if f := find(r, "visit.failing"); f == nil || f.Severity != model.SevNote {
		t.Fatalf("report %v", keysOf(r.Findings))
	}
	if got := fx.alerts.all(); len(got) != 1 || !slices.Equal(got[0].fresh, []string{"visit.failing"}) {
		t.Fatalf("alerts %+v", got)
	}
	// A success resets the count.
	fail = false
	fx.visitOK(t, fx.id)
	if msg, _ := fx.core.VisitError(fx.id); msg != "" {
		t.Errorf("error still recorded: %q", msg)
	}
	fail = true
	for i := 1; i <= 2; i++ {
		if rid, _ := fx.core.VisitNow(ctx, fx.id); rid != 0 {
			t.Errorf("failure %d after a success stored report %d", i, rid)
		}
	}
}

// At the default alert level a failing machine is not alerted.
func TestVisitFailingNotAlertedWhenUrgent(t *testing.T) {
	fx := newFixture(t)
	fx.vis.collect = func(store.Machine, int) (*model.Collection, error) { return nil, errors.New("no route to host") }
	for i := 0; i < 3; i++ {
		fx.core.VisitNow(context.Background(), fx.id)
	}
	if got := fx.alerts.all(); len(got) != 0 {
		t.Errorf("alerts %+v", got)
	}
}

func TestDigestKeyStableAcrossVisits(t *testing.T) {
	fx := newFixture(t)
	other := fx.addMachine(t, "files02", "")
	for i := 0; i < 2; i++ {
		fx.visitOK(t, fx.id)
		fx.visitOK(t, other)
	}
	a, b := fx.vis.contexts[fx.id], fx.vis.contexts[other]
	if len(a) != 2 || len(b) != 2 || !bytes.Equal(a[0].DigestKey, a[1].DigestKey) || !bytes.Equal(b[0].DigestKey, b[1].DigestKey) {
		t.Fatalf("digest keys changed between visits")
	}
	if bytes.Equal(a[0].DigestKey, b[0].DigestKey) {
		t.Error("two machines share a digest key")
	}
	metas, _ := fx.st.Reports(fx.id, 1)
	if err := fx.core.MarkClean(context.Background(), fx.id, metas[0].ID); err != nil {
		t.Fatal(err)
	}
	fx.visitOK(t, fx.id)
	s, _ := fx.st.Snapshot(fx.id)
	if c := fx.vis.contexts[fx.id]; !bytes.Equal(s.DigestKey, a[0].DigestKey) || !bytes.Equal(c[len(c)-1].DigestKey, a[0].DigestKey) {
		t.Error("the snapshot or a later visit uses another digest key")
	}
}

func TestRepoTrustOnlyFromSnapshot(t *testing.T) {
	fx := newFixture(t)
	ours := []model.RepoTrust{{URL: "https://vendor.example/apt", Suite: "stable"}}
	theirs := []model.RepoTrust{{URL: "https://evil.example/apt", Suite: "stable"}}
	trust := ours
	fx.vis.collect = func(store.Machine, int) (*model.Collection, error) {
		c := base()
		c.Packages.RepoTrust = trust
		return c, nil
	}
	rid, _ := fx.visitOK(t, fx.id)
	if opt := fx.lastVerify(t); opt.RepoTrust != nil {
		t.Errorf("no snapshot, yet trusted %v", opt.RepoTrust)
	}
	if err := fx.core.MarkClean(context.Background(), fx.id, rid); err != nil {
		t.Fatal(err)
	}
	trust = theirs
	fx.visitOK(t, fx.id)
	if opt := fx.lastVerify(t); len(opt.RepoTrust) != 1 || opt.RepoTrust[0].URL != ours[0].URL {
		t.Errorf("trusted %v, want the snapshot's %v", opt.RepoTrust, ours)
	}
}

func TestAuditNeverCarriesMachineText(t *testing.T) {
	fx := newFixture(t)
	const mark = "HOSTILE"
	hostile := func() *model.Collection {
		c := cronAdded(hidden(base()))
		c.Host.Hostname = mark + "\x1b]0;pwned\x07host"
		c.CrossView[0].HiddenFromTool = []string{mark + " pid 1 \x1b[2J"}
		c.Persist[0].Lines = []string{mark + " * * * * root /tmp/.x"}
		return c
	}
	ctx := context.Background()
	fx.vis.collect = func(_ store.Machine, n int) (*model.Collection, error) {
		switch n {
		case 1:
			return nil, &visit.LeftOnMachineError{Dirs: []string{"/run/telltale.AbCdEfGh", "/" + mark}, Collection: base(), Err: errors.New(mark + " removal")}
		case 2, 3, 4:
			return nil, errors.New(mark + " exit status 1: " + mark + " stderr")
		case 5:
			return nil, fmt.Errorf("%s: %w", mark, &visit.HostKeyMismatchError{Pinned: "SHA256:" + mark, Offered: "SHA256:" + mark})
		}
		return hostile(), nil
	}
	for i := 0; i < 6; i++ {
		fx.core.VisitNow(ctx, fx.id)
	}
	metas, _ := fx.st.Reports(fx.id, 0)
	if err := fx.core.MarkClean(ctx, fx.id, metas[len(metas)-1].ID); err != nil {
		t.Fatal(err)
	}
	rid, _ := fx.visitOK(t, fx.id)
	if err := fx.core.AcceptChanges(ctx, fx.id, rid, []string{cronKey}); err != nil {
		t.Fatal(err)
	}
	if err := fx.core.AddException(ctx, fx.id, rid, crossKey, mark+" note"); err != nil {
		t.Fatal(err)
	}
	fx.core.AcceptChanges(ctx, fx.id, rid, []string{mark})
	fx.core.AddException(ctx, fx.id, rid, mark, mark)

	log, err := fx.st.AuditLog(0)
	if err != nil || len(log) < 8 {
		t.Fatalf("audit %d entries: %v", len(log), err)
	}
	for _, e := range log {
		if s := e.Actor + e.Action + e.Detail; strings.Contains(s, mark) || strings.ContainsAny(s, "\x1b\x07") {
			t.Errorf("audit entry carries machine text: %+v", e)
		}
	}
}

func TestOneVisitPerMachine(t *testing.T) {
	fx := newFixture(t)
	fx.vis.gate = make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := fx.core.VisitNow(context.Background(), fx.id)
		done <- err
	}()
	waitFor(t, func() bool { return fx.vis.visits(fx.id) == 1 })
	if _, err := fx.core.VisitNow(context.Background(), fx.id); !errors.Is(err, ErrVisitRunning) {
		t.Errorf("second visit: %v", err)
	}
	close(fx.vis.gate)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestVisitTimeout(t *testing.T) {
	fx := newFixture(t)
	if err := fx.st.SetSetting("visit_timeout", "100ms"); err != nil {
		t.Fatal(err)
	}
	fx.vis.gate = make(chan struct{}) // never opened
	start := time.Now()
	if _, err := fx.core.VisitNow(context.Background(), fx.id); err == nil {
		t.Fatal("a visit that never ends succeeded")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %v", d)
	}
	if msg, _ := fx.core.VisitError(fx.id); msg == "" {
		t.Error("a timed-out visit is a failed visit")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func setVar[T any](t *testing.T, p *T, v T) {
	t.Helper()
	old := *p
	*p = v
	t.Cleanup(func() { *p = old })
}

func TestSchedulerRunsDueMachines(t *testing.T) {
	setVar(t, &scheduleTick, 10*time.Millisecond)
	setVar(t, &startJitter, 20*time.Millisecond)
	fx := newFixture(t) // web01: default schedule (daily), never visited
	hourly := fx.addMachine(t, "hourly", "hourly")
	manual := fx.addMachine(t, "manual", "manual")
	weekly := fx.addMachine(t, "weekly", "weekly")
	for id, ago := range map[int64]time.Duration{hourly: 2 * time.Hour, weekly: time.Hour} {
		m, _ := fx.st.Machine(id)
		lv := time.Now().Add(-ago)
		m.LastVisit = &lv
		if err := fx.st.UpdateMachine(*m); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		fx.core.Run(ctx)
		close(stopped)
	}()
	waitFor(t, func() bool { return fx.vis.visits(fx.id) == 1 && fx.vis.visits(hourly) == 1 })
	time.Sleep(100 * time.Millisecond) // several more ticks
	cancel()
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not stop")
	}
	if fx.vis.visits(fx.id) != 1 || fx.vis.visits(hourly) != 1 {
		t.Errorf("due machines visited %d and %d times", fx.vis.visits(fx.id), fx.vis.visits(hourly))
	}
	if n := fx.vis.visits(manual); n != 0 {
		t.Errorf("manual machine visited %d times", n)
	}
	if n := fx.vis.visits(weekly); n != 0 {
		t.Errorf("weekly machine visited an hour after its last visit (%d)", n)
	}
}

// At most four visits run at once, and Run waits for them when it stops.
func TestSchedulerLimitsConcurrency(t *testing.T) {
	setVar(t, &scheduleTick, 10*time.Millisecond)
	setVar(t, &startJitter, time.Millisecond)
	fx := newFixture(t)
	for i := 0; i < 6; i++ {
		fx.addMachine(t, fmt.Sprintf("m%d", i), "hourly")
	}
	fx.vis.gate = make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		fx.core.Run(ctx)
		close(stopped)
	}()
	waitFor(t, func() bool {
		fx.vis.mu.Lock()
		defer fx.vis.mu.Unlock()
		return fx.vis.running == maxVisits
	})
	time.Sleep(100 * time.Millisecond)
	fx.vis.mu.Lock()
	seen := fx.vis.maxSeen
	fx.vis.mu.Unlock()
	if seen != maxVisits {
		t.Errorf("%d visits ran at once", seen)
	}
	cancel()
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not stop")
	}
	fx.vis.mu.Lock()
	running := fx.vis.running
	fx.vis.mu.Unlock()
	if running != 0 {
		t.Errorf("%d visits still running after Run returned", running)
	}
	// Stopping the server is not the machines' failure.
	ms, _ := fx.st.Machines()
	for _, m := range ms {
		if msg, _ := fx.core.VisitError(m.ID); msg != "" {
			t.Errorf("machine %d: error recorded for a visit the server stopped: %q", m.ID, msg)
		}
	}
}

// A sink that hangs costs the visit at most alert_timeout, and it holds no
// visit slot meanwhile; the machine stays busy for owner actions until then.
func TestNotifyDoesNotHoldASlotOrHang(t *testing.T) {
	fx := newFixture(t)
	if err := fx.st.SetSetting("alert_timeout", "300ms"); err != nil {
		t.Fatal(err)
	}
	others := make([]int64, maxVisits)
	for i := range others {
		others[i] = fx.addMachine(t, fmt.Sprintf("other%d", i), "")
	}
	hang := make(chan struct{})
	t.Cleanup(func() { close(hang) })
	fx.alerts.block = hang
	gate := make(chan struct{})
	fx.vis.collect = func(m store.Machine, _ int) (*model.Collection, error) {
		if m.ID != fx.id {
			<-gate
		}
		return hidden(base()), nil
	}
	start := time.Now()
	done := make(chan error, 1)
	go func() {
		_, err := fx.core.VisitNow(context.Background(), fx.id)
		done <- err
	}()
	// The visit is done collecting and stuck in Notify: every slot is free.
	waitFor(t, func() bool { return fx.vis.visits(fx.id) == 1 })
	time.Sleep(50 * time.Millisecond)
	var wg sync.WaitGroup
	for _, id := range others {
		wg.Add(1)
		go func(id int64) {
			defer wg.Done()
			fx.core.VisitNow(context.Background(), id)
		}(id)
	}
	waitFor(t, func() bool {
		fx.vis.mu.Lock()
		defer fx.vis.mu.Unlock()
		return fx.vis.running == maxVisits
	})
	if err := fx.core.MarkClean(context.Background(), fx.id, 1); !errors.Is(err, ErrVisitRunning) {
		t.Errorf("owner action while the alert is pending: %v", err)
	}
	close(gate)
	all := make(chan struct{})
	go func() {
		wg.Wait()
		close(all)
	}()
	select {
	case <-all:
	case <-time.After(5 * time.Second):
		t.Fatal("visits stuck behind a hung alert sink")
	}
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "alert") {
			t.Errorf("err %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("VisitNow did not return")
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("took %v", d)
	}
}

// Owner actions wait for no visit: they are refused while one runs.
func TestOwnerActionsRefusedDuringVisit(t *testing.T) {
	fx := newFixture(t)
	rid, _ := fx.visitOK(t, fx.id)
	fx.vis.gate = make(chan struct{})
	done := make(chan struct{})
	go func() {
		fx.core.VisitNow(context.Background(), fx.id)
		close(done)
	}()
	waitFor(t, func() bool { return fx.vis.visits(fx.id) == 2 })
	ctx := context.Background()
	for name, err := range map[string]error{
		"mark clean":     fx.core.MarkClean(ctx, fx.id, rid),
		"accept changes": fx.core.AcceptChanges(ctx, fx.id, rid, []string{cronKey}),
		"add exception":  fx.core.AddException(ctx, fx.id, rid, crossKey, ""),
	} {
		if !errors.Is(err, ErrVisitRunning) {
			t.Errorf("%s during a visit: %v", name, err)
		}
	}
	close(fx.vis.gate)
	<-done
	if err := fx.core.MarkClean(ctx, fx.id, rid); err != nil {
		t.Errorf("after the visit: %v", err)
	}
}

// A visit that judged against a baseline an owner action changed meanwhile
// saves no accept scopes and rolls nothing forward.
func TestVisitOverlappingOwnerActionSavesNoScopes(t *testing.T) {
	fx := newFixture(t)
	rid, _ := fx.visitOK(t, fx.id)
	if err := fx.core.MarkClean(context.Background(), fx.id, rid); err != nil {
		t.Fatal(err)
	}
	fx.vis.collect = func(store.Machine, int) (*model.Collection, error) { return cronAdded(base()), nil }
	fx.result = func(*model.Collection) *pkgverify.Result {
		// An owner action that slipped in after the visit read the
		// baseline.
		fx.core.bumpGeneration(fx.id)
		return &pkgverify.Result{Mode: pkgverify.ModeArchive}
	}
	rid, r := fx.visitOK(t, fx.id)
	if find(r, cronKey) == nil {
		t.Fatalf("fixture: %v", keysOf(r.Findings))
	}
	err := fx.core.AcceptChanges(context.Background(), fx.id, rid, []string{cronKey})
	if err == nil || !strings.Contains(err.Error(), "baseline changed") {
		t.Errorf("accepted from a report judged against an old baseline: %v", err)
	}
}

// The exception records the value of the report the owner looked at, not
// of a visit that landed since.
func TestAddExceptionUsesThatReport(t *testing.T) {
	fx := newFixture(t)
	items := []string{"pid 666 /tmp/.x"}
	fx.vis.collect = func(store.Machine, int) (*model.Collection, error) {
		c := hidden(base())
		c.CrossView[0].HiddenFromTool = slices.Clone(items)
		return c, nil
	}
	seen, _ := fx.visitOK(t, fx.id)
	items = append(items, "pid 667 /tmp/.y")
	fx.visitOK(t, fx.id)
	ctx := context.Background()
	if err := fx.core.AddException(ctx, fx.id, seen, crossKey, ""); err != nil {
		t.Fatal(err)
	}
	if _, r := fx.visitOK(t, fx.id); find(r, crossKey) == nil {
		t.Error("an exception for one hidden item covers two")
	}
	other := fx.addMachine(t, "files02", "")
	if err := fx.core.AddException(ctx, other, seen, crossKey, ""); err == nil {
		t.Error("exception from another machine's report")
	}
}

func TestAcceptOtherArchInstall(t *testing.T) {
	fx := newFixture(t)
	rid, _ := fx.visitOK(t, fx.id)
	if err := fx.core.MarkClean(context.Background(), fx.id, rid); err != nil {
		t.Fatal(err)
	}
	helper := fileEntry("/usr/lib/i386-linux-gnu/coreutils/helper", "helper")
	helper.Mode = 0o104755
	fx.vis.collect = func(store.Machine, int) (*model.Collection, error) {
		c := base()
		c.Packages.Installed[0].Version = "9.2-1"
		c.Files[0] = fileEntry("/usr/bin/ls", "ls 9.2")
		c.Files = append(c.Files, helper)
		c.Packages.Installed = append(c.Packages.Installed, model.Package{Name: "coreutils", Version: "9.2-1", Arch: "i386",
			Status: "install ok installed", Files: []string{helper.Path}})
		return c, nil
	}
	fx.result = func(*model.Collection) *pkgverify.Result {
		return &pkgverify.Result{Mode: pkgverify.ModeArchive, SourcesUsed: []string{"https://deb.debian.org/debian bookworm"},
			Verified: []pkgverify.FileVerdict{
				{Path: "/usr/bin/ls", Package: "coreutils", Version: "9.2-1", Expected: sum("ls 9.2"), Actual: sum("ls 9.2"), Source: pkgverify.SourceArchive},
				{Path: helper.Path, Package: "coreutils", Version: "9.2-1", Expected: helper.SHA256, Actual: helper.SHA256, Source: pkgverify.SourceArchive}}}
	}
	const key = "snap.pkg_installed:coreutils:i386"
	rid, r := fx.visitOK(t, fx.id)
	if f := find(r, key); f == nil || f.Severity != model.SevBackdoor {
		t.Fatalf("findings %v", keysOf(r.Findings))
	}
	if err := fx.core.AcceptChanges(context.Background(), fx.id, rid, []string{key}); err != nil {
		t.Fatal(err)
	}
	s, _ := fx.st.Snapshot(fx.id)
	if !slices.ContainsFunc(s.Collection.Packages.Installed, func(p model.Package) bool { return p.Name == "coreutils" && p.Arch == "i386" }) {
		t.Fatalf("the accepted install did not roll: %+v", s.Collection.Packages.Installed)
	}
	_, r = fx.visitOK(t, fx.id)
	for _, f := range r.Findings {
		if strings.HasPrefix(f.Key, "snap.pkg_installed:coreutils") {
			t.Errorf("after accepting: %s", f.Key)
		}
	}
}

func TestAlertEscalationIsNew(t *testing.T) {
	f := func(key string, sev model.Severity) model.Finding { return model.Finding{Key: key, Severity: sev} }
	rep := func(fs ...model.Finding) *model.Report { return &model.Report{Findings: fs} }
	st := alertState{Real: []model.Finding{f("a", model.SevNote), f("b", model.SevBackdoor)}}
	fresh, _, next := diffAlerts(st, rep(f("a", model.SevBackdoor), f("b", model.SevTampering)), false, false)
	if !slices.Equal(keysOf(fresh), []string{"a", "b"}) {
		t.Errorf("level all: fresh %v", keysOf(fresh))
	}
	if fresh, _, _ = diffAlerts(next, rep(f("a", model.SevBackdoor), f("b", model.SevTampering)), false, false); len(fresh) != 0 {
		t.Errorf("same severities again: %v", keysOf(fresh))
	}
	fresh, _, _ = diffAlerts(alertState{Real: []model.Finding{f("b", model.SevBackdoor)}}, rep(f("a", model.SevNote), f("b", model.SevTampering)), true, false)
	if !slices.Equal(keysOf(fresh), []string{"b"}) {
		t.Errorf("level urgent: fresh %v", keysOf(fresh))
	}
	fresh, _, next = diffAlerts(alertState{}, rep(f(KeyHostKeyChanged, model.SevTampering)), true, true)
	if len(fresh) != 1 {
		t.Fatalf("synthetic %v", keysOf(fresh))
	}
	if fresh, _, _ = diffAlerts(next, rep(f(KeyHostKeyChanged, model.SevTampering)), true, true); len(fresh) != 0 {
		t.Errorf("synthetic again: %v", keysOf(fresh))
	}
}

// When package verification did not run or finish, a package finding that
// is missing is not resolved: it may only have gone unchecked.
func TestPackageFindingNotResolvedWhenVerificationIncomplete(t *testing.T) {
	mismatch := model.Finding{Key: "pkg.mismatch:/usr/bin/ls", Severity: model.SevTampering}
	uid := model.Finding{Key: "heur.uid0:toor", Severity: model.SevBackdoor}
	st := alertState{Real: []model.Finding{mismatch, uid}}
	incomplete := &model.Report{CouldNotRuleOut: []string{"changed system files (package verification did not run)"}}
	_, resolved, next := diffAlerts(st, incomplete, true, false)
	if !slices.Equal(keysOf(resolved), []string{uid.Key}) || !slices.Equal(keysOf(next.Real), []string{mismatch.Key}) {
		t.Errorf("resolved %v, still known %v", keysOf(resolved), keysOf(next.Real))
	}
	_, resolved, _ = diffAlerts(st, &model.Report{}, true, false)
	if len(resolved) != 2 {
		t.Errorf("full verification: resolved %v", keysOf(resolved))
	}
}

// "Check now" moves the machine's next scheduled visit.
func TestCheckNowMovesTheSchedule(t *testing.T) {
	fx := newFixture(t)
	fx.visitOK(t, fx.id)
	fx.core.mu.Lock()
	due := fx.core.due[fx.id]
	fx.core.mu.Unlock()
	if d := time.Until(due); d < 23*time.Hour || d > 26*time.Hour {
		t.Errorf("next visit in %v, want about a day", d)
	}
}

// The scheduler logs what goes wrong, so a bad server address shows.
func TestSchedulerLogsErrors(t *testing.T) {
	setVar(t, &scheduleTick, 10*time.Millisecond)
	setVar(t, &startJitter, time.Millisecond)
	fx := newFixture(t)
	var buf syncBuffer
	fx.core.Log = log.New(&buf, "", 0)
	fx.core.ServerAddr = "telltale.lan"
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		fx.core.Run(ctx)
		close(stopped)
	}()
	waitFor(t, func() bool { return strings.Contains(buf.String(), fmt.Sprintf("visit to machine %d", fx.id)) })
	cancel()
	<-stopped
	if !strings.Contains(buf.String(), "server address") {
		t.Errorf("log %q", buf.String())
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// The collector says which directory it left its own binary out of; one
// that is not the directory the visit made is a note. The same directory,
// or none (nothing was left out), is not.
func TestOwnDirMismatchIsANote(t *testing.T) {
	fx := newFixture(t)
	made := "/root/telltale.AbCd1234"
	said := made
	fx.vis.collect = func(store.Machine, int) (*model.Collection, error) {
		c := base()
		c.OwnDir, c.VisitDir = said, made
		return c, nil
	}
	if _, r := fx.visitOK(t, fx.id); find(r, KeyOwnDirMismatch) != nil {
		t.Errorf("a note for the directory the visit made: %v", keysOf(r.Findings))
	}
	said = "/tmp/telltale.EfGh5678\x1b[2J"
	_, r := fx.visitOK(t, fx.id)
	f := find(r, KeyOwnDirMismatch)
	if f == nil || f.Severity != model.SevNote || f.ID != "TT-VISIT-004" {
		t.Fatalf("no note for another directory: %v", keysOf(r.Findings))
	}
	if ev := f.Evidence[0]; ev.Before != made || !strings.HasPrefix(ev.After, "/tmp/telltale.EfGh5678") || strings.Contains(ev.After, "\x1b") {
		t.Errorf("evidence %+v", ev)
	}
	said = ""
	if _, r := fx.visitOK(t, fx.id); find(r, KeyOwnDirMismatch) != nil {
		t.Errorf("a note when the collector left nothing out: %v", keysOf(r.Findings))
	}
}
