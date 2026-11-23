package alerts

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"

	"github.com/donaldsteele/bubbles/pkg/bubblesclient"
	"github.com/donaldsteele/bubbles/pkg/protocol"

	"github.com/donaldsteele/telltale/internal/alerts/bubblestest"
	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/store"
)

var t0 = time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)

// syncBuffer is a log the retry goroutine and the test can share.
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

type fixture struct {
	b      *Bubbles
	st     *store.Store
	dbPath string
	fake   *bubblestest.Server
	logs   *syncBuffer
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "server.db")
	st, err := store.Open(dbPath, store.Unlock{KeyFile: filepath.Join(dir, "server.key")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	logs := &syncBuffer{}
	b := &Bubbles{Store: st, Now: func() time.Time { return t0 }, Hostname: "srv1", Log: log.New(logs, "", 0)}
	return &fixture{b: b, st: st, dbPath: dbPath, fake: bubblestest.New(t), logs: logs}
}

// connect stores a connection to the fake as pairing would, with its one
// channel chosen.
func (fx *fixture) connect(t *testing.T) {
	t.Helper()
	conn, err := bubblesclient.Config{BaseURL: fx.fake.URL, Token: bubblestest.Token, CAFingerprint: fx.fake.CAFingerprint}.ConnectionString()
	if err != nil {
		t.Fatal(err)
	}
	if err := fx.st.SetSecretSetting(SettingConn, []byte(conn)); err != nil {
		t.Fatal(err)
	}
	if err := fx.b.saveSealed(SettingChannel, channelRecord{Channel: Channel{ID: "ch-alerts", Name: "telltale-alerts"}, Server: "office chat"}); err != nil {
		t.Fatal(err)
	}
}

func (fx *fixture) queue(t *testing.T) pendingQueue {
	t.Helper()
	q, err := fx.b.loadQueue()
	if err != nil {
		t.Fatal(err)
	}
	return q
}

var machine = store.Machine{ID: 1, Name: "web01", Addr: "192.0.2.7"}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The mapping of findings the judge produced: a changed persistence file
// (its evidence starts with a summary whose values are the file's hashes),
// a package mismatch (a pair of hashes) and checklist findings.
func TestAlertMappingFields(t *testing.T) {
	fx := newFixture(t)
	fx.connect(t)
	r := judgedReport(t)
	persist := judgedFinding(t, r, "snap.persist:/etc/cron.d/backup")
	mismatch := judgedFinding(t, r, "pkg.mismatch:/usr/bin/ls")
	weak := judgedFinding(t, r, "check:TT-FILE-006")
	if err := fx.b.Notify(t.Context(), machine, r.Findings, nil); err != nil {
		t.Fatal(err)
	}
	posts := fx.fake.Posts()
	if len(posts) != len(r.Findings) {
		t.Fatalf("got %d alerts for %d findings", len(posts), len(r.Findings))
	}
	byKey := map[string]protocol.AlertInput{}
	for _, p := range posts {
		byKey[p.DedupeKey] = p
		if p.Channel != "ch-alerts" {
			t.Errorf("%s: channel %q", p.DedupeKey, p.Channel)
		}
		if p.RenotifyAfterS == nil || *p.RenotifyAfterS != 0 {
			t.Errorf("%s: an open alert must not notify again by itself", p.DedupeKey)
		}
		if len([]rune(p.Title)) > protocol.MaxAlertTitle || len([]rune(p.Text)) > protocol.MaxAlertText {
			t.Errorf("%s exceeds bubbles' limits", p.DedupeKey)
		}
	}

	// The persistence file: the changed line, never the summary's hashes,
	// and nothing else of the file.
	a := byKey["telltale:web01:snap.persist:/etc/cron.d/backup"]
	if a.Severity != protocol.SeverityCritical || a.Title != "web01: "+persist.Title {
		t.Errorf("persist alert: severity %q title %q", a.Severity, a.Title)
	}
	for _, want := range []string{mdText(persist.Why), "Changed line in " + mdText("/etc/cron.d/backup:2") + ":\n```\n* * * * * root /tmp/.x/beacon\n```", "Fix:\n```\n"} {
		if !strings.Contains(a.Text, want) {
			t.Errorf("persist alert text has no %q:\n%s", want, a.Text)
		}
	}
	// (The fix command names the file's hash, to refuse a file edited since
	// the scan; what is shown as the change must not.)
	shown, _, _ := strings.Cut(a.Text, "Fix:\n")
	for _, e := range persist.Evidence[:1] {
		if strings.Contains(shown, e.After) || strings.Contains(shown, e.Before) {
			t.Errorf("persist alert shows the summary's hash as a line:\n%s", a.Text)
		}
	}
	if strings.Contains(a.Text, "0 3 * * * root /usr/local/bin/backup") || strings.Contains(a.Text, "size 66") {
		t.Errorf("persist alert carries more of the file than the changed line:\n%s", a.Text)
	}
	wantFields := []protocol.AlertField{{Name: "Machine", Value: "web01", Short: true}, {Name: "Address", Value: "192.0.2.7", Short: true},
		{Name: "Severity", Value: "backdoor sign", Short: true}, {Name: "Path", Value: "/etc/cron.d/backup"}}
	if !slices.Equal(a.Fields, wantFields) {
		t.Errorf("persist alert fields %+v, want %+v", a.Fields, wantFields)
	}

	// The package mismatch: its hashes are evidence, not a changed line.
	p := byKey["telltale:web01:pkg.mismatch:/usr/bin/ls"]
	ev := mismatch.Evidence[0]
	if p.Severity != protocol.SeverityCritical || strings.Contains(p.Text, "line") {
		t.Errorf("package alert: severity %q text:\n%s", p.Severity, p.Text)
	}
	if !strings.Contains(p.Text, "Evidence in "+mdText("/usr/bin/ls")+":\n"+mdText(strings.SplitN(ev.Detail, "\n", 2)[0])+"\n```\n"+ev.Before+" -> "+ev.After+"\n```") {
		t.Errorf("package alert text:\n%s", p.Text)
	}

	// A checklist finding: the value it saw.
	w := byKey["telltale:web01:check:TT-FILE-006"]
	if w.Severity != protocol.SeverityWarning || !strings.Contains(w.Text, "Evidence:\n"+mdText(weak.Evidence[0].Detail)+"\n```\n"+weak.Evidence[0].After+"\n```") {
		t.Errorf("weak setting: severity %q text:\n%s", w.Severity, w.Text)
	}
	if q := fx.queue(t); len(q.Items) != 0 {
		t.Errorf("%d alerts still queued after they were sent", len(q.Items))
	}
	if Severity(model.SevNote) != protocol.SeverityInfo || Severity(model.SevWeak) != protocol.SeverityWarning ||
		Severity(model.SevBackdoor) != protocol.SeverityCritical || Severity(model.SevTampering) != protocol.SeverityCritical {
		t.Error("severity mapping")
	}
}

// A removed line is shown as removed, and redacted once more: kept text is
// redacted by the collector already, and an alert never carries a secret.
func TestAlertRemovedLineRedacted(t *testing.T) {
	fx := newFixture(t)
	fx.connect(t)
	f := model.Finding{Key: "snap.persist:/etc/profile.d/env.sh", Severity: model.SevBackdoor, Title: "Login script changed",
		Evidence: []model.Evidence{
			{Path: "/etc/profile.d/env.sh", Line: 4, Before: sum("a"), After: sum("b"), Detail: "1 line removed"},
			{Path: "/etc/profile.d/env.sh", Line: 4, Before: "export API_TOKEN=s3cr3t-value-123", Detail: "line removed"},
		}}
	if err := fx.b.Notify(t.Context(), machine, []model.Finding{f}, nil); err != nil {
		t.Fatal(err)
	}
	n := fx.fake.Posts()[0]
	if strings.Contains(n.Text, "s3cr3t") || !strings.Contains(n.Text, "Removed line in") || !strings.Contains(n.Text, "<redacted h:") {
		t.Errorf("text:\n%s", n.Text)
	}
}

// A line that was replaced comes out of the judge as the old line removed
// and the new one added, the removed one first. The alert shows the line
// the machine has now, the one somebody put there; the snapshot's line is
// only what it replaced.
func TestAlertReplacedLineShowsTheNewLine(t *testing.T) {
	fx := newFixture(t)
	fx.connect(t)
	f := model.Finding{Key: "snap.persist:/etc/ssh/sshd_config.d/00-lab.conf", Severity: model.SevBackdoor, Title: "SSH server configuration changed",
		Evidence: []model.Evidence{
			{Path: "/etc/ssh/sshd_config.d/00-lab.conf", Line: 1, Before: sum("a"), After: sum("b"), Detail: "1 line added, 1 line removed"},
			{Path: "/etc/ssh/sshd_config.d/00-lab.conf", Line: 1, Before: "PermitRootLogin no", Detail: "line removed"},
			{Path: "/etc/ssh/sshd_config.d/00-lab.conf", Line: 1, After: "PermitRootLogin yes", Detail: "line added"},
		}}
	if err := fx.b.Notify(t.Context(), machine, []model.Finding{f}, nil); err != nil {
		t.Fatal(err)
	}
	n := fx.fake.Posts()[0]
	if !strings.Contains(n.Text, "Changed line in "+mdText("/etc/ssh/sshd_config.d/00-lab.conf:1")+":\n```\nPermitRootLogin yes\n```") || strings.Contains(n.Text, "PermitRootLogin no") ||
		strings.Contains(n.Text, "other changed line") {
		t.Errorf("text:\n%s", n.Text)
	}
}

// The judge numbers removed lines in the old file and added lines in the new
// one, so an earlier change that adds or removes lines moves the number the
// replacement gets. Here a blank line 1 was deleted and then line 5
// replaced: the new line is line 4 of the new file. The alert still shows
// the planted line, not the harmless one it replaced.
func TestAlertReplacementAfterAnEarlierChangeShowsTheNewLine(t *testing.T) {
	const p = "/etc/ssh/sshd_config.d/00-lab.conf"
	for name, evs := range map[string][]model.Evidence{
		"a line removed before": {
			{Path: p, Line: 1, Detail: "line removed"},
			{Path: p, Line: 5, Before: "PermitRootLogin no", Detail: "line removed"},
			{Path: p, Line: 4, After: "PermitRootLogin yes", Detail: "line added"},
		},
		"two lines added before": {
			{Path: p, Line: 1, Detail: "line added"},
			{Path: p, Line: 2, Detail: "line added"},
			{Path: p, Line: 5, Before: "PermitRootLogin no", Detail: "line removed"},
			{Path: p, Line: 7, After: "PermitRootLogin yes", Detail: "line added"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			fx := newFixture(t)
			fx.connect(t)
			f := model.Finding{Key: "snap.persist:" + p, Severity: model.SevBackdoor, Title: "SSH server configuration changed",
				Evidence: append([]model.Evidence{{Path: p, Line: 1, Before: sum("a"), After: sum("b"), Detail: "changed"}}, evs...)}
			if err := fx.b.Notify(t.Context(), machine, []model.Finding{f}, nil); err != nil {
				t.Fatal(err)
			}
			n := fx.fake.Posts()[0]
			if !strings.Contains(n.Text, "Changed line in "+mdText(p+":"+strconv.Itoa(evs[len(evs)-1].Line))+":\n```\nPermitRootLogin yes\n```") ||
				strings.Contains(n.Text, "PermitRootLogin no") || strings.Contains(n.Text, "Removed line") {
				t.Errorf("text:\n%s", n.Text)
			}
		})
	}
	// An added block that does not start where the removed one would be
	// now is not its replacement: the removed line is shown.
	fx := newFixture(t)
	fx.connect(t)
	f := model.Finding{Key: "snap.persist:" + p, Severity: model.SevBackdoor, Title: "SSH server configuration changed",
		Evidence: []model.Evidence{
			{Path: p, Line: 1, Before: sum("a"), After: sum("b"), Detail: "changed"},
			{Path: p, Line: 1, Detail: "line removed"},
			{Path: p, Line: 5, Before: "PermitRootLogin no", Detail: "line removed"},
			{Path: p, Line: 5, After: "# unrelated", Detail: "line added"},
		}}
	if err := fx.b.Notify(t.Context(), machine, []model.Finding{f}, nil); err != nil {
		t.Fatal(err)
	}
	if n := fx.fake.Posts()[0]; !strings.Contains(n.Text, "Removed line in "+mdText(p+":5")+":\n```\nPermitRootLogin no\n```") {
		t.Errorf("not a replacement, text:\n%s", n.Text)
	}
}

// A block of lines replaced by another comes out of the judge as every
// removed line first, then every added one. The alert pairs the first
// removed line with the first line added in its place, so a two-line cron
// replacement shows the job somebody planted, never the snapshot's harmless
// one.
func TestAlertMultiLineReplacementShowsTheNewLine(t *testing.T) {
	const p = "/etc/cron.d/backup"
	for name, evs := range map[string][]model.Evidence{
		"two lines": {
			{Path: p, Line: 2, Before: "0 3 * * * root /usr/local/bin/backup", Detail: "line removed"},
			{Path: p, Line: 3, Before: "30 3 * * * root /usr/local/bin/rotate", Detail: "line removed"},
			{Path: p, Line: 2, After: "* * * * * root /var/tmp/.x/cb", Detail: "line added"},
			{Path: p, Line: 3, After: "30 3 * * * root /usr/local/bin/rotate --all", Detail: "line added"},
		},
		// Blank lines are never shown, and they do not break the pairing.
		"blank lines in the blocks": {
			{Path: p, Line: 1, Detail: "line removed"},
			{Path: p, Line: 2, Before: "0 3 * * * root /usr/local/bin/backup", Detail: "line removed"},
			{Path: p, Line: 3, Before: "30 3 * * * root /usr/local/bin/rotate", Detail: "line removed"},
			{Path: p, Line: 1, Detail: "line added"},
			{Path: p, Line: 2, After: "* * * * * root /var/tmp/.x/cb", Detail: "line added"},
			{Path: p, Line: 3, After: "30 3 * * * root /usr/local/bin/rotate --all", Detail: "line added"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			fx := newFixture(t)
			fx.connect(t)
			f := model.Finding{Key: "snap.persist:" + p, Severity: model.SevBackdoor, Title: "Cron job changed",
				Evidence: append([]model.Evidence{{Path: p, Line: 2, Before: sum("a"), After: sum("b"), Detail: "2 lines added, 2 lines removed"}}, evs...)}
			if err := fx.b.Notify(t.Context(), machine, []model.Finding{f}, nil); err != nil {
				t.Fatal(err)
			}
			n := fx.fake.Posts()[0]
			if !strings.Contains(n.Text, "Changed line in "+mdText(p+":2")+":\n```\n* * * * * root /var/tmp/.x/cb\n```\n"+mdText("2 other changed lines are in telltale's web UI.")) ||
				strings.Contains(n.Text, "/usr/local/bin/backup") || strings.Contains(n.Text, "Removed line") {
				t.Errorf("text:\n%s", n.Text)
			}
		})
	}
}

// The alert shows the first change in order: removing pam_deny.so cannot be
// hidden behind a comment added further down. The other changes are
// counted, the judge's "and N more" included.
func TestAlertShowsTheFirstChangeNotADecoy(t *testing.T) {
	fx := newFixture(t)
	fx.connect(t)
	const p = "/etc/pam.d/common-auth"
	f := model.Finding{Key: "snap.persist:" + p, Severity: model.SevBackdoor, Title: "PAM configuration changed",
		Evidence: []model.Evidence{
			{Path: p, Line: 3, Before: sum("a"), After: sum("b"), Detail: "2 lines added, 1 line removed"},
			{Path: p, Line: 3, Before: "auth requisite pam_deny.so", Detail: "line removed"},
			{Path: p, Line: 7, After: "# tidied up", Detail: "line added"},
			{Path: p, Line: 8, After: "# more tidying", Detail: "line added"},
			{Detail: "and 2 more"},
		}}
	if err := fx.b.Notify(t.Context(), machine, []model.Finding{f}, nil); err != nil {
		t.Fatal(err)
	}
	n := fx.fake.Posts()[0]
	if !strings.Contains(n.Text, "Removed line in "+mdText(p+":3")+":\n```\nauth requisite pam_deny.so\n```\n"+mdText("4 other changed lines are in telltale's web UI.")) ||
		strings.Contains(n.Text, "tidied") || strings.Contains(n.Text, "tidying") {
		t.Errorf("text:\n%s", n.Text)
	}
}

// Nothing is queued or sent before telltale is paired.
func TestNotifyWithoutConnection(t *testing.T) {
	fx := newFixture(t)
	f := model.Finding{Key: "k", Severity: model.SevTampering, Title: "t"}
	if err := fx.b.Notify(t.Context(), machine, []model.Finding{f}, nil); err != nil {
		t.Fatal(err)
	}
	if q := fx.queue(t); len(q.Items) != 0 || fx.fake.Calls() != 0 {
		t.Errorf("queued %d, calls %d", len(q.Items), fx.fake.Calls())
	}
}

func TestDedupeKeyStable(t *testing.T) {
	if k := DedupeKey("web01", "snap.persist:/etc/cron.d/job"); k != "telltale:web01:snap.persist:/etc/cron.d/job" {
		t.Errorf("DedupeKey = %q", k)
	}
	long := "snap.file:/" + strings.Repeat("deep/", 100) + "file"
	k1, k2 := DedupeKey("web01", long), DedupeKey("web01", long)
	if k1 != k2 || len([]rune(k1)) > protocol.MaxAlertDedupeKey || !strings.HasPrefix(k1, "telltale:web01:h:") {
		t.Errorf("long key: %q, %q", k1, k2)
	}
	if DedupeKey("web01", long+"x") == k1 || DedupeKey("web02", long) == k1 {
		t.Error("different findings share a shortened key")
	}
	// Bytes a machine put in a path that are not text get the stable
	// shortened form too: bubbles refuses keys that are not valid text.
	if k := DedupeKey("web01", "snap.file:/tmp/\xff\x1b[2J"); !strings.HasPrefix(k, "telltale:web01:h:") || k != DedupeKey("web01", "snap.file:/tmp/\xff\x1b[2J") {
		t.Errorf("unsafe key: %q", k)
	}
	// The same finding at a higher severity updates the same alert.
	fx := newFixture(t)
	fx.connect(t)
	f := model.Finding{Key: "heur.ld_preload", Severity: model.SevWeak, Title: "ld.so.preload exists"}
	fx.b.Notify(t.Context(), machine, []model.Finding{f}, nil)
	f.Severity = model.SevTampering
	fx.b.Notify(t.Context(), machine, []model.Finding{f}, nil)
	posts := fx.fake.Posts()
	if len(posts) != 2 || posts[0].DedupeKey != posts[1].DedupeKey || posts[1].Severity != protocol.SeverityCritical {
		t.Errorf("posts %+v", posts)
	}
}

func TestResolveOnDisappear(t *testing.T) {
	fx := newFixture(t)
	fx.connect(t)
	f := model.Finding{Key: "snap.persist:/etc/cron.d/job", Severity: model.SevBackdoor, Title: "New cron job"}
	if err := fx.b.Notify(t.Context(), machine, []model.Finding{f}, nil); err != nil {
		t.Fatal(err)
	}
	if err := fx.b.Notify(t.Context(), machine, nil, []model.Finding{f}); err != nil {
		t.Fatal(err)
	}
	want := []protocol.ResolveAlertByKeyRequest{{DedupeKey: "telltale:web01:snap.persist:/etc/cron.d/job", Text: "No longer found on 2026-11-23 10:00 UTC."}}
	if got := fx.fake.Resolves(); !slices.Equal(got, want) {
		t.Errorf("resolves %+v, want %+v", got, want)
	}
	// A resolve for an alert bubbles never had (404) is done, not retried.
	g := model.Finding{Key: "never.posted", Severity: model.SevBackdoor}
	if err := fx.b.Notify(t.Context(), machine, nil, []model.Finding{g}); err != nil {
		t.Fatal(err)
	}
	if q := fx.queue(t); len(q.Items) != 0 {
		t.Errorf("queue %+v", q.Items)
	}
}

func TestPendingRetriedWhenUnreachable(t *testing.T) {
	fx := newFixture(t)
	fx.connect(t)
	fx.b.retryEvery = 20 * time.Millisecond
	fx.fake.SetDown(true)
	f := model.Finding{Key: "snap.persist:/etc/cron.d/job", Severity: model.SevBackdoor, Title: "UNIQUE-TITLE-new-cron-job"}
	if err := fx.b.Notify(t.Context(), machine, []model.Finding{f}, nil); err != nil {
		t.Fatalf("Notify with bubbles down: %v (the alert is queued, not lost)", err)
	}
	// The same finding again while down is still one queued alert.
	fx.b.Notify(t.Context(), machine, []model.Finding{f}, nil)
	if q := fx.queue(t); len(q.Items) != 1 {
		t.Fatalf("queued %d alerts, want 1", len(q.Items))
	}
	if st, _ := fx.b.Status(); st.Trouble != TroubleUnreachable || st.Pending != 1 {
		t.Errorf("status %+v", st)
	}
	// Queued alerts are sealed: the database file never holds their text.
	raw, err := os.ReadFile(fx.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	wal, _ := os.ReadFile(fx.dbPath + "-wal")
	if bytes.Contains(raw, []byte("UNIQUE-TITLE")) || bytes.Contains(wal, []byte("UNIQUE-TITLE")) {
		t.Error("a queued alert is stored in the clear")
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go fx.b.Run(ctx)
	time.Sleep(100 * time.Millisecond)
	if n := len(fx.fake.Posts()); n != 0 {
		t.Fatalf("%d alerts posted while bubbles was down", n)
	}
	fx.fake.SetDown(false)
	waitFor(t, "the queued alert to go out", func() bool { return len(fx.fake.Posts()) == 1 })
	waitFor(t, "the queue to empty", func() bool { return len(fx.queue(t).Items) == 0 })
	if st, _ := fx.b.Status(); st.Trouble != TroubleNone {
		t.Errorf("trouble after delivery: %q", st.Trouble)
	}
}

// The next visit retries too: the core kicks the sink after every visit.
func TestKickRetries(t *testing.T) {
	fx := newFixture(t)
	fx.connect(t)
	fx.b.retryEvery = time.Hour
	clock := t0
	var mu sync.Mutex
	fx.b.Now = func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	fx.fake.SetDown(true)
	fx.b.Notify(t.Context(), machine, []model.Finding{{Key: "k", Severity: model.SevTampering, Title: "t"}}, nil)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go fx.b.Run(ctx)
	fx.fake.SetDown(false)
	mu.Lock()
	clock = clock.Add(kickGap + time.Second)
	mu.Unlock()
	fx.b.Kick()
	waitFor(t, "the kicked retry", func() bool { return len(fx.fake.Posts()) == 1 })
}

func TestPendingQueueBoundAndDroppedSummary(t *testing.T) {
	fx := newFixture(t)
	fx.connect(t)
	fx.fake.SetDown(true)
	var fs []model.Finding
	for i := range MaxPending + 5 {
		sev := model.SevNote
		if i == 2 {
			sev = model.SevTampering
		}
		fs = append(fs, model.Finding{Key: fmt.Sprintf("snap.file:/srv/f%04d", i), Severity: sev, Title: "changed"})
	}
	if err := fx.b.Notify(t.Context(), machine, fs, nil); err != nil {
		t.Fatal(err)
	}
	// The five oldest notes go; the tampering alert, older than most, stays.
	q := fx.queue(t)
	if len(q.Items) != MaxPending || q.Dropped != 5 || q.DroppedSeverity != protocol.SeverityInfo {
		t.Fatalf("queue: %d items, dropped %d (%q)", len(q.Items), q.Dropped, q.DroppedSeverity)
	}
	if q.Items[0].Key != DedupeKey("web01", "snap.file:/srv/f0002") || q.Items[1].Key != DedupeKey("web01", "snap.file:/srv/f0006") {
		t.Errorf("the oldest kept are %q, %q", q.Items[0].Key, q.Items[1].Key)
	}
	if st, _ := fx.b.Status(); st.Dropped != 5 || st.Pending != MaxPending || st.Critical != 1 {
		t.Errorf("status %+v", st)
	}
	fx.fake.SetDown(false)
	if err := fx.b.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	posts := fx.fake.Posts()
	if len(posts) != MaxPending+1 {
		t.Fatalf("posted %d, want the summary and %d alerts", len(posts), MaxPending)
	}
	sum := posts[0]
	if sum.DedupeKey != DroppedKey || sum.Severity != protocol.SeverityInfo || sum.Title != "telltale: 5 lower-priority alerts were not sent because the queue was full" {
		t.Errorf("summary alert %+v", sum)
	}
	if posts[1].DedupeKey != DedupeKey("web01", "snap.file:/srv/f0002") || posts[MaxPending].DedupeKey != DedupeKey("web01", fmt.Sprintf("snap.file:/srv/f%04d", MaxPending+4)) {
		t.Error("queued alerts not sent oldest first")
	}
	if q := fx.queue(t); len(q.Items) != 0 || q.Dropped != 0 {
		t.Errorf("after the flush: %d items, dropped %d", len(q.Items), q.Dropped)
	}
	// The count goes out once.
	fx.b.Notify(t.Context(), machine, []model.Finding{{Key: "x", Severity: model.SevTampering, Title: "x"}}, nil)
	if n := len(fx.fake.Posts()); n != MaxPending+2 {
		t.Errorf("posted %d after one more alert", n)
	}
}

// Reports list the most severe findings first. With one tampering finding
// and a thousand notes, bubbles up, the tampering alert goes out; the one
// note with no room is the one counted, and the summary says why.
func TestQueueKeepsSevereAlerts(t *testing.T) {
	fx := newFixture(t)
	fx.connect(t)
	fs := []model.Finding{{Key: "pkg.mismatch:/usr/bin/ls", Severity: model.SevTampering, Title: "ls replaced"}}
	for i := range MaxPending {
		fs = append(fs, model.Finding{Key: fmt.Sprintf("snap.file:/srv/n%04d", i), Severity: model.SevNote, Title: "note"})
	}
	if err := fx.b.Notify(t.Context(), machine, fs, nil); err != nil {
		t.Fatal(err)
	}
	posts := fx.fake.Posts()
	if !slices.ContainsFunc(posts, func(p protocol.AlertInput) bool { return p.DedupeKey == DedupeKey("web01", "pkg.mismatch:/usr/bin/ls") }) {
		t.Fatal("the tampering alert was dropped for notes")
	}
	if posts[0].Title != "telltale: 1 lower-priority alert was not sent because the queue was full" || strings.Contains(posts[0].Title, "reached") {
		t.Errorf("summary %q", posts[0].Title)
	}
	if len(posts) != MaxPending+1 {
		t.Errorf("%d posts", len(posts))
	}
}

// While bubbles is down, one machine's flood of notes never pushes out
// another machine's critical alert, whichever came first.
func TestQueueFloodAcrossMachines(t *testing.T) {
	fx := newFixture(t)
	fx.connect(t)
	fx.fake.SetDown(true)
	a := store.Machine{ID: 1, Name: "noisy", Addr: "192.0.2.7"}
	b := store.Machine{ID: 2, Name: "db01", Addr: "192.0.2.8"}
	c := store.Machine{ID: 3, Name: "web02", Addr: "192.0.2.9"}
	crit := model.Finding{Key: "snap.persist:/etc/cron.d/x", Severity: model.SevBackdoor, Title: "cron"}
	fx.b.Notify(t.Context(), b, []model.Finding{crit}, nil)
	var notes []model.Finding
	for i := range 2 * MaxPending {
		notes = append(notes, model.Finding{Key: fmt.Sprintf("snap.file:/srv/n%05d", i), Severity: model.SevNote, Title: "note"})
	}
	fx.b.Notify(t.Context(), a, notes, nil)
	fx.b.Notify(t.Context(), c, []model.Finding{crit}, nil)
	q := fx.queue(t)
	keys := map[string]bool{}
	for _, it := range q.Items {
		keys[it.Key] = true
	}
	if len(q.Items) != MaxPending || !keys[DedupeKey("db01", crit.Key)] || !keys[DedupeKey("web02", crit.Key)] {
		t.Fatalf("queue %d items; db01's critical kept %v, web02's %v", len(q.Items), keys[DedupeKey("db01", crit.Key)], keys[DedupeKey("web02", crit.Key)])
	}
	if q.Dropped != 2*MaxPending-(MaxPending-2) || q.DroppedSeverity != protocol.SeverityInfo {
		t.Errorf("dropped %d (%q)", q.Dropped, q.DroppedSeverity)
	}
}

// Only critical alerts push out critical alerts: the oldest goes, and the
// summary does not call them lower-priority.
func TestQueueCriticalsAloneOverflow(t *testing.T) {
	fx := newFixture(t)
	fx.connect(t)
	fx.fake.SetDown(true)
	var fs []model.Finding
	for i := range MaxPending + 3 {
		fs = append(fs, model.Finding{Key: fmt.Sprintf("k%04d", i), Severity: model.SevTampering, Title: "t"})
	}
	fx.b.Notify(t.Context(), machine, fs, nil)
	q := fx.queue(t)
	if len(q.Items) != MaxPending || q.Items[0].Key != DedupeKey("web01", "k0003") || q.DroppedSeverity != protocol.SeverityCritical {
		t.Fatalf("queue %d, first %q, dropped %q", len(q.Items), q.Items[0].Key, q.DroppedSeverity)
	}
	fx.fake.SetDown(false)
	fx.b.Flush(t.Context())
	if p := fx.fake.Posts(); p[0].Title != "telltale: 3 alerts were not sent because the queue was full" || p[0].Severity != protocol.SeverityCritical {
		t.Errorf("summary %+v", p[0])
	}
}

// Enqueuing takes time linear in what is offered, and builds alert text
// only for what is kept.
func TestEnqueueLinear(t *testing.T) {
	fx := newFixture(t)
	fx.connect(t)
	fx.fake.SetDown(true)
	var fs []model.Finding
	for i := range 50000 {
		fs = append(fs, model.Finding{Key: fmt.Sprintf("snap.persist:/etc/cron.d/f%05d", i), Severity: model.SevBackdoor, Title: "x",
			Why: strings.Repeat("w", 900), Fix: strings.Repeat("f", 900), Evidence: []model.Evidence{{Path: "/etc/cron.d/x", After: strings.Repeat("a", 300)}}})
	}
	start := time.Now()
	if err := fx.b.Notify(t.Context(), machine, fs, nil); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("Notify of 50,000 findings took %v", d)
	}
	if q := fx.queue(t); len(q.Items) != MaxPending || q.Dropped != 50000-MaxPending {
		t.Errorf("queue %d, dropped %d", len(q.Items), q.Dropped)
	}
}

// The queue is stored compactly, and the settings pages read only its
// small summary: a queue that cannot be read does not break them.
func TestQueueStorage(t *testing.T) {
	fx := newFixture(t)
	fx.connect(t)
	fx.fake.SetDown(true)
	var fs []model.Finding
	for i := range MaxPending {
		fs = append(fs, model.Finding{Key: fmt.Sprintf("snap.file:/srv/f%04d", i), Severity: model.SevBackdoor,
			Title: strings.Repeat("<", 200), Why: strings.Repeat("<", 900), Fix: strings.Repeat("&", 900),
			Evidence: []model.Evidence{{Path: "/" + strings.Repeat("<", 400), Line: 1, After: strings.Repeat("<", 300)}}})
	}
	fx.b.Notify(t.Context(), machine, fs, nil)
	raw, err := fx.st.SecretSetting(SettingPending)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > 8<<20 {
		t.Errorf("1000 queued alerts take %d bytes", len(raw))
	}
	for _, it := range fx.queue(t).Items {
		if len([]rune(it.Alert.Text)) > protocol.MaxAlertText {
			t.Fatalf("a queued text of %d characters", len([]rune(it.Alert.Text)))
		}
	}
	if err := fx.st.SetSecretSetting(SettingPending, []byte("{not json")); err != nil {
		t.Fatal(err)
	}
	st, err := fx.b.Status()
	if err != nil || st.Pending != MaxPending || st.Critical != MaxPending || st.Trouble != TroubleUnreachable {
		t.Errorf("status %+v, %v", st, err)
	}
}

func TestRunStopsOnShutdown(t *testing.T) {
	fx := newFixture(t)
	fx.connect(t)
	if err := fx.st.SetSetting(SettingAlertTimeout, "100ms"); err != nil {
		t.Fatal(err)
	}
	fx.b.retryEvery = 10 * time.Millisecond
	fx.fake.HangAll()
	// Queued without trying: the fake hangs and Notify would wait for it.
	in := protocol.AlertInput{DedupeKey: "k", Title: "t", Severity: "info"}
	if err := fx.b.enqueue([]queued{{key: "k", severity: "info", build: func() pendingItem { return pendingItem{Key: "k", Severity: "info", Alert: &in} }}}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		fx.b.Run(ctx)
		close(done)
	}()
	// Each retry gives up after alert_timeout, and the next one starts.
	waitFor(t, "several bounded retries", func() bool { return fx.fake.Calls() >= 3 })
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop when its context ended")
	}
	if q := fx.queue(t); len(q.Items) != 1 {
		t.Errorf("the queued alert was lost: %+v", q.Items)
	}
}

func TestNotifyHonoursContext(t *testing.T) {
	fx := newFixture(t)
	fx.connect(t)
	fx.fake.HangAll()
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := fx.b.Notify(ctx, machine, []model.Finding{{Key: "k", Severity: model.SevTampering, Title: "t"}}, nil)
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("Notify took %v with a context of 200ms", d)
	}
	if err != nil {
		t.Errorf("Notify: %v (the alert is queued)", err)
	}
	if q := fx.queue(t); len(q.Items) != 1 {
		t.Errorf("queue after a cut-off send: %+v", q.Items)
	}
	// A context that has already ended queues nothing.
	if err := fx.b.Notify(ctx, machine, []model.Finding{{Key: "k2", Severity: model.SevTampering, Title: "t"}}, nil); err == nil {
		t.Error("Notify with an ended context returned nil")
	}
	if q := fx.queue(t); len(q.Items) != 1 {
		t.Errorf("queue after an ended context: %d items", len(q.Items))
	}
}

// proseOf is a Markdown text without its fenced code blocks, and the lines
// of those blocks.
func proseOf(t *testing.T, md string) (prose string, code []string) {
	t.Helper()
	lines := strings.Split(md, "\n")
	var out []string
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		if strings.HasPrefix(l, "```") {
			fence := l
			if strings.Trim(fence, "`") != "" {
				t.Fatalf("a fence with an info string: %q", l)
			}
			j := i + 1
			for ; j < len(lines) && lines[j] != fence; j++ {
				if strings.HasPrefix(lines[j], "```") && strings.Trim(lines[j], "`") == "" && len(lines[j]) >= len(fence) {
					t.Fatalf("a code line closes its fence: %q", lines[j])
				}
				code = append(code, lines[j])
			}
			if j == len(lines) {
				t.Fatalf("an unclosed fence in:\n%s", md)
			}
			i = j
			continue
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n"), code
}

func TestHostileTextEscaped(t *testing.T) {
	fx := newFixture(t)
	fx.connect(t)
	const hostile = "\x1b]8;;https://evil.example\x07click\x1b]8;;\x07 \u202e[x](https://evil.example) <b>bold</b> **@channel** &#x202e; `code`\r\nNEXT"
	f := model.Finding{
		Key:      "snap.persist:/etc/cron.d/evil",
		Severity: model.SevTampering,
		Title:    "Cron job " + hostile,
		Why:      "Why: " + hostile,
		Fix:      "rm '/etc/cron.d/" + hostile + "'",
		Evidence: []model.Evidence{
			{Path: "/etc/cron.d/" + hostile, Line: 1, Before: "absent", After: sum("x"), Detail: "new file, 1 line added"},
			{Path: "/etc/cron.d/" + hostile, Line: 1, After: "* * * * * root ``````" + hostile, Detail: "line added"},
		},
	}
	m := store.Machine{ID: 1, Name: "web01", Addr: "192.0.2.7"}
	if err := fx.b.Notify(t.Context(), m, []model.Finding{f}, nil); err != nil {
		t.Fatal(err)
	}
	posts := fx.fake.Posts()
	if len(posts) != 1 {
		t.Fatalf("%d posts", len(posts))
	}
	a := posts[0]
	noControl := func(where, s string, allowNewline bool) {
		for _, r := range s {
			if (r == '\n' && allowNewline) || r == ' ' {
				continue
			}
			if unicode.IsControl(r) || !unicode.IsPrint(r) {
				t.Errorf("%s holds %U:\n%q", where, r, s)
				return
			}
		}
	}
	noControl("title", a.Title, false)
	noControl("text", a.Text, true)
	for _, fl := range a.Fields {
		noControl("field "+fl.Name, fl.Value, false)
	}
	// Title and fields are plain text on the card, and go into a Markdown
	// body for other clients: no character reference and no link survive.
	for _, s := range append([]string{a.Title}, a.Fields[3].Value) {
		if strings.Contains(s, "&#x202e;") || strings.Contains(s, "https://") {
			t.Errorf("plain text keeps a reference or a link: %q", s)
		}
		if !strings.Contains(s, `\x26#x202e;`) || !strings.Contains(s, "https[:]//evil.example") {
			t.Errorf("plain text not neutralised as expected: %q", s)
		}
	}
	// The text: outside code blocks every ASCII punctuation character is
	// backslash-escaped, so nothing is markup, a link, an entity or a
	// mention; inside them nothing is interpreted, and no line closes its
	// block early.
	prose, code := proseOf(t, a.Text)
	for i := 0; i < len(prose); i++ {
		c := prose[i]
		if c == '\\' {
			i++
			continue
		}
		if c < 0x80 && strings.IndexByte(asciiPunct, c) >= 0 && !isLabelPunct(prose, i) {
			t.Fatalf("unescaped %q at %d in the text's prose:\n%s", c, i, prose)
		}
	}
	if len(code) != 2 || !strings.Contains(code[0], "``````") || !strings.Contains(code[1], "rm '/etc/cron.d/") {
		t.Errorf("code lines %q", code)
	}
	for _, s := range []string{a.Title, a.Text, a.Fields[3].Value} {
		if strings.Contains(s, "\r") || strings.Contains(s, "\nNEXT") {
			t.Errorf("a line break survived: %q", s)
		}
	}
	// A line that is nothing but backticks must not close its code block
	// and turn what follows into Markdown.
	fences := model.Finding{Key: "heur.fences", Severity: model.SevTampering, Title: "fences",
		Fix:      "```",
		Evidence: []model.Evidence{{Path: "/etc/cron.d/fences", After: "````"}}}
	if err := fx.b.Notify(t.Context(), m, []model.Finding{fences}, nil); err != nil {
		t.Fatal(err)
	}
	posts = fx.fake.Posts()
	_, code = proseOf(t, posts[len(posts)-1].Text)
	if !slices.Equal(code, []string{"````", "```"}) {
		t.Errorf("code lines %q", code)
	}
	// Evidence that is not a line: its hostile detail is escaped text, its
	// values a code line.
	other := model.Finding{Key: "pkg.mismatch:/usr/bin/ls", Severity: model.SevTampering, Title: "ls",
		Evidence: []model.Evidence{{Path: "/usr/bin/" + hostile, Before: "aaa", After: hostile, Detail: "differs: " + hostile}}}
	if err := fx.b.Notify(t.Context(), m, []model.Finding{other}, nil); err != nil {
		t.Fatal(err)
	}
	posts = fx.fake.Posts()
	prose, code = proseOf(t, posts[len(posts)-1].Text)
	for i := 0; i < len(prose); i++ {
		if c := prose[i]; c == 0x5c {
			i++
		} else if c < 0x80 && strings.IndexByte(asciiPunct, c) >= 0 && !isLabelPunct(prose, i) {
			t.Fatalf("unescaped %q in the evidence prose:\n%s", c, prose)
		}
	}
	if len(code) != 1 || !strings.HasPrefix(code[0], "aaa -> ") || !strings.HasPrefix(prose, "Evidence in ") {
		t.Errorf("evidence: %q\n%s", code, prose)
	}
}

// isLabelPunct allows the punctuation of telltale's own labels ("Fix:",
// "Changed line in ...:").
func isLabelPunct(prose string, i int) bool {
	return prose[i] == ':' && (i+1 == len(prose) || prose[i+1] == '\n')
}

func TestPairingFlowStoresConnection(t *testing.T) {
	fx := newFixture(t)
	for _, bad := range []string{"8.8.8.8", "bubbles.example.com", "https://203.0.113.5:28225", "192.168.1.20:99999"} {
		if _, err := fx.b.Inspect(t.Context(), bad); err == nil {
			t.Errorf("Inspect(%q) accepted a server that is not on the local network or not valid", bad)
		}
	}
	in, err := fx.b.Inspect(t.Context(), fx.fake.Address())
	if err != nil {
		t.Fatal(err)
	}
	groups := strings.Fields(bubblesclient.FormatFingerprint(fx.fake.CAFingerprint))
	if in.Start != strings.Join(groups[:4], " ") || in.Rest != strings.Join(groups[4:], " ") || in.ServerName != "office chat" {
		t.Errorf("inspection %+v", in)
	}
	if _, err := fx.b.StartPairing(t.Context(), "not-an-id"); err == nil {
		t.Error("pairing started without an inspected server")
	}
	ps, err := fx.b.StartPairing(t.Context(), in.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ps.State != PairPending || ps.Code != "123 456" || ps.AdminURL != fx.fake.URL+"/admin/pairing" {
		t.Errorf("pair status %+v", ps)
	}
	if _, err := fx.b.StartPairing(t.Context(), in.ID); err == nil {
		t.Error("the inspection ID worked twice")
	}
	req := fx.fake.Request()
	fx.fake.Approve()
	if req == nil || req.AppName != "telltale" || req.Description != "telltale server on srv1" || !slices.Equal(req.RequestedScopes, Scopes) {
		t.Errorf("pairing request %+v", req)
	}
	if ok, _ := fx.b.Connected(); ok {
		t.Error("connected before the chat admin approved")
	}
	waitFor(t, "the approval", func() bool { return fx.b.PairStatus().State == PairApproved })
	raw, err := fx.st.SecretSetting(SettingConn)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := bubblesclient.ParseConnectionString(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Token != bubblestest.Token || cfg.CAFingerprint != fx.fake.CAFingerprint || cfg.BaseURL != fx.fake.URL {
		t.Errorf("stored connection %+v", cfg)
	}
	st, err := fx.b.Status()
	if err != nil {
		t.Fatal(err)
	}
	// The bot is in one channel: alerts go there.
	if !st.Connected || st.Channel.ID != "ch-alerts" || st.ServerName != "office chat" || st.Choosing {
		t.Errorf("status %+v", st)
	}
	if !slices.Contains(auditActions(t, fx.st), "bubbles connected") {
		t.Errorf("audit %q", auditActions(t, fx.st))
	}
	// Alerts now go through the new connection.
	if err := fx.b.SendTest(t.Context()); err != nil {
		t.Fatal(err)
	}
	if p := fx.fake.Posts(); len(p) != 1 || p[0].DedupeKey != TestKey || p[0].Channel != "ch-alerts" {
		t.Errorf("test alert %+v", p)
	}
	if r := fx.fake.Resolves(); len(r) != 1 || r[0].DedupeKey != TestKey || r[0].Text != "Test finished." {
		t.Errorf("test alert not closed: %+v", r)
	}
}

func TestPairingChannelChoiceAndCancel(t *testing.T) {
	fx := newFixture(t)
	fx.fake.SetChannels(protocol.PairingChannel{ID: "c1", Name: "ops"}, protocol.PairingChannel{ID: "c2", Name: "security"})
	in, err := fx.b.Inspect(t.Context(), fx.fake.Address())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fx.b.StartPairing(t.Context(), in.ID); err != nil {
		t.Fatal(err)
	}
	fx.fake.Approve()
	waitFor(t, "the approval", func() bool { return fx.b.PairStatus().State == PairApproved })
	st, _ := fx.b.Status()
	if st.Channel.ID != "" || !st.Choosing || len(st.Choices) != 2 {
		t.Fatalf("with two channels the owner chooses: %+v", st)
	}
	// Alerts wait for the choice.
	fx.b.Notify(t.Context(), machine, []model.Finding{{Key: "k", Severity: model.SevTampering, Title: "t"}}, nil)
	if len(fx.fake.Posts()) != 0 || len(fx.queue(t).Items) != 1 {
		t.Fatal("an alert went out before a channel was chosen, or was lost")
	}
	if _, err := fx.b.SetChannel("not-a-channel"); err == nil {
		t.Error("a channel the bot is not in was accepted")
	}
	if ch, err := fx.b.SetChannel("c2"); err != nil || ch.Name != "security" {
		t.Fatalf("SetChannel: %+v %v", ch, err)
	}
	if err := fx.b.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if p := fx.fake.Posts(); len(p) != 1 || p[0].Channel != "c2" {
		t.Errorf("posts %+v", p)
	}

	// A second pairing that the owner cancels: bubbles is told, and the
	// connection that works stays.
	fx.fake.ResetPairing()
	in, err = fx.b.Inspect(t.Context(), fx.fake.Address())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fx.b.StartPairing(t.Context(), in.ID); err != nil {
		t.Fatal(err)
	}
	fx.b.CancelPairing(t.Context())
	cancelled := fx.fake.Cancelled()
	if !cancelled || fx.b.PairStatus().State != PairNone {
		t.Errorf("cancelled %v, status %+v", cancelled, fx.b.PairStatus())
	}
	if ok, _ := fx.b.Connected(); !ok {
		t.Error("cancelling a new pairing dropped the connection")
	}
	if err := fx.b.Disconnect(); err != nil {
		t.Fatal(err)
	}
	if ok, _ := fx.b.Connected(); ok {
		t.Error("still connected after Disconnect")
	}
	if raw, _ := fx.st.SecretSetting(SettingConn); len(raw) != 0 {
		t.Error("the connection string survived Disconnect")
	}
}

func auditActions(t *testing.T, st *store.Store) []string {
	t.Helper()
	log, err := st.AuditLog(0)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range log {
		out = append(out, e.Action)
	}
	return out
}

// Only bubbles servers on the local network are paired with, so the token
// and the alerts never leave it. Checked before anything is fetched.
func TestParseTargetLocalOnly(t *testing.T) {
	for in, want := range map[string]target{
		"192.168.1.20":               {host: "192.168.1.20", port: 28225, onboard: 28226},
		"10.0.0.5:30000":             {host: "10.0.0.5", port: 30000, onboard: 30001},
		"https://172.16.0.9:28225/":  {host: "172.16.0.9", port: 28225, onboard: 28226},
		"office.local":               {host: "office.local", port: 28225, onboard: 28226},
		"[fd00::5]:443":              {host: "fd00::5", port: 443, onboard: 444},
		"100.64.1.1":                 {host: "100.64.1.1", port: 28225, onboard: 28226},
		"bubbles://192.168.1.2:9000": {host: "192.168.1.2", port: 9000, onboard: 9001},
	} {
		got, err := parseTarget(in)
		if err != nil || got != want {
			t.Errorf("parseTarget(%q) = %+v, %v; want %+v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "8.8.8.8", "203.0.113.5:28225", "bubbles.example.com", "https://1.1.1.1", "[2001:db8::1]:443",
		"fe80::1%eth0", "192.168.1.20:0", "192.168.1.20:99999", "ftp://192.168.1.2", "https://user@192.168.1.2", "-x.local", "a..local"} {
		if got, err := parseTarget(bad); err == nil {
			t.Errorf("parseTarget(%q) = %+v, want a refusal", bad, got)
		}
	}
}

// Code fences grow with the backtick runs they hold, so a machine could
// make the text longer than bubbles takes, and bubbles would refuse the
// alert. The text is cut down instead, and the alert still goes out.
func TestAlertTextFitsBubblesLimit(t *testing.T) {
	fx := newFixture(t)
	fx.connect(t)
	ticks := strings.Repeat("`", 3000)
	f := model.Finding{Key: "heur.x", Severity: model.SevTampering, Title: "x", Why: strings.Repeat("why? ", 400), Fix: ticks,
		Evidence: []model.Evidence{{Path: "/etc/" + strings.Repeat("p", 500), After: ticks}}}
	if err := fx.b.Notify(t.Context(), machine, []model.Finding{f}, nil); err != nil {
		t.Fatal(err)
	}
	p := fx.fake.Posts()
	if len(p) != 1 {
		t.Fatalf("%d posts", len(p))
	}
	if n := len([]rune(p[0].Text)); n > protocol.MaxAlertText {
		t.Errorf("text of %d characters", n)
	}
	proseOf(t, p[0].Text)
	if !strings.Contains(p[0].Text, "telltale's web UI") {
		t.Errorf("a shortened text does not say where the rest is:\n%.300s", p[0].Text)
	}
}

// Title and fields are plain text on bubbles' card, but also go into a
// Markdown body: no link form survives there, with or without "//".
func TestPlainNeutralisesLinks(t *testing.T) {
	for _, s := range []string{"/tmp/[click](http:evil.example)", "/tmp/<http:evil.example>", "/tmp/[x](HTTPS:/evil.example)",
		"/tmp/[x](mailto:a@b.example)", "/tmp/<mallory@evil.example>", "/tmp/write to mallory@evil.example", "https://evil.example/x", "&#x202e;"} {
		got := plain(s)
		low := strings.ToLower(got)
		for _, bad := range []string{"http:", "https:", "mailto:", "](", "<http", "<mallory", "@evil", "&#x"} {
			if strings.Contains(low, bad) {
				t.Errorf("plain(%q) = %q keeps %q", s, got, bad)
			}
		}
	}
	// Ordinary text stays as it was.
	for _, s := range []string{"/usr/lib/systemd/system/getty@tty1.service", "root@laptop", "a && b", "/etc/cron.d/backup"} {
		if got := plain(s); got != s {
			t.Errorf("plain(%q) = %q", s, got)
		}
	}
}

// fill queues more notes than there is room for while bubbles is down, so
// some are counted as not sent.
func (fx *fixture) fill(t *testing.T, prefix string, extra int) {
	t.Helper()
	fx.fake.SetDown(true)
	var fs []model.Finding
	for i := range MaxPending + extra {
		fs = append(fs, model.Finding{Key: fmt.Sprintf("%s%05d", prefix, i), Severity: model.SevNote, Title: "note"})
	}
	fx.b.Notify(t.Context(), machine, fs, nil)
	fx.fake.SetDown(false)
}

// The summary goes through the same path as other alerts: after the
// channel changed, the open summary is closed and a new one posted in the
// new channel, and an alert still open in the old channel moves.
func TestSummaryAndAlertsAfterChannelChange(t *testing.T) {
	fx := newFixture(t)
	fx.connect(t)
	fx.fake.SetChannels(protocol.PairingChannel{ID: "ch-alerts", Name: "telltale-alerts"}, protocol.PairingChannel{ID: "c2", Name: "ops"})
	open := model.Finding{Key: "heur.ld_preload", Severity: model.SevWeak, Title: "preload"}
	fx.b.Notify(t.Context(), machine, []model.Finding{open}, nil)
	fx.fill(t, "a", 2)
	if err := fx.b.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if ch, ok := fx.fake.Open(DroppedKey); !ok || ch != "ch-alerts" {
		t.Fatalf("first summary open in %q (%v)", ch, ok)
	}
	if _, err := fx.b.Channels(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := fx.b.SetChannel("c2"); err != nil {
		t.Fatal(err)
	}
	fx.fill(t, "b", 1)
	if err := fx.b.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if ch, ok := fx.fake.Open(DroppedKey); !ok || ch != "c2" {
		t.Errorf("new summary open in %q (%v), want the new channel", ch, ok)
	}
	if !slices.Contains(fx.fake.Resolves(), protocol.ResolveAlertByKeyRequest{DedupeKey: DroppedKey, Text: "A newer count follows."}) {
		t.Errorf("the old summary was not closed: %+v", fx.fake.Resolves())
	}
	if st, _ := fx.b.Status(); st.Dropped != 0 {
		t.Errorf("count kept after it went out: %d", st.Dropped)
	}
	// An alert open in the old channel that rises in severity moves.
	open.Severity = model.SevTampering
	fx.b.Notify(t.Context(), machine, []model.Finding{open}, nil)
	if ch, _ := fx.fake.Open(DedupeKey("web01", open.Key)); ch != "c2" {
		t.Errorf("escalated alert open in %q", ch)
	}
	if !slices.Contains(fx.fake.Resolves(), protocol.ResolveAlertByKeyRequest{DedupeKey: DedupeKey("web01", open.Key), Text: "Moved to #ops."}) {
		t.Errorf("not moved: %+v", fx.fake.Resolves())
	}
}

// A cancel or a disconnect that comes while the token is on its way wins:
// the token is not kept.
func TestPairingCancelWinsOverToken(t *testing.T) {
	for name, stop := range map[string]func(b *Bubbles){
		"cancel":     func(b *Bubbles) { b.CancelPairing(context.Background()) },
		"disconnect": func(b *Bubbles) { b.Disconnect() },
	} {
		t.Run(name, func(t *testing.T) {
			fx := newFixture(t)
			fx.b.afterWait = func() { stop(fx.b) }
			in, err := fx.b.Inspect(t.Context(), fx.fake.Address())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fx.b.StartPairing(t.Context(), in.ID); err != nil {
				t.Fatal(err)
			}
			fx.fake.Approve()
			fx.b.Wait()
			if raw, _ := fx.st.SecretSetting(SettingConn); len(raw) != 0 {
				t.Errorf("the token was kept after the %s", name)
			}
			if slices.Contains(auditActions(t, fx.st), "bubbles connected") {
				t.Error("audited as connected")
			}
		})
	}
}

// A request still waiting for the chat admin ends with Context, and Wait
// returns: the server's shutdown waits for it.
func TestPairingWaitEndsWithContext(t *testing.T) {
	fx := newFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	fx.b.Context = ctx
	in, err := fx.b.Inspect(t.Context(), fx.fake.Address())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fx.b.StartPairing(t.Context(), in.ID); err != nil {
		t.Fatal(err)
	}
	cancel()
	done := make(chan struct{})
	go func() {
		fx.b.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Wait did not return after Context ended")
	}
}

// Pairing again with the server telltale is connected to names the app it
// was paired as, so the chat admin reconnects it instead of adding another.
func TestRepairingReplacesApp(t *testing.T) {
	fx := newFixture(t)
	pair := func(addr string) {
		t.Helper()
		in, err := fx.b.Inspect(t.Context(), addr)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fx.b.StartPairing(t.Context(), in.ID); err != nil {
			t.Fatal(err)
		}
	}
	pair(fx.fake.Address())
	if r := fx.fake.Request(); r.ReplacesAppID != "" {
		t.Errorf("first pairing names app %q", r.ReplacesAppID)
	}
	fx.fake.Approve()
	waitFor(t, "the approval", func() bool { return fx.b.PairStatus().State == PairApproved })
	var rec channelRecord
	if err := fx.b.loadSealed(SettingChannel, &rec); err != nil || rec.AppID != bubblestest.AppID {
		t.Fatalf("app id kept %q, %v", rec.AppID, err)
	}
	fx.fake.ResetPairing()
	pair(fx.fake.Address())
	if r := fx.fake.Request(); r == nil || r.ReplacesAppID != bubblestest.AppID {
		t.Errorf("second pairing with the same server: %+v", r)
	}
	other := bubblestest.New(t)
	pair(other.Address())
	if r := other.Request(); r == nil || r.ReplacesAppID != "" {
		t.Errorf("pairing with another server names this one's app: %+v", r)
	}
}

// A persistence finding whose only evidence is the judge's summary (a
// change of mode or owner, or evidence cut short) never shows the
// summary's hash as a line.
func TestPersistSummaryNeverALine(t *testing.T) {
	fx := newFixture(t)
	fx.connect(t)
	h := sum("new content")
	f := model.Finding{Key: "snap.persist:/etc/cron.d/job", Severity: model.SevBackdoor, Title: "cron",
		Evidence: []model.Evidence{{Path: "/etc/cron.d/job", Line: 2, Before: sum("old"), After: h, Detail: "mode or owner changed"}}}
	if err := fx.b.Notify(t.Context(), machine, []model.Finding{f}, nil); err != nil {
		t.Fatal(err)
	}
	text := fx.fake.Posts()[0].Text
	if strings.Contains(text, "line") || !strings.Contains(text, "Evidence in ") || !strings.Contains(text, mdText("mode or owner changed")) {
		t.Errorf("text:\n%s", text)
	}
}
