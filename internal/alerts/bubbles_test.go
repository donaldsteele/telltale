package alerts

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
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

func TestAlertMappingFields(t *testing.T) {
	fx := newFixture(t)
	fx.connect(t)
	cron := model.Finding{Key: "snap.persist:/etc/cron.d/job", Severity: model.SevBackdoor, Title: "New cron job /etc/cron.d/job",
		Why: "A new cron job runs as root every minute",
		Fix: "rm /etc/cron.d/job",
		Evidence: []model.Evidence{
			{Path: "/etc/cron.d/job", Line: 2, After: "* * * * * root /usr/local/bin/beacon\nSECOND LINE OF THE FILE", Detail: "new line"},
			{Path: "/etc/cron.d/other", Line: 1, After: "ANOTHER FILE LINE"},
		}}
	tamper := model.Finding{Key: "pkg.mismatch:/usr/bin/ls", Severity: model.SevTampering, Title: "/usr/bin/ls does not match its package",
		Why: "The program differs from the one Debian shipped", Fix: "apt-get install --reinstall coreutils",
		Evidence: []model.Evidence{{Path: "/usr/bin/ls", Before: "sha256:aaaa", After: "sha256:bbbb"}}}
	weak := model.Finding{Key: "chk.ssh_root_login", Severity: model.SevWeak, Title: "SSH root login is allowed",
		Why: "Anyone with the root password can log in", Evidence: []model.Evidence{{Path: "/etc/ssh/sshd_config", Line: 30, After: "PermitRootLogin yes"}}}
	note := model.Finding{Key: "snap.file_removed:/etc/motd", Severity: model.SevNote, Title: "A line was removed",
		Evidence: []model.Evidence{{Path: "/etc/profile.d/env.sh", Line: 4, Before: "export API_TOKEN=s3cr3t-value-123"}}}
	if err := fx.b.Notify(t.Context(), machine, []model.Finding{cron, tamper, weak, note}, nil); err != nil {
		t.Fatal(err)
	}
	posts := fx.fake.Posts()
	if len(posts) != 4 {
		t.Fatalf("got %d alerts, want one per finding", len(posts))
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
	}
	a := byKey["telltale:web01:snap.persist:/etc/cron.d/job"]
	if a.Severity != protocol.SeverityCritical || a.Title != "web01: New cron job /etc/cron.d/job" {
		t.Errorf("cron alert: severity %q title %q", a.Severity, a.Title)
	}
	for _, want := range []string{"A new cron job runs as root every minute", "* * * * * root /usr/local/bin/beacon", "Fix:\n```\nrm /etc/cron.d/job\n```"} {
		if !strings.Contains(a.Text, want) {
			t.Errorf("cron alert text has no %q:\n%s", want, a.Text)
		}
	}
	// Only the one changed line: nothing more of that file, nothing of
	// another evidence item.
	for _, never := range []string{"SECOND LINE OF THE FILE", "ANOTHER FILE LINE"} {
		if strings.Contains(a.Text, never) {
			t.Errorf("cron alert text carries more file content (%q):\n%s", never, a.Text)
		}
	}
	wantFields := []protocol.AlertField{{Name: "Machine", Value: "web01", Short: true}, {Name: "Address", Value: "192.0.2.7", Short: true},
		{Name: "Severity", Value: "backdoor sign", Short: true}, {Name: "Path", Value: "/etc/cron.d/job"}}
	if !slices.Equal(a.Fields, wantFields) {
		t.Errorf("cron alert fields %+v, want %+v", a.Fields, wantFields)
	}
	if p := byKey["telltale:web01:pkg.mismatch:/usr/bin/ls"]; p.Severity != protocol.SeverityCritical {
		t.Errorf("tampering: severity %q", p.Severity)
	}
	if p := byKey["telltale:web01:chk.ssh_root_login"]; p.Severity != protocol.SeverityWarning || !strings.Contains(p.Text, "PermitRootLogin yes") || strings.Contains(p.Text, "Fix:") {
		t.Errorf("weak setting: severity %q text:\n%s", p.Severity, p.Text)
	}
	n := byKey["telltale:web01:snap.file_removed:/etc/motd"]
	if n.Severity != protocol.SeverityInfo {
		t.Errorf("note: severity %q", n.Severity)
	}
	// The line is kept text, redacted already; it is redacted once more.
	if strings.Contains(n.Text, "s3cr3t") || !strings.Contains(n.Text, "Removed line") || !strings.Contains(n.Text, "<redacted h:") {
		t.Errorf("note text:\n%s", n.Text)
	}
	for _, p := range posts {
		if len([]rune(p.Title)) > protocol.MaxAlertTitle || len([]rune(p.Text)) > protocol.MaxAlertText {
			t.Errorf("%s exceeds bubbles' limits", p.DedupeKey)
		}
	}
	if q := fx.queue(t); len(q.Items) != 0 {
		t.Errorf("%d alerts still queued after they were sent", len(q.Items))
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
	q := fx.queue(t)
	if len(q.Items) != MaxPending || q.Dropped != 5 || q.DroppedSeverity != protocol.SeverityCritical {
		t.Fatalf("queue: %d items, dropped %d (%q)", len(q.Items), q.Dropped, q.DroppedSeverity)
	}
	if q.Items[0].Key != DedupeKey("web01", "snap.file:/srv/f0005") {
		t.Errorf("the oldest kept is %q, want the sixth", q.Items[0].Key)
	}
	if st, _ := fx.b.Status(); st.Dropped != 5 || st.Pending != MaxPending {
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
	if sum.DedupeKey != DroppedKey || sum.Severity != protocol.SeverityCritical || !strings.Contains(sum.Title, "dropped 5 alerts") {
		t.Errorf("summary alert %+v", sum)
	}
	if posts[1].DedupeKey != DedupeKey("web01", "snap.file:/srv/f0005") || posts[MaxPending].DedupeKey != DedupeKey("web01", fmt.Sprintf("snap.file:/srv/f%04d", MaxPending+4)) {
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

func TestRunStopsOnShutdown(t *testing.T) {
	fx := newFixture(t)
	fx.connect(t)
	if err := fx.st.SetSetting(SettingAlertTimeout, "100ms"); err != nil {
		t.Fatal(err)
	}
	fx.b.retryEvery = 10 * time.Millisecond
	fx.fake.HangAll()
	// Queued without trying: the fake hangs and Notify would wait for it.
	if err := fx.b.enqueue([]pendingItem{{Key: "k", Alert: protocol.AlertInput{DedupeKey: "k", Title: "t", Severity: "info"}}}); err != nil {
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
		Evidence: []model.Evidence{{Path: "/etc/cron.d/" + hostile, Line: 1, After: "* * * * * root ``````" + hostile}},
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
	fences := model.Finding{Key: "snap.persist:/etc/cron.d/fences", Severity: model.SevTampering, Title: "fences",
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
