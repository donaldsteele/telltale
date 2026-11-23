// Package alerts sends server mode's findings to bubbles, the owner's
// self-hosted LAN chat, as alerts: one per finding, deduplicated by a key
// that names the machine and the finding, and resolved when the finding is
// gone. pairing.go connects to a bubbles server the way netdiag does.
//
// What a machine sent (host names, titles, paths, lines, fix commands) is
// escaped with escape.Terminal and then neutralised for the way bubbles
// shows it. bubbles shows an alert's title and fields as plain text on its
// alert card, and writes them into a Markdown body for clients without
// cards: there the title is escaped by bubbles but entities and links are
// not, and fields are escaped for a table cell only. So title and field
// values get no character reference that Markdown would decode, and no
// link: no http, https or mailto scheme, inline link, autolink or e-mail
// address (plain). The alert text is Markdown on the card too, with
// links, entities and @mentions: every machine string in it is either
// backslash-escaped character by character (mdText) or a line in a fenced
// code block (mdCode), where Markdown interprets nothing. An alert carries
// at most one line of a file: the changed line of the finding's evidence
// (or the line a check matched), which is kept text and so already
// redacted, and is redacted once more here. Other evidence (hashes,
// versions) is shown as evidence, never as a line.
//
// Alerts bubbles cannot take now wait, sealed, in the store (at most
// MaxPending; past that the least severe are left out, the oldest first
// among equals, and counted, and the count goes out as one summary alert
// with the next send). They are sent again after the next visit (Kick) and
// every RetryEvery (Run).
package alerts

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/donaldsteele/bubbles/pkg/bubblesclient"
	"github.com/donaldsteele/bubbles/pkg/protocol"

	"github.com/donaldsteele/telltale/internal/escape"
	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/redact"
	"github.com/donaldsteele/telltale/internal/store"
)

// Sealed settings. The connection string carries the app token: it is
// kept in SettingConn only, never logged, audited or shown.
const (
	SettingConn    = "bubbles_conn"
	SettingChannel = "bubbles_channel"
	SettingPending = "bubbles_pending"
	// SettingStatus is a small summary of the queue and the last trouble.
	SettingStatus = "bubbles_status"
	// SettingAlertTimeout is the server's alert_timeout setting
	// (server.SettingAlertTimeout; the server package imports this one).
	// It bounds every retry the way it bounds Notify.
	SettingAlertTimeout = "alert_timeout"
)

const (
	// AppName is the app name telltale pairs under.
	AppName = "telltale"
	// MaxPending bounds the alerts kept while bubbles cannot be reached.
	MaxPending = 1000
	// RetryEvery is how often Run tries the pending alerts again.
	RetryEvery = 5 * time.Minute
	// TestKey is the test alert's dedupe key.
	TestKey = "telltale:test"
	// DroppedKey is the dedupe key of the summary alert about alerts
	// dropped while bubbles could not be reached.
	DroppedKey = "telltale:dropped"

	defaultAlertTimeout = time.Minute
	// callTimeout bounds one call the owner waits for in the web UI.
	callTimeout = 20 * time.Second
	// kickGap: a Kick right after a failed try does not try again.
	kickGap = 30 * time.Second
	// saveEvery: a flush records its progress every so many alerts.
	saveEvery = 50
	// Bounds on the parts of an alert, before Markdown escaping (which at
	// most doubles them), so the text stays under protocol.MaxAlertText.
	maxWhy, maxWhere, maxLine, maxFix = 900, 150, 300, 900
)

// Scopes are the app token scopes telltale asks for: posting and resolving
// alerts, and listing its bot's channels to choose one.
var Scopes = []string{protocol.ScopeAlertsWrite, protocol.ScopeChannelsRead}

// Bubbles is the alert sink for bubbles (server.AlertSink), the pairing
// wizard's state and the retry loop. Set Store, then use it from any
// goroutine.
type Bubbles struct {
	Store *store.Store
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// Log is the server log; nil means the standard logger.
	Log *log.Logger
	// Context ends pairing requests still waiting for the chat admin; nil
	// means context.Background.
	Context context.Context
	// Hostname names this server to bubbles ("telltale server on ...");
	// "" means os.Hostname.
	Hostname string

	initOnce   sync.Once
	retryEvery time.Duration  // RetryEvery; tests shorten it
	qmu        sync.Mutex     // the pending queue in the store
	sending    chan struct{}  // held by the one flush that sends
	pairing    sync.WaitGroup // the goroutine waiting for the chat admin
	afterWait  func()         // tests: runs when a pairing request got its token
	kick       chan struct{}
	redactKey  []byte

	mu       sync.Mutex // the fields below
	trouble  Trouble
	since    time.Time
	lastTry  time.Time
	clConn   string // the connection string cl was made from
	cl       *bubblesclient.Client
	cands    map[string]candidate
	pair     *pairSession
	choices  []Channel // the bot's channels, as last listed
	choosing bool      // the owner asked to choose a channel again
}

func (b *Bubbles) init() {
	b.initOnce.Do(func() {
		if b.retryEvery == 0 {
			b.retryEvery = RetryEvery
		}
		b.sending = make(chan struct{}, 1)
		b.kick = make(chan struct{}, 1)
		b.redactKey = make([]byte, 32)
		if _, err := rand.Read(b.redactKey); err != nil {
			panic("telltale: no randomness: " + err.Error())
		}
		b.cands = map[string]candidate{}
	})
}

func (b *Bubbles) now() time.Time {
	if b.Now != nil {
		return b.Now()
	}
	return time.Now()
}

func (b *Bubbles) logf(format string, args ...any) {
	if b.Log != nil {
		b.Log.Printf(format, args...)
		return
	}
	log.Printf(format, args...)
}

func (b *Bubbles) baseContext() context.Context {
	if b.Context != nil {
		return b.Context
	}
	return context.Background()
}

func (b *Bubbles) hostname() string {
	if b.Hostname != "" {
		return b.Hostname
	}
	h, _ := os.Hostname()
	return strings.TrimSpace(h)
}

func (b *Bubbles) audit(action string) {
	if err := b.Store.Audit("server", action, ""); err != nil {
		b.logf("telltale server: could not write %q to the audit log: %v", action, err)
	}
}

// alertTimeout is the alert_timeout setting: 60 seconds when unset or
// unreadable.
func (b *Bubbles) alertTimeout() time.Duration {
	v, _ := b.Store.Setting(SettingAlertTimeout)
	if d, err := time.ParseDuration(v); err == nil && d > 0 {
		return d
	}
	return defaultAlertTimeout
}

// Channel is a bubbles channel telltale's bot is in.
type Channel struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// channelRecord is SettingChannel: where alerts go, and the server's name
// as bubbles gave it.
type channelRecord struct {
	Channel
	Server string `json:"server,omitempty"`
	// AppID is the app telltale was paired as, for ReplacesAppID.
	AppID string `json:"app_id,omitempty"`
}

func (b *Bubbles) loadSealed(key string, v any) error {
	raw, err := b.Store.SecretSetting(key)
	if err != nil || len(raw) == 0 {
		return err
	}
	return json.Unmarshal(raw, v)
}

func (b *Bubbles) saveSealed(key string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return b.Store.SetSecretSetting(key, raw)
}

// connection reads SettingConn; ok is false when telltale is not paired.
func (b *Bubbles) connection() (cfg bubblesclient.Config, raw string, ok bool, err error) {
	v, err := b.Store.SecretSetting(SettingConn)
	if err != nil || len(v) == 0 {
		return bubblesclient.Config{}, "", false, err
	}
	cfg, err = bubblesclient.ParseConnectionString(string(v))
	if err != nil {
		// The parser's message never holds the token.
		return bubblesclient.Config{}, "", false, fmt.Errorf("alerts: the stored bubbles connection cannot be read: %w", err)
	}
	return cfg, string(v), true, nil
}

// client is the bubbles client for the stored connection, or nil when
// telltale is not paired, and where alerts go.
func (b *Bubbles) client() (*bubblesclient.Client, channelRecord, error) {
	cfg, raw, ok, err := b.connection()
	if err != nil || !ok {
		return nil, channelRecord{}, err
	}
	var ch channelRecord
	if err := b.loadSealed(SettingChannel, &ch); err != nil {
		return nil, channelRecord{}, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cl == nil || b.clConn != raw {
		cl, err := bubblesclient.New(cfg)
		if err != nil {
			return nil, channelRecord{}, fmt.Errorf("alerts: the stored bubbles connection cannot be used: %w", err)
		}
		b.cl, b.clConn = cl, raw
	}
	return b.cl, ch, nil
}

// Connected reports whether telltale is paired with a bubbles server.
func (b *Bubbles) Connected() (bool, error) {
	_, _, ok, err := b.connection()
	return ok, err
}

// DedupeKey is the alert key of a finding on a machine:
// "telltale:<machine>:<finding key>". A key bubbles would refuse as too
// long (or one holding bytes that are not text) is shortened, stably, to
// "telltale:<machine>:h:<the first 32 hex digits of its SHA-256>".
func DedupeKey(machine, findingKey string) string {
	k := "telltale:" + escape.Terminal(machine) + ":" + findingKey
	if utf8.RuneCountInString(k) <= protocol.MaxAlertDedupeKey && !escape.HasUnsafe(findingKey) && utf8.ValidString(findingKey) {
		return k
	}
	sum := sha256.Sum256([]byte(findingKey))
	return "telltale:" + escape.Terminal(machine) + ":h:" + hex.EncodeToString(sum[:16])
}

// Severity is a finding's alert severity: critical for tampering and
// backdoor signs, warning for a weak setting, info for a note.
func Severity(s model.Severity) string {
	switch {
	case s >= model.SevBackdoor:
		return protocol.SeverityCritical
	case s == model.SevWeak:
		return protocol.SeverityWarning
	}
	return protocol.SeverityInfo
}

func severityRank(s string) int {
	switch s {
	case protocol.SeverityCritical:
		return 2
	case protocol.SeverityWarning:
		return 1
	}
	return 0
}

var (
	// entityRE is a Markdown character reference ("&#x202e;", "&amp;"),
	// which would decode to a character the text never showed.
	entityRE = regexp.MustCompile(`&(#[0-9]{1,8}|#[xX][0-9a-fA-F]{1,8}|[A-Za-z][A-Za-z0-9]{0,31});`)
	// schemeRE is "scheme://" and linkRE the schemes a Markdown link
	// destination or a linkifier accepts, with or without "//"
	// ("http:evil.example" is a link too).
	schemeRE = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.\-]*):(//)`)
	linkRE   = regexp.MustCompile(`(?i)(https?|mailto):`)
	// inlineLinkRE is the "](" of an inline link or image, autolinkRE an
	// autolink ("<scheme:...>", "<user@host>"), emailRE an address a
	// linkifier turns into a mailto link.
	inlineLinkRE = regexp.MustCompile(`\]\(`)
	autolinkRE   = regexp.MustCompile(`<([A-Za-z][A-Za-z0-9+.\-]{1,31}:[^<>\s]*|[^<>\s@]+@[^<>\s]+)>`)
	emailRE      = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)+`)
	// unitSuffix are systemd unit types: "getty@tty1.service" is a unit.
	unitSuffix = map[string]bool{"service": true, "socket": true, "timer": true, "target": true, "mount": true, "automount": true,
		"path": true, "slice": true, "scope": true, "device": true, "swap": true}
)

// plain makes a machine string safe for the alert's title and field
// values, which bubbles shows as plain text on its card and writes into a
// Markdown body for other clients: escape.Terminal, then no character
// reference (its & is written \x26, as escape.Terminal writes bytes it
// hides), no link scheme ("https://" and "http:" are written "https[:]//"
// and "http[:]", the usual way to defang an address), no inline link or
// autolink ("](" and "<" are written "]\x28" and "\x3c"), and no e-mail
// address ("a[@]b.example").
func plain(s string) string {
	s = escape.Terminal(s)
	s = entityRE.ReplaceAllStringFunc(s, func(m string) string { return `\x26` + m[1:] })
	s = autolinkRE.ReplaceAllStringFunc(s, func(m string) string { return `\x3c` + m[1:] })
	s = schemeRE.ReplaceAllString(s, "${1}[:]${2}")
	s = linkRE.ReplaceAllString(s, "${1}[:]")
	s = inlineLinkRE.ReplaceAllString(s, `]\x28`)
	return emailRE.ReplaceAllStringFunc(s, func(m string) string {
		at := strings.LastIndexByte(m, 0x40)
		if unitSuffix[strings.ToLower(m[strings.LastIndexByte(m, 0x2e)+1:])] {
			return m // a systemd template unit, not an address
		}
		return m[:at] + "[@]" + m[at+1:]
	})
}

const asciiPunct = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"

// mdText writes a machine string as literal Markdown text:
// escape.Terminal, then every ASCII punctuation character backslash-
// escaped, so nothing in it is emphasis, a link, an image, an entity, an
// autolink or a mention.
func mdText(s string) string {
	s = strings.TrimSpace(escape.Terminal(s))
	var b strings.Builder
	for _, r := range s {
		if r < utf8.RuneSelf && strings.ContainsRune(asciiPunct, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// mdCode writes a machine string as the one line of a fenced code block,
// where Markdown interprets nothing. escape.Terminal leaves no line break,
// and the fence is longer than any run of backticks in the line, so the
// line cannot close it.
func mdCode(s string) string {
	s = escape.Terminal(s)
	run, longest := 0, 0
	for i := 0; i < len(s); i++ {
		if s[i] == '`' {
			run++
			longest = max(longest, run)
		} else {
			run = 0
		}
	}
	fence := strings.Repeat("`", max(3, longest+1))
	return fence + "\n" + s + "\n" + fence
}

// truncate cuts s to at most n runes, marking a cut with "…".
func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(s, "\n")
	return l
}

// The kinds of evidence an alert can show.
const (
	evidenceChange = iota // a line added to or removed from a file
	evidenceLine          // a line of a file a heuristic matched
	evidenceOther         // anything else: hashes, versions, a summary
)

// alertEvidence picks the one piece of evidence an alert shows, what it
// is, and, for a changed line, how many other changed lines the finding
// has. A changed line comes first: the first change, in the judge's order,
// of the evidence it marks "line added" or "line removed". The one
// exception is a replaced line, a removed line with lines added in its
// place (after the rest of its block of removed lines, see replacement):
// then the added one is shown, the line the machine has now. Taking the first change in order means a harmless second change (a
// comment added further down) cannot stand in for the one that matters. A
// snapshot finding about a persistence file starts with a summary of the
// file (its After is the file's hash, its Line the first changed line),
// which is never shown as a line. Then a line a check matched in a file (a
// line number and its text). Anything else is shown as evidence, not as a
// line. Only the first line of any text is used.
func alertEvidence(f model.Finding) (e model.Evidence, kind, others int, ok bool) {
	evs := f.Evidence
	var summary *model.Evidence
	if strings.HasPrefix(f.Key, "snap.persist:") && len(evs) > 0 {
		summary, evs = &evs[0], evs[1:]
	}
	var lines, changes []model.Evidence
	firstAt := -1 // the first change's place in lines
	more := 0
	for _, x := range evs {
		if x.Detail == "line added" || x.Detail == "line removed" {
			lines = append(lines, x)
		}
		if (x.Detail == "line added" && x.After != "") || (x.Detail == "line removed" && x.Before != "") {
			if firstAt < 0 {
				firstAt = len(lines) - 1
			}
			changes = append(changes, x)
		} else if m := moreRE.FindStringSubmatch(x.Detail); m != nil && x.Path == "" && x.Before == "" && x.After == "" {
			more, _ = strconv.Atoi(m[1]) // the judge's "and N more" after the evidence it kept
		}
	}
	if len(changes) > 0 {
		first, shown := changes[0], 1
		if added, ok := replacement(lines, firstAt); ok {
			first, shown = added, 2
		}
		return first, evidenceChange, len(changes) - shown + more, true
	}
	if summary == nil {
		for _, x := range evs {
			if x.Line > 0 && x.After != "" {
				return x, evidenceLine, 0, true
			}
		}
	}
	if summary != nil {
		return *summary, evidenceOther, 0, true
	}
	for _, x := range evs {
		if x.After != "" || x.Before != "" || x.Detail != "" {
			return x, evidenceOther, 0, true
		}
	}
	return model.Evidence{}, 0, 0, false
}

// replacement reports the line added in place of a removed line, the first
// change: lines[at]. The judge lists a replaced block as every removed line
// and then every added one (removed lines 2 and 3, then added lines 2 and
// 3), numbering removed lines in the old file and added lines in the new
// one. So the removed line was replaced when its block of removed lines,
// one after another in the same file, is followed by a block of lines added
// in that file from the same line number on. The line shown is the first
// added line that is not blank.
func replacement(lines []model.Evidence, at int) (model.Evidence, bool) {
	if at < 0 || lines[at].Detail != "line removed" {
		return model.Evidence{}, false
	}
	next := func(i int) bool { // lines[i] directly follows lines[i-1] in one block
		a, b := lines[i-1], lines[i]
		return b.Path == a.Path && b.Detail == a.Detail && b.Line == a.Line+1
	}
	start := at // blank removed lines may come first
	for start > 0 && next(start) {
		start--
	}
	i := at + 1
	for i < len(lines) && next(i) {
		i++
	}
	if i == len(lines) || lines[i].Detail != "line added" || lines[i].Path != lines[start].Path || lines[i].Line != lines[start].Line {
		return model.Evidence{}, false
	}
	for ; i < len(lines); i++ {
		if lines[i].After != "" {
			return lines[i], true
		}
		if i+1 < len(lines) && !next(i+1) {
			break
		}
	}
	return model.Evidence{}, false
}

// moreRE is the evidence the judge adds when it kept only some of a
// finding's evidence.
var moreRE = regexp.MustCompile(`^and ([0-9]{1,9}) more$`)

func where(e model.Evidence) string {
	w := e.Path
	if e.Line > 0 && w != "" {
		w += ":" + strconv.Itoa(e.Line)
	}
	return w
}

// evidenceText is the alert text's evidence part. A file's content is at
// most one line: the changed or matched line, kept text the collector
// redacted, redacted once more here.
func (b *Bubbles) evidenceText(f model.Finding) string {
	e, kind, others, ok := alertEvidence(f)
	if !ok {
		return ""
	}
	in := ""
	if w := where(e); w != "" {
		in = " in " + mdText(truncate(escape.Terminal(w), maxWhere))
	}
	code := func(s string) string {
		s, _ = redact.Line(b.redactKey, firstLine(s))
		return mdCode(truncate(escape.Terminal(s), maxLine))
	}
	switch kind {
	case evidenceChange:
		t := "Changed line" + in + ":\n" + code(e.After)
		if e.Detail == "line removed" {
			t = "Removed line" + in + ":\n" + code(e.Before)
		}
		switch {
		case others == 1:
			t += "\n" + mdText("1 other changed line is in telltale's web UI.")
		case others > 1:
			t += "\n" + mdText(strconv.Itoa(others)+" other changed lines are in telltale's web UI.")
		}
		return t
	case evidenceLine:
		return "Line" + in + ":\n" + code(e.After)
	}
	label := "Evidence" + in + ":"
	if e.Detail != "" {
		label += "\n" + mdText(truncate(escape.Terminal(firstLine(e.Detail)), maxWhere))
	}
	before, after := firstLine(e.Before), firstLine(e.After)
	switch {
	case before != "" && after != "":
		return label + "\n" + code(before+" -> "+after)
	case after != "":
		return label + "\n" + code(after)
	case before != "":
		return label + "\n" + code(before+" -> (gone)")
	}
	return label
}

func evidencePath(f model.Finding) string {
	for _, e := range f.Evidence {
		if e.Path != "" {
			return e.Path
		}
	}
	return ""
}

// alertFor maps a finding to its alert (channel left empty: it is set when
// the alert is sent, so a channel chosen later applies).
func (b *Bubbles) alertFor(m store.Machine, f model.Finding, now time.Time) protocol.AlertInput {
	zero := 0
	at := now.UTC().Format(time.RFC3339)
	var why, changed, fix string
	if w := truncate(escape.Terminal(f.Why), maxWhy); w != "" {
		why = mdText(w)
	}
	changed = b.evidenceText(f)
	if f.Fix != "" {
		cmd := truncate(escape.Terminal(f.Fix), maxFix)
		if escape.HasUnsafe(f.Fix) {
			cmd += "   (contains control characters; do not paste, edit by hand)"
		}
		fix = "Fix:\n" + mdCode(cmd)
	}
	in := protocol.AlertInput{
		Severity:       Severity(f.Severity),
		Title:          truncate(plain(m.Name)+": "+plain(f.Title), protocol.MaxAlertTitle),
		Text:           alertText(why, changed, fix),
		DedupeKey:      DedupeKey(m.Name, f.Key),
		RenotifyAfterS: &zero,
		OccurredAt:     &at,
	}
	field := func(name, value string, short bool) {
		if value != "" {
			in.Fields = append(in.Fields, protocol.AlertField{Name: name, Value: truncate(value, protocol.MaxAlertFieldValue), Short: short})
		}
	}
	field("Machine", plain(m.Name), true)
	field("Address", plain(m.Addr), true)
	field("Severity", f.Severity.String(), true)
	field("Path", plain(evidencePath(f)), false)
	return in
}

// alertText joins the parts of an alert's text. A code block's fence grows
// with the backticks its line holds, so the parts can be longer than
// bubbles takes, and bubbles would refuse the whole alert: then the why
// goes first, then the fix, then the changed line, and the text says where
// the rest is. Cutting a part instead could leave a fence open.
func alertText(why, changed, fix string) string {
	join := func(parts ...string) string {
		var keep []string
		for _, p := range parts {
			if p != "" {
				keep = append(keep, p)
			}
		}
		return strings.Join(keep, "\n\n")
	}
	const note = "Some of this finding is too long for an alert: see telltale's web UI."
	for _, t := range []string{join(why, changed, fix), join(changed, fix, note), join(changed, note)} {
		if utf8.RuneCountInString(t) <= protocol.MaxAlertText {
			return t
		}
	}
	return note
}

// pendingItem is one alert or resolve waiting to be sent. Alert's channel
// is set when it is sent. Severity orders what is dropped when the queue
// is full: for a resolve it is the resolved finding's.
type pendingItem struct {
	ID       uint64               `json:"id"`
	Key      string               `json:"key"`
	Severity string               `json:"severity"`
	Resolve  bool                 `json:"resolve,omitempty"`
	Note     string               `json:"note,omitempty"`
	Alert    *protocol.AlertInput `json:"alert,omitempty"`
	Queued   time.Time            `json:"queued"`
}

// pendingQueue is SettingPending: at most MaxPending items, one per
// dedupe key, oldest first, and how many were dropped since the last
// summary alert (with the highest severity among them).
type pendingQueue struct {
	Next            uint64        `json:"next"`
	Items           []pendingItem `json:"items"`
	Dropped         int           `json:"dropped,omitempty"`
	DroppedSeverity string        `json:"dropped_severity,omitempty"`
}

// queueStatus is SettingStatus: a small summary of the queue and of the
// last trouble, kept beside it, so the settings pages never read the whole
// queue.
type queueStatus struct {
	Pending         int       `json:"pending"`
	Critical        int       `json:"critical,omitempty"`
	Warning         int       `json:"warning,omitempty"`
	Info            int       `json:"info,omitempty"`
	Dropped         int       `json:"dropped,omitempty"`
	DroppedSeverity string    `json:"dropped_severity,omitempty"`
	Trouble         Trouble   `json:"trouble,omitempty"`
	Since           time.Time `json:"since,omitzero"`
}

// sealCompact stores v sealed, as JSON without the HTML escaping that
// would write each "<", ">" and "&" of an alert's text as six bytes.
func (b *Bubbles) sealCompact(key string, v any) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return err
	}
	return b.Store.SetSecretSetting(key, bytes.TrimSuffix(buf.Bytes(), []byte("\n")))
}

func (b *Bubbles) loadQueue() (pendingQueue, error) {
	var q pendingQueue
	err := b.loadSealed(SettingPending, &q)
	return q, err
}

func (b *Bubbles) loadStatus() (queueStatus, error) {
	var st queueStatus
	err := b.loadSealed(SettingStatus, &st)
	return st, err
}

// updateQueue changes the stored queue, and its summary, under qmu.
func (b *Bubbles) updateQueue(f func(q *pendingQueue)) error {
	b.qmu.Lock()
	defer b.qmu.Unlock()
	q, err := b.loadQueue()
	if err != nil {
		return err
	}
	f(&q)
	if err := b.sealCompact(SettingPending, q); err != nil {
		return err
	}
	st, err := b.loadStatus()
	if err != nil {
		return err
	}
	st.Pending, st.Critical, st.Warning, st.Info = len(q.Items), 0, 0, 0
	for _, it := range q.Items {
		switch itemSeverity(it) {
		case protocol.SeverityCritical:
			st.Critical++
		case protocol.SeverityWarning:
			st.Warning++
		default:
			st.Info++
		}
	}
	st.Dropped, st.DroppedSeverity = q.Dropped, q.DroppedSeverity
	return b.sealCompact(SettingStatus, st)
}

func itemSeverity(it pendingItem) string {
	if it.Severity == "" && it.Alert != nil {
		return it.Alert.Severity
	}
	return it.Severity
}

// queued is an alert or resolve offered to the queue. Its item, with the
// alert's text, is built only when the queue keeps it.
type queued struct {
	key      string
	severity string
	build    func() pendingItem
}

// enqueue adds alerts and resolves to the queue, in time linear in the
// queue and the offer. A newer offer for a dedupe key replaces the item
// waiting for it: only the latest state of an alert matters (a resolve of
// an alert that never went out is one bubbles ignores). When more than
// MaxPending would wait, the least severe go first, the oldest first among
// equals, so a critical alert is never dropped for a less severe one; only
// when critical alerts alone fill the queue does the oldest of them go.
// What is dropped is counted, for the summary alert.
func (b *Bubbles) enqueue(offers []queued) error {
	return b.updateQueue(func(q *pendingQueue) {
		last := make(map[string]int, len(offers))
		for i, o := range offers {
			last[o.key] = i
		}
		var count [3]int
		kept := q.Items[:0]
		for _, x := range q.Items {
			if _, replaced := last[x.Key]; !replaced {
				kept = append(kept, x)
				count[severityRank(itemSeverity(x))]++
			}
		}
		q.Items = kept
		fresh := make([]queued, 0, len(last))
		for i, o := range offers {
			if last[o.key] == i {
				fresh = append(fresh, o)
				count[severityRank(o.severity)]++
			}
		}
		var drop [3]int
		over := len(q.Items) + len(fresh) - MaxPending
		for r := 0; r < len(drop) && over > 0; r++ {
			drop[r] = min(count[r], over)
			over -= drop[r]
		}
		dropped := func(sev string) {
			q.Dropped++
			if severityRank(sev) >= severityRank(q.DroppedSeverity) {
				q.DroppedSeverity = sev
			}
		}
		// The items waiting are older than the offers: they go first.
		kept = q.Items[:0]
		for _, x := range q.Items {
			if r := severityRank(itemSeverity(x)); drop[r] > 0 {
				drop[r]--
				dropped(itemSeverity(x))
				continue
			}
			kept = append(kept, x)
		}
		q.Items = kept
		for _, o := range fresh {
			if r := severityRank(o.severity); drop[r] > 0 {
				drop[r]--
				dropped(o.severity)
				continue
			}
			it := o.build()
			q.Next++
			it.ID = q.Next
			q.Items = append(q.Items, it)
		}
	})
}

// Notify queues an alert for each new finding and a resolve for each
// resolved one, then sends what is queued, within ctx. It returns nil once
// the alerts are queued: those bubbles cannot take now stay in the store
// and are sent again later (Run, Kick). It does nothing when telltale is
// not paired with bubbles.
func (b *Bubbles) Notify(ctx context.Context, m store.Machine, newFindings, resolved []model.Finding) error {
	b.init()
	if err := ctx.Err(); err != nil {
		return err
	}
	if ok, err := b.Connected(); err != nil || !ok {
		return err
	}
	now := b.now()
	offers := make([]queued, 0, len(newFindings)+len(resolved))
	for _, f := range newFindings {
		key, sev := DedupeKey(m.Name, f.Key), Severity(f.Severity)
		offers = append(offers, queued{key: key, severity: sev, build: func() pendingItem {
			in := b.alertFor(m, f, now)
			return pendingItem{Key: key, Severity: sev, Alert: &in, Queued: now}
		}})
	}
	note := "No longer found on " + now.UTC().Format("2006-01-02 15:04 UTC") + "."
	for _, f := range resolved {
		key, sev := DedupeKey(m.Name, f.Key), Severity(f.Severity)
		offers = append(offers, queued{key: key, severity: sev, build: func() pendingItem {
			return pendingItem{Key: key, Severity: sev, Resolve: true, Note: note, Queued: now}
		}})
	}
	if len(offers) == 0 {
		return nil
	}
	if err := b.enqueue(offers); err != nil {
		return err
	}
	if err := b.Flush(ctx); err != nil && !errors.Is(err, ErrNoChannel) {
		b.logf("telltale server: bubbles alerts for machine %d are queued and will be sent later: %s", m.ID, escape.Terminal(err.Error()))
	}
	return nil
}

// ErrNoChannel means no channel for alerts was chosen yet; alerts wait.
var ErrNoChannel = errors.New("alerts: no bubbles channel chosen for alerts yet")

// outcome is what a send's error means for the item.
type outcome int

const (
	sent    outcome = iota // done: take it off the queue
	dropped                // bubbles refused it for good: take it off
	keep                   // try again later; stop for now
)

// classify reads a send's error, and records what it says about the
// connection (Trouble). A resolve bubbles answers 404 or 403 to has no
// alert of telltale's to close, so it is done; a post answered so cannot
// go to the channel, so it waits for another channel.
func (b *Bubbles) classify(err error, resolve bool) outcome {
	var ae *bubblesclient.APIError
	switch {
	case err == nil:
		b.setTrouble(TroubleNone)
		return sent
	case errors.Is(err, context.Canceled):
		// Says nothing about bubbles: the caller stopped waiting.
		return keep
	case errors.Is(err, context.DeadlineExceeded):
		b.setTrouble(TroubleUnreachable)
		return keep
	case errors.Is(err, bubblesclient.ErrServerIdentityChanged):
		b.setTrouble(TroubleIdentityChanged)
		return keep
	case errors.Is(err, bubblesclient.ErrUnauthorized):
		b.setTrouble(TroubleNeedsReconnect)
		return keep
	case errors.Is(err, bubblesclient.ErrRateLimited), errors.Is(err, bubblesclient.ErrUnavailable):
		b.setTrouble(TroubleUnreachable)
		return keep
	case errors.As(err, &ae):
		switch {
		case ae.Status == http.StatusNotFound || ae.Status == http.StatusForbidden:
			if resolve {
				b.setTrouble(TroubleNone)
				return sent
			}
			b.setTrouble(TroubleNotAllowed)
			return keep
		case ae.Status == http.StatusConflict && archived(ae) && !resolve:
			b.setTrouble(TroubleArchived)
			return keep
		}
		b.setTrouble(TroubleNone)
		b.logf("telltale server: bubbles turned down an alert, which is dropped: %s", refusal(ae))
		return dropped
	}
	b.logf("telltale server: an alert could not be sent to bubbles and is dropped: %s", escape.Terminal(err.Error()))
	return dropped
}

// archived is bubbles' 409 for an archived channel; its other 409 is a
// key whose alert is open in another channel.
func archived(ae *bubblesclient.APIError) bool { return strings.Contains(ae.Message, "archived") }

func openElsewhere(err error) bool {
	var ae *bubblesclient.APIError
	return errors.As(err, &ae) && ae.Status == http.StatusConflict && !archived(ae)
}

// refusal is what bubbles said when it refused a request, for the log.
func refusal(ae *bubblesclient.APIError) string {
	s := fmt.Sprintf("%d %s", ae.Status, ae.Message)
	for k, v := range ae.FieldErrors() {
		s += "; " + k + ": " + v
	}
	return escape.Terminal(s)
}

// send posts or resolves one item. A post whose key is still open in
// another channel (the channel was changed) closes it there and posts
// again, as netdiag does.
func send(ctx context.Context, cl *bubblesclient.Client, ch channelRecord, it pendingItem) error {
	if it.Resolve || it.Alert == nil {
		return cl.ResolveAlert(ctx, it.Key, it.Note)
	}
	in := *it.Alert
	in.Channel = ch.ID
	_, err := cl.PostAlert(ctx, in)
	if openElsewhere(err) && cl.ResolveAlert(ctx, it.Key, "Moved to #"+escape.Terminal(ch.Name)+".") == nil {
		_, err = cl.PostAlert(ctx, in)
	}
	return err
}

// droppedAlert is the summary of n alerts the queue had no room for. The
// queue drops the least severe first, so they are lower-priority than
// every alert kept, unless critical alerts alone filled it.
func droppedAlert(n int, sev string, now time.Time) protocol.AlertInput {
	if sev == "" {
		sev = protocol.SeverityInfo
	}
	zero := 0
	at := now.UTC().Format(time.RFC3339)
	what := "1 lower-priority alert was"
	if n != 1 {
		what = strconv.Itoa(n) + " lower-priority alerts were"
	}
	if sev == protocol.SeverityCritical {
		what = "1 alert was"
		if n != 1 {
			what = strconv.Itoa(n) + " alerts were"
		}
	}
	return protocol.AlertInput{
		Severity: sev,
		Title:    "telltale: " + what + " not sent because the queue was full",
		Text: fmt.Sprintf("telltale keeps at most %d alerts waiting to be sent. When more wait, the least severe are not sent, the oldest first. "+
			"Open telltale's web UI to see every machine's findings.", MaxPending),
		Fields:         []protocol.AlertField{{Name: "Not sent", Value: strconv.Itoa(n), Short: true}},
		DedupeKey:      DroppedKey,
		RenotifyAfterS: &zero,
		OccurredAt:     &at,
	}
}

// Flush sends the queued alerts in order, until none are left, bubbles
// cannot take more, or ctx ends. The count of alerts the queue had no room
// for goes first, as one summary alert; the summary sent before is closed
// first, so each count is an alert of its own. Only one flush sends at a
// time; another waits for it within its ctx. Not being paired is not an
// error; having no channel yet is ErrNoChannel.
func (b *Bubbles) Flush(ctx context.Context) error {
	b.init()
	select {
	case b.sending <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-b.sending }()
	b.mu.Lock()
	b.lastTry = b.now()
	b.mu.Unlock()
	cl, ch, err := b.client()
	if err != nil || cl == nil {
		return err
	}
	if ch.ID == "" {
		b.setTrouble(TroubleNoChannel)
		return ErrNoChannel
	}
	st, err := b.loadStatus()
	if err != nil {
		return err
	}
	if st.Dropped > 0 {
		n := st.Dropped
		err := cl.ResolveAlert(ctx, DroppedKey, "A newer count follows.")
		if b.classify(err, true) == keep {
			return err
		}
		sum := droppedAlert(n, st.DroppedSeverity, b.now())
		err = send(ctx, cl, ch, pendingItem{Key: DroppedKey, Alert: &sum})
		if b.classify(err, false) == keep {
			return err
		}
		if err := b.updateQueue(func(q *pendingQueue) {
			if q.Dropped -= n; q.Dropped <= 0 {
				q.Dropped, q.DroppedSeverity = 0, ""
			}
		}); err != nil {
			return err
		}
	}
	var after uint64 // items up to this ID were tried in this flush
	for {
		q, err := b.loadQueue()
		if err != nil {
			return err
		}
		var batch []pendingItem
		for _, it := range q.Items {
			if it.ID > after {
				batch = append(batch, it)
			}
		}
		if len(batch) == 0 {
			return nil
		}
		done := map[uint64]bool{}
		save := func() error {
			if len(done) == 0 {
				return nil
			}
			err := b.updateQueue(func(q *pendingQueue) {
				kept := q.Items[:0]
				for _, x := range q.Items {
					if !done[x.ID] {
						kept = append(kept, x)
					}
				}
				q.Items = kept
			})
			clear(done)
			return err
		}
		for _, it := range batch {
			if err := ctx.Err(); err != nil {
				return errors.Join(err, save())
			}
			err := send(ctx, cl, ch, it)
			if b.classify(err, it.Resolve) == keep {
				return errors.Join(err, save())
			}
			done[it.ID] = true
			after = it.ID
			if len(done) >= saveEvery {
				if err := save(); err != nil {
					return err
				}
			}
		}
		if err := save(); err != nil {
			return err
		}
	}
}

// TryNow sends the queued alerts at once, within the alert_timeout
// setting (the settings page's Try now).
func (b *Bubbles) TryNow(ctx context.Context) error {
	b.init()
	ctx, cancel := context.WithTimeout(ctx, b.alertTimeout())
	defer cancel()
	return b.Flush(ctx)
}

// Kick asks Run to try the queued alerts now (the core calls it after
// every visit). It never blocks.
func (b *Bubbles) Kick() {
	b.init()
	select {
	case b.kick <- struct{}{}:
	default:
	}
}

// Run tries the queued alerts again every RetryEvery and after every
// Kick, each try bounded by the alert_timeout setting, until ctx ends. The
// server command runs it for as long as the server runs.
func (b *Bubbles) Run(ctx context.Context) {
	b.init()
	t := time.NewTicker(b.retryEvery)
	defer t.Stop()
	for {
		kicked := false
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-b.kick:
			kicked = true
		}
		b.retry(ctx, kicked)
	}
}

// retry is one try of Run: nothing when nothing waits, and nothing for a
// Kick right after a try that failed.
func (b *Bubbles) retry(ctx context.Context, kicked bool) {
	if st, err := b.loadStatus(); err != nil || (st.Pending == 0 && st.Dropped == 0) {
		return
	}
	b.mu.Lock()
	recent := b.trouble != TroubleNone && b.now().Sub(b.lastTry) < kickGap
	b.mu.Unlock()
	if kicked && recent {
		return
	}
	rctx, cancel := context.WithTimeout(ctx, b.alertTimeout())
	defer cancel()
	if err := b.Flush(rctx); err != nil && ctx.Err() == nil && !errors.Is(err, ErrNoChannel) {
		b.logf("telltale server: queued bubbles alerts not sent yet: %s", escape.Terminal(err.Error()))
	}
}

// Trouble is what the last call to bubbles found wrong.
type Trouble string

const (
	TroubleNone            Trouble = ""
	TroubleUnreachable     Trouble = "unreachable"
	TroubleNeedsReconnect  Trouble = "needs_reconnect"
	TroubleIdentityChanged Trouble = "identity_changed"
	TroubleNotAllowed      Trouble = "not_allowed"
	TroubleArchived        Trouble = "archived"
	TroubleNoChannel       Trouble = "no_channel"
)

// The UI's words for each trouble, after netdiag's.
const (
	identityMsg     = "Warning: the chat server's identity changed. telltale stopped sending alerts. This happens when the chat server is reinstalled, or when something is pretending to be it. Ask your chat admin before you reconnect."
	unauthorizedMsg = "The chat server no longer accepts telltale. Click Reconnect."
	unreachableMsg  = "telltale can't reach the chat server. Alerts wait and go out when it can."
	notAllowedMsg   = "telltale isn't allowed to post in the alert channel. Ask your chat admin to add telltale to it, or choose another channel."
	archivedMsg     = "The alert channel is archived. Choose another channel."
	noChannelMsg    = "Choose a channel for alerts. Alerts wait until you do."
	turnedDownMsg   = "The chat server turned down telltale's request. Ask your chat admin to check bubbles' log."
	noTalkMsg       = "telltale couldn't talk to the chat server. Try again in a moment, or ask your chat admin whether it is running."
)

// Message is the trouble in plain words, "" for none.
func (t Trouble) Message() string {
	switch t {
	case TroubleUnreachable:
		return unreachableMsg
	case TroubleNeedsReconnect:
		return unauthorizedMsg
	case TroubleIdentityChanged:
		return identityMsg
	case TroubleNotAllowed:
		return notAllowedMsg
	case TroubleArchived:
		return archivedMsg
	case TroubleNoChannel:
		return noChannelMsg
	}
	return ""
}

// setTrouble records what a call found. A changed identity sticks until a
// new pairing: nothing is trusted again by itself.
func (b *Bubbles) setTrouble(t Trouble) {
	b.mu.Lock()
	if b.trouble == TroubleIdentityChanged || b.trouble == t {
		b.mu.Unlock()
		return
	}
	b.trouble, b.since = t, b.now()
	since := b.since
	b.mu.Unlock()
	if t != TroubleNone {
		b.logf("telltale server: bubbles: %s", t.Message())
	}
	b.saveTrouble(t, since)
}

// clearTrouble forgets the trouble, a changed identity too: a new
// connection or channel is trusted afresh.
func (b *Bubbles) clearTrouble() {
	b.mu.Lock()
	b.trouble, b.since = TroubleNone, time.Time{}
	b.mu.Unlock()
	b.saveTrouble(TroubleNone, time.Time{})
}

// saveTrouble records the trouble in the queue's summary, for the
// settings pages.
func (b *Bubbles) saveTrouble(t Trouble, since time.Time) {
	b.qmu.Lock()
	defer b.qmu.Unlock()
	st, err := b.loadStatus()
	if err == nil {
		if t == TroubleNone {
			since = time.Time{}
		}
		st.Trouble, st.Since = t, since
		err = b.sealCompact(SettingStatus, st)
	}
	if err != nil {
		b.logf("telltale server: bubbles: could not record the connection's state: %s", escape.Terminal(err.Error()))
	}
}

// explain puts an error from a call the owner made into plain words; what
// bubbles said goes to the log only.
func (b *Bubbles) explain(err error) string {
	var ae *bubblesclient.APIError
	switch {
	case errors.Is(err, bubblesclient.ErrServerIdentityChanged):
		return identityMsg
	case errors.Is(err, bubblesclient.ErrUnauthorized):
		return unauthorizedMsg
	case errors.Is(err, bubblesclient.ErrRateLimited):
		return "The chat server is busy. Try again in a minute."
	case errors.Is(err, bubblesclient.ErrUnavailable), errors.Is(err, context.DeadlineExceeded):
		return "telltale can't reach the chat server."
	case errors.As(err, &ae):
		b.logf("telltale server: bubbles refused a request: %s", refusal(ae))
		return turnedDownMsg
	}
	b.logf("telltale server: talking to bubbles: %s", escape.Terminal(err.Error()))
	return noTalkMsg
}

// Status is the connection as the settings page shows it. Every string in
// it is escaped.
type Status struct {
	Connected  bool
	Address    string // host:port of the bubbles server
	ServerName string
	Channel    Channel
	Pending    int
	Critical   int // of Pending
	Dropped    int
	Trouble    Trouble
	Since      time.Time
	// Choosing is set when the owner asked to choose the channel again, or
	// none is chosen; Choices are the bot's channels as last listed.
	Choosing bool
	Choices  []Channel
}

// Status reads the connection and the queue's summary (never the whole
// queue).
func (b *Bubbles) Status() (Status, error) {
	b.init()
	cfg, _, ok, err := b.connection()
	if err != nil || !ok {
		return Status{}, err
	}
	var ch channelRecord
	if err := b.loadSealed(SettingChannel, &ch); err != nil {
		return Status{}, err
	}
	qs, err := b.loadStatus()
	if err != nil {
		return Status{}, err
	}
	st := Status{Connected: true, Address: escape.Terminal(strings.TrimPrefix(cfg.BaseURL, "https://")), ServerName: escape.Terminal(ch.Server),
		Channel: Channel{ID: ch.ID, Name: escape.Terminal(ch.Name)}, Pending: qs.Pending, Critical: qs.Critical, Dropped: qs.Dropped,
		Trouble: qs.Trouble, Since: qs.Since}
	b.mu.Lock()
	st.Choosing = b.choosing || ch.ID == ""
	for _, c := range b.choices {
		st.Choices = append(st.Choices, Channel{ID: c.ID, Name: escape.Terminal(c.Name)})
	}
	b.mu.Unlock()
	if st.Trouble == TroubleNoChannel && ch.ID != "" {
		st.Trouble = TroubleNone
	}
	return st, nil
}

// SendTest posts a test alert to the alert channel and resolves it again
// at once, both directly (not through the queue), so a missing channel
// membership or scope shows at once. The error is in plain words.
func (b *Bubbles) SendTest(ctx context.Context) error {
	b.init()
	cl, ch, err := b.client()
	if err != nil {
		return err
	}
	if cl == nil {
		return errors.New("telltale is not connected to bubbles.")
	}
	b.mu.Lock()
	changed := b.trouble == TroubleIdentityChanged
	b.mu.Unlock()
	if changed {
		return errors.New(identityMsg)
	}
	if ch.ID == "" {
		return errors.New("Choose a channel for alerts first.")
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	text := "telltale can post its alerts here. This test closes again at once."
	if h := b.hostname(); h != "" {
		text = "The telltale server on " + mdText(h) + " can post its alerts here. This test closes again at once."
	}
	zero := 0
	at := b.now().UTC().Format(time.RFC3339)
	in := protocol.AlertInput{Channel: ch.ID, Severity: protocol.SeverityInfo, Title: "Test alert from telltale", Text: text,
		DedupeKey: TestKey, RenotifyAfterS: &zero, OccurredAt: &at}
	_, err = cl.PostAlert(ctx, in)
	if openElsewhere(err) && cl.ResolveAlert(ctx, TestKey, "Test finished.") == nil {
		_, err = cl.PostAlert(ctx, in)
	}
	if err != nil {
		b.classify(err, false)
		var ae *bubblesclient.APIError
		if errors.As(err, &ae) {
			switch {
			case ae.Status == http.StatusNotFound || ae.Status == http.StatusForbidden:
				return fmt.Errorf("telltale isn't allowed to post in #%s. Ask your chat admin to add telltale to that channel.", escape.Terminal(ch.Name))
			case ae.Status == http.StatusConflict && archived(ae):
				return fmt.Errorf("The channel #%s is archived. Choose another channel.", escape.Terminal(ch.Name))
			}
		}
		return errors.New(b.explain(err))
	}
	b.setTrouble(TroubleNone)
	b.Kick()
	if err := cl.ResolveAlert(ctx, TestKey, "Test finished."); err != nil {
		return fmt.Errorf("The test alert reached #%s but telltale could not close it: %s", escape.Terminal(ch.Name), b.explain(err))
	}
	return nil
}

// Disconnect forgets the connection, the channel and the queued alerts.
// Apps cannot revoke their own token in bubbles, so the page asks the
// owner to have the chat admin remove telltale in bubbles too.
func (b *Bubbles) Disconnect() error {
	b.init()
	b.mu.Lock()
	b.stopPairLocked()
	b.trouble, b.since = TroubleNone, time.Time{}
	b.cl, b.clConn, b.choices, b.choosing = nil, "", nil, false
	b.mu.Unlock()
	if err := b.Store.SetSecretSetting(SettingConn, nil); err != nil {
		return err
	}
	if err := b.Store.SetSecretSetting(SettingChannel, nil); err != nil {
		return err
	}
	b.qmu.Lock()
	defer b.qmu.Unlock()
	if err := b.Store.SetSecretSetting(SettingPending, nil); err != nil {
		return err
	}
	return b.Store.SetSecretSetting(SettingStatus, nil)
}
