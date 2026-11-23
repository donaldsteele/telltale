package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"html"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"golang.org/x/crypto/ssh"

	"github.com/donaldsteele/telltale/internal/alerts"
	"github.com/donaldsteele/telltale/internal/escape"
	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/repokeys"
	"github.com/donaldsteele/telltale/internal/store"
	"github.com/donaldsteele/telltale/internal/visit"
	"github.com/donaldsteele/telltale/web"
)

const (
	testListen    = "192.0.2.10:8443"
	testOrigin    = "https://192.0.2.10:8443"
	testSetupCode = "first-run-code-for-tests"
	testPassword  = "correct horse battery staple"
	testClientIP  = "192.0.2.50"
)

// fakeCore records the owner's actions instead of doing them.
type fakeCore struct {
	mu         sync.Mutex
	visits     []int64
	visitErr   error
	cleans     [][2]int64
	accepts    []acceptCall
	exceptions []exceptionCall
	actionErr  error
	visitError map[int64]string
	visiting   map[int64]bool
	acceptable map[int64]Acceptable
}

type acceptCall struct {
	machine, report int64
	keys            []string
}

type exceptionCall struct {
	machine, report int64
	key, note       string
}

func newFakeCore() *fakeCore {
	return &fakeCore{visitError: map[int64]string{}, visiting: map[int64]bool{}, acceptable: map[int64]Acceptable{}}
}

func (f *fakeCore) VisitNow(_ context.Context, id int64) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.visits = append(f.visits, id)
	return 0, f.visitErr
}

func (f *fakeCore) MarkClean(_ context.Context, id, rid int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.actionErr != nil {
		return f.actionErr
	}
	f.cleans = append(f.cleans, [2]int64{id, rid})
	return nil
}

func (f *fakeCore) AcceptChanges(_ context.Context, id, rid int64, keys []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.actionErr != nil {
		return f.actionErr
	}
	f.accepts = append(f.accepts, acceptCall{id, rid, slices.Clone(keys)})
	return nil
}

func (f *fakeCore) AddException(_ context.Context, id, rid int64, key, note string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.actionErr != nil {
		return f.actionErr
	}
	f.exceptions = append(f.exceptions, exceptionCall{id, rid, key, note})
	return nil
}

func (f *fakeCore) VisitError(id int64) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.visitError[id], nil
}

func (f *fakeCore) Leftovers(int64) ([]string, error) { return nil, nil }

func (f *fakeCore) Visiting(id int64) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.visiting[id]
}

func (f *fakeCore) Acceptable(id int64) (Acceptable, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.acceptable[id], nil
}

func (f *fakeCore) visitCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.visits)
}

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// webClient is one browser talking to a UI: its cookie jar, its address and the
// CSRF token of the last page it read.
type webClient struct {
	t     *testing.T
	ui    *UI
	st    *store.Store
	core  *fakeCore
	clock *testClock
	ip    string
	jar   map[string]*http.Cookie
	csrf  string
	fetch *fakeFetch
	bub   *alerts.Bubbles
	dir   string // the store's directory
}

type fakeFetch struct {
	mu   sync.Mutex
	key  ssh.PublicKey
	err  error
	addr []string
}

func (f *fakeFetch) FetchHostKey(_ context.Context, addr string) (ssh.PublicKey, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addr = append(f.addr, addr)
	if f.err != nil {
		return nil, "", f.err
	}
	return f.key, ssh.FingerprintSHA256(f.key), nil
}

// cheapPasswordHashes makes password hashing fast for the test.
func cheapPasswordHashes(t *testing.T) {
	old := hashParams
	hashParams = argonParams{time: 1, memoryKiB: 64, threads: 1}
	t.Cleanup(func() { hashParams = old })
}

func newWeb(t *testing.T) *webClient {
	t.Helper()
	cheapPasswordHashes(t)
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "server.db"), store.Unlock{KeyFile: filepath.Join(dir, "server.key")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hk, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	w := &webClient{t: t, st: st, core: newFakeCore(), clock: &testClock{t: t0}, ip: testClientIP, jar: map[string]*http.Cookie{}, fetch: &fakeFetch{key: hk}, dir: dir}
	w.bub = &alerts.Bubbles{Store: st, Hostname: "srv1", Log: log.New(io.Discard, "", 0)}
	ui, err := NewUI(UIOptions{
		Core:            w.core,
		Store:           st,
		Listen:          testListen,
		ServerAddr:      testServerAddr,
		CertFingerprint: "AA:BB:CC",
		SetupCode:       testSetupCode,
		Now:             w.clock.now,
		FetchHostKey:    w.fetch.FetchHostKey,
		Context:         context.Background(),
		Bubbles:         w.bub,
	})
	if err != nil {
		t.Fatal(err)
	}
	w.ui = ui
	return w
}

// browser is another browser on the same UI, from ip.
func (w *webClient) browser(ip string) *webClient {
	return &webClient{t: w.t, ui: w.ui, st: w.st, core: w.core, clock: w.clock, ip: ip, jar: map[string]*http.Cookie{}, fetch: w.fetch, bub: w.bub, dir: w.dir}
}

var csrfRE = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

// do sends one request the way a browser on the LAN would: over TLS, to the
// configured address, with the jar's cookies, and for a POST the page's own
// Origin. mods change it before it is sent.
func (w *webClient) do(method, target string, form url.Values, mods ...func(*http.Request)) *httptest.ResponseRecorder {
	w.t.Helper()
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	r := httptest.NewRequest(method, "https://"+testListen+target, body)
	r.Host = testListen
	r.RemoteAddr = net.JoinHostPort(w.ip, "40000")
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
	r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 8443}))
	if method == http.MethodPost {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", testOrigin)
		r.Header.Set("Sec-Fetch-Site", "same-origin")
	}
	for _, c := range w.jar {
		r.AddCookie(c)
	}
	for _, m := range mods {
		m(r)
	}
	rec := httptest.NewRecorder()
	w.ui.ServeHTTP(rec, r)
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge < 0 || c.Value == "" {
			delete(w.jar, c.Name)
		} else {
			w.jar[c.Name] = c
		}
	}
	if m := csrfRE.FindStringSubmatch(rec.Body.String()); m != nil {
		w.csrf = html.UnescapeString(m[1])
	}
	return rec
}

func (w *webClient) get(target string) *httptest.ResponseRecorder {
	w.t.Helper()
	return w.do(http.MethodGet, target, nil)
}

// post sends a form with the CSRF token of the last page read.
func (w *webClient) post(target string, form url.Values, mods ...func(*http.Request)) *httptest.ResponseRecorder {
	w.t.Helper()
	if form == nil {
		form = url.Values{}
	}
	if _, ok := form["csrf"]; !ok {
		form.Set("csrf", w.csrf)
	}
	return w.do(http.MethodPost, target, form, mods...)
}

func (w *webClient) setup() {
	w.t.Helper()
	w.get("/setup")
	rec := w.post("/setup", url.Values{"code": {testSetupCode}, "password": {testPassword}, "repeat": {testPassword}})
	if rec.Code != http.StatusSeeOther {
		w.t.Fatalf("setup: %d %s", rec.Code, rec.Body)
	}
}

func (w *webClient) login(password string) *httptest.ResponseRecorder {
	w.t.Helper()
	w.get("/login")
	return w.post("/login", url.Values{"password": {password}})
}

// loggedIn is a set-up UI with this browser logged in and holding a page's
// CSRF token.
func loggedIn(t *testing.T) *webClient {
	t.Helper()
	w := newWeb(t)
	w.setup()
	if rec := w.login(testPassword); rec.Code != http.StatusSeeOther {
		t.Fatalf("login: %d %s", rec.Code, rec.Body)
	}
	if rec := w.get("/"); rec.Code != http.StatusOK {
		t.Fatalf("machines page: %d", rec.Code)
	}
	return w
}

func wantStatus(t *testing.T, rec *httptest.ResponseRecorder, code int) {
	t.Helper()
	if rec.Code != code {
		t.Fatalf("status %d, want %d; body:\n%s", rec.Code, code, rec.Body)
	}
}

func wantRedirect(t *testing.T, rec *httptest.ResponseRecorder, to string) {
	t.Helper()
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != to {
		t.Fatalf("got %d to %q, want a redirect to %q; body:\n%s", rec.Code, rec.Header().Get("Location"), to, rec.Body)
	}
}

func auditActions(t *testing.T, st *store.Store) []string {
	t.Helper()
	log, err := st.AuditLog(0)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for i := len(log) - 1; i >= 0; i-- {
		out = append(out, log[i].Action+": "+log[i].Detail)
	}
	return out
}

func hasAudit(t *testing.T, st *store.Store, entry string) bool {
	t.Helper()
	return slices.Contains(auditActions(t, st), entry)
}

func (w *webClient) addMachine(name string) int64 {
	w.t.Helper()
	id, err := w.st.AddMachine(store.Machine{Name: name, Addr: "198.51.100.7", HostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHostKeyHostKeyHostKeyHostKeyHostKeyHostKeyHost"})
	if err != nil {
		w.t.Fatal(err)
	}
	return id
}

func (w *webClient) addReport(id int64, findings ...model.Finding) int64 {
	w.t.Helper()
	rep := &model.Report{Schema: model.ReportSchema, Host: model.Host{Hostname: "web01", OSPretty: "Debian 12", Arch: "amd64"}, Time: w.clock.now(), Findings: findings, Explained: []model.Finding{}}
	for _, f := range findings {
		if f.Severity >= model.SevBackdoor {
			rep.ExitCode = 2
		} else if rep.ExitCode == 0 {
			rep.ExitCode = 1
		}
	}
	rid, err := w.st.PutReport(id, rep, &model.Collection{Schema: model.CollectionSchema})
	if err != nil {
		w.t.Fatal(err)
	}
	return rid
}

func finding(key string, sev model.Severity, title string) model.Finding {
	return model.Finding{Key: key, ID: "TT-TEST", Severity: sev, Title: title, Why: "because " + title, Source: "heuristic",
		Evidence: []model.Evidence{{Path: "/etc/" + key, Line: 3, After: "value of " + key}}}
}

func TestFirstRunRequiresPasswordSetup(t *testing.T) {
	w := newWeb(t)
	// Before a password exists every page leads to the setup page.
	for _, p := range []string{"/", "/login", "/settings", "/machines/1"} {
		wantRedirect(t, w.get(p), "/setup")
	}
	rec := w.get("/setup")
	wantStatus(t, rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), `name="code"`) {
		t.Errorf("the setup page does not ask for the code the server printed:\n%s", rec.Body)
	}
	set := func(code, pw, repeat string, mods ...func(*http.Request)) *httptest.ResponseRecorder {
		w.get("/setup")
		return w.post("/setup", url.Values{"code": {code}, "password": {pw}, "repeat": {repeat}}, mods...)
	}
	noPassword := func(what string) {
		t.Helper()
		if ok, err := hasPassword(w.st); err != nil || ok {
			t.Fatalf("%s: a password was set (%v)", what, err)
		}
	}
	// The code printed on the server's console is required.
	if rec := set("wrong-code", testPassword, testPassword); rec.Code != http.StatusForbidden {
		t.Errorf("wrong code: status %d", rec.Code)
	}
	noPassword("wrong code")
	// Only through the configured listen address.
	otherAddr := func(r *http.Request) {
		*r = *r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("192.0.2.99"), Port: 8443}))
	}
	if rec := set(testSetupCode, testPassword, testPassword, otherAddr); rec.Code != http.StatusForbidden {
		t.Errorf("another local address: status %d", rec.Code)
	}
	noPassword("another local address")
	// A short password, or two that differ, are refused.
	if rec := set(testSetupCode, "short", "short"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "at least") {
		t.Errorf("short password: status %d", rec.Code)
	}
	if rec := set(testSetupCode, testPassword, testPassword+"x"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "do not match") {
		t.Errorf("passwords that differ: status %d", rec.Code)
	}
	noPassword("bad passwords")
	// Without the form's CSRF token.
	w.get("/setup")
	if rec := w.post("/setup", url.Values{"csrf": {"nope"}, "code": {testSetupCode}, "password": {testPassword}, "repeat": {testPassword}}); rec.Code != http.StatusForbidden {
		t.Errorf("no CSRF token: status %d", rec.Code)
	}
	noPassword("no CSRF token")

	wantRedirect(t, set(testSetupCode, testPassword, testPassword), "/login")
	if !hasAudit(t, w.st, "admin password set: from "+testClientIP) {
		t.Errorf("audit log: %q", auditActions(t, w.st))
	}
	// Once a password exists the setup page is gone, for everyone.
	wantRedirect(t, w.get("/setup"), "/login")
	other := w.browser("192.0.2.66")
	other.get("/login")
	rec = other.post("/setup", url.Values{"code": {testSetupCode}, "password": {"another password entirely"}, "repeat": {"another password entirely"}})
	if rec.Code != http.StatusForbidden && rec.Code != http.StatusSeeOther {
		t.Errorf("setup after the password was set: status %d", rec.Code)
	}
	if rec := other.login("another password entirely"); rec.Code == http.StatusSeeOther {
		t.Fatal("a second setup replaced the password")
	}
	if rec := w.login(testPassword); rec.Code != http.StatusSeeOther {
		t.Errorf("login with the password set at first run: %d", rec.Code)
	}
}

func TestLoginAndCSRF(t *testing.T) {
	w := newWeb(t)
	w.setup()
	id := w.addMachine("web01")

	// Not logged in: pages lead to the login page, actions are refused.
	wantRedirect(t, w.get("/"), "/login")
	w.get("/login")
	if rec := w.post("/machines/"+strconv.FormatInt(id, 10)+"/check", nil); rec.Code != http.StatusForbidden {
		t.Errorf("check now without a session: %d", rec.Code)
	}
	// The login form has its own CSRF token.
	w.get("/login")
	if rec := w.post("/login", url.Values{"csrf": {""}, "password": {testPassword}}); rec.Code != http.StatusForbidden {
		t.Errorf("login without a CSRF token: %d", rec.Code)
	}
	if rec := w.login("wrong password here"); rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "That password is not right") {
		t.Errorf("wrong password: %d %s", rec.Code, rec.Body)
	}
	if !hasAudit(t, w.st, "login failed: from "+testClientIP) {
		t.Errorf("failed login not audited: %q", auditActions(t, w.st))
	}
	rec := w.login(testPassword)
	wantRedirect(t, rec, "/")
	if !hasAudit(t, w.st, "login: from "+testClientIP) {
		t.Errorf("login not audited: %q", auditActions(t, w.st))
	}
	var sc *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			sc = c
		}
	}
	if sc == nil {
		t.Fatal("no session cookie")
	}
	if !sc.Secure || !sc.HttpOnly || sc.SameSite != http.SameSiteStrictMode || sc.Path != "/" || sc.Domain != "" {
		t.Errorf("session cookie %+v: want Secure, HttpOnly, SameSite=Strict, Path=/ and no Domain", sc)
	}
	if raw, err := decodeToken(sc.Value); err != nil || len(raw) != 32 {
		t.Errorf("session token is not 32 random bytes: %v", err)
	}
	// The token itself is not what the server keeps.
	if w.ui.sessions.has(sc.Value) {
		t.Error("the session table is keyed by the raw token")
	}

	wantStatus(t, w.get("/"), http.StatusOK)
	check := "/machines/" + strconv.FormatInt(id, 10) + "/check"
	if rec := w.post(check, url.Values{"csrf": {""}}); rec.Code != http.StatusForbidden {
		t.Errorf("POST without a CSRF token: %d, want 403", rec.Code)
	}
	if rec := w.post(check, url.Values{"csrf": {w.csrf + "x"}}); rec.Code != http.StatusForbidden {
		t.Errorf("POST with a wrong CSRF token: %d, want 403", rec.Code)
	}
	// The login page's token is not a session's.
	pre := w.jar[preCookie]
	if pre != nil {
		if rec := w.post(check, url.Values{"csrf": {pre.Value}}); rec.Code != http.StatusForbidden {
			t.Errorf("POST with the login form's token: %d, want 403", rec.Code)
		}
	}
	if n := w.core.visitCount(); n != 0 {
		t.Fatalf("%d visits started by refused requests", n)
	}
	wantRedirect(t, w.post(check, nil), "/machines/"+strconv.FormatInt(id, 10))
	deadline := time.Now().Add(5 * time.Second)
	for w.core.visitCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := w.core.visitCount(); n != 1 {
		t.Errorf("visits = %d, want 1", n)
	}
	if !hasAudit(t, w.st, fmt.Sprintf("check now: machine %d", id)) {
		t.Errorf("check now not audited: %q", auditActions(t, w.st))
	}
	// A GET never changes anything.
	if rec := w.get(check); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET of an action: %d", rec.Code)
	}
}

func TestCheckNowWhileAVisitRuns(t *testing.T) {
	w := loggedIn(t)
	id := w.addMachine("web01")
	w.core.visitErr = ErrVisitRunning
	path := "/machines/" + strconv.FormatInt(id, 10)
	wantRedirect(t, w.post(path+"/check", nil), path)
	rec := w.get(path)
	if !strings.Contains(rec.Body.String(), "A visit is running, try again in a moment.") {
		t.Errorf("no plain message about the running visit:\n%s", rec.Body)
	}
}

func TestMachinesListShowsWorstFinding(t *testing.T) {
	w := loggedIn(t)
	a := w.addMachine("web01")
	w.addReport(a, finding("heur.note", model.SevNote, "A small note"), finding("heur.crossview:ps", model.SevTampering, "ps hides a process"), finding("heur.weak", model.SevWeak, "A weak setting"))
	b := w.addMachine("db01")
	hostile := w.addMachine(`<b>x</b>`)
	w.addReport(hostile, finding("heur.<i>", model.SevBackdoor, "<script>alert(1)</script>"))
	last := t0.Add(time.Hour)
	m, _ := w.st.Machine(a)
	m.LastVisit = &last
	if err := w.st.UpdateMachine(*m); err != nil {
		t.Fatal(err)
	}

	rec := w.get("/")
	wantStatus(t, rec, http.StatusOK)
	body := rec.Body.String()
	row := func(id int64) string {
		t.Helper()
		re := regexp.MustCompile(`(?s)<tr id="machine-` + strconv.FormatInt(id, 10) + `".*?</tr>`)
		s := re.FindString(body)
		if s == "" {
			t.Fatalf("no row for machine %d:\n%s", id, body)
		}
		return s
	}
	ra := row(a)
	if !strings.Contains(ra, "TAMPERING") || !strings.Contains(ra, "ps hides a process") {
		t.Errorf("web01's row does not show its worst finding:\n%s", ra)
	}
	if strings.Contains(ra, "A small note") || strings.Contains(ra, "A weak setting") {
		t.Errorf("web01's row shows a lesser finding as its worst:\n%s", ra)
	}
	if !strings.Contains(ra, "3 findings") {
		t.Errorf("web01's row does not count its findings:\n%s", ra)
	}
	if !strings.Contains(ra, "2026-11-22 10:00") {
		t.Errorf("web01's row does not show the last visit:\n%s", ra)
	}
	if !strings.Contains(ra, `action="/machines/`+strconv.FormatInt(a, 10)+`/check"`) || !strings.Contains(ra, "Check now") {
		t.Errorf("web01's row has no Check now button:\n%s", ra)
	}
	if rb := row(b); !strings.Contains(rb, "Not visited yet") {
		t.Errorf("db01's row:\n%s", rb)
	}
	if strings.Contains(body, "<script>alert") || strings.Contains(body, "<b>x</b>") || strings.Contains(body, "<i>") {
		t.Errorf("machine text reached the page as markup:\n%s", body)
	}
}

func TestMarkCleanNeedsConfirmation(t *testing.T) {
	w := loggedIn(t)
	id := w.addMachine("web01")
	old := w.addReport(id, finding("heur.old_only", model.SevNote, "Only in the older report"))
	w.clock.advance(time.Hour)
	latest := w.addReport(id, finding("heur.uid0:toor", model.SevBackdoor, "A second account with user ID 0"))
	mp := "/machines/" + strconv.FormatInt(id, 10)

	// The machine page offers the snapshot from the report it shows.
	rec := w.get(mp)
	if !strings.Contains(rec.Body.String(), mp+"/clean?report="+strconv.FormatInt(latest, 10)) {
		t.Errorf("the machine page does not link the snapshot to its report:\n%s", rec.Body)
	}
	rec = w.get(mp + "?report=" + strconv.FormatInt(old, 10))
	if !strings.Contains(rec.Body.String(), mp+"/clean?report="+strconv.FormatInt(old, 10)) {
		t.Errorf("an older report's page does not link the snapshot to that report:\n%s", rec.Body)
	}

	// A POST that skips the confirmation does nothing.
	if rec := w.post(mp+"/clean", url.Values{"report": {strconv.FormatInt(latest, 10)}}); rec.Code != http.StatusBadRequest {
		t.Errorf("mark clean without confirming: %d", rec.Code)
	}
	if len(w.core.cleans) != 0 {
		t.Fatalf("MarkClean ran without the confirmation: %v", w.core.cleans)
	}

	// The confirmation lists that report's findings and posts its ID back.
	rec = w.get(mp + "/clean?report=" + strconv.FormatInt(old, 10))
	wantStatus(t, rec, http.StatusOK)
	body := rec.Body.String()
	if !strings.Contains(body, "Only in the older report") || strings.Contains(body, "A second account with user ID 0") {
		t.Errorf("the confirmation does not list exactly that report's findings:\n%s", body)
	}
	if !strings.Contains(body, `name="report" value="`+strconv.FormatInt(old, 10)+`"`) || !strings.Contains(body, `name="confirm" value="yes"`) {
		t.Errorf("the confirmation form does not post the report back:\n%s", body)
	}
	wantRedirect(t, w.post(mp+"/clean", url.Values{"report": {strconv.FormatInt(old, 10)}, "confirm": {"yes"}}), mp)
	if want := [][2]int64{{id, old}}; !slices.Equal(w.core.cleans, want) {
		t.Errorf("MarkClean calls %v, want %v", w.core.cleans, want)
	}

	// Another machine's report is not this machine's.
	other := w.addMachine("db01")
	if rec := w.get("/machines/" + strconv.FormatInt(other, 10) + "/clean?report=" + strconv.FormatInt(old, 10)); rec.Code != http.StatusNotFound {
		t.Errorf("another machine's report: %d", rec.Code)
	}

	// While a visit runs: a plain message.
	w.core.actionErr = ErrVisitRunning
	w.get(mp + "/clean?report=" + strconv.FormatInt(latest, 10))
	rec = w.post(mp+"/clean", url.Values{"report": {strconv.FormatInt(latest, 10)}, "confirm": {"yes"}})
	if rec.Code == http.StatusSeeOther {
		rec = w.get(rec.Header().Get("Location"))
	}
	if !strings.Contains(rec.Body.String(), "A visit is running, try again in a moment.") {
		t.Errorf("no plain message about the running visit:\n%s", rec.Body)
	}
}

func TestAcceptChangesNeedsConfirmation(t *testing.T) {
	w := loggedIn(t)
	id := w.addMachine("web01")
	rid := w.addReport(id,
		finding("snap.persist:/etc/cron.d/job", model.SevBackdoor, "A new cron job"),
		finding("snap.file:/usr/local/bin/tool", model.SevNote, "A changed program"),
		finding("pkg.mismatch:/usr/local/bin/tool", model.SevTampering, "The program does not match its package"),
		finding("heur.ld_preload", model.SevBackdoor, "ld.so.preload exists"))
	w.core.acceptable[id] = Acceptable{ReportID: rid, With: map[string][]string{
		"snap.persist:/etc/cron.d/job":     nil,
		"snap.file:/usr/local/bin/tool":    {"pkg.mismatch:/usr/local/bin/tool"},
		"pkg.mismatch:/usr/local/bin/tool": {"snap.file:/usr/local/bin/tool"},
	}}
	mp := "/machines/" + strconv.FormatInt(id, 10)
	rec := w.get(mp + "/changes")
	wantStatus(t, rec, http.StatusOK)
	body := rec.Body.String()
	if !strings.Contains(body, "A new cron job") || !strings.Contains(body, "A changed program") {
		t.Errorf("the review does not show the changes:\n%s", body)
	}
	if strings.Contains(body, "ld.so.preload exists") {
		t.Errorf("the review offers a finding that is not a change since the snapshot:\n%s", body)
	}
	// Accepting the program accepts its package finding with it. The link
	// names the group by one of its findings; the server works out the rest.
	groupLink := mp + "/accept?" + url.Values{"report": {strconv.FormatInt(rid, 10)}, "group": {"snap.file:/usr/local/bin/tool"}}.Encode()
	if !strings.Contains(body, html.EscapeString(groupLink)) {
		t.Errorf("the review has no link %q:\n%s", groupLink, body)
	}
	acc := url.Values{"report": {strconv.FormatInt(rid, 10)}, "group": {"snap.file:/usr/local/bin/tool"}}
	if rec := w.post(mp+"/accept", acc); rec.Code != http.StatusBadRequest {
		t.Errorf("accept without confirming: %d", rec.Code)
	}
	if len(w.core.accepts) != 0 {
		t.Fatal("AcceptChanges ran without the confirmation")
	}
	rec = w.get(groupLink)
	wantStatus(t, rec, http.StatusOK)
	if b := rec.Body.String(); !strings.Contains(b, "A changed program") || !strings.Contains(b, "The program does not match its package") || strings.Contains(b, "A new cron job") {
		t.Errorf("the confirmation does not list exactly the chosen changes:\n%s", b)
	}
	wantRedirect(t, w.post(mp+"/accept", confirmForm(t, rec.Body.String())), mp)
	if len(w.core.accepts) != 1 || w.core.accepts[0].report != rid || !slices.Equal(w.core.accepts[0].keys, []string{"snap.file:/usr/local/bin/tool", "pkg.mismatch:/usr/local/bin/tool"}) {
		t.Errorf("AcceptChanges calls %+v", w.core.accepts)
	}
	// All at once.
	if !strings.Contains(body, "Accept all 3 changes") {
		t.Errorf("the review has no all-at-once accept:\n%s", body)
	}
	rec = w.get(mp + "/accept?" + url.Values{"report": {strconv.FormatInt(rid, 10)}, "all": {"1"}}.Encode())
	wantStatus(t, rec, http.StatusOK)
	wantRedirect(t, w.post(mp+"/accept", confirmForm(t, rec.Body.String())), mp)
	if len(w.core.accepts) != 2 || len(w.core.accepts[1].keys) != 3 {
		t.Errorf("AcceptChanges calls %+v", w.core.accepts)
	}
	// A group that is not in the report, nothing named, or a report that is
	// not the one the changes come from, is refused.
	for name, q := range map[string]url.Values{
		"unknown group": {"report": {strconv.FormatInt(rid, 10)}, "group": {"heur.ld_preload"}},
		"nothing named": {"report": {strconv.FormatInt(rid, 10)}},
		"other report":  {"report": {strconv.FormatInt(w.addReport(id), 10)}, "all": {"1"}},
	} {
		if rec := w.get(mp + "/accept?" + q.Encode()); rec.Code == http.StatusOK {
			t.Errorf("%s: the confirmation page was shown", name)
		}
	}
}

// confirmForm reads the hidden fields of a confirmation page's form, the way
// the browser sends them back.
func confirmForm(t *testing.T, page string) url.Values {
	t.Helper()
	form := url.Values{}
	for _, m := range regexp.MustCompile(`<input type="hidden" name="([a-z_]+)" value="([^"]*)">`).FindAllStringSubmatch(page, -1) {
		if m[1] != "csrf" {
			form.Add(m[1], html.UnescapeString(m[2]))
		}
	}
	if form.Get("confirm") != "yes" {
		t.Fatalf("the page has no confirmation form:\n%s", page)
	}
	return form
}

// Accepting thousands of changes at once must not put their keys in a URL:
// the server caps request headers at 64 KiB, which about 1,300 keys fill.
func TestAcceptAllLargeChangeSet(t *testing.T) {
	w := loggedIn(t)
	id := w.addMachine("web01")
	const n = 3000
	var fs []model.Finding
	with := map[string][]string{}
	for i := range n {
		k := fmt.Sprintf("snap.file:/usr/share/app/assets/a-rather-long-file-name-number-%05d.js", i)
		fs = append(fs, finding(k, model.SevNote, "A changed file"))
		with[k] = nil
	}
	rid := w.addReport(id, fs...)
	w.core.acceptable[id] = Acceptable{ReportID: rid, With: with}
	mp := "/machines/" + strconv.FormatInt(id, 10)
	body := w.get(mp + "/changes").Body.String()
	m := regexp.MustCompile(`<a class="btn" href="([^"]+)">Accept all 3000 changes</a>`).FindStringSubmatch(body)
	if m == nil {
		t.Fatal("the review has no accept-all link")
	}
	link := html.UnescapeString(m[1])
	if len(link) > 200 {
		t.Fatalf("the accept-all link is %d bytes long", len(link))
	}
	for _, href := range regexp.MustCompile(`href="(/machines/[^"]+/accept\?[^"]+)"`).FindAllStringSubmatch(body, -1) {
		if len(href[1]) > 400 {
			t.Fatalf("an accept link is %d bytes long", len(href[1]))
		}
	}
	rec := w.get(link)
	wantStatus(t, rec, http.StatusOK)
	form := confirmForm(t, rec.Body.String())
	if len(form["key"]) != 0 {
		t.Errorf("the confirmation form carries %d keys", len(form["key"]))
	}
	// Without the confirmation the error page links back to a short URL.
	noConfirm := url.Values{"report": form["report"], "all": form["all"], "sum": form["sum"]}
	rec = w.post(mp+"/accept", noConfirm)
	wantStatus(t, rec, http.StatusBadRequest)
	if back := regexp.MustCompile(`href="([^"]*accept[^"]*)"`).FindStringSubmatch(rec.Body.String()); back == nil || len(back[1]) > 200 {
		t.Errorf("the way back from the error page: %q", back)
	}
	wantRedirect(t, w.post(mp+"/accept", form), mp)
	if len(w.core.accepts) != 1 || len(w.core.accepts[0].keys) != n {
		t.Fatalf("AcceptChanges got %d calls", len(w.core.accepts))
	}
	// The set is worked out again when the form comes back: if it changed
	// since the owner saw it, nothing is accepted.
	delete(with, fs[0].Key)
	form = confirmForm(t, w.get(link).Body.String())
	with[fs[0].Key] = nil
	if rec := w.post(mp+"/accept", form); rec.Code == http.StatusSeeOther {
		t.Error("a changed set was accepted without being shown again")
	}
	if len(w.core.accepts) != 1 {
		t.Errorf("AcceptChanges got %d calls", len(w.core.accepts))
	}
}

func TestAddExceptionNeedsConfirmation(t *testing.T) {
	w := loggedIn(t)
	id := w.addMachine("web01")
	rid := w.addReport(id, finding("heur.unowned_setuid:/usr/local/bin/helper", model.SevBackdoor, "A setuid program no package owns"))
	mp := "/machines/" + strconv.FormatInt(id, 10)
	key := "heur.unowned_setuid:/usr/local/bin/helper"
	form := url.Values{"report": {strconv.FormatInt(rid, 10)}, "key": {key}, "note": {"our own helper"}}
	if rec := w.post(mp+"/exception", form); rec.Code != http.StatusBadRequest {
		t.Errorf("exception without confirming: %d", rec.Code)
	}
	rec := w.get(mp + "/exception?report=" + strconv.FormatInt(rid, 10) + "&key=" + url.QueryEscape(key))
	wantStatus(t, rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), "A setuid program no package owns") {
		t.Errorf("the confirmation does not show the finding:\n%s", rec.Body)
	}
	form.Set("confirm", "yes")
	wantRedirect(t, w.post(mp+"/exception", form), mp)
	if want := []exceptionCall{{id, rid, key, "our own helper"}}; !slices.Equal(w.core.exceptions, want) {
		t.Errorf("AddException calls %+v, want %+v", w.core.exceptions, want)
	}
}

func TestEnrolShowsFingerprintThenSnippets(t *testing.T) {
	w := loggedIn(t)
	wantStatus(t, w.get("/enrol"), http.StatusOK)
	rec := w.post("/enrol", url.Values{"name": {"web02"}, "addr": {"198.51.100.8"}})
	wantStatus(t, rec, http.StatusOK)
	body := rec.Body.String()
	fp := ssh.FingerprintSHA256(w.fetch.key)
	if !strings.Contains(html.UnescapeString(body), fp) { // base64 "+" is written &#43;
		t.Fatalf("the fingerprint is not shown:\n%s", body)
	}
	if !strings.Contains(body, "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub") {
		t.Errorf("no instructions for comparing the fingerprint:\n%s", body)
	}
	if strings.Contains(body, "Match Address") || strings.Contains(body, "from=") {
		t.Errorf("the snippets are shown before the owner confirmed the fingerprint:\n%s", body)
	}
	if ms, _ := w.st.Machines(); len(ms) != 0 {
		t.Fatalf("a machine was enrolled before the fingerprint was confirmed: %+v", ms)
	}
	m := regexp.MustCompile(`name="pending" value="([^"]+)"`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no confirmation form:\n%s", body)
	}
	// The confirmation must be explicit.
	if rec := w.post("/enrol/confirm", url.Values{"pending": {m[1]}}); rec.Code != http.StatusBadRequest {
		t.Errorf("confirm without confirm=yes: %d", rec.Code)
	}
	rec = w.post("/enrol/confirm", url.Values{"pending": {m[1]}, "confirm": {"yes"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("confirm: %d %s", rec.Code, rec.Body)
	}
	ms, _ := w.st.Machines()
	if len(ms) != 1 || ms[0].Name != "web02" || ms[0].Addr != "198.51.100.8" {
		t.Fatalf("machines %+v", ms)
	}
	if want := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(w.fetch.key))); ms[0].HostKey != want {
		t.Errorf("pinned host key %q, want %q", ms[0].HostKey, want)
	}
	if !hasAudit(t, w.st, fmt.Sprintf("enrol: machine %d", ms[0].ID)) {
		t.Errorf("enrolment not audited: %q", auditActions(t, w.st))
	}
	// The same confirmation cannot be used twice.
	if rec := w.post("/enrol/confirm", url.Values{"pending": {m[1]}, "confirm": {"yes"}}); rec.Code == http.StatusSeeOther {
		t.Error("a used confirmation enrolled again")
	}
	snip := w.get(rec.Header().Get("Location"))
	wantStatus(t, snip, http.StatusOK)
	_, line, err := visit.ServerKey(w.st)
	if err != nil {
		t.Fatal(err)
	}
	wantKeys, wantMatch, err := visit.EnrolSnippets(testServerAddr, line)
	if err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]string{"snippet-keys": wantKeys, "snippet-sshd": wantMatch} {
		got := regexp.MustCompile(`(?s)<code id="` + id + `">(.*?)</code>`).FindStringSubmatch(snip.Body.String())
		if got == nil || html.UnescapeString(got[1]) != want {
			t.Errorf("%s: got %q, want %q", id, got, want)
		}
	}
	if !strings.Contains(snip.Body.String(), fmt.Sprintf(`action="/machines/%d/check"`, ms[0].ID)) {
		t.Errorf("the snippets page has no Check now:\n%s", snip.Body)
	}

	// A machine that cannot be reached: an error, nothing enrolled.
	w.fetch.err = errors.New("connection refused")
	w.get("/enrol")
	rec = w.post("/enrol", url.Values{"name": {"web03"}, "addr": {"198.51.100.9"}})
	if !strings.Contains(rec.Body.String(), "connection refused") || strings.Contains(rec.Body.String(), `name="pending"`) {
		t.Errorf("fetch failure:\n%s", rec.Body)
	}
	// Names are checked before anything is fetched.
	w.fetch.err = nil
	n := len(w.fetch.addr)
	for _, name := range []string{"", "web 04", "<b>", strings.Repeat("a", 65)} {
		w.get("/enrol")
		if rec := w.post("/enrol", url.Values{"name": {name}, "addr": {"198.51.100.9"}}); strings.Contains(rec.Body.String(), `name="pending"`) {
			t.Errorf("name %q accepted", name)
		}
	}
	if len(w.fetch.addr) != n {
		t.Errorf("fetched a host key for a refused name")
	}
}

func TestFixCommandEscapedInHTML(t *testing.T) {
	w := loggedIn(t)
	id := w.addMachine("web01")
	quoted := finding(`heur.x:"><script>k()</script>`, model.SevBackdoor, `A "quoted" <script>alert(1)</script> title`)
	quoted.Fix = `echo "<script>alert('x')</script>" > /tmp/x && rm -- '/tmp/a b'`
	control := finding("heur.control", model.SevWeak, "Control bytes\x1b[2J in the title")
	control.Fix = "printf 'x' > /etc/\x1b]0;pwned\x07motd"
	control.Why = "it rang\x07 the bell"
	hostile := finding("heur.hostile", model.SevTampering, "Hostile")
	hostile.Fix = "rm -rf -- '</code></pre><script>evil()</script><pre><code>'"
	hostile.Evidence = []model.Evidence{{Path: `/etc/<img src=x onerror=alert(1)>`, Before: "a\x1b[31mred", After: `"><svg onload=alert(2)>`, Detail: "\u202eevil"}}
	w.addReport(id, quoted, control, hostile)

	rec := w.get("/machines/" + strconv.FormatInt(id, 10))
	wantStatus(t, rec, http.StatusOK)
	body := rec.Body.String()
	for _, bad := range []string{"<script>alert", "<script>evil", "<script>k()", "<img src=x", "<svg", "\x1b", "\x07", "\u202e", `"><svg`, `"><script`} {
		if strings.Contains(body, bad) {
			t.Errorf("the page holds %q raw", bad)
		}
	}
	if !strings.Contains(body, "&lt;/code&gt;&lt;/pre&gt;&lt;script&gt;evil()") {
		t.Errorf("the hostile Fix is not shown escaped:\n%s", body)
	}
	if !strings.Contains(body, `\x1b[2J`) || !strings.Contains(body, `\x07`) || !strings.Contains(body, `\u{202E}`) {
		t.Errorf("control characters are not shown as escapes:\n%s", body)
	}

	// Each Fix is shown byte for byte, and its copy button copies exactly
	// that; a Fix marked "do not paste" has no copy button.
	codes := regexp.MustCompile(`(?s)<code id="(fix-\d+)">(.*?)</code>`).FindAllStringSubmatch(body, -1)
	got := map[string]string{}
	for _, c := range codes {
		got[html.UnescapeString(c[2])] = c[1]
	}
	for _, f := range []model.Finding{quoted, hostile} {
		fid, ok := got[f.Fix]
		if !ok {
			t.Errorf("the Fix %q is not shown byte for byte; shown: %q", f.Fix, got)
			continue
		}
		if !strings.Contains(body, `data-copy="`+fid+`"`) {
			t.Errorf("no copy button for %s", fid)
		}
	}
	marked := ""
	for text, fid := range got {
		if strings.Contains(text, "do not paste") {
			marked = fid
			if strings.ContainsAny(text, "\x1b\x07") {
				t.Errorf("the marked Fix holds control bytes: %q", text)
			}
		}
	}
	if marked == "" {
		t.Fatalf("the Fix with control bytes is not marked \"do not paste\": %q", got)
	}
	if strings.Contains(body, `data-copy="`+marked+`"`) {
		t.Errorf("the Fix marked \"do not paste\" has a copy button")
	}
	if !escape.HasUnsafe(control.Fix) {
		t.Fatal("test setup: the control Fix should be unsafe")
	}
}

const wantCSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

func TestSecurityHeaders(t *testing.T) {
	w := newWeb(t)
	w.setup()
	check := func(rec *httptest.ResponseRecorder, what string, authenticated bool) {
		t.Helper()
		h := rec.Header()
		for k, v := range map[string]string{
			"Content-Security-Policy": wantCSP,
			"X-Content-Type-Options":  "nosniff",
			"Referrer-Policy":         "no-referrer",
			"X-Frame-Options":         "DENY",
		} {
			if got := h.Get(k); got != v {
				t.Errorf("%s: %s = %q, want %q", what, k, got, v)
			}
		}
		if !strings.HasPrefix(h.Get("Strict-Transport-Security"), "max-age=") {
			t.Errorf("%s: no HSTS header", what)
		}
		if authenticated && h.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: Cache-Control = %q, want no-store", what, h.Get("Cache-Control"))
		}
	}
	check(w.get("/login"), "login page", false)
	w.login(testPassword)
	check(w.get("/"), "machines page", true)
	check(w.get("/settings"), "settings page", true)
	check(w.get("/audit"), "audit page", true)
	check(w.get("/no-such-page"), "not found", true)
	css := w.get("/static/styles.css")
	wantStatus(t, css, http.StatusOK)
	if ct := css.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/css") {
		t.Errorf("styles.css Content-Type %q", ct)
	}
	check(css, "styles.css", false)
	js := w.get("/static/app.js")
	wantStatus(t, js, http.StatusOK)
	if ct := js.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/javascript") {
		t.Errorf("app.js Content-Type %q", ct)
	}

	// The CSP allows no inline script or style, so the templates must
	// have none.
	err := fs.WalkDir(web.FS, "templates", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(web.FS, p)
		if err != nil {
			return err
		}
		s := strings.ToLower(string(b))
		for _, bad := range []string{"<style", " style=", "javascript:", " onclick", " onload", " onsubmit"} {
			if strings.Contains(s, bad) {
				t.Errorf("%s holds %q", p, bad)
			}
		}
		for _, m := range regexp.MustCompile(`<script[^>]*>`).FindAllString(s, -1) {
			if !strings.Contains(m, `src="/static/`) {
				t.Errorf("%s holds an inline script %q", p, m)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSessionExpiry(t *testing.T) {
	w := loggedIn(t)
	wantStatus(t, w.get("/"), http.StatusOK)
	// Idle for more than 12 hours: logged out.
	w.clock.advance(12*time.Hour + time.Minute)
	wantRedirect(t, w.get("/"), "/login")

	// In use all the time: still logged out after 7 days.
	w.login(testPassword)
	for i := 0; i < 27; i++ { // 27 * 6h = 6 days 18 hours
		w.clock.advance(6 * time.Hour)
		wantStatus(t, w.get("/"), http.StatusOK)
	}
	w.clock.advance(6*time.Hour + time.Minute)
	wantRedirect(t, w.get("/"), "/login")

	// Logging out ends the session on the server, not only in the browser.
	w.login(testPassword)
	w.get("/")
	stolen := *w.jar[sessionCookie]
	wantRedirect(t, w.post("/logout", nil), "/login")
	if _, ok := w.jar[sessionCookie]; ok {
		t.Error("logout left the session cookie in the browser")
	}
	if !hasAudit(t, w.st, "logout: from "+testClientIP) {
		t.Errorf("logout not audited: %q", auditActions(t, w.st))
	}
	w.jar[sessionCookie] = &stolen
	wantRedirect(t, w.get("/"), "/login")
}

func TestPasswordChangeEndsAllSessions(t *testing.T) {
	w := loggedIn(t)
	other := w.browser("192.0.2.51")
	if rec := other.login(testPassword); rec.Code != http.StatusSeeOther {
		t.Fatalf("second login: %d", rec.Code)
	}
	wantStatus(t, other.get("/"), http.StatusOK)

	w.get("/settings")
	newPW := "a different long password"
	// The current password is required.
	rec := w.post("/settings/password", url.Values{"current": {"not the password"}, "password": {newPW}, "repeat": {newPW}})
	if rec.Code == http.StatusSeeOther {
		t.Fatal("password changed without the current password")
	}
	w.get("/settings")
	wantRedirect(t, w.post("/settings/password", url.Values{"current": {testPassword}, "password": {newPW}, "repeat": {newPW}}), "/login?changed=1")
	if !hasAudit(t, w.st, "password changed: from "+testClientIP) {
		t.Errorf("password change not audited: %q", auditActions(t, w.st))
	}
	wantRedirect(t, w.get("/"), "/login")
	wantRedirect(t, other.get("/"), "/login")
	if rec := w.login(testPassword); rec.Code == http.StatusSeeOther {
		t.Error("the old password still works")
	}
	if rec := w.login(newPW); rec.Code != http.StatusSeeOther {
		t.Errorf("the new password does not work: %d", rec.Code)
	}
}

func TestHostAndOriginChecked(t *testing.T) {
	w := loggedIn(t)
	id := w.addMachine("web01")
	check := "/machines/" + strconv.FormatInt(id, 10) + "/check"

	// A page asked for under another name (DNS rebinding) is refused.
	for _, host := range []string{"evil.example:8443", "192.0.2.10:9999", "192.0.2.11:8443", ""} {
		rec := w.do(http.MethodGet, "/", nil, func(r *http.Request) { r.Host = host })
		if rec.Code != http.StatusMisdirectedRequest {
			t.Errorf("Host %q: %d", host, rec.Code)
		}
	}
	// X-Forwarded-Host changes nothing.
	rec := w.do(http.MethodGet, "/", nil, func(r *http.Request) { r.Header.Set("X-Forwarded-Host", "evil.example") })
	wantStatus(t, rec, http.StatusOK)

	for name, mod := range map[string]func(*http.Request){
		"another origin":           func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") },
		"plain http origin":        func(r *http.Request) { r.Header.Set("Origin", "http://192.0.2.10:8443") },
		"null origin, cross-site":  func(r *http.Request) { r.Header.Set("Origin", "null"); r.Header.Set("Sec-Fetch-Site", "cross-site") },
		"no origin, no fetch site": func(r *http.Request) { r.Header.Del("Origin"); r.Header.Del("Sec-Fetch-Site") },
		"null origin only":         func(r *http.Request) { r.Header.Set("Origin", "null"); r.Header.Del("Sec-Fetch-Site") },
	} {
		w.get("/")
		if rec := w.post(check, nil, mod); rec.Code != http.StatusForbidden {
			t.Errorf("%s: %d, want 403", name, rec.Code)
		}
	}
	if n := w.core.visitCount(); n != 0 {
		t.Fatalf("%d visits from refused requests", n)
	}
	// With Referrer-Policy: no-referrer a browser sends Origin: null on
	// its own form posts; Sec-Fetch-Site tells it apart.
	w.get("/")
	rec = w.post(check, nil, func(r *http.Request) { r.Header.Set("Origin", "null"); r.Header.Set("Sec-Fetch-Site", "same-origin") })
	wantRedirect(t, rec, "/machines/"+strconv.FormatInt(id, 10))

	// Bodies are limited to 1 MiB.
	w.get("/")
	big := url.Values{"csrf": {w.csrf}, "pad": {strings.Repeat("a", 2<<20)}}
	rec = w.do(http.MethodPost, check, big)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("a 2 MiB body: %d, want 413", rec.Code)
	}
}

func TestLoginRateLimit(t *testing.T) {
	w := newWeb(t)
	w.setup()
	for i := 0; i < 5; i++ {
		if rec := w.login("wrong password " + strconv.Itoa(i)); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i, rec.Code)
		}
	}
	// The sixth attempt within a minute is refused, even with the right
	// password, and the password is not even checked.
	rec := w.login(testPassword)
	if rec.Code != http.StatusTooManyRequests || !strings.Contains(rec.Body.String(), "Too many") {
		t.Fatalf("sixth attempt: %d %s", rec.Code, rec.Body)
	}
	if !hasAudit(t, w.st, "login refused, too many failures: from "+testClientIP) {
		t.Errorf("refusal not audited: %q", auditActions(t, w.st))
	}
	// X-Forwarded-For does not move the attempt to another address.
	rec = w.do(http.MethodPost, "/login", url.Values{"csrf": {w.csrf}, "password": {testPassword}}, func(r *http.Request) {
		r.Header.Set("X-Forwarded-For", "203.0.113.9")
		r.Header.Set("X-Real-IP", "203.0.113.9")
	})
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("with X-Forwarded-For: %d", rec.Code)
	}
	// Another address is not affected.
	if rec := w.browser("192.0.2.77").login(testPassword); rec.Code != http.StatusSeeOther {
		t.Errorf("another address: %d", rec.Code)
	}
	// A minute later it works again.
	w.clock.advance(61 * time.Second)
	if rec := w.login(testPassword); rec.Code != http.StatusSeeOther {
		t.Errorf("a minute later: %d %s", rec.Code, rec.Body)
	}
}

// armoredKey makes an OpenPGP key and returns it armored: the public part,
// or with private set the secret key.
func armoredKey(t *testing.T, private bool) (string, string) {
	t.Helper()
	e, err := openpgp.NewEntity("Example Repo", "", "repo@example.invalid", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	kind := openpgp.PublicKeyType
	if private {
		kind = openpgp.PrivateKeyType
	}
	aw, err := armor.Encode(&buf, kind, nil)
	if err != nil {
		t.Fatal(err)
	}
	if private {
		err = e.SerializePrivate(aw, nil)
	} else {
		err = e.Serialize(aw)
	}
	if err != nil {
		t.Fatal(err)
	}
	aw.Close()
	return buf.String(), repokeys.Fingerprint(e)
}

func TestSettingsRepositoryKeys(t *testing.T) {
	w := loggedIn(t)
	key, fp := armoredKey(t, false)
	w.get("/settings")
	// The first step only shows the key: its fingerprint and the addresses
	// it would vouch for. Nothing is stored yet.
	rec := w.post("/settings/keys", url.Values{"key": {key}, "url": {"https://Download.Docker.com/linux/debian/"}})
	wantStatus(t, rec, http.StatusOK)
	preview := rec.Body.String()
	if !strings.Contains(preview, groupFingerprint(fp)) || !strings.Contains(preview, "https://download.docker.com/linux/debian") {
		t.Errorf("the preview does not show the key's fingerprint and address:\n%s", preview)
	}
	if keys, _ := OwnerKeys(w.st); len(keys) != 0 {
		t.Fatalf("the key was stored before the owner confirmed it: %+v", keys)
	}
	form := confirmForm(t, preview)
	if form.Get("pending") == "" || form.Get("key") != "" || form.Get("url") != "" {
		t.Errorf("the confirmation must name the previewed key by a one-time ID only: %v", form)
	}
	// Without the confirmation, or with an ID the server never gave out,
	// nothing is added.
	if rec := w.post("/settings/keys/confirm", url.Values{"pending": form["pending"]}); rec.Code == http.StatusSeeOther {
		t.Error("added without the confirmation")
	}
	if rec := w.post("/settings/keys/confirm", url.Values{"pending": {newToken()}, "confirm": {"yes"}}); rec.Code == http.StatusSeeOther {
		t.Error("added under an unknown ID")
	}
	wantRedirect(t, w.post("/settings/keys/confirm", form), "/settings#keys")
	keys, err := OwnerKeys(w.st)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].URLPattern != "https://download.docker.com/linux/debian" || keys[0].Key.Fingerprint != fp {
		t.Fatalf("owner keys %+v", keys)
	}
	// The ID works once.
	if rec := w.post("/settings/keys/confirm", form); rec.Code == http.StatusSeeOther {
		t.Error("the same preview was added twice")
	}
	page := w.get("/settings").Body.String()
	if !strings.Contains(page, groupFingerprint(fp)) || !strings.Contains(page, "https://download.docker.com/linux/debian") {
		t.Errorf("the settings page does not list the key by fingerprint and address:\n%s", page)
	}
	if !hasAudit(t, w.st, fmt.Sprintf("repository key added: key %d", keys[0].ID)) {
		t.Errorf("not audited: %q", auditActions(t, w.st))
	}

	priv, _ := armoredKey(t, true)
	for name, form := range map[string]url.Values{
		"private key":      {"key": {priv}, "url": {"https://example.com/repo"}},
		"no key":           {"key": {"hello"}, "url": {"https://example.com/repo"}},
		"official archive": {"key": {key}, "url": {"http://deb.debian.org/debian"}},
		"not http":         {"key": {key}, "url": {"ftp://example.com/repo"}},
		"dot segment":      {"key": {key}, "url": {"https://example.com/a/../b"}},
		"no address":       {"key": {key}, "url": {""}},
		"twice":            {"key": {key}, "url": {"https://download.docker.com/linux/debian"}},
	} {
		w.get("/settings")
		if rec := w.post("/settings/keys", form); rec.Code == http.StatusOK && strings.Contains(rec.Body.String(), `name="pending"`) {
			t.Errorf("%s: offered for confirmation", name)
		}
	}
	if keys, _ := OwnerKeys(w.st); len(keys) != 1 {
		t.Fatalf("owner keys after refusals: %+v", keys)
	}
	w.get("/settings")
	wantRedirect(t, w.post(fmt.Sprintf("/settings/keys/%d/remove", keys[0].ID), nil), "/settings#keys")
	if keys, _ := OwnerKeys(w.st); len(keys) != 0 {
		t.Errorf("owner keys after removal: %+v", keys)
	}
}

func TestSettingsGeneral(t *testing.T) {
	w := loggedIn(t)
	page := w.get("/settings").Body.String()
	signer, _, err := visit.ServerKey(w.st)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{ssh.FingerprintSHA256(signer.PublicKey()), "AA:BB:CC", testServerAddr, `id="bubbles"`, `id="mcp"`} {
		if !strings.Contains(html.UnescapeString(page), want) {
			t.Errorf("the settings page lacks %q", want)
		}
	}
	wantRedirect(t, w.post("/settings/general", url.Values{"schedule": {"hourly"}, "alert_level": {"all"}}), "/settings")
	if v, _ := w.st.Setting(SettingAlertLevel); v != "all" {
		t.Errorf("alert level %q", v)
	}
	if v, _ := w.st.Setting(SettingDefaultSchedule); v != "hourly" {
		t.Errorf("default schedule %q", v)
	}
	w.get("/settings")
	if rec := w.post("/settings/general", url.Values{"schedule": {"sometimes"}, "alert_level": {"all"}}); rec.Code == http.StatusSeeOther {
		t.Error("an unknown schedule was accepted")
	}
	if !hasAudit(t, w.st, "settings changed: general") {
		t.Errorf("not audited: %q", auditActions(t, w.st))
	}
	// The audit page lists the log.
	if a := w.get("/audit").Body.String(); !strings.Contains(a, "settings changed") || !strings.Contains(a, "login") {
		t.Errorf("audit page:\n%s", a)
	}
}

func TestCertificateKeptPrivateAndReused(t *testing.T) {
	dir := t.TempDir()
	ips := []net.IP{net.ParseIP("192.0.2.10")}
	cert, fp, err := LoadOrCreateCert(dir, ips)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^([0-9A-F]{2}:){31}[0-9A-F]{2}$`).MatchString(fp) {
		t.Errorf("fingerprint %q is not colon-separated SHA-256 hex", fp)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := leaf.PublicKey.(*ecdsa.PublicKey); !ok || leaf.PublicKeyAlgorithm != x509.ECDSA {
		t.Errorf("certificate key %T, want ECDSA", leaf.PublicKey)
	}
	if len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(ips[0]) {
		t.Errorf("certificate names %v", leaf.IPAddresses)
	}
	fi, err := os.Stat(filepath.Join(dir, "tls.key"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode %v (%v), want 0600", fi.Mode().Perm(), err)
	}
	// The next start uses the same certificate, so the owner's browser
	// keeps trusting it.
	_, fp2, err := LoadOrCreateCert(dir, ips)
	if err != nil || fp2 != fp {
		t.Errorf("second start: %q %v, want the same fingerprint", fp2, err)
	}
	// A key file opened up by someone is made private again.
	os.Chmod(filepath.Join(dir, "tls.key"), 0o644)
	if _, _, err := LoadOrCreateCert(dir, ips); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(filepath.Join(dir, "tls.key")); fi.Mode().Perm() != 0o600 {
		t.Errorf("key file mode %v after load, want 0600", fi.Mode().Perm())
	}
	// A symbolic link in the key's place is not followed.
	other := t.TempDir()
	os.WriteFile(filepath.Join(other, "secret"), []byte("x"), 0o600)
	link := t.TempDir()
	os.Symlink(filepath.Join(other, "secret"), filepath.Join(link, "tls.key"))
	os.WriteFile(filepath.Join(link, "tls.crt"), []byte("x"), 0o644)
	if _, _, err := LoadOrCreateCert(link, ips); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("symlinked key: %v", err)
	}
	cfg := TLSConfig(cert)
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion %x", cfg.MinVersion)
	}
}
