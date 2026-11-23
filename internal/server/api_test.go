package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/donaldsteele/telltale/internal/model"
)

// api sends one API request the way telltale mcp does: over TLS, to the
// configured address, with the token as a bearer token ("" sends none).
func (w *webClient) api(method, target, token string, mods ...func(*http.Request)) *httptest.ResponseRecorder {
	w.t.Helper()
	r := httptest.NewRequest(method, "https://"+testListen+target, nil)
	r.Host = testListen
	r.RemoteAddr = net.JoinHostPort(w.ip, "40000")
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
	r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 8443}))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	for _, m := range mods {
		m(r)
	}
	rec := httptest.NewRecorder()
	w.ui.ServeHTTP(rec, r)
	return rec
}

func (w *webClient) newToken(name string) (string, APIToken) {
	w.t.Helper()
	tok, t, err := CreateAPIToken(w.st, name, w.clock.now())
	if err != nil {
		w.t.Fatal(err)
	}
	return tok, t
}

func apiError(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var e APIError
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil || e.Error == "" {
		t.Fatalf("not a JSON error (%v): %s", err, rec.Body)
	}
	return e.Error
}

func wantJSONHeaders(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	h := rec.Header()
	if ct := h.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type %q", ct)
	}
	if h.Get("Cache-Control") != "no-store" || h.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("Cache-Control %q, X-Content-Type-Options %q", h.Get("Cache-Control"), h.Get("X-Content-Type-Options"))
	}
}

func TestAPIRejectsMissingToken(t *testing.T) {
	w := newWeb(t)
	w.setup()
	mid := w.addMachine("web01")
	w.addReport(mid, finding("ssh.root_login", model.SevWeak, "Root can log in over SSH"))
	tok, tt := w.newToken("laptop")

	for name, mod := range map[string]func(*http.Request){
		"no header": func(*http.Request) {},
		"basic": func(r *http.Request) {
			r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("admin:"+testPassword)))
		},
		"wrong token":    func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+newToken()) },
		"not a token":    func(r *http.Request) { r.Header.Set("Authorization", "Bearer x") },
		"empty bearer":   func(r *http.Request) { r.Header.Set("Authorization", "Bearer ") },
		"token as query": func(r *http.Request) { r.URL.RawQuery = "token=" + url.QueryEscape(tok) },
	} {
		b := w.browser("192.0.2." + strconv.Itoa(60+len(name)))
		rec := b.api(http.MethodGet, "/api/v1/machines", "", mod)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401: %s", name, rec.Code, rec.Body)
			continue
		}
		wantJSONHeaders(t, rec)
		if !strings.HasPrefix(rec.Header().Get("WWW-Authenticate"), "Bearer") {
			t.Errorf("%s: WWW-Authenticate %q", name, rec.Header().Get("WWW-Authenticate"))
		}
		if msg := apiError(t, rec); !strings.Contains(msg, "Bearer") && !strings.Contains(msg, "token") {
			t.Errorf("%s: unclear message %q", name, msg)
		}
	}
	// Every endpoint needs the token, the visit too.
	for _, p := range []string{"/api/v1/machines", "/api/v1/machines/1/report", "/api/v1/reports/1", "/api/v1/machines/1/compare", "/api/v1/nothing"} {
		if rec := w.browser("192.0.2.90").api(http.MethodGet, p, ""); rec.Code != http.StatusUnauthorized {
			t.Errorf("GET %s without a token: %d", p, rec.Code)
		}
	}
	if rec := w.browser("192.0.2.91").api(http.MethodPost, "/api/v1/machines/1/visit", ""); rec.Code != http.StatusUnauthorized || w.core.visitCount() != 0 {
		t.Errorf("visit without a token: %d, %d visits", rec.Code, w.core.visitCount())
	}

	// The right token is let in, with JSON that is never cached.
	rec := w.api(http.MethodGet, "/api/v1/machines", tok)
	wantStatus(t, rec, http.StatusOK)
	wantJSONHeaders(t, rec)
	var ms APIMachines
	if err := json.Unmarshal(rec.Body.Bytes(), &ms); err != nil || len(ms.Machines) != 1 || ms.Machines[0].Name != "web01" || ms.Machines[0].Latest == nil || ms.Machines[0].Worst == nil || ms.Machines[0].Worst.Key != "ssh.root_login" {
		t.Fatalf("machines (%v): %s", err, rec.Body)
	}

	// Failed tries are limited per address the way logins are; the right
	// token from that address waits too, other addresses do not.
	bad := w.browser("192.0.2.77")
	for i := 0; i < loginFailures; i++ {
		if rec := bad.api(http.MethodGet, "/api/v1/machines", newToken()); rec.Code != http.StatusUnauthorized {
			t.Fatalf("try %d: %d", i, rec.Code)
		}
	}
	rec = bad.api(http.MethodGet, "/api/v1/machines", tok)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("after %d failures: %d %q", loginFailures, rec.Code, rec.Header().Get("Retry-After"))
	}
	apiError(t, rec)
	wantStatus(t, w.api(http.MethodGet, "/api/v1/machines", tok), http.StatusOK)
	if !hasAudit(t, w.st, "api refused, too many failures: from 192.0.2.77") || !hasAudit(t, w.st, "api token refused: from 192.0.2.77") {
		t.Errorf("failures not audited: %q", auditActions(t, w.st))
	}
	w.clock.advance(loginWindow)
	wantStatus(t, bad.api(http.MethodGet, "/api/v1/machines", tok), http.StatusOK)

	// A revoked token stops working at once.
	if _, err := RevokeAPIToken(w.st, tt.ID); err != nil {
		t.Fatal(err)
	}
	if rec := w.api(http.MethodGet, "/api/v1/machines", tok); rec.Code != http.StatusUnauthorized {
		t.Errorf("revoked token: %d", rec.Code)
	}

	// The API is behind the same Host check as the UI.
	tok2, _ := w.newToken("desk")
	rec = w.api(http.MethodGet, "/api/v1/machines", tok2, func(r *http.Request) { r.Host = "telltale.example:8443" })
	if rec.Code != http.StatusMisdirectedRequest {
		t.Errorf("wrong Host: %d", rec.Code)
	}
}

var tokenRE = regexp.MustCompile(`<code id="api-token">([^<]+)</code>`)

func TestAPITokenHashedAtRest(t *testing.T) {
	w := loggedIn(t)
	w.addMachine("web01")
	w.get("/settings")

	// Made in Settings, as an owner action, and shown once.
	rec := w.post("/settings/tokens", url.Values{"name": {"laptop"}})
	wantStatus(t, rec, http.StatusOK)
	m := tokenRE.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatalf("the new token is not shown:\n%s", rec.Body)
	}
	tok := html.UnescapeString(m[1])
	raw, err := decodeToken(tok)
	if err != nil {
		t.Fatalf("token %q is not 32 random bytes: %v", tok, err)
	}
	for _, want := range []string{"telltale mcp", "--server https://" + testListen, "--fingerprint SHA256:AA:BB:CC", "--token-file /home/you/.telltale-token"} {
		if !strings.Contains(html.UnescapeString(rec.Body.String()), want) {
			t.Errorf("the page does not show %q", want)
		}
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("the page with the token may be cached: %q", rec.Header().Get("Cache-Control"))
	}
	wantStatus(t, w.api(http.MethodGet, "/api/v1/machines", tok), http.StatusOK)

	// Only the SHA-256 is kept.
	stored, err := w.st.SecretSetting(apiTokensSetting)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if !bytes.Contains(stored, []byte(hex.EncodeToString(sum[:]))) {
		t.Errorf("the stored list does not hold the token's SHA-256: %s", stored)
	}
	for _, form := range []string{tok, base64.StdEncoding.EncodeToString(raw), base64.RawStdEncoding.EncodeToString(raw), hex.EncodeToString(raw), string(raw)} {
		if bytes.Contains(stored, []byte(form)) {
			t.Errorf("the stored list holds the token itself (%q): %s", form, stored)
		}
	}
	db, err := os.ReadFile(filepath.Join(w.dir, "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(db, []byte(tok)) || bytes.Contains(db, raw) {
		t.Error("the database file holds the token")
	}

	// It is never shown again.
	rec = w.get("/settings")
	if strings.Contains(rec.Body.String(), tok) {
		t.Error("the settings page shows the token again")
	}
	if !strings.Contains(rec.Body.String(), "laptop") {
		t.Error("the settings page does not list the token by name")
	}
	if !hasAudit(t, w.st, "api token created: token 1 (laptop)") {
		t.Errorf("creation not audited: %q", auditActions(t, w.st))
	}
	for _, e := range auditActions(t, w.st) {
		if strings.Contains(e, tok) {
			t.Errorf("the audit log holds the token: %q", e)
		}
	}

	// Names are checked; a second token of the same name is refused.
	for _, name := range []string{"", "laptop", "a\x1bb", strings.Repeat("x", 65), "<b>"} {
		w.get("/settings")
		if rec := w.post("/settings/tokens", url.Values{"name": {name}}); rec.Code != http.StatusBadRequest || tokenRE.MatchString(rec.Body.String()) {
			t.Errorf("name %q: %d", name, rec.Code)
		}
	}
	// Without the session's CSRF token nothing is made.
	if rec := w.post("/settings/tokens", url.Values{"name": {"desk"}, "csrf": {"x"}}); rec.Code != http.StatusForbidden {
		t.Errorf("no CSRF: %d", rec.Code)
	}

	// Revoking is an owner action too, and audited.
	w.get("/settings")
	wantRedirect(t, w.post("/settings/tokens/1/revoke", nil), "/settings#mcp")
	if rec := w.api(http.MethodGet, "/api/v1/machines", tok); rec.Code != http.StatusUnauthorized {
		t.Errorf("revoked token: %d", rec.Code)
	}
	if !hasAudit(t, w.st, "api token revoked: token 1 (laptop)") {
		t.Errorf("revocation not audited: %q", auditActions(t, w.st))
	}
	w.get("/settings")
	if rec := w.post("/settings/tokens/1/revoke", nil); rec.Code != http.StatusNotFound {
		t.Errorf("revoking twice: %d", rec.Code)
	}
}

func bodyOf(s string) io.ReadCloser { return io.NopCloser(strings.NewReader(s)) }

func TestAPIEndpoints(t *testing.T) {
	w := newWeb(t)
	w.setup()
	tok, _ := w.newToken("laptop")
	mid := w.addMachine("web01")
	other := w.addMachine("db01")
	r1 := w.addReport(mid, finding("a", model.SevWeak, "A"), finding("b", model.SevBackdoor, "B"))
	w.clock.advance(time.Hour)
	r2 := w.addReport(mid, finding("b", model.SevBackdoor, "B"), finding("c", model.SevNote, "C"))
	r3 := w.addReport(other, finding("x", model.SevNote, "X"))

	var rep APIReport
	rec := w.api(http.MethodGet, "/api/v1/machines/"+strconv.FormatInt(mid, 10)+"/report", tok)
	wantStatus(t, rec, http.StatusOK)
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil || rep.ID != r2 || rep.MachineID != mid || rep.Machine != "web01" || len(rep.Report.Findings) != 2 {
		t.Fatalf("latest report (%v): %s", err, rec.Body)
	}
	rec = w.api(http.MethodGet, "/api/v1/reports/"+strconv.FormatInt(r1, 10), tok)
	wantStatus(t, rec, http.StatusOK)
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil || rep.ID != r1 || rep.Report.Findings[0].Key != "a" {
		t.Fatalf("report (%v): %s", err, rec.Body)
	}
	for _, p := range []string{"/api/v1/reports/999", "/api/v1/reports/x", "/api/v1/machines/999/report", "/api/v1/machines/x/report"} {
		rec := w.api(http.MethodGet, p, tok)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: %d", p, rec.Code)
		}
		apiError(t, rec)
	}
	empty := w.addMachine("new01")
	if rec := w.api(http.MethodGet, "/api/v1/machines/"+strconv.FormatInt(empty, 10)+"/report", tok); rec.Code != http.StatusNotFound || !strings.Contains(apiError(t, rec), "not been visited") {
		t.Errorf("unvisited machine: %d %s", rec.Code, rec.Body)
	}

	// Compare: what is new in b, what went away since a, what stayed.
	var cmp APIComparison
	q := "/api/v1/machines/" + strconv.FormatInt(mid, 10) + "/compare?a=" + strconv.FormatInt(r1, 10) + "&b=" + strconv.FormatInt(r2, 10)
	rec = w.api(http.MethodGet, q, tok)
	wantStatus(t, rec, http.StatusOK)
	if err := json.Unmarshal(rec.Body.Bytes(), &cmp); err != nil {
		t.Fatal(err)
	}
	keys := func(fs []model.Finding) string {
		var k []string
		for _, f := range fs {
			k = append(k, f.Key)
		}
		return strings.Join(k, ",")
	}
	if cmp.A.ID != r1 || cmp.B.ID != r2 || keys(cmp.New) != "c" || keys(cmp.Resolved) != "a" || keys(cmp.Still) != "b" {
		t.Errorf("compare: %s", rec.Body)
	}
	// Without a and b: the latest against the one before it.
	rec = w.api(http.MethodGet, "/api/v1/machines/"+strconv.FormatInt(mid, 10)+"/compare", tok)
	wantStatus(t, rec, http.StatusOK)
	if err := json.Unmarshal(rec.Body.Bytes(), &cmp); err != nil || cmp.A.ID != r1 || cmp.B.ID != r2 {
		t.Errorf("compare by default (%v): %s", err, rec.Body)
	}
	// Another machine's report is not this machine's.
	rec = w.api(http.MethodGet, "/api/v1/machines/"+strconv.FormatInt(mid, 10)+"/compare?a="+strconv.FormatInt(r3, 10)+"&b="+strconv.FormatInt(r2, 10), tok)
	if rec.Code != http.StatusNotFound {
		t.Errorf("compare with another machine's report: %d", rec.Code)
	}
	rec = w.api(http.MethodGet, "/api/v1/machines/"+strconv.FormatInt(other, 10)+"/compare", tok)
	if rec.Code != http.StatusNotFound || !strings.Contains(apiError(t, rec), "earlier report") {
		t.Errorf("compare with one report: %d %s", rec.Code, rec.Body)
	}

	// A visit that ends at once says so.
	rec = w.api(http.MethodPost, "/api/v1/machines/"+strconv.FormatInt(mid, 10)+"/visit", tok)
	wantStatus(t, rec, http.StatusOK)
	var v APIVisit
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil || v.Status != "done" {
		t.Errorf("visit (%v): %s", err, rec.Body)
	}
	if !hasAudit(t, w.st, "check now: machine 1 by token 1") {
		t.Errorf("visit not audited: %q", auditActions(t, w.st))
	}
}

func TestAPINeverExposesOwnerActions(t *testing.T) {
	w := newWeb(t)
	w.setup()
	tok, _ := w.newToken("laptop")
	mid := w.addMachine("web01")
	rid := w.addReport(mid, finding("a", model.SevWeak, "A"))
	m, r := strconv.FormatInt(mid, 10), strconv.FormatInt(rid, 10)
	w.core.acceptable[mid] = Acceptable{ReportID: rid, With: map[string][]string{"a": nil}}

	// The API's view of the core has no owner action in it at all.
	bt := reflect.TypeFor[apiBackend]()
	for _, name := range []string{"MarkClean", "AcceptChanges", "AddException"} {
		if _, ok := bt.MethodByName(name); ok {
			t.Errorf("the API can reach %s", name)
		}
	}
	st := reflect.TypeFor[apiStore]()
	for _, name := range []string{"AddException", "RemoveException", "PutSnapshot", "UpdateMachine", "AddMachine", "SetSecretSetting", "SetSetting", "PutReport"} {
		if _, ok := st.MethodByName(name); ok {
			t.Errorf("the API can reach the store's %s", name)
		}
	}

	paths := []string{
		"/api/v1/machines/" + m + "/clean",
		"/api/v1/machines/" + m + "/clean?report=" + r,
		"/api/v1/machines/" + m + "/accept",
		"/api/v1/machines/" + m + "/accept?report=" + r + "&all=1",
		"/api/v1/machines/" + m + "/exception",
		"/api/v1/machines/" + m + "/exception?report=" + r + "&key=a",
		"/api/v1/machines/" + m + "/exception/remove",
		"/api/v1/machines/" + m + "/exception/remove?exception=1",
		"/api/v1/machines/" + m + "/exceptions/1",
		"/api/v1/exceptions/1",
		"/api/v1/machines/" + m + "/changes",
		"/api/v1/machines/" + m + "/snapshot",
		"/api/v1/machines/" + m + "/schedule",
		"/api/v1/machines/" + m + "/check",
		"/api/v1/machines/" + m + "/enrolled",
		"/api/v1/machines/" + m + "/report",
		"/api/v1/machines/" + m + "/visit",
		"/api/v1/machines/" + m,
		"/api/v1/machines",
		"/api/v1/reports/" + r,
		"/api/v1/reports/" + r + "/accept",
		"/api/v1/reports/" + r + "/clean",
		"/api/v1/enrol",
		"/api/v1/enrol/confirm",
		"/api/v1/settings",
		"/api/v1/settings/tokens",
		"/api/v1/settings/password",
		"/api/v1/settings/keys",
		"/api/v1/audit",
		"/api/v1/tokens",
		"/api/v2/machines/" + m + "/clean",
		"/api/machines/" + m + "/clean",
	}
	read := map[string]bool{"/api/v1/machines": true, "/api/v1/machines/" + m + "/report": true, "/api/v1/reports/" + r: true}
	for _, p := range paths {
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodGet} {
			if method == http.MethodGet && read[p] {
				continue
			}
			if method == http.MethodPost && p == "/api/v1/machines/"+m+"/visit" {
				continue
			}
			form := url.Values{"report": {r}, "all": {"1"}, "key": {"a"}, "confirm": {"yes"}, "note": {"x"}}
			rec := w.api(method, p, tok, func(req *http.Request) {
				req.Body = http.NoBody
				if method != http.MethodGet {
					req.Body = bodyOf(form.Encode())
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				}
			})
			if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s %s: %d, want 404 or 405: %s", method, p, rec.Code, rec.Body)
			}
		}
	}
	w.core.mu.Lock()
	defer w.core.mu.Unlock()
	if len(w.core.cleans)+len(w.core.accepts)+len(w.core.exceptions)+len(w.core.removed) != 0 || len(w.core.visits) != 0 {
		t.Errorf("an owner action ran through the API: %v %v %v %v", w.core.cleans, w.core.accepts, w.core.exceptions, w.core.visits)
	}
	if ex, err := w.st.Exceptions(mid); err != nil || len(ex) != 0 {
		t.Errorf("exceptions: %v %v", ex, err)
	}
}

func TestAPIIgnoresSessionCookie(t *testing.T) {
	w := loggedIn(t)
	mid := w.addMachine("web01")
	path := "/api/v1/machines/" + strconv.FormatInt(mid, 10) + "/visit"
	withSession := func(r *http.Request) {
		for _, c := range w.jar {
			r.AddCookie(c)
		}
	}
	if _, ok := w.jar[sessionCookie]; !ok {
		t.Fatal("no session cookie")
	}
	// A logged-in browser gets nothing from the API: not a read, and not a
	// visit even with the page's CSRF token and Origin.
	rec := w.api(http.MethodGet, "/api/v1/machines", "", withSession)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(apiError(t, rec), "Bearer") {
		t.Errorf("read with a session: %d %s", rec.Code, rec.Body)
	}
	rec = w.api(http.MethodPost, path, "", withSession, func(r *http.Request) {
		r.Body = bodyOf(url.Values{"csrf": {w.csrf}}.Encode())
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", testOrigin)
		r.Header.Set("Sec-Fetch-Site", "same-origin")
	})
	if rec.Code != http.StatusUnauthorized || w.core.visitCount() != 0 {
		t.Errorf("visit with a session: %d, %d visits", rec.Code, w.core.visitCount())
	}
	// With a token as well, the token decides and the cookie is ignored.
	tok, _ := w.newToken("laptop")
	wantStatus(t, w.api(http.MethodGet, "/api/v1/machines", tok, withSession), http.StatusOK)
	// And a token never opens the web UI.
	rec = w.do(http.MethodGet, "/", nil, func(r *http.Request) {
		r.Header.Del("Cookie")
		r.Header.Set("Authorization", "Bearer "+tok)
	})
	wantRedirect(t, rec, "/login")
	rec = w.do(http.MethodPost, "/machines/"+strconv.FormatInt(mid, 10)+"/check", url.Values{}, func(r *http.Request) {
		r.Header.Del("Cookie")
		r.Header.Set("Authorization", "Bearer "+tok)
	})
	if rec.Code != http.StatusForbidden || w.core.visitCount() != 0 {
		t.Errorf("UI check now with a token: %d, %d visits", rec.Code, w.core.visitCount())
	}
}

func TestVisitRateLimited(t *testing.T) {
	w := newWeb(t)
	w.setup()
	tokA, _ := w.newToken("laptop")
	tokB, _ := w.newToken("desk")
	m1, m2 := w.addMachine("web01"), w.addMachine("db01")
	visit := func(tok string, id int64) *httptest.ResponseRecorder {
		return w.api(http.MethodPost, "/api/v1/machines/"+strconv.FormatInt(id, 10)+"/visit", tok)
	}
	wantStatus(t, visit(tokA, m1), http.StatusOK)
	rec := visit(tokA, m1)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second visit within a minute: %d", rec.Code)
	}
	if ra, err := strconv.Atoi(rec.Header().Get("Retry-After")); err != nil || ra < 1 || ra > 60 {
		t.Errorf("Retry-After %q", rec.Header().Get("Retry-After"))
	}
	apiError(t, rec)
	if n := w.core.visitCount(); n != 1 {
		t.Errorf("%d visits, want 1", n)
	}
	// Per machine and per token.
	wantStatus(t, visit(tokA, m2), http.StatusOK)
	wantStatus(t, visit(tokB, m1), http.StatusOK)
	w.clock.advance(59 * time.Second)
	if rec := visit(tokA, m1); rec.Code != http.StatusTooManyRequests {
		t.Errorf("after 59 s: %d", rec.Code)
	}
	w.clock.advance(time.Second)
	wantStatus(t, visit(tokA, m1), http.StatusOK)

	// A running visit is a plain 409, and since no visit started it does
	// not use up the minute: the clock does not move below.
	w.clock.advance(time.Minute)
	w.core.mu.Lock()
	w.core.visiting[m1] = true
	w.core.mu.Unlock()
	rec = visit(tokA, m1)
	if rec.Code != http.StatusConflict || !strings.Contains(apiError(t, rec), "A visit to this machine is running") {
		t.Errorf("visit while one runs: %d %s", rec.Code, rec.Body)
	}
	w.core.mu.Lock()
	w.core.visiting[m1] = false
	w.core.visitErr = ErrVisitRunning
	w.core.mu.Unlock()
	rec = visit(tokA, m1)
	if rec.Code != http.StatusConflict || !strings.Contains(apiError(t, rec), "A visit to this machine is running") {
		t.Errorf("visit that finds one running: %d %s", rec.Code, rec.Body)
	}
	w.core.mu.Lock()
	w.core.visitErr = nil
	w.core.mu.Unlock()
	wantStatus(t, visit(tokA, m1), http.StatusOK)
	if rec := visit(tokA, m1); rec.Code != http.StatusTooManyRequests {
		t.Errorf("a visit that started uses up the minute: %d", rec.Code)
	}
	// A visit that fails says so, escaped.
	w.core.mu.Lock()
	w.core.visitErr = errors.New("ssh: \x1b[31mno route")
	w.core.mu.Unlock()
	w.clock.advance(time.Minute)
	rec = visit(tokA, m1)
	wantStatus(t, rec, http.StatusOK)
	var v APIVisit
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil || v.Status != "failed" || strings.Contains(v.Message, "\x1b") || !strings.Contains(v.Message, `\x1b`) {
		t.Errorf("failed visit (%v): %+v", err, v)
	}
	// Unknown machines are 404 and use up nothing.
	if rec := visit(tokA, 999); rec.Code != http.StatusNotFound {
		t.Errorf("unknown machine: %d", rec.Code)
	}
}

func TestAPIFailureLimitCountsOnlyWrongTokens(t *testing.T) {
	w := newWeb(t)
	w.setup()
	w.addMachine("web01")
	tok, _ := w.newToken("laptop")
	refusals := func(ip string) []string {
		var out []string
		for _, e := range auditActions(t, w.st) {
			if strings.HasPrefix(e, "api ") && strings.HasSuffix(e, "from "+ip) {
				out = append(out, e)
			}
		}
		return out
	}

	// Valid requests in parallel from one address (an MCP client's tool
	// calls run at once) all get in, and none is recorded as a failure.
	var wg sync.WaitGroup
	codes := make([]int, 10)
	for i := range codes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes[i] = w.api(http.MethodGet, "/api/v1/machines", tok).Code
		}()
	}
	wg.Wait()
	for i, c := range codes {
		if c != http.StatusOK {
			t.Errorf("parallel request %d: %d", i, c)
		}
	}
	if r := refusals(testClientIP); len(r) != 0 {
		t.Errorf("valid requests audited as failures: %q", r)
	}

	// Requests that carry no token (a web page's preflights, a browser
	// opening the address) are refused but never counted, so they cannot
	// lock out the owner's token.
	page := w.browser("192.0.2.80")
	for i := 0; i < 2*loginFailures; i++ {
		method, mod := http.MethodGet, func(*http.Request) {}
		if i%2 == 0 {
			method, mod = http.MethodOptions, func(r *http.Request) {
				r.Header.Set("Origin", "https://evil.example")
				r.Header.Set("Access-Control-Request-Method", "GET")
				r.Header.Set("Access-Control-Request-Headers", "authorization")
			}
		}
		if rec := page.api(method, "/api/v1/machines", "", mod); rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s without a token: %d", method, rec.Code)
		}
	}
	wantStatus(t, page.api(http.MethodGet, "/api/v1/machines", tok), http.StatusOK)
	if r := refusals("192.0.2.80"); len(r) != 0 {
		t.Errorf("requests without a token audited as failures: %q", r)
	}

	// Wrong tokens are counted: after loginFailures of them the address
	// waits, the right token from it too.
	bad := w.browser("192.0.2.81")
	for i := 0; i < loginFailures; i++ {
		if rec := bad.api(http.MethodGet, "/api/v1/machines", newToken()); rec.Code != http.StatusUnauthorized {
			t.Fatalf("wrong token %d: %d", i, rec.Code)
		}
	}
	if rec := bad.api(http.MethodGet, "/api/v1/machines", newToken()); rec.Code != http.StatusTooManyRequests {
		t.Errorf("wrong token %d: %d", loginFailures+1, rec.Code)
	}
	if rec := bad.api(http.MethodGet, "/api/v1/machines", tok); rec.Code != http.StatusTooManyRequests {
		t.Errorf("right token while over the limit: %d", rec.Code)
	}
	if !hasAudit(t, w.st, "api refused, too many failures: from 192.0.2.81") {
		t.Errorf("lockout not audited: %q", refusals("192.0.2.81"))
	}
	// Another address is not affected.
	wantStatus(t, page.api(http.MethodGet, "/api/v1/machines", tok), http.StatusOK)
}
