package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/donaldsteele/telltale/internal/escape"
	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/store"
)

// The JSON API under /api/v1/ is what telltale mcp talks to. It is served on
// the web UI's listener, behind the same Host check and TLS, but it is a
// separate door: it takes only a bearer token made in Settings, never the
// browser session, so a page cannot make a browser call it.
//
// It reads machines and reports, and it can ask for a visit. Nothing else:
// taking a snapshot, accepting changes and adding or removing exceptions are the owner's
// decisions in the web UI and are not reachable from here. apiBackend and
// apiStore are all the API is given, so that holds by construction.

// apiBackend is what the API may do with the core.
type apiBackend interface {
	VisitNow(ctx context.Context, machineID int64) (int64, error)
	VisitError(machineID int64) (string, error)
	Visiting(machineID int64) bool
}

// apiStore is what the API may do with the store: read, and append to the
// audit log.
type apiStore interface {
	Machine(id int64) (*store.Machine, error)
	Machines() ([]store.Machine, error)
	Reports(machineID int64, limit int) ([]store.ReportMeta, error)
	ReportOnly(reportID int64) (*model.Report, int64, error)
	SecretSetting(key string) ([]byte, error)
	Audit(actor, action, detail string) error
}

// apiTokensSetting is the sealed setting that holds the API tokens: names
// and SHA-256 hashes only. A token is 32 random bytes, so a plain hash is
// enough; the token itself is shown once and never stored. Sealing the list
// also means nobody with only the database file can add a token.
const apiTokensSetting = "api_tokens"

const (
	maxAPITokens = 32
	// visitEvery is how often one token may ask for a visit to one
	// machine.
	visitEvery = time.Minute
	actorAPI   = "api"
)

// errNoAPIToken means there is no token with that ID.
var errNoAPIToken = errors.New("there is no such API token")

var tokenNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$`)

// APIToken is one API token as stored: its SHA-256, never the token.
type APIToken struct {
	ID      int64     `json:"id"`
	Name    string    `json:"name"`
	SHA256  string    `json:"sha256"`
	Created time.Time `json:"created"`
}

type apiTokenList struct {
	Next   int64      `json:"next"`
	Tokens []APIToken `json:"tokens"`
}

// apiTokensMu serializes changes to the token list within this process.
var apiTokensMu sync.Mutex

type secretReader interface {
	SecretSetting(key string) ([]byte, error)
}

func loadAPITokens(st secretReader) (apiTokenList, error) {
	var l apiTokenList
	b, err := st.SecretSetting(apiTokensSetting)
	if err != nil || len(b) == 0 {
		return l, err
	}
	if err := json.Unmarshal(b, &l); err != nil {
		return apiTokenList{}, fmt.Errorf("server: the stored API tokens are unreadable: %w", err)
	}
	return l, nil
}

func saveAPITokens(st *store.Store, l apiTokenList) error {
	b, err := json.Marshal(l)
	if err != nil {
		return err
	}
	return st.SetSecretSetting(apiTokensSetting, b)
}

// APITokens lists the API tokens, oldest first.
func APITokens(st *store.Store) ([]APIToken, error) {
	l, err := loadAPITokens(st)
	return l.Tokens, err
}

// CreateAPIToken makes a token with a name the owner chose and returns it;
// only its hash is kept. Names are short plain text (letters, digits,
// spaces, dots, dashes, underscores) and unique.
func CreateAPIToken(st *store.Store, name string, now time.Time) (string, APIToken, error) {
	if !tokenNameRE.MatchString(name) {
		return "", APIToken{}, errors.New("give the token a short name: letters, digits, spaces, dots, dashes and underscores, up to 64, starting with a letter or digit")
	}
	apiTokensMu.Lock()
	defer apiTokensMu.Unlock()
	l, err := loadAPITokens(st)
	if err != nil {
		return "", APIToken{}, err
	}
	if len(l.Tokens) >= maxAPITokens {
		return "", APIToken{}, fmt.Errorf("there can be at most %d tokens; revoke one first", maxAPITokens)
	}
	if slices.ContainsFunc(l.Tokens, func(t APIToken) bool { return strings.EqualFold(t.Name, name) }) {
		return "", APIToken{}, errors.New("there is already a token with that name")
	}
	tok := newToken()
	sum, _ := tokenHash(tok)
	l.Next++
	t := APIToken{ID: l.Next, Name: name, SHA256: hex.EncodeToString(sum[:]), Created: now.UTC()}
	l.Tokens = append(l.Tokens, t)
	if err := saveAPITokens(st, l); err != nil {
		return "", APIToken{}, err
	}
	return tok, t, nil
}

// RevokeAPIToken removes a token; it is refused from the next request on.
func RevokeAPIToken(st *store.Store, id int64) (APIToken, error) {
	apiTokensMu.Lock()
	defer apiTokensMu.Unlock()
	l, err := loadAPITokens(st)
	if err != nil {
		return APIToken{}, err
	}
	i := slices.IndexFunc(l.Tokens, func(t APIToken) bool { return t.ID == id })
	if i < 0 {
		return APIToken{}, errNoAPIToken
	}
	t := l.Tokens[i]
	l.Tokens = slices.Delete(l.Tokens, i, i+1)
	return t, saveAPITokens(st, l)
}

// findAPIToken returns the stored token a presented one hashes to. Every
// stored hash is compared, each in constant time.
func findAPIToken(st secretReader, presented string) (APIToken, bool, error) {
	sum, ok := tokenHash(presented)
	if !ok {
		return APIToken{}, false, nil
	}
	l, err := loadAPITokens(st)
	if err != nil {
		return APIToken{}, false, err
	}
	var found APIToken
	match := 0
	for _, t := range l.Tokens {
		want, err := hex.DecodeString(t.SHA256)
		if err != nil || len(want) != sha256.Size {
			continue
		}
		if subtle.ConstantTimeCompare(sum[:], want) == 1 {
			found, match = t, 1
		}
	}
	return found, match == 1, nil
}

// The API's JSON. Strings in reports are the machine's own text, unescaped:
// JSON is the source of truth, and whoever shows them escapes them (telltale
// mcp does, with escape.Terminal).

// APIError is every error the API answers.
type APIError struct {
	Error string `json:"error"`
}

// APIReportMeta describes a report without its findings.
type APIReportMeta struct {
	ID       int64     `json:"id"`
	Time     time.Time `json:"time"`
	ExitCode int       `json:"exit_code"`
	Findings int       `json:"findings"`
}

// APIFindingBrief names a finding.
type APIFindingBrief struct {
	Key      string         `json:"key"`
	Severity model.Severity `json:"severity"`
	Title    string         `json:"title"`
}

// APIMachine is one machine in GET /api/v1/machines. Snapshot is whether it
// has a known-good snapshot; VisitError is the last failed visit's error,
// escaped and bounded by the server.
type APIMachine struct {
	ID         int64            `json:"id"`
	Name       string           `json:"name"`
	Addr       string           `json:"addr"`
	Schedule   string           `json:"schedule"`
	Snapshot   bool             `json:"snapshot"`
	LastVisit  *time.Time       `json:"last_visit,omitempty"`
	Visiting   bool             `json:"visiting"`
	VisitError string           `json:"visit_error,omitempty"`
	Latest     *APIReportMeta   `json:"latest_report,omitempty"`
	Worst      *APIFindingBrief `json:"worst_finding,omitempty"`
}

// APIMachines is GET /api/v1/machines.
type APIMachines struct {
	Machines []APIMachine `json:"machines"`
}

// APIReport is one stored report.
type APIReport struct {
	ID        int64         `json:"id"`
	MachineID int64         `json:"machine_id"`
	Machine   string        `json:"machine"`
	Report    *model.Report `json:"report"`
}

// APIComparison compares two of a machine's reports by finding: New are in
// B and not in A, Resolved in A and not in B, Still in both (as in B).
type APIComparison struct {
	MachineID int64           `json:"machine_id"`
	Machine   string          `json:"machine"`
	A         APIReportMeta   `json:"a"`
	B         APIReportMeta   `json:"b"`
	New       []model.Finding `json:"new"`
	Resolved  []model.Finding `json:"resolved"`
	Still     []model.Finding `json:"still"`
}

// APIVisit answers POST /api/v1/machines/{id}/visit. Status is "started"
// (still running), "done" (ReportID is its report) or "failed".
type APIVisit struct {
	Status   string `json:"status"`
	ReportID int64  `json:"report_id,omitempty"`
	Message  string `json:"message"`
}

type api struct {
	core    apiBackend
	store   apiStore
	now     func() time.Time
	ctx     context.Context
	logf    func(format string, args ...any)
	visits  *sync.WaitGroup
	limiter *limiter // failed token attempts, per peer address
	mux     *http.ServeMux

	visitMu   sync.Mutex
	lastVisit map[[2]int64]time.Time // (token, machine) → last request
}

type apiTokenKey struct{}

func newAPI(core apiBackend, st apiStore, now func() time.Time, ctx context.Context, logf func(string, ...any), visits *sync.WaitGroup) *api {
	a := &api{core: core, store: st, now: now, ctx: ctx, logf: logf, visits: visits, limiter: newLimiter(), lastVisit: map[[2]int64]time.Time{}}
	m := http.NewServeMux()
	m.HandleFunc("GET /api/v1/machines", a.machines)
	m.HandleFunc("GET /api/v1/machines/{id}/report", a.latestReport)
	m.HandleFunc("GET /api/v1/reports/{id}", a.report)
	m.HandleFunc("GET /api/v1/machines/{id}/compare", a.compare)
	m.HandleFunc("POST /api/v1/machines/{id}/visit", a.visit)
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeAPIError(w, http.StatusNotFound, "There is no such API endpoint.")
	})
	a.mux = m
	return a
}

func (a *api) audit(actor, action, format string, args ...any) {
	if err := a.store.Audit(actor, action, fmt.Sprintf(format, args...)); err != nil {
		a.logf("telltale server: could not write \"%s\" to the audit log: %v", action, err)
	}
}

func writeAPI(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		status, b = http.StatusInternalServerError, []byte(`{"error":"The answer could not be written."}`)
	}
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	w.Write(append(b, '\n'))
}

func writeAPIError(w http.ResponseWriter, status int, msg string) {
	writeAPI(w, status, APIError{Error: msg})
}

func (a *api) serverError(w http.ResponseWriter, r *http.Request, err error) {
	a.logf("telltale server: %s %s: %v", r.Method, r.URL.Path, err)
	writeAPIError(w, http.StatusInternalServerError, "Something went wrong on the server: "+escape.Terminal(err.Error()))
}

// bearerToken is the token in "Authorization: Bearer <token>"; any other
// form, or more than one Authorization header, is no token.
func bearerToken(r *http.Request) (string, bool) {
	vs := r.Header.Values("Authorization")
	if len(vs) != 1 {
		return "", false
	}
	scheme, tok, ok := strings.Cut(vs[0], " ")
	tok = strings.TrimSpace(tok)
	return tok, ok && strings.EqualFold(scheme, "Bearer") && tok != ""
}

// ServeHTTP checks the token and hands the request to its endpoint. The
// session cookie is never read: a request with only a session is refused
// like one with nothing.
func (a *api) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	tok, ok := a.authenticate(w, r)
	if !ok {
		return
	}
	a.mux.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), apiTokenKey{}, tok)))
}

// authenticate checks the bearer token. Wrong tokens are counted per peer
// address like failed logins: after loginFailures in a minute the address
// waits, even with a good token. Only a token that was presented and did
// not match counts. A request with no token (a web page's CORS preflight,
// a browser opening the address) is refused but not counted, so a page
// cannot lock out the owner's token, and valid requests running in
// parallel never count at all.
func (a *api) authenticate(w http.ResponseWriter, r *http.Request) (APIToken, bool) {
	ip := peerIP(r)
	now := a.now()
	if over, first := a.limiter.over(ip, now); over {
		if first {
			a.audit(actorAPI, "api refused, too many failures", "from %s", ip)
		}
		w.Header().Set("Retry-After", strconv.Itoa(int(loginWindow.Seconds())))
		writeAPIError(w, http.StatusTooManyRequests, "Too many failed token attempts from your address. Wait a minute and try again.")
		return APIToken{}, false
	}
	unauthorized := func(msg string) (APIToken, bool) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="telltale"`)
		writeAPIError(w, http.StatusUnauthorized, msg)
		return APIToken{}, false
	}
	presented, ok := bearerToken(r)
	if !ok {
		if _, err := r.Cookie(sessionCookie); err == nil {
			return unauthorized("The API does not take a browser session. Send a token from the web UI's settings as Authorization: Bearer <token>.")
		}
		return unauthorized("The API needs a token from the web UI's settings, sent as Authorization: Bearer <token>.")
	}
	t, found, err := findAPIToken(a.store, presented)
	if err != nil {
		// The server's trouble, not a failed try.
		a.serverError(w, r, err)
		return APIToken{}, false
	}
	if !found {
		a.limiter.fail(ip, now)
		a.audit(actorAPI, "api token refused", "from %s", ip)
		return unauthorized("That token is not valid: it was revoked, or it was never made on this server.")
	}
	return t, true
}

func tokenOf(r *http.Request) APIToken {
	t, _ := r.Context().Value(apiTokenKey{}).(APIToken)
	return t
}

// machine loads the machine {id} names; on failure it has answered.
func (a *api) machine(w http.ResponseWriter, r *http.Request) (*store.Machine, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeAPIError(w, http.StatusNotFound, "There is no such machine.")
		return nil, false
	}
	m, err := a.store.Machine(id)
	if err != nil {
		writeAPIError(w, http.StatusNotFound, "There is no such machine.")
		return nil, false
	}
	return m, true
}

func meta(m store.ReportMeta) APIReportMeta {
	return APIReportMeta{ID: m.ID, Time: m.Time, ExitCode: m.ExitCode, Findings: m.Findings}
}

func (a *api) machines(w http.ResponseWriter, r *http.Request) {
	ms, err := a.store.Machines()
	if err != nil {
		a.serverError(w, r, err)
		return
	}
	out := APIMachines{Machines: make([]APIMachine, 0, len(ms))}
	for _, m := range ms {
		am := APIMachine{ID: m.ID, Name: m.Name, Addr: m.Addr, Schedule: m.Schedule, Snapshot: m.Clean, LastVisit: m.LastVisit, Visiting: a.core.Visiting(m.ID)}
		am.VisitError, _ = a.core.VisitError(m.ID)
		metas, err := a.store.Reports(m.ID, 1)
		if err != nil {
			a.serverError(w, r, err)
			return
		}
		if len(metas) > 0 {
			lm := meta(metas[0])
			am.Latest = &lm
			rep, _, err := a.store.ReportOnly(metas[0].ID)
			if err != nil {
				a.serverError(w, r, err)
				return
			}
			if f := worst(rep.Findings); f != nil {
				am.Worst = &APIFindingBrief{Key: f.Key, Severity: f.Severity, Title: f.Title}
			}
		}
		out.Machines = append(out.Machines, am)
	}
	writeAPI(w, http.StatusOK, out)
}

func (a *api) latestReport(w http.ResponseWriter, r *http.Request) {
	m, ok := a.machine(w, r)
	if !ok {
		return
	}
	metas, err := a.store.Reports(m.ID, 1)
	if err != nil {
		a.serverError(w, r, err)
		return
	}
	if len(metas) == 0 {
		writeAPIError(w, http.StatusNotFound, "This machine has not been visited yet, so it has no report.")
		return
	}
	a.writeReport(w, r, metas[0].ID)
}

func (a *api) report(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeAPIError(w, http.StatusNotFound, "There is no such report.")
		return
	}
	a.writeReport(w, r, id)
}

func (a *api) writeReport(w http.ResponseWriter, r *http.Request, id int64) {
	rep, mid, err := a.store.ReportOnly(id)
	if err != nil {
		writeAPIError(w, http.StatusNotFound, "There is no such report.")
		return
	}
	out := APIReport{ID: id, MachineID: mid, Report: rep}
	if m, err := a.store.Machine(mid); err == nil {
		out.Machine = m.Name
	}
	writeAPI(w, http.StatusOK, out)
}

// findingKey identifies a finding across reports.
func findingKey(f model.Finding) string {
	if f.Key != "" {
		return f.Key
	}
	return f.ID + "\x00" + f.Title
}

// compare compares two of the machine's reports, ?a= and ?b=. Without b it
// takes the latest report; without a, the report before b.
func (a *api) compare(w http.ResponseWriter, r *http.Request) {
	m, ok := a.machine(w, r)
	if !ok {
		return
	}
	metas, err := a.store.Reports(m.ID, 0)
	if err != nil {
		a.serverError(w, r, err)
		return
	}
	pick := func(name string, def func() (store.ReportMeta, bool)) (store.ReportMeta, bool) {
		v := r.URL.Query().Get(name)
		if v == "" {
			return def()
		}
		id, err := strconv.ParseInt(v, 10, 64)
		if i := slices.IndexFunc(metas, func(x store.ReportMeta) bool { return x.ID == id }); err == nil && i >= 0 {
			return metas[i], true
		}
		writeAPIError(w, http.StatusNotFound, "This machine has no report "+strconv.Quote(v)+".")
		return store.ReportMeta{}, false
	}
	bm, ok := pick("b", func() (store.ReportMeta, bool) {
		if len(metas) == 0 {
			writeAPIError(w, http.StatusNotFound, "This machine has not been visited yet, so it has no report.")
			return store.ReportMeta{}, false
		}
		return metas[0], true
	})
	if !ok {
		return
	}
	am, ok := pick("a", func() (store.ReportMeta, bool) {
		i := slices.IndexFunc(metas, func(x store.ReportMeta) bool { return x.ID == bm.ID })
		if i+1 >= len(metas) {
			writeAPIError(w, http.StatusNotFound, "There is no earlier report to compare with.")
			return store.ReportMeta{}, false
		}
		return metas[i+1], true
	})
	if !ok {
		return
	}
	ra, _, err := a.store.ReportOnly(am.ID)
	if err != nil {
		a.serverError(w, r, err)
		return
	}
	rb, _, err := a.store.ReportOnly(bm.ID)
	if err != nil {
		a.serverError(w, r, err)
		return
	}
	out := APIComparison{MachineID: m.ID, Machine: m.Name, A: meta(am), B: meta(bm), New: []model.Finding{}, Resolved: []model.Finding{}, Still: []model.Finding{}}
	inA, inB := map[string]bool{}, map[string]bool{}
	for _, f := range ra.Findings {
		inA[findingKey(f)] = true
	}
	for _, f := range rb.Findings {
		k := findingKey(f)
		inB[k] = true
		if inA[k] {
			out.Still = append(out.Still, f)
		} else {
			out.New = append(out.New, f)
		}
	}
	for _, f := range ra.Findings {
		if !inB[findingKey(f)] {
			out.Resolved = append(out.Resolved, f)
		}
	}
	writeAPI(w, http.StatusOK, out)
}

const visitRunningText = "A visit to this machine is running; try again when it is done."

// reserveVisit takes the token's one visit a minute for the machine and
// returns 0, or says how long until it is free. Taking it at once, under
// the lock, keeps two requests sent together from both getting it.
func (a *api) reserveVisit(tokenID, machineID int64, now time.Time) time.Duration {
	a.visitMu.Lock()
	defer a.visitMu.Unlock()
	for k, t := range a.lastVisit {
		if now.Sub(t) >= visitEvery {
			delete(a.lastVisit, k)
		}
	}
	k := [2]int64{tokenID, machineID}
	if t, ok := a.lastVisit[k]; ok {
		return visitEvery - now.Sub(t)
	}
	a.lastVisit[k] = now
	return 0
}

// releaseVisit gives back the reservation made at at, when no visit
// started after all (one was already running).
func (a *api) releaseVisit(tokenID, machineID int64, at time.Time) {
	a.visitMu.Lock()
	defer a.visitMu.Unlock()
	k := [2]int64{tokenID, machineID}
	if t, ok := a.lastVisit[k]; ok && t.Equal(at) {
		delete(a.lastVisit, k)
	}
}

// visit starts a visit, like the web UI's "Check now": it waits a moment for
// a visit that ends at once and otherwise says it has started. Only a visit
// that starts uses up the token's minute for the machine; a 409 does not.
func (a *api) visit(w http.ResponseWriter, r *http.Request) {
	m, ok := a.machine(w, r)
	if !ok {
		return
	}
	tok := tokenOf(r)
	at := a.now()
	if wait := a.reserveVisit(tok.ID, m.ID, at); wait > 0 {
		secs := int((wait + time.Second - 1) / time.Second)
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		writeAPIError(w, http.StatusTooManyRequests, fmt.Sprintf("This token asked for a visit to this machine less than a minute ago. Try again in %d seconds.", secs))
		return
	}
	if a.core.Visiting(m.ID) {
		a.releaseVisit(tok.ID, m.ID, at)
		writeAPIError(w, http.StatusConflict, visitRunningText)
		return
	}
	a.audit(actorAPI, "check now", "machine %d by token %d", m.ID, tok.ID)
	type result struct {
		rid int64
		err error
	}
	done := make(chan result, 1)
	a.visits.Add(1)
	go func() {
		defer a.visits.Done()
		rid, err := a.core.VisitNow(a.ctx, m.ID)
		if errors.Is(err, ErrVisitRunning) {
			a.releaseVisit(tok.ID, m.ID, at)
		}
		done <- result{rid, err}
	}()
	select {
	case res := <-done:
		switch {
		case errors.Is(res.err, ErrVisitRunning):
			writeAPIError(w, http.StatusConflict, visitRunningText)
		case res.err != nil:
			writeAPI(w, http.StatusOK, APIVisit{Status: "failed", ReportID: res.rid, Message: "The visit did not work: " + escape.Terminal(res.err.Error())})
		default:
			writeAPI(w, http.StatusOK, APIVisit{Status: "done", ReportID: res.rid, Message: "The visit is done; its report is the machine's latest."})
		}
	case <-time.After(checkNowWait):
		go func() {
			if res := <-done; res.err != nil && !errors.Is(res.err, ErrVisitRunning) {
				a.logf("telltale server: visit to machine %d: %v", m.ID, res.err)
			}
		}()
		writeAPI(w, http.StatusAccepted, APIVisit{Status: "started", Message: "The visit has started. Ask for the machine's latest report in a minute or two."})
	}
}
