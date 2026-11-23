package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/donaldsteele/telltale/internal/escape"
	"github.com/donaldsteele/telltale/internal/report"
	"github.com/donaldsteele/telltale/internal/store"
	"github.com/donaldsteele/telltale/internal/version"
	"github.com/donaldsteele/telltale/internal/visit"
	"github.com/donaldsteele/telltale/web"
)

// Backend is what the web UI needs from the core; *Core is the real one.
type Backend interface {
	VisitNow(ctx context.Context, machineID int64) (int64, error)
	MarkClean(ctx context.Context, machineID, reportID int64) error
	AcceptChanges(ctx context.Context, machineID, reportID int64, keys []string) error
	AddException(ctx context.Context, machineID, reportID int64, key, note string) error
	VisitError(machineID int64) (string, error)
	Leftovers(machineID int64) ([]string, error)
	Visiting(machineID int64) bool
	Acceptable(machineID int64) (Acceptable, error)
}

// UIOptions configures the web UI.
type UIOptions struct {
	Core  Backend
	Store *store.Store
	// Listen is the address the UI is served on, as bound ("ip:port").
	// Every request must name it in its Host header (a page asked for
	// under any other name, as DNS rebinding does, is refused), and the
	// first-run setup is only served on it. For a wildcard address the
	// connection's own local address stands in for it.
	Listen string
	// ServerAddr is the address machines see the server connect from, for
	// the enrolment snippets.
	ServerAddr string
	// CertFingerprint is the TLS certificate's SHA-256, shown in settings.
	CertFingerprint string
	// SetupCode is the one-time code the server printed at start; the
	// first-run setup asks for it, so nobody else on the network can set
	// the admin password first. Empty turns the setup page off.
	SetupCode string
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// FetchHostKey gets a machine's host key for enrolment; nil means
	// visit.FetchHostKey.
	FetchHostKey func(ctx context.Context, addr string) (ssh.PublicKey, string, error)
	// Context ends the visits "Check now" starts; nil means
	// context.Background.
	Context context.Context
	// Log is the server log; nil means the standard logger.
	Log *log.Logger
}

// UI is the web UI. It is an http.Handler; serve it over TLS only.
type UI struct {
	o        UIOptions
	listen   netip.AddrPort
	sessions *sessions
	limiter  *limiter
	pages    map[string]*template.Template
	static   map[string]staticFile
	mux      *http.ServeMux
	setupMu  sync.Mutex
	pwSet    atomic.Bool
	visits   sync.WaitGroup // visits Check now started
}

type staticFile struct {
	data        []byte
	contentType string
	etag        string
}

const (
	sessionCookie = "__Host-telltale"
	preCookie     = "__Host-telltale-pre"
	maxBody       = 1 << 20
	// cspHeader allows nothing inline: every script and style is a file
	// under /static/.
	cspHeader = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
)

// NewUI checks the options and builds the UI.
func NewUI(o UIOptions) (*UI, error) {
	if o.Core == nil || o.Store == nil {
		return nil, errors.New("server: the web UI needs a core and a store")
	}
	lp, err := netip.ParseAddrPort(o.Listen)
	if err != nil {
		return nil, fmt.Errorf("server: listen address %q: %w", o.Listen, err)
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.FetchHostKey == nil {
		o.FetchHostKey = visit.FetchHostKey
	}
	if o.Context == nil {
		o.Context = context.Background()
	}
	u := &UI{o: o, listen: netip.AddrPortFrom(lp.Addr().Unmap(), lp.Port()), sessions: newSessions(), limiter: newLimiter()}
	if err := u.loadTemplates(); err != nil {
		return nil, err
	}
	if err := u.loadStatic(); err != nil {
		return nil, err
	}
	u.routes()
	return u, nil
}

func (u *UI) logf(format string, args ...any) {
	if u.o.Log != nil {
		u.o.Log.Printf(format, args...)
		return
	}
	log.Printf(format, args...)
}

// audit writes an audit entry: fixed phrases and IDs or addresses only.
func (u *UI) audit(actor, action, format string, args ...any) {
	if err := u.o.Store.Audit(actor, action, fmt.Sprintf(format, args...)); err != nil {
		u.logf("telltale server: could not write \"%s\" to the audit log: %v", action, err)
	}
}

var timeLayout = "2006-01-02 15:04 UTC"

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(timeLayout)
}

// checkNowArgs is what the "checknow" template part takes.
type checkNowArgs struct {
	ID      int64
	CSRF    string
	Primary bool
}

var templateFuncs = template.FuncMap{
	"checkArgs": func(id int64, csrf string, primary bool) checkNowArgs {
		return checkNowArgs{ID: id, CSRF: csrf, Primary: primary}
	},
}

func (u *UI) loadTemplates() error {
	base, err := template.New("layout.html").Funcs(templateFuncs).ParseFS(web.FS, "templates/layout.html", "templates/parts.html")
	if err != nil {
		return fmt.Errorf("server: templates: %w", err)
	}
	names, err := fs.Glob(web.FS, "templates/*.html")
	if err != nil {
		return err
	}
	u.pages = map[string]*template.Template{}
	for _, n := range names {
		name := strings.TrimSuffix(strings.TrimPrefix(n, "templates/"), ".html")
		if name == "layout" || name == "parts" {
			continue
		}
		t, err := base.Clone()
		if err != nil {
			return err
		}
		if _, err := t.ParseFS(web.FS, n); err != nil {
			return fmt.Errorf("server: template %s: %w", n, err)
		}
		u.pages[name] = t
	}
	return nil
}

func (u *UI) loadStatic() error {
	u.static = map[string]staticFile{}
	for name, ct := range map[string]string{"styles.css": "text/css; charset=utf-8", "app.js": "text/javascript; charset=utf-8", "icon.svg": "image/svg+xml"} {
		b, err := fs.ReadFile(web.FS, "static/"+name)
		if err != nil {
			return fmt.Errorf("server: static file %s: %w", name, err)
		}
		sum := sha256.Sum256(b)
		u.static["/static/"+name] = staticFile{data: b, contentType: ct, etag: `"` + hex.EncodeToString(sum[:8]) + `"`}
	}
	return nil
}

// setSecurityHeaders are on every response.
func setSecurityHeaders(h http.Header) {
	h.Set("Content-Security-Policy", cspHeader)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Strict-Transport-Security", "max-age=31536000")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
}

// parseHostPort reads "ip:port" or a bare IP (port 443, as browsers write
// the default port).
func parseHostPort(s string) (netip.AddrPort, bool) {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
	}
	if a, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")); err == nil && a.Zone() == "" {
		return netip.AddrPortFrom(a.Unmap(), 443), true
	}
	return netip.AddrPort{}, false
}

// localAddr is the address the connection came in on.
func localAddr(r *http.Request) (netip.AddrPort, bool) {
	la, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if !ok {
		return netip.AddrPort{}, false
	}
	ap, err := netip.ParseAddrPort(la.String())
	if err != nil {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ap.Addr().Unmap().WithZone(""), ap.Port()), true
}

// expectedHost is the address requests must name: the listen address, or
// for a wildcard listen address the one the connection came in on.
func (u *UI) expectedHost(r *http.Request) (netip.AddrPort, bool) {
	if !u.listen.Addr().IsUnspecified() {
		return u.listen, true
	}
	la, ok := localAddr(r)
	if !ok {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(la.Addr(), u.listen.Port()), true
}

func (u *UI) hostOK(r *http.Request) bool {
	want, ok := u.expectedHost(r)
	if !ok {
		return false
	}
	got, ok := parseHostPort(r.Host)
	return ok && got == want
}

// originOK checks a POST came from the UI's own pages. Origin must be the
// UI's own origin. A browser sends "Origin: null" on its own form posts
// under Referrer-Policy: no-referrer, and old ones send none; then the
// Fetch Metadata header, which pages cannot set, must say same-origin.
func (u *UI) originOK(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" || o == "null" {
		return r.Header.Get("Sec-Fetch-Site") == "same-origin"
	}
	ou, err := url.Parse(o)
	if err != nil || ou.Scheme != "https" || ou.User != nil || (ou.Path != "" && ou.Path != "/") || ou.RawQuery != "" {
		return false
	}
	want, ok := u.expectedHost(r)
	got, ok2 := parseHostPort(ou.Host)
	return ok && ok2 && got == want
}

// fromListenAddr reports whether the connection came in on the configured
// listen address (for a wildcard one, on a loopback address: the first-run
// setup is then done from the server itself).
func (u *UI) fromListenAddr(r *http.Request) bool {
	la, ok := localAddr(r)
	if !ok {
		return false
	}
	if u.listen.Addr().IsUnspecified() {
		return la.Addr().IsLoopback() && la.Port() == u.listen.Port()
	}
	return la == u.listen
}

// peerIP is the TCP peer's address. Headers such as X-Forwarded-For are
// never read: the UI is not meant to sit behind a proxy.
func peerIP(r *http.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.IPv6Unspecified()
	}
	return ap.Addr().Unmap().WithZone("")
}

// Wait waits for the visits Check now started; they end with
// UIOptions.Context.
func (u *UI) Wait() { u.visits.Wait() }

// passwordSet reports whether the admin password exists; once it does it
// never stops existing, so that is remembered.
func (u *UI) passwordSet() (bool, error) {
	if u.pwSet.Load() {
		return true, nil
	}
	ok, err := hasPassword(u.o.Store)
	if ok {
		u.pwSet.Store(true)
	}
	return ok, err
}

// ServeHTTP checks every request (host, body size, origin and form of a
// POST, first run) and hands it to its page.
func (u *UI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w.Header())
	if !u.hostOK(r) {
		http.Error(w, "Misdirected request: open the telltale server at https://"+u.o.Listen+"/", http.StatusMisdirectedRequest)
		return
	}
	if f, ok := u.static[r.URL.Path]; ok && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		w.Header().Set("Content-Type", f.contentType)
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("ETag", f.etag)
		http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(f.data))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	if r.Method == http.MethodPost {
		if !u.originOK(r) {
			u.fail(w, r, http.StatusForbidden, "This form did not come from this server's own pages, so it was refused.")
			return
		}
		if err := r.ParseForm(); err != nil {
			var tooBig *http.MaxBytesError
			if errors.As(err, &tooBig) {
				u.fail(w, r, http.StatusRequestEntityTooLarge, "That form was too large.")
				return
			}
			u.fail(w, r, http.StatusBadRequest, "That form could not be read.")
			return
		}
	}
	set, err := u.passwordSet()
	if err != nil {
		u.serverError(w, r, err)
		return
	}
	if !set && r.URL.Path != "/setup" {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}
		u.fail(w, r, http.StatusForbidden, "Set the admin password first.")
		return
	}
	u.mux.ServeHTTP(w, r)
}

// reqCtx is one request to a page that needs a login.
type reqCtx struct {
	w     http.ResponseWriter
	r     *http.Request
	sess  *session
	token string
}

// pageData is what every page template gets.
type pageData struct {
	Title    string
	Nav      string
	LoggedIn bool
	CSRF     string
	Flash    string
	Error    string
	Version  string
	Body     any
}

func (u *UI) routes() {
	m := http.NewServeMux()
	m.HandleFunc("GET /setup", u.setupPage)
	m.HandleFunc("POST /setup", u.setupPost)
	m.HandleFunc("GET /login", u.loginPage)
	m.HandleFunc("POST /login", u.loginPost)
	m.HandleFunc("POST /logout", u.authed(u.logout))

	m.HandleFunc("GET /{$}", u.authed(u.machinesPage))
	m.HandleFunc("GET /machines/{id}", u.authed(u.machinePage))
	m.HandleFunc("POST /machines/{id}/check", u.authed(u.checkNow))
	m.HandleFunc("POST /machines/{id}/schedule", u.authed(u.setSchedule))
	m.HandleFunc("GET /machines/{id}/clean", u.authed(u.cleanPage))
	m.HandleFunc("POST /machines/{id}/clean", u.authed(u.cleanPost))
	m.HandleFunc("GET /machines/{id}/changes", u.authed(u.changesPage))
	m.HandleFunc("GET /machines/{id}/accept", u.authed(u.acceptPage))
	m.HandleFunc("POST /machines/{id}/accept", u.authed(u.acceptPost))
	m.HandleFunc("GET /machines/{id}/exception", u.authed(u.exceptionPage))
	m.HandleFunc("POST /machines/{id}/exception", u.authed(u.exceptionPost))
	m.HandleFunc("GET /machines/{id}/enrolled", u.authed(u.snippetsPage))

	m.HandleFunc("GET /enrol", u.authed(u.enrolPage))
	m.HandleFunc("POST /enrol", u.authed(u.enrolFetch))
	m.HandleFunc("POST /enrol/confirm", u.authed(u.enrolConfirm))

	m.HandleFunc("GET /settings", u.authed(u.settingsPage))
	m.HandleFunc("POST /settings/general", u.authed(u.settingsGeneral))
	m.HandleFunc("POST /settings/password", u.authed(u.settingsPassword))
	m.HandleFunc("POST /settings/keys", u.authed(u.settingsAddKey))
	m.HandleFunc("POST /settings/keys/{id}/remove", u.authed(u.settingsRemoveKey))
	m.HandleFunc("GET /audit", u.authed(u.auditPage))
	u.mux = m
}

// authed wraps a page that needs a login. A GET without a session goes to
// the login page; a POST without a session, or without the session's CSRF
// token, is refused.
func (u *UI) authed(h func(*reqCtx)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var tok string
		if c, err := r.Cookie(sessionCookie); err == nil {
			tok = c.Value
		}
		sess := u.sessions.get(tok, u.o.Now())
		if sess == nil {
			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			u.fail(w, r, http.StatusForbidden, "You are not logged in, or your session ended. Log in and try again.")
			return
		}
		if r.Method == http.MethodPost && !sameToken(r.PostForm.Get("csrf"), sess.csrf) {
			u.fail(w, r, http.StatusForbidden, "This form has expired. Go back, reload the page and try again.")
			return
		}
		h(&reqCtx{w: w, r: r, sess: sess, token: tok})
	}
}

// render writes a page with status.
func (u *UI) render(w http.ResponseWriter, status int, name string, d pageData) {
	t := u.pages[name]
	if t == nil {
		http.Error(w, "missing page "+name, http.StatusInternalServerError)
		return
	}
	d.Version = escape.Terminal(version.Version)
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout", d); err != nil {
		u.logf("telltale server: page %s: %v", name, err)
		http.Error(w, "The page could not be shown.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	w.Write(buf.Bytes())
}

// page renders a logged-in page, taking the session's flash message.
func (u *UI) page(c *reqCtx, status int, name, title, nav string, body any, errMsg string) {
	var flash string
	u.sessions.with(func() { flash, c.sess.flash = c.sess.flash, "" })
	u.render(c.w, status, name, pageData{Title: title, Nav: nav, LoggedIn: true, CSRF: c.sess.csrf, Flash: flash, Error: errMsg, Body: body})
}

// redirect sends a logged-in browser on with a message for the next page.
func (u *UI) redirect(c *reqCtx, to, flash string) {
	if flash != "" {
		u.sessions.with(func() { c.sess.flash = flash })
	}
	http.Redirect(c.w, c.r, to, http.StatusSeeOther)
}

// fail answers with a plain error page.
func (u *UI) fail(w http.ResponseWriter, r *http.Request, status int, msg string) {
	u.render(w, status, "error", pageData{Title: http.StatusText(status), Error: msg})
}

func (u *UI) serverError(w http.ResponseWriter, r *http.Request, err error) {
	u.logf("telltale server: %s %s: %v", r.Method, r.URL.Path, err)
	u.fail(w, r, http.StatusInternalServerError, "Something went wrong on the server: "+escape.Terminal(err.Error()))
}

// setCookie sets one of the UI's cookies: Secure, HttpOnly, SameSite=Strict,
// host-only (__Host- prefix), for the whole site.
func setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", MaxAge: maxAge, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

func clearCookie(w http.ResponseWriter, name string) { setCookie(w, name, "", -1) }

// preToken is the login and setup forms' CSRF token: a random value in a
// cookie that the form must echo.
func preToken(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(preCookie); err == nil {
		if _, err := decodeToken(c.Value); err == nil {
			return c.Value
		}
	}
	tok := newToken()
	setCookie(w, preCookie, tok, 0)
	return tok
}

func preTokenOK(r *http.Request) bool {
	c, err := r.Cookie(preCookie)
	return err == nil && sameToken(r.PostForm.Get("csrf"), c.Value)
}

// machineID reads the {id} in the path and loads the machine; a missing one
// is answered with 404 and nil.
func (u *UI) machine(c *reqCtx) *store.Machine {
	id, err := strconv.ParseInt(c.r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		u.fail(c.w, c.r, http.StatusNotFound, "There is no such machine.")
		return nil
	}
	m, err := u.o.Store.Machine(id)
	if err != nil {
		u.fail(c.w, c.r, http.StatusNotFound, "There is no such machine.")
		return nil
	}
	return m
}

// actionError is an owner action's error in plain words.
func actionError(err error) string {
	if errors.Is(err, ErrVisitRunning) {
		return "A visit is running, try again in a moment."
	}
	return "That did not work: " + escape.Terminal(err.Error())
}

// fixText is a fix command as shown; canCopy is false for one marked "do
// not paste".
func fixText(fix string) (text string, canCopy bool) {
	return report.FixText(fix), !escape.HasUnsafe(fix)
}
