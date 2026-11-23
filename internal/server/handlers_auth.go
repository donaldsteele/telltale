package server

import (
	"net/http"
	"strings"
)

type setupView struct {
	Listen string
}

// setupPage is the first-run page that sets the admin password. It exists
// only while there is no password.
func (u *UI) setupPage(w http.ResponseWriter, r *http.Request) {
	if set, err := u.passwordSet(); err != nil {
		u.serverError(w, r, err)
		return
	} else if set {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	u.renderSetup(w, r, http.StatusOK, "")
}

func (u *UI) renderSetup(w http.ResponseWriter, r *http.Request, status int, msg string) {
	u.render(w, status, "setup", pageData{Title: "First run", CSRF: preToken(w, r), Error: msg, Body: setupView{Listen: u.o.Listen}})
}

// setupPost sets the first admin password. It needs the form's CSRF token,
// a connection to the configured listen address, the one-time code the
// server printed at start, and that no password exists yet.
func (u *UI) setupPost(w http.ResponseWriter, r *http.Request) {
	ip := peerIP(r)
	if set, err := u.passwordSet(); err != nil {
		u.serverError(w, r, err)
		return
	} else if set {
		u.fail(w, r, http.StatusForbidden, "The admin password is already set. Log in instead.")
		return
	}
	if !preTokenOK(r) {
		u.fail(w, r, http.StatusForbidden, "This form has expired. Reload the page and try again.")
		return
	}
	if !u.fromListenAddr(r) || u.o.SetupCode == "" {
		u.renderSetup(w, r, http.StatusForbidden, "The first-run setup is only available at the address in the server's configuration ("+u.o.Listen+").")
		return
	}
	pw, repeat := r.PostForm.Get("password"), r.PostForm.Get("repeat")
	if msg := checkPasswordRules(pw, repeat); msg != "" {
		u.renderSetup(w, r, http.StatusOK, msg)
		return
	}
	now := u.o.Now()
	if ok, first := u.limiter.attempt(ip, now); !ok {
		if first {
			u.audit("web", "setup refused, too many failures", "from %s", ip)
		}
		u.renderSetup(w, r, http.StatusTooManyRequests, "Too many wrong codes. Wait a minute and try again.")
		return
	}
	if !sameToken(normalizeCode(r.PostForm.Get("code")), normalizeCode(u.o.SetupCode)) {
		u.audit("web", "setup failed", "from %s", ip)
		u.renderSetup(w, r, http.StatusForbidden, "That is not the code the server printed when it started.")
		return
	}
	hash, err := hashPassword(pw)
	if err != nil {
		u.serverError(w, r, err)
		return
	}
	u.setupMu.Lock()
	defer u.setupMu.Unlock()
	// Two setups at once: only the first sets the password.
	if set, err := hasPassword(u.o.Store); err != nil {
		u.serverError(w, r, err)
		return
	} else if set {
		u.fail(w, r, http.StatusForbidden, "The admin password is already set. Log in instead.")
		return
	}
	if err := u.o.Store.SetSecretSetting(passwordSetting, []byte(hash)); err != nil {
		u.serverError(w, r, err)
		return
	}
	u.pwSet.Store(true)
	u.limiter.succeed(ip)
	u.audit(actorOwner, "admin password set", "from %s", ip)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// normalizeCode lets the setup code be typed in either case, with or
// without its dashes and spaces.
func normalizeCode(s string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(s)))
}

type loginView struct {
	Changed bool
}

func (u *UI) loginPage(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil && u.sessions.get(c.Value, u.o.Now()) != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	u.renderLogin(w, r, http.StatusOK, "")
}

func (u *UI) renderLogin(w http.ResponseWriter, r *http.Request, status int, msg string) {
	u.render(w, status, "login", pageData{Title: "Log in", CSRF: preToken(w, r), Error: msg, Body: loginView{Changed: r.URL.Query().Get("changed") == "1"}})
}

// loginPost checks the password. At most five tries a minute per client
// address; every success and failure is audited with the address.
func (u *UI) loginPost(w http.ResponseWriter, r *http.Request) {
	if !preTokenOK(r) {
		u.fail(w, r, http.StatusForbidden, "This form has expired. Reload the page and try again.")
		return
	}
	ip := peerIP(r)
	now := u.o.Now()
	if ok, first := u.limiter.attempt(ip, now); !ok {
		if first {
			u.audit("web", "login refused, too many failures", "from %s", ip)
		}
		u.renderLogin(w, r, http.StatusTooManyRequests, "Too many failed logins from your address. Wait a minute and try again.")
		return
	}
	stored, err := u.o.Store.SecretSetting(passwordSetting)
	if err != nil {
		u.serverError(w, r, err)
		return
	}
	if !checkPassword(r.PostForm.Get("password"), string(stored)) {
		u.audit("web", "login failed", "from %s", ip)
		u.renderLogin(w, r, http.StatusUnauthorized, "That password is not right.")
		return
	}
	u.limiter.succeed(ip)
	// A fresh session every time: whatever token the browser had before
	// is ended, never promoted.
	if c, err := r.Cookie(sessionCookie); err == nil {
		u.sessions.end(c.Value)
	}
	tok, _ := u.sessions.create(now, ip.String())
	setCookie(w, sessionCookie, tok, int(sessionLifetime.Seconds()))
	u.audit(actorOwner, "login", "from %s", ip)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (u *UI) logout(c *reqCtx) {
	u.sessions.end(c.token)
	clearCookie(c.w, sessionCookie)
	u.audit(actorOwner, "logout", "from %s", peerIP(c.r))
	http.Redirect(c.w, c.r, "/login", http.StatusSeeOther)
}
