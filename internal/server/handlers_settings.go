package server

import (
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/donaldsteele/telltale/internal/escape"
	"github.com/donaldsteele/telltale/internal/visit"
)

type ownerKeyView struct {
	ID          int64
	Fingerprint string
	URL         string
	Added       string
}

type settingsView struct {
	Schedules   []option
	AlertLevels []option
	SSHKeyFP    string
	SSHKeyLine  string
	SSHKeyError string
	ServerAddr  string
	CertFP      string
	Keys        []ownerKeyView
	KeyURL      string
	KeyText     string
}

// groupFingerprint writes an OpenPGP fingerprint in groups of four, the
// way gpg shows it.
func groupFingerprint(fp string) string {
	var parts []string
	for i := 0; i < len(fp); i += 4 {
		parts = append(parts, fp[i:min(i+4, len(fp))])
	}
	return strings.Join(parts, " ")
}

func (u *UI) settingsView() (settingsView, error) {
	sched, err := u.o.Store.Setting(SettingDefaultSchedule)
	if err != nil {
		return settingsView{}, err
	}
	level, err := u.o.Store.Setting(SettingAlertLevel)
	if err != nil {
		return settingsView{}, err
	}
	v := settingsView{
		Schedules: scheduleOptions(sched),
		AlertLevels: []option{
			{Value: "urgent", Label: "Tampering and backdoor signs only", Selected: level != "all"},
			{Value: "all", Label: "Every new finding", Selected: level == "all"},
		},
		ServerAddr: u.o.ServerAddr,
		CertFP:     u.o.CertFingerprint,
	}
	if signer, line, err := visit.ServerKey(u.o.Store); err != nil {
		v.SSHKeyError = escape.Terminal(err.Error())
	} else {
		v.SSHKeyFP, v.SSHKeyLine = ssh.FingerprintSHA256(signer.PublicKey()), line
	}
	keys, err := OwnerKeys(u.o.Store)
	if err != nil {
		return settingsView{}, err
	}
	for _, k := range keys {
		v.Keys = append(v.Keys, ownerKeyView{ID: k.ID, Fingerprint: groupFingerprint(escape.Terminal(k.Key.Fingerprint)), URL: escape.Terminal(k.URLPattern), Added: fmtTime(k.Added)})
	}
	return v, nil
}

func (u *UI) settingsPage(c *reqCtx) {
	u.renderSettings(c, http.StatusOK, settingsView{}, "")
}

// renderSettings shows the settings page; form carries what the owner had
// typed into the key form when it is shown again with an error.
func (u *UI) renderSettings(c *reqCtx, status int, form settingsView, msg string) {
	v, err := u.settingsView()
	if err != nil {
		u.serverError(c.w, c.r, err)
		return
	}
	v.KeyURL, v.KeyText = form.KeyURL, form.KeyText
	u.page(c, status, "settings", "Settings", "settings", v, msg)
}

func (u *UI) settingsGeneral(c *reqCtx) {
	sched := c.r.PostForm.Get("schedule")
	level := c.r.PostForm.Get("alert_level")
	if !validSchedule(sched) || (level != "urgent" && level != "all") {
		u.renderSettings(c, http.StatusBadRequest, settingsView{}, "Choose one of the schedules and alert levels offered.")
		return
	}
	if err := u.o.Store.SetSetting(SettingDefaultSchedule, sched); err != nil {
		u.serverError(c.w, c.r, err)
		return
	}
	if err := u.o.Store.SetSetting(SettingAlertLevel, level); err != nil {
		u.serverError(c.w, c.r, err)
		return
	}
	u.audit(actorOwner, "settings changed", "general")
	u.redirect(c, "/settings", "Settings saved.")
}

// settingsPassword changes the admin password. It needs the current one
// (counted like a login) and ends every session, this one included.
func (u *UI) settingsPassword(c *reqCtx) {
	ip := peerIP(c.r)
	if ok, first := u.limiter.attempt(ip, u.o.Now()); !ok {
		if first {
			u.audit("web", "login refused, too many failures", "from %s", ip)
		}
		u.renderSettings(c, http.StatusTooManyRequests, settingsView{}, "Too many wrong passwords from your address. Wait a minute and try again.")
		return
	}
	stored, err := u.o.Store.SecretSetting(passwordSetting)
	if err != nil {
		u.serverError(c.w, c.r, err)
		return
	}
	if !checkPassword(c.r.PostForm.Get("current"), string(stored)) {
		u.audit("web", "password change failed", "from %s", ip)
		u.renderSettings(c, http.StatusUnauthorized, settingsView{}, "The current password is not right; the password was not changed.")
		return
	}
	u.limiter.succeed(ip)
	pw := c.r.PostForm.Get("password")
	if msg := checkPasswordRules(pw, c.r.PostForm.Get("repeat")); msg != "" {
		u.renderSettings(c, http.StatusBadRequest, settingsView{}, msg+" The password was not changed.")
		return
	}
	hash, err := hashPassword(pw)
	if err != nil {
		u.serverError(c.w, c.r, err)
		return
	}
	if err := u.o.Store.SetSecretSetting(passwordSetting, []byte(hash)); err != nil {
		u.serverError(c.w, c.r, err)
		return
	}
	u.sessions.endAll()
	clearCookie(c.w, sessionCookie)
	u.audit(actorOwner, "password changed", "from %s", ip)
	http.Redirect(c.w, c.r, "/login?changed=1", http.StatusSeeOther)
}

func (u *UI) settingsAddKey(c *reqCtx) {
	text, addr := c.r.PostForm.Get("key"), c.r.PostForm.Get("url")
	added, err := AddOwnerKey(u.o.Store, text, addr, u.o.Now())
	if err != nil {
		form := settingsView{KeyURL: strings.TrimSpace(addr), KeyText: text}
		u.renderSettings(c, http.StatusBadRequest, form, "The key was not added: "+escape.Terminal(err.Error()))
		return
	}
	for _, k := range added {
		u.audit(actorOwner, "repository key added", "key %d", k.ID)
	}
	u.redirect(c, "/settings#keys", "Repository key added. It is used from the next visit, only for that address.")
}

func (u *UI) settingsRemoveKey(c *reqCtx) {
	id, err := strconv.ParseInt(c.r.PathValue("id"), 10, 64)
	if err != nil {
		u.fail(c.w, c.r, http.StatusNotFound, "There is no such key.")
		return
	}
	if err := RemoveOwnerKey(u.o.Store, id); err != nil {
		u.fail(c.w, c.r, http.StatusNotFound, "There is no such key.")
		return
	}
	u.audit(actorOwner, "repository key removed", "key %d", id)
	u.redirect(c, "/settings#keys", "Repository key removed.")
}

type auditRow struct {
	Time, Actor, Action, Detail string
}

func (u *UI) auditPage(c *reqCtx) {
	log, err := u.o.Store.AuditLog(500)
	if err != nil {
		u.serverError(c.w, c.r, err)
		return
	}
	rows := make([]auditRow, 0, len(log))
	for _, e := range log {
		rows = append(rows, auditRow{Time: fmtTime(e.Time), Actor: escape.Terminal(e.Actor), Action: escape.Terminal(e.Action), Detail: escape.Terminal(e.Detail)})
	}
	u.page(c, http.StatusOK, "audit", "Audit log", "audit", rows, "")
}
