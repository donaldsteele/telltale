package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode"

	"golang.org/x/crypto/ssh"

	"github.com/donaldsteele/telltale/internal/escape"
	"github.com/donaldsteele/telltale/internal/store"
)

// pendingEnrol is a host key fetched and shown to the owner, waiting for
// the owner to say it matches. It is kept in the session, so the key the
// owner confirms is the one the server fetched, not one a form sent back.
type pendingEnrol struct {
	name, addr  string
	hostKey     string // authorized_keys form: "type base64"
	fingerprint string
	created     time.Time
}

const (
	maxPending       = 8
	pendingLifetime  = 30 * time.Minute
	fetchHostTimeout = 20 * time.Second
)

var machineNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

type enrolView struct {
	Name, Addr string
}

func (u *UI) enrolPage(c *reqCtx) {
	u.page(c, http.StatusOK, "enrol", "Enrol a machine", "enrol", enrolView{}, "")
}

// checkMachineAddr accepts a host name or IP address, with an optional
// port, as the owner types it to reach the machine over SSH.
func checkMachineAddr(addr string) string {
	if addr == "" {
		return "Give the machine's address."
	}
	if len(addr) > 255 || strings.IndexFunc(addr, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) || r > unicode.MaxASCII }) >= 0 || strings.HasPrefix(addr, "-") {
		return "That address has characters an address cannot have."
	}
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if host == "" || strings.ContainsAny(host, "/@,;'\"\\") {
		return "That is not a host name or IP address."
	}
	return ""
}

func hostKeyFile(keyType string) string {
	switch {
	case keyType == ssh.KeyAlgoED25519:
		return "/etc/ssh/ssh_host_ed25519_key.pub"
	case strings.HasPrefix(keyType, "ecdsa-"):
		return "/etc/ssh/ssh_host_ecdsa_key.pub"
	case keyType == ssh.KeyAlgoRSA:
		return "/etc/ssh/ssh_host_rsa_key.pub"
	}
	return "/etc/ssh/ssh_host_*_key.pub"
}

type enrolKeyView struct {
	Name, Addr  string
	Fingerprint string
	KeyType     string
	KeyFile     string
	Pending     string
}

// enrolFetch is the first step: fetch the machine's host key and show its
// fingerprint for the owner to compare. Nothing is stored yet.
func (u *UI) enrolFetch(c *reqCtx) {
	name := strings.TrimSpace(c.r.PostForm.Get("name"))
	addr := strings.TrimSpace(c.r.PostForm.Get("addr"))
	form := enrolView{Name: escape.Terminal(name), Addr: escape.Terminal(addr)}
	bad := func(msg string) { u.page(c, http.StatusBadRequest, "enrol", "Enrol a machine", "enrol", form, msg) }
	if !machineNameRE.MatchString(name) {
		bad("Give the machine a short name: letters, digits, dots, dashes and underscores, up to 64, starting with a letter or digit.")
		return
	}
	if msg := checkMachineAddr(addr); msg != "" {
		bad(msg)
		return
	}
	if taken, err := u.nameTaken(name); err != nil {
		u.serverError(c.w, c.r, err)
		return
	} else if taken {
		bad("There is already a machine called " + name + ".")
		return
	}
	ctx, cancel := context.WithTimeout(c.r.Context(), fetchHostTimeout)
	defer cancel()
	key, fp, err := u.o.FetchHostKey(ctx, addr)
	if err != nil {
		u.page(c, http.StatusOK, "enrol", "Enrol a machine", "enrol", form, "Could not get the machine's SSH host key: "+escape.Terminal(err.Error()))
		return
	}
	p := pendingEnrol{name: name, addr: addr, hostKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))), fingerprint: fp, created: u.o.Now()}
	id := newToken()
	u.sessions.with(func() {
		for k, x := range c.sess.pending {
			if u.o.Now().Sub(x.created) > pendingLifetime {
				delete(c.sess.pending, k)
			}
		}
		for len(c.sess.pending) >= maxPending {
			for k := range c.sess.pending {
				delete(c.sess.pending, k)
				break
			}
		}
		c.sess.pending[id] = p
	})
	v := enrolKeyView{Name: form.Name, Addr: form.Addr, Fingerprint: fp, KeyType: escape.Terminal(key.Type()), KeyFile: hostKeyFile(key.Type()), Pending: id}
	u.page(c, http.StatusOK, "enrol_key", "Compare the fingerprint", "enrol", v, "")
}

func (u *UI) nameTaken(name string) (bool, error) {
	ms, err := u.o.Store.Machines()
	if err != nil {
		return false, err
	}
	for _, m := range ms {
		if strings.EqualFold(m.Name, name) {
			return true, nil
		}
	}
	return false, nil
}

// enrolConfirm is the second step, after the owner compared the
// fingerprint: pin the key the server fetched and enrol the machine.
func (u *UI) enrolConfirm(c *reqCtx) {
	id := c.r.PostForm.Get("pending")
	if !u.confirmed(c, "/enrol") {
		return
	}
	var p pendingEnrol
	var ok bool
	u.sessions.with(func() {
		p, ok = c.sess.pending[id]
		delete(c.sess.pending, id)
	})
	if !ok || u.o.Now().Sub(p.created) > pendingLifetime {
		u.fail(c.w, c.r, http.StatusBadRequest, "This confirmation has expired or was already used. Start the enrolment again.")
		return
	}
	if taken, err := u.nameTaken(p.name); err != nil {
		u.serverError(c.w, c.r, err)
		return
	} else if taken {
		u.fail(c.w, c.r, http.StatusBadRequest, "There is already a machine called "+p.name+".")
		return
	}
	sched, _ := u.o.Store.Setting(SettingDefaultSchedule)
	if !validSchedule(sched) {
		sched = ScheduleDaily
	}
	mid, err := u.o.Store.AddMachine(store.Machine{Name: p.name, Addr: p.addr, HostKey: p.hostKey, Schedule: sched, Created: u.o.Now()})
	if err != nil {
		u.serverError(c.w, c.r, err)
		return
	}
	u.audit(actorOwner, "enrol", "machine %d", mid)
	u.redirect(c, fmt.Sprintf("/machines/%d/enrolled", mid), "Enrolled. Its host key is pinned: the server will refuse any other.")
}
