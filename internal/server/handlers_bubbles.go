package server

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/donaldsteele/telltale/internal/alerts"
	"github.com/donaldsteele/telltale/internal/escape"
)

// The bubbles pages: the pairing wizard (as netdiag's) and the connection's
// status and actions. Every action is an owner action (a logged-in POST
// with the CSRF token), and is audited with a fixed phrase only: nothing
// the bubbles server or the owner typed goes into the audit log. The
// alerts package escapes what bubbles says before these pages get it, and
// html/template escapes it again for HTML.

// pairRefresh is how often the waiting page checks for the approval.
const pairRefresh = 3

type bubblesView struct {
	Status alerts.Status
	Pair   alerts.PairStatus
	// Waiting: a pairing request waits for the chat admin. Ended: one
	// ended without a token, and Pair.Message says why.
	Waiting, Ended bool
	// Broken: the stored connection cannot be read; Trouble says why.
	Broken  bool
	Trouble string
	Since   string
	// Address is the address form's value.
	Address string
}

func (u *UI) bubblesView() (bubblesView, error) {
	st, err := u.o.Bubbles.Status()
	if err != nil {
		return bubblesView{Broken: true, Trouble: "The bubbles connection cannot be read: " + escape.Terminal(err.Error())}, nil
	}
	v := bubblesView{Status: st, Pair: u.o.Bubbles.PairStatus(), Trouble: st.Trouble.Message(), Address: st.Address}
	if !st.Since.IsZero() {
		v.Since = fmtTime(st.Since)
	}
	switch v.Pair.State {
	case alerts.PairPending:
		v.Waiting = true
	case alerts.PairNone, alerts.PairApproved:
	default:
		v.Ended = true
	}
	return v, nil
}

func (u *UI) bubblesPage(c *reqCtx) {
	u.renderBubbles(c, http.StatusOK, "", "")
}

// renderBubbles shows the bubbles page; address is what the owner typed,
// shown again with an error.
func (u *UI) renderBubbles(c *reqCtx, status int, address, msg string) {
	v, err := u.bubblesView()
	if err != nil {
		u.serverError(c.w, c.r, err)
		return
	}
	if address != "" {
		v.Address = escape.Terminal(address)
	}
	refresh := 0
	if v.Waiting {
		refresh = pairRefresh
	}
	if v.Ended {
		// Shown once; the next visit to the page starts afresh.
		u.o.Bubbles.FinishPairing()
	}
	var flash string
	u.sessions.with(func() { flash, c.sess.flash = c.sess.flash, "" })
	u.render(c.w, status, "bubbles", pageData{Title: "Alerts through bubbles", Nav: "settings", LoggedIn: true, CSRF: c.sess.csrf,
		Flash: flash, Error: msg, Refresh: refresh, Body: v})
}

// bubblesInspect is the wizard's first step: fetch the CA of the server at
// the address the owner typed and show its fingerprint to compare. Nothing
// is trusted or stored yet.
func (u *UI) bubblesInspect(c *reqCtx) {
	addr := strings.TrimSpace(c.r.PostForm.Get("address"))
	if addr == "" || len(addr) > 300 {
		u.renderBubbles(c, http.StatusBadRequest, addr, "Give the bubbles server's address.")
		return
	}
	in, err := u.o.Bubbles.Inspect(c.r.Context(), addr)
	if err != nil {
		u.renderBubbles(c, http.StatusBadRequest, addr, escape.Terminal(err.Error()))
		return
	}
	u.audit(actorOwner, "bubbles fingerprint shown", "")
	u.page(c, http.StatusOK, "bubbles_fp", "Is this the right server?", "settings", in, "")
}

// bubblesNoMatch is "It doesn't": stop, and say why.
func (u *UI) bubblesNoMatch(c *reqCtx) {
	u.audit(actorOwner, "bubbles fingerprint did not match", "")
	u.page(c, http.StatusOK, "bubbles_nomatch", "Stop here", "settings", nil, "")
}

// bubblesPair is the second step, after the owner compared the
// fingerprint: ask the server the owner inspected for a token, pinning the
// CA that was fetched (held under the one-time candidate ID).
func (u *UI) bubblesPair(c *reqCtx) {
	if !u.confirmed(c, "/settings/bubbles") {
		return
	}
	if _, err := u.o.Bubbles.StartPairing(c.r.Context(), c.r.PostForm.Get("candidate")); err != nil {
		u.renderBubbles(c, http.StatusBadRequest, "", escape.Terminal(err.Error()))
		return
	}
	u.audit(actorOwner, "bubbles pairing requested", "")
	u.redirect(c, "/settings/bubbles", "")
}

func (u *UI) bubblesCancel(c *reqCtx) {
	u.o.Bubbles.CancelPairing(c.r.Context())
	u.audit(actorOwner, "bubbles pairing cancelled", "")
	u.redirect(c, "/settings/bubbles", "The request to connect was cancelled.")
}

// bubblesChannels lists the bot's channels again, to choose the alert
// channel (Look again, Change channel).
func (u *UI) bubblesChannels(c *reqCtx) {
	if _, err := u.o.Bubbles.Channels(c.r.Context()); err != nil {
		u.renderBubbles(c, http.StatusOK, "", escape.Terminal(err.Error()))
		return
	}
	u.redirect(c, "/settings/bubbles", "")
}

func (u *UI) bubblesChannel(c *reqCtx) {
	ch, err := u.o.Bubbles.SetChannel(c.r.PostForm.Get("channel"))
	if err != nil {
		u.renderBubbles(c, http.StatusBadRequest, "", escape.Terminal(err.Error()))
		return
	}
	u.audit(actorOwner, "bubbles channel chosen", "")
	u.redirect(c, "/settings/bubbles", "Alerts will go to #"+ch.Name+".")
}

func (u *UI) bubblesTest(c *reqCtx) {
	st, err := u.o.Bubbles.Status()
	if err != nil {
		u.serverError(c.w, c.r, err)
		return
	}
	if err := u.o.Bubbles.SendTest(c.r.Context()); err != nil {
		u.audit(actorOwner, "bubbles test alert failed", "")
		u.renderBubbles(c, http.StatusOK, "", escape.Terminal(err.Error()))
		return
	}
	u.audit(actorOwner, "bubbles test alert sent", "")
	u.redirect(c, "/settings/bubbles", "The test alert reached #"+st.Channel.Name+" and was closed again.")
}

// bubblesRetry is Try now: send the waiting alerts at once, within the
// alert timeout.
func (u *UI) bubblesRetry(c *reqCtx) {
	if err := u.o.Bubbles.TryNow(c.r.Context()); err != nil {
		u.renderBubbles(c, http.StatusOK, "", "The waiting alerts could not all be sent yet. They go out when bubbles takes them.")
		return
	}
	u.redirect(c, "/settings/bubbles", "The waiting alerts were sent.")
}

func (u *UI) bubblesDisconnectPage(c *reqCtx) {
	u.page(c, http.StatusOK, "bubbles_disconnect", "Disconnect from bubbles?", "settings", nil, "")
}

func (u *UI) bubblesDisconnect(c *reqCtx) {
	if !u.confirmed(c, "/settings/bubbles/disconnect") {
		return
	}
	if err := u.o.Bubbles.Disconnect(); err != nil {
		u.serverError(c.w, c.r, err)
		return
	}
	u.audit(actorOwner, "bubbles disconnected", "")
	u.redirect(c, "/settings/bubbles", "Disconnected. telltale sends no more alerts to bubbles.")
}

// countWord is "1 alert" or "N alerts".
func countWord(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}
