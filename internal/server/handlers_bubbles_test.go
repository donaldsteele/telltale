package server

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/donaldsteele/bubbles/pkg/bubblesclient"
	"github.com/donaldsteele/bubbles/pkg/protocol"

	"github.com/donaldsteele/telltale/internal/alerts"
	"github.com/donaldsteele/telltale/internal/alerts/bubblestest"
)

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The wizard, as netdiag's: the owner types the address, compares the CA
// fingerprint (the first four groups large), shows the chat admin the code,
// waits, and alerts go to the bot's channel. Every step is an owner action:
// logged in, POST, CSRF token. The audit log gets fixed phrases only.
func TestBubblesPairingWizard(t *testing.T) {
	w := loggedIn(t)
	fake := bubblestest.New(t)
	fake.SetInstanceName("office chat")

	page := w.get("/settings").Body.String()
	if !strings.Contains(page, `href="/settings/bubbles"`) || !strings.Contains(page, "Not connected") {
		t.Errorf("the settings page does not lead to the bubbles wizard:\n%s", page)
	}
	rec := w.get("/settings/bubbles")
	wantStatus(t, rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), `name="address"`) {
		t.Fatalf("no address form:\n%s", rec.Body)
	}
	// Owner actions only: no GET, no POST without the CSRF token.
	for _, p := range []string{"/settings/bubbles/inspect", "/settings/bubbles/pair", "/settings/bubbles/test", "/settings/bubbles/disconnect"} {
		if rec := w.post(p, url.Values{"csrf": {"wrong"}, "address": {fake.Address()}, "confirm": {"yes"}}); rec.Code != http.StatusForbidden {
			t.Errorf("POST %s without the CSRF token: %d", p, rec.Code)
		}
	}
	if rec := w.get("/settings/bubbles/inspect?address=" + url.QueryEscape(fake.Address())); rec.Code == http.StatusOK {
		t.Error("the fingerprint step answers a GET")
	}

	w.get("/settings/bubbles")
	rec = w.post("/settings/bubbles/inspect", url.Values{"address": {fake.Address()}})
	wantStatus(t, rec, http.StatusOK)
	fp := rec.Body.String()
	groups := strings.Fields(bubblesclient.FormatFingerprint(fake.CAFingerprint))
	if !strings.Contains(fp, `<p class="fingerprint fpbig">`+strings.Join(groups[:4], " ")+`</p>`) || !strings.Contains(fp, strings.Join(groups[4:], " ")) {
		t.Errorf("the fingerprint page does not show the first four groups large and the rest:\n%s", fp)
	}
	if !strings.Contains(fp, "office chat") || !strings.Contains(fp, "Admin &gt; Overview") {
		t.Errorf("the fingerprint page:\n%s", fp)
	}
	form := confirmForm(t, fp)
	if form.Get("candidate") == "" || form.Get("fingerprint") != "" {
		t.Errorf("the confirmation must name the fetched CA by a one-time ID only: %v", form)
	}
	// Without the confirmation nothing is asked of bubbles.
	if rec := w.post("/settings/bubbles/pair", url.Values{"candidate": form["candidate"]}); rec.Code != http.StatusBadRequest {
		t.Errorf("pairing without the confirmation: %d", rec.Code)
	}
	if fake.Request() != nil {
		t.Fatal("bubbles was asked to pair before the owner confirmed the fingerprint")
	}
	wantRedirect(t, w.post("/settings/bubbles/pair", form), "/settings/bubbles")
	rec = w.get("/settings/bubbles")
	body := rec.Body.String()
	if !strings.Contains(body, "123 456") || !strings.Contains(body, `<meta http-equiv="refresh" content="3">`) || !strings.Contains(body, "Admin &gt; Pairing") {
		t.Errorf("the waiting page does not show the code and check again:\n%s", body)
	}
	if req := fake.Request(); req == nil || req.AppName != "telltale" {
		t.Fatalf("pairing request %+v", req)
	}
	fake.Approve()
	waitUntil(t, "the approval", func() bool { return w.bub.PairStatus().State == alerts.PairApproved })
	body = w.get("/settings/bubbles").Body.String()
	if !strings.Contains(body, "#telltale-alerts") || !strings.Contains(body, `action="/settings/bubbles/test"`) || strings.Contains(body, `http-equiv="refresh"`) {
		t.Errorf("after the approval:\n%s", body)
	}
	if raw, _ := w.st.SecretSetting(alerts.SettingConn); !strings.HasPrefix(string(raw), "bubbles://") {
		t.Errorf("connection not stored: %q", raw)
	}
	wantRedirect(t, w.post("/settings/bubbles/test", nil), "/settings/bubbles")
	if p := fake.Posts(); len(p) != 1 || p[0].DedupeKey != alerts.TestKey {
		t.Errorf("test alert: %+v", p)
	}
	if !strings.Contains(w.get("/settings/bubbles").Body.String(), "The test alert reached #telltale-alerts") {
		t.Error("no word that the test alert went out")
	}
	page = w.get("/settings").Body.String()
	if !strings.Contains(page, "#telltale-alerts") {
		t.Errorf("the settings page does not show where alerts go:\n%s", page)
	}

	// Disconnecting needs its confirmation page.
	if rec := w.post("/settings/bubbles/disconnect", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("disconnect without confirming: %d", rec.Code)
	}
	rec = w.get("/settings/bubbles/disconnect")
	wantStatus(t, rec, http.StatusOK)
	wantRedirect(t, w.post("/settings/bubbles/disconnect", confirmForm(t, rec.Body.String())), "/settings/bubbles")
	if ok, _ := w.bub.Connected(); ok {
		t.Error("still connected")
	}

	acts := auditActions(t, w.st)
	for _, want := range []string{"bubbles fingerprint shown: ", "bubbles pairing requested: ", "bubbles connected: ", "bubbles test alert sent: ", "bubbles disconnected: "} {
		if !hasAudit(t, w.st, want) {
			t.Errorf("no audit entry %q in %q", want, acts)
		}
	}
	for _, a := range acts {
		if strings.Contains(a, "office") || strings.Contains(a, bubblestest.Token) || strings.Contains(a, "127.0.0.1") || strings.Contains(a, "telltale-alerts") {
			t.Errorf("the audit log holds text from bubbles or the owner's input: %q", a)
		}
	}
}

// "It doesn't match" stops the wizard, says why, and is audited.
func TestBubblesFingerprintMismatch(t *testing.T) {
	w := loggedIn(t)
	fake := bubblestest.New(t)
	w.get("/settings/bubbles")
	w.post("/settings/bubbles/inspect", url.Values{"address": {fake.Address()}})
	rec := w.post("/settings/bubbles/nomatch", nil)
	wantStatus(t, rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), "Stop here and tell your chat admin.") {
		t.Errorf("nomatch page:\n%s", rec.Body)
	}
	if !hasAudit(t, w.st, "bubbles fingerprint did not match: ") || fake.Request() != nil {
		t.Errorf("audit %q, request %+v", auditActions(t, w.st), fake.Request())
	}
}

// What a bubbles server says (its name, its channels' names) is escaped on
// the pages, and a server on the internet is refused.
func TestBubblesPagesEscapeServerText(t *testing.T) {
	w := loggedIn(t)
	fake := bubblestest.New(t)
	fake.SetInstanceName("<script>alert(1)</script>\x1b[31mevil")
	fake.SetChannels(protocol.PairingChannel{ID: "c1", Name: "ops<b>\x07"}, protocol.PairingChannel{ID: "c2", Name: "sec"})
	w.get("/settings/bubbles")
	rec := w.post("/settings/bubbles/inspect", url.Values{"address": {fake.Address()}})
	wantStatus(t, rec, http.StatusOK)
	if b := rec.Body.String(); strings.Contains(b, "<script>") || strings.Contains(b, "\x1b") || !strings.Contains(b, `\x1b[31mevil`) {
		t.Errorf("the server's name is not escaped:\n%s", b)
	}
	wantRedirect(t, w.post("/settings/bubbles/pair", confirmForm(t, rec.Body.String())), "/settings/bubbles")
	fake.Approve()
	waitUntil(t, "the approval", func() bool { return w.bub.PairStatus().State == alerts.PairApproved })
	body := w.get("/settings/bubbles").Body.String()
	if strings.Contains(body, "<b>") || strings.Contains(body, "\x07") || !strings.Contains(body, "Which channel should alerts go to?") {
		t.Errorf("the channel choice:\n%s", body)
	}
	wantRedirect(t, w.post("/settings/bubbles/channel", url.Values{"channel": {"c2"}}), "/settings/bubbles")
	if st, _ := w.bub.Status(); st.Channel.ID != "c2" {
		t.Errorf("channel %+v", st.Channel)
	}
	if !hasAudit(t, w.st, "bubbles channel chosen: ") {
		t.Errorf("audit %q", auditActions(t, w.st))
	}
	w.get("/settings/bubbles")
	if rec := w.post("/settings/bubbles/inspect", url.Values{"address": {"203.0.113.9"}}); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "local network") {
		t.Errorf("a server on the internet: %d\n%s", rec.Code, rec.Body)
	}
}

// A stored connection that cannot be read is said so, and can be
// disconnected; the settings page still works.
func TestBubblesUnreadableConnection(t *testing.T) {
	w := loggedIn(t)
	if err := w.st.SetSecretSetting(alerts.SettingConn, []byte("not a connection string")); err != nil {
		t.Fatal(err)
	}
	rec := w.get("/settings")
	wantStatus(t, rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), "The bubbles connection cannot be read") {
		t.Errorf("settings page:\n%s", rec.Body)
	}
	rec = w.get("/settings/bubbles")
	wantStatus(t, rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), `href="/settings/bubbles/disconnect"`) {
		t.Errorf("bubbles page:\n%s", rec.Body)
	}
	rec = w.get("/settings/bubbles/disconnect")
	wantRedirect(t, w.post("/settings/bubbles/disconnect", confirmForm(t, rec.Body.String())), "/settings/bubbles")
	if raw, _ := w.st.SecretSetting(alerts.SettingConn); len(raw) != 0 {
		t.Error("not cleared")
	}
}
