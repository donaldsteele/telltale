package server

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/store"
)

// An exception the owner removes stops hiding its finding: the next visit
// reports it, and alerts about it, again.
func TestRemoveExceptionBringsTheFindingBack(t *testing.T) {
	fx := newFixture(t)
	fx.vis.collect = func(store.Machine, int) (*model.Collection, error) { return uid0(base()), nil }
	rid, _ := fx.visitOK(t, fx.id)
	ctx := context.Background()
	const mark = "HOSTILE\x1b[2J"
	if err := fx.core.AddException(ctx, fx.id, rid, "heur.uid0:toor", mark); err != nil {
		t.Fatal(err)
	}
	if _, r := fx.visitOK(t, fx.id); find(r, "heur.uid0:toor") != nil {
		t.Fatal("the exception does not hide the finding")
	}
	rows, err := fx.st.ExceptionRows(fx.id)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows %+v: %v", rows, err)
	}
	other := fx.addMachine(t, "files02", "")
	if err := fx.core.RemoveException(ctx, other, rows[0].ID); err == nil {
		t.Error("removed through another machine")
	}
	if err := fx.core.RemoveException(ctx, fx.id, rows[0].ID+100); err == nil {
		t.Error("removed an exception that does not exist")
	}
	before := len(fx.alerts.all())
	if err := fx.core.RemoveException(ctx, fx.id, rows[0].ID); err != nil {
		t.Fatal(err)
	}
	if exc, _ := fx.st.Exceptions(fx.id); len(exc) != 0 {
		t.Fatalf("still there: %+v", exc)
	}
	_, r := fx.visitOK(t, fx.id)
	if find(r, "heur.uid0:toor") == nil || len(r.Exceptions) != 0 {
		t.Errorf("the finding did not come back: %v, exceptions %+v", keysOf(r.Findings), r.Exceptions)
	}
	if got := fx.alerts.all(); len(got) != before+1 || !slices.Contains(got[len(got)-1].fresh, "heur.uid0:toor") {
		t.Errorf("no alert for the finding that came back: %+v", got)
	}

	// The audit entry holds fixed words and IDs only.
	log, _ := fx.st.AuditLog(0)
	found := false
	for _, e := range log {
		if strings.Contains(e.Actor+e.Action+e.Detail, "HOSTILE") || strings.ContainsAny(e.Actor+e.Action+e.Detail, "\x1b") {
			t.Errorf("audit entry carries the owner's note or machine text: %+v", e)
		}
		if e.Action == "remove exception" {
			found = true
			if e.Actor != actorOwner || e.Detail != "machine "+strconv.FormatInt(fx.id, 10)+" exception "+strconv.FormatInt(rows[0].ID, 10) {
				t.Errorf("audit entry %+v", e)
			}
		}
	}
	if !found {
		t.Error("removing an exception is not in the audit log")
	}
}

func TestRemoveExceptionRefusedDuringAVisit(t *testing.T) {
	fx := newFixture(t)
	fx.vis.collect = func(store.Machine, int) (*model.Collection, error) { return uid0(base()), nil }
	rid, _ := fx.visitOK(t, fx.id)
	ctx := context.Background()
	if err := fx.core.AddException(ctx, fx.id, rid, "heur.uid0:toor", ""); err != nil {
		t.Fatal(err)
	}
	rows, _ := fx.st.ExceptionRows(fx.id)
	fx.vis.gate = make(chan struct{})
	done := make(chan struct{})
	go func() {
		fx.core.VisitNow(context.Background(), fx.id)
		close(done)
	}()
	waitFor(t, func() bool { return fx.vis.visits(fx.id) == 2 })
	if err := fx.core.RemoveException(ctx, fx.id, rows[0].ID); !errors.Is(err, ErrVisitRunning) {
		t.Errorf("during a visit: %v", err)
	}
	close(fx.vis.gate)
	<-done
	if err := fx.core.RemoveException(ctx, fx.id, rows[0].ID); err != nil {
		t.Errorf("after the visit: %v", err)
	}
}

// The web UI: listed with a link, a confirmation page, a POST with the CSRF
// token, and nothing without a session.
func TestRemoveExceptionInTheUI(t *testing.T) {
	w := loggedIn(t)
	id := w.addMachine("web01")
	if err := w.st.AddException(id, model.Exception{FindingKey: "heur.unowned_setuid:/usr/local/bin/helper", AcceptedValue: "sha256 abc", Note: "our own helper"}); err != nil {
		t.Fatal(err)
	}
	rows, _ := w.st.ExceptionRows(id)
	eid := strconv.FormatInt(rows[0].ID, 10)
	mp := "/machines/" + strconv.FormatInt(id, 10)
	link := mp + "/exception/remove?exception=" + eid

	page := w.get(mp)
	wantStatus(t, page, http.StatusOK)
	if !strings.Contains(page.Body.String(), `href="`+strings.ReplaceAll(link, "&", "&amp;")+`"`) {
		t.Errorf("the machine page has no link to remove the exception:\n%s", page.Body)
	}
	form := url.Values{"exception": {eid}}
	if rec := w.post(mp+"/exception/remove", form); rec.Code != http.StatusBadRequest {
		t.Errorf("removal without confirming: %d", rec.Code)
	}
	rec := w.get(link)
	wantStatus(t, rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), "heur.unowned_setuid:/usr/local/bin/helper") || !strings.Contains(rec.Body.String(), "our own helper") {
		t.Errorf("the confirmation does not show the exception:\n%s", rec.Body)
	}
	if len(w.core.removed) != 0 {
		t.Fatalf("a GET removed something: %+v", w.core.removed)
	}
	confirm := confirmForm(t, rec.Body.String())
	if rec := w.post(mp+"/exception/remove", confirm, func(r *http.Request) { r.PostForm = nil }, func(r *http.Request) {}); rec.Code != http.StatusSeeOther {
		t.Fatalf("confirmed removal: %d %s", rec.Code, rec.Body)
	}
	if want := [][2]int64{{id, rows[0].ID}}; !slices.Equal(w.core.removed, want) {
		t.Errorf("RemoveException calls %+v, want %+v", w.core.removed, want)
	}

	// A bad CSRF token, an unknown exception and no session all change nothing.
	w.core.removed = nil
	bad := url.Values{"exception": {eid}, "confirm": {"yes"}, "csrf": {"nope"}}
	if rec := w.post(mp+"/exception/remove", bad); rec.Code != http.StatusForbidden {
		t.Errorf("bad CSRF token: %d", rec.Code)
	}
	if rec := w.get(mp + "/exception/remove?exception=999999"); rec.Code != http.StatusNotFound {
		t.Errorf("unknown exception: %d", rec.Code)
	}
	anon := w.browser("192.0.2.77")
	if rec := anon.post(mp+"/exception/remove", url.Values{"exception": {eid}, "confirm": {"yes"}}); rec.Code == http.StatusOK || rec.Code == http.StatusSeeOther && rec.Header().Get("Location") == mp {
		t.Errorf("without a session: %d -> %s", rec.Code, rec.Header().Get("Location"))
	}
	if len(w.core.removed) != 0 {
		t.Errorf("removed without the owner's confirmed request: %+v", w.core.removed)
	}
}

// The log line for a failed request never carries raw control characters,
// whatever the path or the error holds: a log is read in a terminal.
func TestServerErrorLogEscapesThePath(t *testing.T) {
	var buf strings.Builder
	u := &UI{o: UIOptions{Log: log.New(&buf, "", 0)}}
	if err := u.loadTemplates(); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "https://192.0.2.10:8443/x", nil)
	r.URL.Path = "/machines/1\x1b]0;owned\x07\n2026/11/23 forged line\x1b[2J"
	u.serverError(httptest.NewRecorder(), r, errors.New("store: \x1b[31mred\x07"))
	got := buf.String()
	if strings.ContainsAny(strings.TrimSuffix(got, "\n"), "\x1b\x07\n\r") {
		t.Errorf("raw control characters in the log line: %q", got)
	}
	if !strings.Contains(got, "/machines/1") || !strings.Contains(got, "forged line") || !strings.Contains(got, "red") {
		t.Errorf("the log line lost the path or the error: %q", got)
	}
}
