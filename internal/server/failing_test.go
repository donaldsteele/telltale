package server

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/store"
	"github.com/donaldsteele/telltale/internal/visit"
)

func refused() error {
	return fmt.Errorf("visit web01: log in to 192.0.2.7:22: %w: ssh: handshake failed", visit.ErrLoginRefused)
}

func unreachable() error {
	return errors.New("visit web01: log in to 192.0.2.7:22: dial tcp 192.0.2.7:22: i/o timeout")
}

// failingFixture is a machine with one good visit behind it, at the default
// alert level, whose next visits fail with what *fail returns.
func failingFixture(t *testing.T) (*fixture, *func() error) {
	t.Helper()
	fx := newFixture(t)
	var fail func() error
	fx.vis.collect = func(store.Machine, int) (*model.Collection, error) {
		if fail != nil {
			return nil, fail()
		}
		return base(), nil
	}
	fx.visitOK(t, fx.id)
	if got := fx.alerts.all(); len(got) != 0 {
		t.Fatalf("alerts after a clean visit: %+v", got)
	}
	return fx, &fail
}

// The server's key line or Match block was removed: the machine answers and
// refuses the login. After a good visit that is a backdoor sign and one
// alert, whatever the alert level; a good visit resolves it.
func TestLostAccessAfterGoodVisitIsBackdoorSignAndAlerts(t *testing.T) {
	fx, fail := failingFixture(t)
	*fail = refused
	ctx := context.Background()
	for i := 1; i <= 2; i++ {
		if rid, err := fx.core.VisitNow(ctx, fx.id); rid != 0 || err == nil {
			t.Fatalf("failure %d: report %d, err %v", i, rid, err)
		}
	}
	if got := fx.alerts.all(); len(got) != 0 {
		t.Fatalf("alerted before the third failure: %+v", got)
	}
	rid, err := fx.core.VisitNow(ctx, fx.id)
	if rid == 0 || err == nil {
		t.Fatalf("third failure: report %d, err %v", rid, err)
	}
	r, _, _ := fx.st.Report(rid)
	if f := find(r, "visit.failing"); f == nil || f.Severity != model.SevBackdoor {
		t.Fatalf("report %+v", r.Findings)
	}
	if got := fx.alerts.all(); len(got) != 1 || !slices.Equal(got[0].fresh, []string{"visit.failing"}) || len(got[0].resolved) != 0 {
		t.Fatalf("alerts %+v", got)
	}
	// The outage goes on: no second report, no second alert.
	for i := 0; i < 4; i++ {
		if rid, _ := fx.core.VisitNow(ctx, fx.id); rid != 0 {
			t.Errorf("failure %d of the same outage stored report %d", i+4, rid)
		}
	}
	if got := fx.alerts.all(); len(got) != 1 {
		t.Fatalf("alerts during the outage: %+v", got)
	}
	// A good visit resolves it.
	*fail = nil
	fx.visitOK(t, fx.id)
	got := fx.alerts.all()
	if len(got) != 2 || len(got[1].fresh) != 0 || !slices.Equal(got[1].resolved, []string{"visit.failing"}) {
		t.Fatalf("alerts after the good visit: %+v", got)
	}
	// And the next outage alerts again.
	*fail = refused
	for i := 0; i < 3; i++ {
		fx.core.VisitNow(ctx, fx.id)
	}
	if got := fx.alerts.all(); len(got) != 3 || !slices.Equal(got[2].fresh, []string{"visit.failing"}) {
		t.Fatalf("alerts for the second outage: %+v", got)
	}
}

// Plain unreachability after a good visit is a weak setting, and still one
// alert at the default alert level.
func TestUnreachableAfterGoodVisitIsWeakAndAlerts(t *testing.T) {
	fx, fail := failingFixture(t)
	*fail = unreachable
	ctx := context.Background()
	var rid int64
	for i := 0; i < 3; i++ {
		rid, _ = fx.core.VisitNow(ctx, fx.id)
	}
	if rid == 0 {
		t.Fatal("no report after three failures")
	}
	r, _, _ := fx.st.Report(rid)
	if f := find(r, "visit.failing"); f == nil || f.Severity != model.SevWeak {
		t.Fatalf("report %+v", r.Findings)
	}
	if got := fx.alerts.all(); len(got) != 1 || !slices.Equal(got[0].fresh, []string{"visit.failing"}) {
		t.Fatalf("alerts %+v", got)
	}
	for i := 0; i < 3; i++ {
		if rid, _ := fx.core.VisitNow(ctx, fx.id); rid != 0 {
			t.Errorf("the same outage stored report %d", rid)
		}
	}
	if got := fx.alerts.all(); len(got) != 1 {
		t.Fatalf("alerts during the outage: %+v", got)
	}

	// The machine comes back within reach and now refuses the login: worse
	// than what the owner was told, so it is said once more.
	*fail = refused
	rid, _ = fx.core.VisitNow(ctx, fx.id)
	if rid == 0 {
		t.Fatal("no report when the outage turned into a refused login")
	}
	r, _, _ = fx.st.Report(rid)
	if f := find(r, "visit.failing"); f == nil || f.Severity != model.SevBackdoor {
		t.Fatalf("report %+v", r.Findings)
	}
	if got := fx.alerts.all(); len(got) != 2 || !slices.Equal(got[1].fresh, []string{"visit.failing"}) {
		t.Fatalf("alerts %+v", got)
	}
	if rid, _ := fx.core.VisitNow(ctx, fx.id); rid != 0 {
		t.Errorf("a further refused login stored report %d", rid)
	}
	if got := fx.alerts.all(); len(got) != 2 {
		t.Fatalf("alerts %+v", got)
	}
}

func failures(t *testing.T, fx *fixture) string {
	t.Helper()
	v, _ := fx.st.Setting(failuresSetting(fx.id))
	return v
}

// A visit that kills the server (a collection that exhausts its memory) is
// never seen to fail. So the attempt is counted before the visit starts and
// the count is cleared only by a visit that works: a server that dies three
// times in a row on one machine says so at its next start, instead of
// visiting again.
func TestAVisitThatKillsTheServerIsCounted(t *testing.T) {
	fx, fail := failingFixture(t)
	if got := failures(t, fx); got != "0" {
		t.Fatalf("after a good visit: %q", got)
	}
	// While a visit runs, the attempt is already on disk.
	var during string
	fx.vis.collect = func(store.Machine, int) (*model.Collection, error) {
		during = failures(t, fx)
		return base(), nil
	}
	fx.visitOK(t, fx.id)
	if during != "1" || failures(t, fx) != "0" {
		t.Fatalf("during the visit %q, after it %q", during, failures(t, fx))
	}
	_ = fail

	// Three attempts that never came back: the count is all that is left.
	if err := fx.st.SetSetting(failuresSetting(fx.id), "3"); err != nil {
		t.Fatal(err)
	}
	before := fx.vis.visits(fx.id)
	rid, err := fx.core.VisitNow(context.Background(), fx.id)
	if rid == 0 || err == nil {
		t.Fatalf("report %d, err %v", rid, err)
	}
	if fx.vis.visits(fx.id) != before {
		t.Error("the machine was visited again before the owner was told")
	}
	r, _, _ := fx.st.Report(rid)
	if f := find(r, "visit.failing"); f == nil || f.Severity != model.SevBackdoor {
		t.Fatalf("report %+v", r.Findings)
	}
	if got := fx.alerts.all(); len(got) != 1 || !slices.Equal(got[0].fresh, []string{"visit.failing"}) {
		t.Fatalf("alerts %+v", got)
	}
	// Told once; the next round visits again, and a visit that works
	// resolves it.
	fx.vis.collect = func(store.Machine, int) (*model.Collection, error) { return base(), nil }
	fx.visitOK(t, fx.id)
	if got := fx.alerts.all(); len(got) != 2 || !slices.Equal(got[1].resolved, []string{"visit.failing"}) || failures(t, fx) != "0" {
		t.Fatalf("alerts %+v, failures %q", got, failures(t, fx))
	}
}

// A failure that is recorded counts once, not twice, and what is not the
// machine's failure does not count at all.
func TestFailedVisitsAreCountedOnce(t *testing.T) {
	fx, fail := failingFixture(t)
	*fail = unreachable
	fx.core.VisitNow(context.Background(), fx.id)
	if got := failures(t, fx); got != "1" {
		t.Errorf("after one failure: %q", got)
	}
	fx.core.VisitNow(context.Background(), fx.id)
	if got := failures(t, fx); got != "2" {
		t.Errorf("after two failures: %q", got)
	}
	// A changed host key is its own finding and is not a failed visit.
	*fail = func() error {
		return fmt.Errorf("x: %w", &visit.HostKeyMismatchError{Pinned: "SHA256:a", Offered: "SHA256:b"})
	}
	fx.core.VisitNow(context.Background(), fx.id)
	if got := failures(t, fx); got != "2" {
		t.Errorf("after a changed host key: %q", got)
	}
	// Nor is a visit the server itself cut short by stopping.
	ctx, cancel := context.WithCancel(context.Background())
	*fail = func() error { cancel(); return context.Canceled }
	fx.core.VisitNow(ctx, fx.id)
	if got := failures(t, fx); got != "2" {
		t.Errorf("after the server stopped a visit: %q", got)
	}
}

// After a login that worked, what the machine sends is its own doing: a
// collector that is killed, output over the bound, something that is not a
// collection, or one with more entries than any machine has. On a machine
// that had good visits each is a backdoor sign, so nobody can pick a quieter
// failure than a refused login. No directory to run from stays weak.
func TestFailuresAfterLoginAreBackdoorSigns(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		key  string
		sev  model.Severity
		word string
	}{
		"collector failed": {fmt.Errorf("visit web01: %w: collect: killed by signal KILL", visit.ErrCollectorFailed), "visit.failing", model.SevBackdoor, "collector"},
		"oversized":        {fmt.Errorf("visit web01: %w: %w: more than 1000000 files", visit.ErrCollectorFailed, visit.ErrOversized), "visit.oversized", model.SevBackdoor, "more entries"},
		"no exec dir":      {fmt.Errorf("visit web01: %w (noexec)", visit.ErrNoExecDir), "visit.failing", model.SevWeak, ""},
		"connection lost":  {errors.New("visit web01: collect: the command or the connection ended without an exit status"), "visit.failing", model.SevWeak, ""},
	} {
		t.Run(name, func(t *testing.T) {
			fx, fail := failingFixture(t)
			*fail = func() error { return tc.err }
			var rid int64
			for i := 0; i < 3; i++ {
				rid, _ = fx.core.VisitNow(context.Background(), fx.id)
			}
			if rid == 0 {
				t.Fatal("no report")
			}
			r, _, _ := fx.st.Report(rid)
			f := find(r, tc.key)
			if f == nil || f.Severity != tc.sev || len(r.Findings) != 1 {
				t.Fatalf("report %+v", r.Findings)
			}
			if tc.word != "" && !strings.Contains(f.Title+f.Why, tc.word) {
				t.Errorf("finding %q / %q", f.Title, f.Why)
			}
			if strings.Contains(f.Title+f.Why+f.Fix, "web01") || strings.Contains(f.Title+f.Why+f.Fix, "KILL") {
				t.Errorf("the error's text reached the finding: %+v", f)
			}
			if got := fx.alerts.all(); len(got) != 1 || !slices.Equal(got[0].fresh, []string{tc.key}) {
				t.Fatalf("alerts %+v", got)
			}
			// The page shows such a report as one about the visit, and a
			// good visit resolves it.
			if !synthetic(r) {
				t.Error("not treated as a report about the visit")
			}
			*fail = nil
			fx.visitOK(t, fx.id)
			if got := fx.alerts.all(); len(got) != 2 || !slices.Equal(got[1].resolved, []string{tc.key}) {
				t.Fatalf("alerts after the good visit: %+v", got)
			}
		})
	}
}
