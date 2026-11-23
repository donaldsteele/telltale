package server

import (
	"context"
	"errors"
	"fmt"
	"slices"
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
