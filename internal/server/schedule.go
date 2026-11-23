package server

import (
	"context"
	"math/rand/v2"
	"strconv"
	"sync"
	"time"

	"github.com/donaldsteele/telltale/internal/store"
)

// Schedules a machine can have. Anything else, the empty string included,
// is daily.
const (
	ScheduleHourly = "hourly"
	ScheduleDaily  = "daily"
	ScheduleWeekly = "weekly"
	ScheduleManual = "manual" // only "check now"
)

// Variables, so tests can shorten them.
var (
	// scheduleTick is how often Run looks for machines that are due.
	scheduleTick = time.Minute
	// startJitter spreads the first visits to machines never visited, or
	// overdue when the server starts, over this long.
	startJitter = 5 * time.Minute
)

// interval is how often a schedule visits; false for manual.
func interval(schedule string) (time.Duration, bool) {
	switch schedule {
	case ScheduleManual:
		return 0, false
	case ScheduleHourly:
		return time.Hour, true
	case ScheduleWeekly:
		return 7 * 24 * time.Hour, true
	}
	return 24 * time.Hour, true
}

// jitter is a random delay below max (none when max is not positive).
func jitter(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	return rand.N(max)
}

// scheduler is Run's view of when each machine is due.
type scheduler struct {
	mu      sync.Mutex
	next    map[int64]time.Time
	every   map[int64]time.Duration
	running map[int64]bool
}

// Run visits machines on their schedules until ctx ends: daily by default,
// hourly, weekly, or never for manual. Each next visit is a schedule's
// interval after the last one plus up to a twentieth of it at random, so
// machines on the same schedule do not all go at once; machines never
// visited, or overdue when Run starts, are spread over a few minutes. One
// visit runs per machine and at most four in all (VisitNow). When ctx ends,
// Run stops starting visits and returns once the running ones have ended;
// they end with ctx too, each removing its collector from the machine.
func (c *Core) Run(ctx context.Context) {
	c.init()
	s := &scheduler{next: map[int64]time.Time{}, every: map[int64]time.Duration{}, running: map[int64]bool{}}
	var wg sync.WaitGroup
	defer wg.Wait()
	tick := time.NewTicker(scheduleTick)
	defer tick.Stop()
	for {
		c.dispatch(ctx, s, &wg)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// dispatch starts a visit to every machine that is due.
func (c *Core) dispatch(ctx context.Context, s *scheduler, wg *sync.WaitGroup) {
	if ctx.Err() != nil {
		return
	}
	ms, err := c.Store.Machines()
	if err != nil {
		return // tried again at the next tick
	}
	now := c.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, m := range ms {
		every, auto := interval(m.Schedule)
		if !auto || s.running[m.ID] {
			continue
		}
		due, ok := s.next[m.ID]
		if !ok || s.every[m.ID] != every {
			due = c.firstDue(m, every, now)
			s.next[m.ID], s.every[m.ID] = due, every
		}
		if now.Before(due) {
			continue
		}
		s.running[m.ID] = true
		wg.Add(1)
		go func(id int64, every time.Duration) {
			defer wg.Done()
			c.VisitNow(ctx, id) // errors are recorded on the machine and in reports
			s.mu.Lock()
			defer s.mu.Unlock()
			s.running[id] = false
			s.next[id] = c.now().Add(every + jitter(every/20))
		}(m.ID, every)
	}
}

// firstDue is when a machine Run has not scheduled yet is due: an interval
// after its last visit or attempt, or soon when that is past or there was
// none.
func (c *Core) firstDue(m store.Machine, every time.Duration, now time.Time) time.Time {
	var last time.Time
	if m.LastVisit != nil {
		last = *m.LastVisit
	}
	if v, _ := c.Store.Setting(attemptSetting(m.ID)); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			if t := time.Unix(0, n); t.After(last) {
				last = t
			}
		}
	}
	if !last.IsZero() {
		if due := last.Add(every + jitter(every/20)); due.After(now) {
			return due
		}
	}
	return now.Add(jitter(startJitter))
}
