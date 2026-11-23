package server

import (
	"context"
	"errors"
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

// Run visits machines on their schedules until ctx ends: daily by default,
// hourly, weekly, or never for manual. Each next visit is a schedule's
// interval after the last one (a "check now" included) plus up to a
// twentieth of it at random, so machines on the same schedule do not all go
// at once; machines never visited, or overdue when Run starts, are spread
// over a few minutes. One visit runs per machine and at most four in all
// (VisitNow). Visit errors go to the server log. When ctx ends, Run stops
// starting visits and returns once the running ones have ended; they end
// with ctx too, each removing its collector from the machine.
func (c *Core) Run(ctx context.Context) {
	c.init()
	var wg sync.WaitGroup
	defer wg.Wait()
	tick := time.NewTicker(scheduleTick)
	defer tick.Stop()
	for {
		c.dispatch(ctx, &wg)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// dispatch starts a visit to every machine that is due.
func (c *Core) dispatch(ctx context.Context, wg *sync.WaitGroup) {
	if ctx.Err() != nil {
		return
	}
	ms, err := c.Store.Machines()
	if err != nil {
		c.logf("telltale server: list the machines to visit: %v", err)
		return // tried again at the next tick
	}
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, m := range ms {
		every, auto := interval(m.Schedule)
		if !auto {
			delete(c.due, m.ID)
			continue
		}
		if c.queued[m.ID] || c.busy[m.ID] {
			continue
		}
		due, ok := c.due[m.ID]
		if !ok || c.dueEvery[m.ID] != every {
			due = c.firstDue(m, every, now)
			c.due[m.ID], c.dueEvery[m.ID] = due, every
		}
		if now.Before(due) {
			continue
		}
		c.queued[m.ID] = true
		wg.Add(1)
		go func(id int64) {
			defer wg.Done()
			_, err := c.VisitNow(ctx, id) // reschedules the machine
			c.mu.Lock()
			delete(c.queued, id)
			c.mu.Unlock()
			// A running visit reschedules the machine itself; a stop is
			// not news.
			if err != nil && !errors.Is(err, ErrVisitRunning) && ctx.Err() == nil {
				c.logf("telltale server: visit to machine %d: %v", id, err)
			}
		}(m.ID)
	}
}

// reschedule makes the machine's next scheduled visit an interval from now.
func (c *Core) reschedule(id int64) {
	m, err := c.Store.Machine(id)
	if err != nil {
		return
	}
	every, auto := interval(m.Schedule)
	c.mu.Lock()
	defer c.mu.Unlock()
	if !auto {
		delete(c.due, id)
		return
	}
	c.due[id], c.dueEvery[id] = c.now().Add(every+jitter(every/20)), every
}

// firstDue is when a machine not scheduled yet is due: an interval after
// its last visit or attempt, or soon when that is past or there was none.
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
