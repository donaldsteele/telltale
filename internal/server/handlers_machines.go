package server

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/donaldsteele/telltale/internal/escape"
	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/report"
	"github.com/donaldsteele/telltale/internal/store"
	"github.com/donaldsteele/telltale/internal/visit"
)

// Every string below that came from a machine (titles, evidence, keys,
// host names) passes through escape.Terminal here, and html/template
// escapes it again for HTML when the page is written.

type evidenceView struct {
	Where, Change, When, Detail string
}

type findingView struct {
	Key, Label, Class, Title, Why, Refs string
	Evidence                            []evidenceView
	Fix, FixID                          string
	CanCopy                             bool
	ExceptURL                           string
}

type reportView struct {
	ID              int64
	Time            string
	Host            string
	ComparedAgainst string
	CouldNotRuleOut []string
	Findings        []findingView
	Explained       []string
	Skipped         []string
	Exceptions      []string
	Synthetic       bool
}

func sevClass(s model.Severity) string {
	switch s {
	case model.SevTampering:
		return "tampering"
	case model.SevBackdoor:
		return "backdoor"
	case model.SevWeak:
		return "weak"
	case model.SevNote:
		return "note"
	}
	return "explained"
}

func evidenceViews(evs []model.Evidence) []evidenceView {
	out := make([]evidenceView, 0, len(evs))
	for _, e := range evs {
		v := evidenceView{Detail: escape.Terminal(e.Detail)}
		if e.Path != "" {
			v.Where = escape.Terminal(e.Path)
			if e.Line > 0 {
				v.Where += ":" + strconv.Itoa(e.Line)
			}
		}
		switch {
		case e.Before != "" && e.After != "":
			v.Change = escape.Terminal(e.Before) + "  →  " + escape.Terminal(e.After)
		case e.After != "":
			v.Change = "→ " + escape.Terminal(e.After)
		case e.Before != "":
			v.Change = escape.Terminal(e.Before) + "  →  (gone)"
		}
		if e.When != nil {
			v.When = "changed " + fmtTime(*e.When)
		}
		out = append(out, v)
	}
	return out
}

// findingViews ranks findings (most severe first, the report's own order
// within a severity) and builds their views. machineID and reportID make
// the exception links; 0 leaves them out.
func findingViews(fs []model.Finding, machineID, reportID int64, idPrefix string) []findingView {
	ranked := slices.Clone(fs)
	slices.SortStableFunc(ranked, func(a, b model.Finding) int { return int(b.Severity) - int(a.Severity) })
	out := make([]findingView, 0, len(ranked))
	for i, f := range ranked {
		v := findingView{
			Key:      escape.Terminal(f.Key),
			Label:    report.Label(f.Severity),
			Class:    sevClass(f.Severity),
			Title:    escape.Terminal(f.Title),
			Why:      escape.Terminal(f.Why),
			Evidence: evidenceViews(f.Evidence),
			FixID:    idPrefix + strconv.Itoa(i),
		}
		var refs []string
		for _, r := range f.Refs {
			refs = append(refs, escape.Terminal(r))
		}
		v.Refs = strings.Join(refs, ", ")
		if f.Fix != "" {
			v.Fix, v.CanCopy = fixText(f.Fix)
		}
		if machineID > 0 && f.Key != "" && !strings.HasPrefix(f.Key, sourceVisit+".") {
			q := url.Values{"report": {strconv.FormatInt(reportID, 10)}, "key": {f.Key}}
			v.ExceptURL = fmt.Sprintf("/machines/%d/exception?%s", machineID, q.Encode())
		}
		out = append(out, v)
	}
	return out
}

func buildReportView(rid, machineID int64, r *model.Report) *reportView {
	v := &reportView{
		ID:        rid,
		Time:      fmtTime(r.Time),
		Findings:  findingViews(r.Findings, machineID, rid, "fix-"),
		Synthetic: synthetic(r),
	}
	h := r.Host
	if h.Hostname != "" {
		v.Host = escape.Terminal(h.Hostname)
		var more []string
		for _, s := range []string{h.OSPretty, h.Arch} {
			if s != "" {
				more = append(more, escape.Terminal(s))
			}
		}
		if len(more) > 0 {
			v.Host += " (" + strings.Join(more, ", ") + ")"
		}
	}
	var ca []string
	for _, s := range r.ComparedAgainst {
		ca = append(ca, escape.Terminal(s))
	}
	v.ComparedAgainst = strings.Join(ca, ", ")
	for _, s := range r.CouldNotRuleOut {
		v.CouldNotRuleOut = append(v.CouldNotRuleOut, escape.Terminal(s))
	}
	for _, f := range r.Explained {
		v.Explained = append(v.Explained, escape.Terminal(f.Title))
	}
	for _, s := range r.Skipped {
		v.Skipped = append(v.Skipped, escape.Terminal(s.Check)+": "+escape.Terminal(s.Reason))
	}
	for _, e := range r.Exceptions {
		v.Exceptions = append(v.Exceptions, exceptionText(e))
	}
	return v
}

func exceptionText(e model.Exception) string {
	s := escape.Terminal(e.FindingKey) + " = " + escape.Terminal(e.AcceptedValue)
	if e.Note != "" {
		s += " (" + escape.Terminal(e.Note) + ")"
	}
	if !e.At.IsZero() {
		s += ", accepted " + e.At.UTC().Format("2006-01-02")
	}
	return s
}

// worst is the most severe of a report's findings: the first of the highest
// severity in the report's order.
func worst(fs []model.Finding) *model.Finding {
	var w *model.Finding
	for i := range fs {
		if w == nil || fs[i].Severity > w.Severity {
			w = &fs[i]
		}
	}
	return w
}

func countText(n int) string {
	switch n {
	case 0:
		return "No findings"
	case 1:
		return "1 finding"
	}
	return strconv.Itoa(n) + " findings"
}

type machineRow struct {
	ID                    int64
	Name, Addr, LastVisit string
	Visited, Clean        bool
	Visiting, Failing     bool
	WorstLabel            string
	WorstClass            string
	WorstTitle            string
	Count                 string
}

func (u *UI) machinesPage(c *reqCtx) {
	ms, err := u.o.Store.Machines()
	if err != nil {
		u.serverError(c.w, c.r, err)
		return
	}
	rows := make([]machineRow, 0, len(ms))
	for _, m := range ms {
		row := machineRow{ID: m.ID, Name: escape.Terminal(m.Name), Addr: escape.Terminal(m.Addr), Clean: m.Clean, Visiting: u.o.Core.Visiting(m.ID)}
		if m.LastVisit != nil {
			row.LastVisit = fmtTime(*m.LastVisit)
		}
		if e, _ := u.o.Core.VisitError(m.ID); e != "" {
			row.Failing = true
		}
		metas, err := u.o.Store.Reports(m.ID, 1)
		if err != nil {
			u.serverError(c.w, c.r, err)
			return
		}
		if len(metas) > 0 {
			row.Visited = true
			rep, _, err := u.o.Store.ReportOnly(metas[0].ID)
			if err != nil {
				u.serverError(c.w, c.r, err)
				return
			}
			row.Count = countText(len(rep.Findings))
			if w := worst(rep.Findings); w != nil {
				row.WorstLabel, row.WorstClass, row.WorstTitle = report.Label(w.Severity), sevClass(w.Severity), escape.Terminal(w.Title)
			}
		}
		rows = append(rows, row)
	}
	u.page(c, http.StatusOK, "machines", "Machines", "machines", rows, "")
}

type historyRow struct {
	ID       int64
	Time     string
	Summary  string
	Class    string
	Count    string
	Selected bool
}

type option struct {
	Value, Label string
	Selected     bool
}

var schedules = []option{
	{Value: ScheduleHourly, Label: "Every hour"},
	{Value: ScheduleDaily, Label: "Every day"},
	{Value: ScheduleWeekly, Label: "Every week"},
	{Value: ScheduleManual, Label: "Only when I press Check now"},
}

func scheduleOptions(cur string) []option {
	if cur == "" {
		cur = ScheduleDaily
	}
	out := slices.Clone(schedules)
	for i := range out {
		out[i].Selected = out[i].Value == cur
	}
	return out
}

func validSchedule(s string) bool {
	return slices.ContainsFunc(schedules, func(o option) bool { return o.Value == s })
}

func exitSummary(code int) (string, string) {
	switch code {
	case 0:
		return "Nothing found", "ok"
	case 1:
		return "Notes or weak settings", "weak"
	case 2:
		return "Tampering or backdoor signs", "tampering"
	}
	return "Could not run", "note"
}

type machineView struct {
	ID                    int64
	Name, Addr, LastVisit string
	Clean, Visiting       bool
	VisitError            string
	Leftovers             []string
	Schedules             []option
	Report                *reportView
	Latest                bool
	CleanURL              string
	Changes               int
	History               []historyRow
	Exceptions            []string
}

// machinePage shows one machine and one of its reports: the latest, or the
// one ?report= names.
func (u *UI) machinePage(c *reqCtx) {
	m := u.machine(c)
	if m == nil {
		return
	}
	v := machineView{ID: m.ID, Name: escape.Terminal(m.Name), Addr: escape.Terminal(m.Addr), Clean: m.Clean, Visiting: u.o.Core.Visiting(m.ID), Schedules: scheduleOptions(m.Schedule)}
	if m.LastVisit != nil {
		v.LastVisit = fmtTime(*m.LastVisit)
	}
	// Stored already escaped and bounded by the core.
	v.VisitError, _ = u.o.Core.VisitError(m.ID)
	left, _ := u.o.Core.Leftovers(m.ID)
	for _, d := range left {
		v.Leftovers = append(v.Leftovers, escape.Terminal(d))
	}
	metas, err := u.o.Store.Reports(m.ID, 50)
	if err != nil {
		u.serverError(c.w, c.r, err)
		return
	}
	rid := int64(0)
	if len(metas) > 0 {
		rid = metas[0].ID
		v.Latest = true
	}
	if q := c.r.URL.Query().Get("report"); q != "" {
		n, err := strconv.ParseInt(q, 10, 64)
		if err != nil {
			u.fail(c.w, c.r, http.StatusNotFound, "There is no such report.")
			return
		}
		v.Latest = len(metas) > 0 && metas[0].ID == n
		rid = n
	}
	if rid > 0 {
		rep, mid, err := u.o.Store.ReportOnly(rid)
		if err != nil || mid != m.ID {
			u.fail(c.w, c.r, http.StatusNotFound, "This machine has no such report.")
			return
		}
		v.Report = buildReportView(rid, m.ID, rep)
		if !v.Report.Synthetic {
			v.CleanURL = fmt.Sprintf("/machines/%d/clean?report=%d", m.ID, rid)
		}
	}
	for _, meta := range metas {
		s, cl := exitSummary(meta.ExitCode)
		v.History = append(v.History, historyRow{ID: meta.ID, Time: fmtTime(meta.Time), Summary: s, Class: cl, Count: countText(meta.Findings), Selected: meta.ID == rid})
	}
	if a, err := u.o.Core.Acceptable(m.ID); err == nil && !a.Stale && len(metas) > 0 && a.ReportID == metas[0].ID {
		v.Changes = len(a.With)
	}
	exc, err := u.o.Store.Exceptions(m.ID)
	if err != nil {
		u.serverError(c.w, c.r, err)
		return
	}
	for _, e := range exc {
		v.Exceptions = append(v.Exceptions, exceptionText(e))
	}
	u.page(c, http.StatusOK, "machine", v.Name, "machines", v, "")
}

// checkNowWait is how long "Check now" waits for a visit that ends at once
// (one already running, a machine that refuses the connection) before it
// says the visit has started.
var checkNowWait = time.Second

func (u *UI) checkNow(c *reqCtx) {
	m := u.machine(c)
	if m == nil {
		return
	}
	u.audit(actorOwner, "check now", "machine %d", m.ID)
	done := make(chan error, 1)
	u.visits.Add(1)
	go func() {
		defer u.visits.Done()
		_, err := u.o.Core.VisitNow(u.o.Context, m.ID)
		done <- err
	}()
	to := fmt.Sprintf("/machines/%d", m.ID)
	select {
	case err := <-done:
		if err != nil {
			u.redirect(c, to, actionError(err))
			return
		}
		u.redirect(c, to, "The visit is done. The report below is the new one.")
	case <-time.After(checkNowWait):
		go func() {
			if err := <-done; err != nil && !errors.Is(err, ErrVisitRunning) {
				u.logf("telltale server: visit to machine %d: %v", m.ID, err)
			}
		}()
		u.redirect(c, to, "The visit has started. Reload this page in a minute or two to see its report.")
	}
}

func (u *UI) setSchedule(c *reqCtx) {
	m := u.machine(c)
	if m == nil {
		return
	}
	s := c.r.PostForm.Get("schedule")
	if !validSchedule(s) {
		u.fail(c.w, c.r, http.StatusBadRequest, "That is not one of the schedules.")
		return
	}
	m.Schedule = s
	if err := u.o.Store.UpdateMachine(*m); err != nil {
		u.serverError(c.w, c.r, err)
		return
	}
	u.audit(actorOwner, "schedule changed", "machine %d", m.ID)
	u.redirect(c, fmt.Sprintf("/machines/%d", m.ID), "Schedule saved.")
}

// machineReport loads the report the form or query names and checks it is
// this machine's. On failure it has answered and returns nil.
func (u *UI) machineReport(c *reqCtx, m *store.Machine, value string) (int64, *model.Report) {
	rid, err := strconv.ParseInt(value, 10, 64)
	if err != nil || rid <= 0 {
		u.fail(c.w, c.r, http.StatusBadRequest, "No report was given.")
		return 0, nil
	}
	rep, mid, err := u.o.Store.ReportOnly(rid)
	if err != nil || mid != m.ID {
		u.fail(c.w, c.r, http.StatusNotFound, "This machine has no such report.")
		return 0, nil
	}
	return rid, rep
}

// confirmed reports whether the form carries the explicit confirmation;
// without it the action is refused.
func (u *UI) confirmed(c *reqCtx, back string) bool {
	if c.r.PostForm.Get("confirm") == "yes" {
		return true
	}
	u.render(c.w, http.StatusBadRequest, "error", pageData{Title: "Confirm first", LoggedIn: true, CSRF: c.sess.csrf,
		Error: "Nothing was changed: this needs the confirmation page first.", Body: errorView{Back: back}})
	return false
}

type errorView struct {
	Back string
}

type cleanView struct {
	MachineID int64
	Name      string
	ReportID  int64
	Report    *reportView
	Replaces  bool
}

func (u *UI) cleanPage(c *reqCtx) {
	m := u.machine(c)
	if m == nil {
		return
	}
	rid, rep := u.machineReport(c, m, c.r.URL.Query().Get("report"))
	if rep == nil {
		return
	}
	if synthetic(rep) {
		u.fail(c.w, c.r, http.StatusBadRequest, "That report is about a visit that collected nothing, so no snapshot can be taken from it.")
		return
	}
	v := cleanView{MachineID: m.ID, Name: escape.Terminal(m.Name), ReportID: rid, Report: buildReportView(rid, 0, rep), Replaces: m.Clean}
	u.page(c, http.StatusOK, "clean", "Take the snapshot", "machines", v, "")
}

func (u *UI) cleanPost(c *reqCtx) {
	m := u.machine(c)
	if m == nil {
		return
	}
	rid, rep := u.machineReport(c, m, c.r.PostForm.Get("report"))
	if rep == nil {
		return
	}
	back := fmt.Sprintf("/machines/%d/clean?report=%d", m.ID, rid)
	if !u.confirmed(c, back) {
		return
	}
	to := fmt.Sprintf("/machines/%d", m.ID)
	if err := u.o.Core.MarkClean(c.r.Context(), m.ID, rid); err != nil {
		u.redirect(c, to, actionError(err))
		return
	}
	u.redirect(c, to, "Snapshot taken. Every later visit is compared with it.")
}

// changeGroup is findings that are accepted together.
type changeGroup struct {
	Findings  []findingView
	AcceptURL string
	Blocked   []string
}

type changesView struct {
	MachineID int64
	Name      string
	ReportID  int64
	Stale     bool
	Groups    []changeGroup
	AllURL    string
	AllCount  int
	Blocked   bool
}

func (u *UI) acceptURL(machineID, reportID int64, keys []string) string {
	q := url.Values{"report": {strconv.FormatInt(reportID, 10)}, "key": keys}
	return fmt.Sprintf("/machines/%d/accept?%s", machineID, q.Encode())
}

// changesPage is the re-baseline review: the latest report's changes since
// the snapshot, each with its evidence, grouped by what must be accepted
// together, with an accept for each group and one for all of them.
func (u *UI) changesPage(c *reqCtx) {
	m := u.machine(c)
	if m == nil {
		return
	}
	a, err := u.o.Core.Acceptable(m.ID)
	if err != nil {
		u.serverError(c.w, c.r, err)
		return
	}
	v := changesView{MachineID: m.ID, Name: escape.Terminal(m.Name), ReportID: a.ReportID, Stale: a.Stale}
	if a.ReportID == 0 || a.Stale || len(a.With) == 0 {
		u.page(c, http.StatusOK, "changes", "Changes since the snapshot", "machines", v, "")
		return
	}
	rep, mid, err := u.o.Store.ReportOnly(a.ReportID)
	if err != nil || mid != m.ID {
		u.fail(c.w, c.r, http.StatusNotFound, "The machine's latest report could not be read.")
		return
	}
	byKey := map[string]model.Finding{}
	var order []string
	for _, f := range rep.Findings {
		if _, ok := a.With[f.Key]; ok {
			byKey[f.Key] = f
			order = append(order, f.Key)
		}
	}
	// Groups: findings joined by With, in the report's order.
	seen := map[string]bool{}
	var all []string
	for _, k := range order {
		if seen[k] {
			continue
		}
		var keys, blocked []string
		queue := []string{k}
		seen[k] = true
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			keys = append(keys, cur)
			for _, w := range a.With[cur] {
				if _, ok := a.With[w]; !ok {
					if !slices.Contains(blocked, escape.Terminal(w)) {
						blocked = append(blocked, escape.Terminal(w))
					}
					continue
				}
				if !seen[w] {
					seen[w] = true
					queue = append(queue, w)
				}
			}
		}
		var fs []model.Finding
		for _, key := range keys {
			if f, ok := byKey[key]; ok {
				fs = append(fs, f)
			}
		}
		g := changeGroup{Findings: findingViews(fs, 0, 0, fmt.Sprintf("fix-%d-", len(v.Groups))), Blocked: blocked}
		if len(blocked) == 0 {
			g.AcceptURL = u.acceptURL(m.ID, a.ReportID, keys)
			all = append(all, keys...)
		} else {
			v.Blocked = true
		}
		v.Groups = append(v.Groups, g)
	}
	if len(all) > 0 {
		v.AllURL, v.AllCount = u.acceptURL(m.ID, a.ReportID, all), len(all)
	}
	u.page(c, http.StatusOK, "changes", "Changes since the snapshot", "machines", v, "")
}

type acceptView struct {
	MachineID int64
	Name      string
	ReportID  int64
	Keys      []string
	Findings  []findingView
}

const maxAcceptKeys = 10000

// formKey is a finding key as a hidden form field: percent-encoded, so a key
// holding any byte a machine put in it is plain ASCII in the page.
// keysFromForm decodes the fields again.
func formKey(k string) string { return url.QueryEscape(k) }

func keysFromForm(vs []string) ([]string, bool) {
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		k, err := url.QueryUnescape(v)
		if err != nil {
			return nil, false
		}
		out = append(out, k)
	}
	return out, true
}

// acceptKeys reads the chosen findings and checks each is in the report.
func (u *UI) acceptKeys(c *reqCtx, rep *model.Report, keys []string) ([]model.Finding, bool) {
	if len(keys) == 0 || len(keys) > maxAcceptKeys {
		u.fail(c.w, c.r, http.StatusBadRequest, "No changes were chosen.")
		return nil, false
	}
	var fs []model.Finding
	for _, k := range keys {
		i := slices.IndexFunc(rep.Findings, func(f model.Finding) bool { return f.Key == k })
		if i < 0 {
			u.fail(c.w, c.r, http.StatusBadRequest, "One of the chosen changes is not in that report.")
			return nil, false
		}
		fs = append(fs, rep.Findings[i])
	}
	return fs, true
}

func (u *UI) acceptPage(c *reqCtx) {
	m := u.machine(c)
	if m == nil {
		return
	}
	q := c.r.URL.Query()
	rid, rep := u.machineReport(c, m, q.Get("report"))
	if rep == nil {
		return
	}
	keys := q["key"]
	fs, ok := u.acceptKeys(c, rep, keys)
	if !ok {
		return
	}
	v := acceptView{MachineID: m.ID, Name: escape.Terminal(m.Name), ReportID: rid, Findings: findingViews(fs, 0, 0, "fix-")}
	for _, k := range keys {
		v.Keys = append(v.Keys, formKey(k))
	}
	u.page(c, http.StatusOK, "accept", "Accept changes", "machines", v, "")
}

func (u *UI) acceptPost(c *reqCtx) {
	m := u.machine(c)
	if m == nil {
		return
	}
	rid, rep := u.machineReport(c, m, c.r.PostForm.Get("report"))
	if rep == nil {
		return
	}
	keys, ok := keysFromForm(c.r.PostForm["key"])
	if !ok {
		u.fail(c.w, c.r, http.StatusBadRequest, "The chosen changes could not be read.")
		return
	}
	if _, ok := u.acceptKeys(c, rep, keys); !ok {
		return
	}
	if !u.confirmed(c, u.acceptURL(m.ID, rid, keys)) {
		return
	}
	to := fmt.Sprintf("/machines/%d", m.ID)
	if err := u.o.Core.AcceptChanges(c.r.Context(), m.ID, rid, keys); err != nil {
		u.redirect(c, to, actionError(err))
		return
	}
	n := "1 change"
	if len(keys) != 1 {
		n = strconv.Itoa(len(keys)) + " changes"
	}
	u.redirect(c, to, "Accepted "+n+" into the snapshot. The next visit is compared with the new snapshot.")
}

type exceptionView struct {
	MachineID int64
	Name      string
	ReportID  int64
	Key       string
	FormKey   string
	Finding   findingView
}

const maxNote = 500

// exceptionFinding finds the finding an exception is asked for.
func (u *UI) exceptionFinding(c *reqCtx, rep *model.Report, key string) (model.Finding, bool) {
	if strings.HasPrefix(key, sourceVisit+".") {
		u.fail(c.w, c.r, http.StatusBadRequest, "Findings about the visit itself cannot be accepted.")
		return model.Finding{}, false
	}
	for _, list := range [][]model.Finding{rep.Findings, rep.Explained} {
		if i := slices.IndexFunc(list, func(f model.Finding) bool { return f.Key == key }); i >= 0 {
			return list[i], true
		}
	}
	u.fail(c.w, c.r, http.StatusBadRequest, "That finding is not in that report.")
	return model.Finding{}, false
}

func (u *UI) exceptionPage(c *reqCtx) {
	m := u.machine(c)
	if m == nil {
		return
	}
	q := c.r.URL.Query()
	rid, rep := u.machineReport(c, m, q.Get("report"))
	if rep == nil {
		return
	}
	f, ok := u.exceptionFinding(c, rep, q.Get("key"))
	if !ok {
		return
	}
	v := exceptionView{MachineID: m.ID, Name: escape.Terminal(m.Name), ReportID: rid, Key: escape.Terminal(f.Key), FormKey: formKey(f.Key), Finding: findingViews([]model.Finding{f}, 0, 0, "fix-")[0]}
	u.page(c, http.StatusOK, "exception", "Accept as an exception", "machines", v, "")
}

func (u *UI) exceptionPost(c *reqCtx) {
	m := u.machine(c)
	if m == nil {
		return
	}
	rid, rep := u.machineReport(c, m, c.r.PostForm.Get("report"))
	if rep == nil {
		return
	}
	keys, ok := keysFromForm([]string{c.r.PostForm.Get("key")})
	if !ok {
		u.fail(c.w, c.r, http.StatusBadRequest, "The finding could not be read.")
		return
	}
	key := keys[0]
	if _, ok := u.exceptionFinding(c, rep, key); !ok {
		return
	}
	note := strings.TrimSpace(c.r.PostForm.Get("note"))
	if len([]rune(note)) > maxNote {
		u.fail(c.w, c.r, http.StatusBadRequest, fmt.Sprintf("Keep the note under %d characters.", maxNote))
		return
	}
	q := url.Values{"report": {strconv.FormatInt(rid, 10)}, "key": {key}}
	if !u.confirmed(c, fmt.Sprintf("/machines/%d/exception?%s", m.ID, q.Encode())) {
		return
	}
	to := fmt.Sprintf("/machines/%d", m.ID)
	if err := u.o.Core.AddException(c.r.Context(), m.ID, rid, key, note); err != nil {
		u.redirect(c, to, actionError(err))
		return
	}
	u.redirect(c, to, "Accepted as an exception. It stays accepted while its value stays the same.")
}

type snippetsView struct {
	MachineID int64
	Name      string
	Keys      string
	SSHD      string
	Error     string
}

// snippetsPage shows the two snippets that let the server log in as root
// by key from its own address only, and "Check now".
func (u *UI) snippetsPage(c *reqCtx) {
	m := u.machine(c)
	if m == nil {
		return
	}
	v := snippetsView{MachineID: m.ID, Name: escape.Terminal(m.Name)}
	_, line, err := visit.ServerKey(u.o.Store)
	if err == nil {
		v.Keys, v.SSHD, err = visit.EnrolSnippets(u.o.ServerAddr, line)
	}
	if err != nil {
		v.Error = escape.Terminal(err.Error())
	}
	u.page(c, http.StatusOK, "snippets", "Let the server in", "machines", v, "")
}
