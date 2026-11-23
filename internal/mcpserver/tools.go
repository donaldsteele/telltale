package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/donaldsteele/telltale/internal/escape"
	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/report"
	"github.com/donaldsteele/telltale/internal/server"
)

// requestFailedText is the error when a request did not get an answer
// from the server; the detail goes in server_message.
const requestFailedText = "The request to the telltale server did not work; the detail is in server_message."

// maxListed bounds each list of findings in one result.
const maxListed = 200

type tools struct{ c *Client }

// Tool inputs.

type noArgs struct{}

type machineArgs struct {
	Machine string `json:"machine" jsonschema:"the machine's name or id, as list_machines shows them"`
}

type explainArgs struct {
	Machine  string `json:"machine" jsonschema:"the machine's name or id, as list_machines shows them"`
	Key      string `json:"key" jsonschema:"the finding's key, as latest_report or compare_reports shows it"`
	ReportID int64  `json:"report_id,omitempty" jsonschema:"a report id; the machine's latest report when left out"`
}

type compareArgs struct {
	Machine string `json:"machine" jsonschema:"the machine's name or id, as list_machines shows them"`
	A       int64  `json:"a,omitempty" jsonschema:"the older report's id; the report before b when left out"`
	B       int64  `json:"b,omitempty" jsonschema:"the newer report's id; the machine's latest report when left out"`
}

// Tool results. Every string field that holds machine text is escaped with
// escape.Terminal; Note is always UntrustedNote.

type machineRef struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

type reportMetaOut struct {
	ID       int64  `json:"id"`
	Time     string `json:"time"`
	ExitCode int    `json:"exit_code"`
	Summary  string `json:"summary"`
	Findings int    `json:"findings"`
}

type findingBrief struct {
	Key      string `json:"key"`
	ID       string `json:"id,omitempty"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Where    string `json:"where,omitempty"`
}

type machineOut struct {
	ID           int64          `json:"id"`
	Name         string         `json:"name"`
	Address      string         `json:"address"`
	Schedule     string         `json:"schedule,omitempty"`
	HasSnapshot  bool           `json:"has_snapshot"`
	LastVisit    string         `json:"last_visit,omitempty"`
	VisitRunning bool           `json:"visit_running"`
	VisitError   string         `json:"visit_error,omitempty"`
	LatestReport *reportMetaOut `json:"latest_report,omitempty"`
	WorstFinding *findingBrief  `json:"worst_finding,omitempty"`
}

type listMachinesOut struct {
	Note     string       `json:"note"`
	Machines []machineOut `json:"machines"`
}

type hostOut struct {
	Hostname string `json:"hostname"`
	OS       string `json:"os,omitempty"`
	Arch     string `json:"arch,omitempty"`
	Kernel   string `json:"kernel,omitempty"`
}

type skipOut struct {
	Check  string `json:"check"`
	Reason string `json:"reason"`
}

type exceptionOut struct {
	Key           string `json:"key"`
	AcceptedValue string `json:"accepted_value"`
	OwnerNote     string `json:"owner_note,omitempty"`
	Accepted      string `json:"accepted,omitempty"`
}

type reportOut struct {
	ID                int64          `json:"id"`
	Time              string         `json:"time"`
	ExitCode          int            `json:"exit_code"`
	Summary           string         `json:"summary"`
	Host              hostOut        `json:"host"`
	ComparedAgainst   []string       `json:"compared_against,omitempty"`
	CouldNotRuleOut   []string       `json:"could_not_rule_out,omitempty"`
	Findings          []findingBrief `json:"findings"`
	FindingsNotShown  int            `json:"findings_not_shown,omitempty"`
	Explained         []findingBrief `json:"explained,omitempty"`
	ExplainedNotShown int            `json:"explained_not_shown,omitempty"`
	Skipped           []skipOut      `json:"skipped,omitempty"`
	Exceptions        []exceptionOut `json:"exceptions,omitempty"`
}

type latestReportOut struct {
	Note    string     `json:"note"`
	Machine machineRef `json:"machine"`
	Report  reportOut  `json:"report"`
}

type evidenceOut struct {
	Path   string `json:"path,omitempty"`
	Line   int    `json:"line,omitempty"`
	Before string `json:"before,omitempty"`
	After  string `json:"after,omitempty"`
	Detail string `json:"detail,omitempty"`
	When   string `json:"changed,omitempty"`
}

type findingOut struct {
	Key      string        `json:"key"`
	ID       string        `json:"id,omitempty"`
	Severity string        `json:"severity"`
	Title    string        `json:"title"`
	Why      string        `json:"why,omitempty"`
	Evidence []evidenceOut `json:"evidence,omitempty"`
	// Fix is the command a person could run, byte for byte as telltale
	// built it (every machine value in it is shell-quoted to printable
	// ASCII); one holding a control character anyway is escaped and
	// marked, and FixSafeToCopy is false.
	Fix           string   `json:"fix,omitempty"`
	FixSafeToCopy bool     `json:"fix_safe_to_copy"`
	Refs          []string `json:"refs,omitempty"`
}

type explainOut struct {
	Note     string     `json:"note"`
	Fixes    string     `json:"fixes"`
	Machine  machineRef `json:"machine"`
	ReportID int64      `json:"report_id"`
	Finding  findingOut `json:"finding"`
}

type compareOut struct {
	Note     string         `json:"note"`
	Machine  machineRef     `json:"machine"`
	A        reportMetaOut  `json:"a"`
	B        reportMetaOut  `json:"b"`
	New      []findingBrief `json:"new"`
	Resolved []findingBrief `json:"resolved"`
	Still    []findingBrief `json:"still"`
	NotShown int            `json:"not_shown,omitempty"`
}

type checkNowOut struct {
	Note          string     `json:"note"`
	Machine       machineRef `json:"machine"`
	Status        string     `json:"status"`
	ReportID      int64      `json:"report_id,omitempty"`
	ServerMessage string     `json:"server_message"`
}

// toolError is every error result. Error is the tool's own words; what the
// server said is apart, escaped, in ServerMessage.
type toolError struct {
	Note          string `json:"note"`
	Error         string `json:"error"`
	ServerStatus  int    `json:"server_status,omitempty"`
	ServerMessage string `json:"server_message,omitempty"`
}

// userError is an error in the tool's own words.
type userError string

func (e userError) Error() string { return string(e) }

func (t *tools) register(s *mcp.Server) {
	no := false
	readOnly := func(title string) *mcp.ToolAnnotations {
		return &mcp.ToolAnnotations{Title: title, ReadOnlyHint: true, DestructiveHint: &no, IdempotentHint: true, OpenWorldHint: &no}
	}
	desc := func(s string) string { return s + " " + UntrustedNote }
	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_machines",
		Description: desc("List the machines the telltale server checks: id, name, address, whether a known-good snapshot exists, the last visit, and the latest report's summary and most severe finding."),
		Annotations: readOnly("List machines"),
	}, t.listMachines)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "latest_report",
		Description: desc("Show a machine's latest report: when it was taken, the host, and its findings, most severe first, each with its key. Give the machine's name or id. explain_finding with a key gives the evidence and the fix."),
		Annotations: readOnly("Latest report"),
	}, t.latestReport)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "explain_finding",
		Description: desc("Explain one finding: its title, why it matters, the evidence, the fix command and references. Give the machine's name or id and the finding's key; the latest report is used unless report_id is given. " + NeverRunsFixes + "."),
		Annotations: readOnly("Explain a finding"),
	}, t.explainFinding)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "compare_reports",
		Description: desc("Compare two of a machine's reports: the findings that are new, resolved and still there. Give the machine's name or id; a and b are report ids, by default the report before the latest (a) and the latest (b)."),
		Annotations: readOnly("Compare reports"),
	}, t.compareReports)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "check_now",
		Description: desc("Ask the telltale server to visit a machine now and judge it. A visit only reads the machine. At most one request a minute per machine; when a visit is already running, the server says so. Read the new report with latest_report when the visit is done."),
		Annotations: &mcp.ToolAnnotations{Title: "Check a machine now", ReadOnlyHint: false, DestructiveHint: &no, IdempotentHint: false, OpenWorldHint: &no},
	}, t.checkNow)
}

// respond is a result: the note, then any of the tool's own lines, then the
// data as JSON (also as the structured content).
func respond(data any, lines ...string) (*mcp.CallToolResult, any, error) {
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fail(err)
	}
	content := []mcp.Content{&mcp.TextContent{Text: UntrustedNote}}
	for _, l := range lines {
		content = append(content, &mcp.TextContent{Text: l})
	}
	content = append(content, &mcp.TextContent{Text: string(b)})
	return &mcp.CallToolResult{Content: content, StructuredContent: json.RawMessage(b)}, nil, nil
}

// fail is an error result, laid out like any other.
func fail(err error) (*mcp.CallToolResult, any, error) {
	e := toolError{Note: UntrustedNote}
	var se *ServerError
	var fe *FingerprintError
	var ue userError
	switch {
	case errors.As(err, &se):
		e.Error = fmt.Sprintf("The telltale server refused the request (HTTP %d %s); its message is in server_message.", se.Status, http.StatusText(se.Status))
		e.ServerStatus = se.Status
		e.ServerMessage = escape.Terminal(se.Message)
	case errors.As(err, &fe):
		e.Error = escape.Terminal(fe.Error())
	case errors.As(err, &ue):
		e.Error = string(ue)
	default:
		e.Error = requestFailedText
		e.ServerMessage = escape.Terminal(err.Error())
	}
	b, _ := json.MarshalIndent(e, "", "  ")
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: UntrustedNote}, &mcp.TextContent{Text: string(b)}}}, nil, nil
}

// machine finds the machine a name or id names. A name is matched in any
// case; a number matches that id and also a machine of that name, and when
// both exist the answer is an error that lists their ids.
func (t *tools) machine(ctx context.Context, s string) (server.APIMachine, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return server.APIMachine{}, userError("Give a machine's name or id; list_machines shows them.")
	}
	ms, err := t.c.Machines(ctx)
	if err != nil {
		return server.APIMachine{}, err
	}
	n, nerr := strconv.ParseInt(s, 10, 64)
	var hits []server.APIMachine
	for _, m := range ms {
		if (nerr == nil && m.ID == n) || strings.EqualFold(m.Name, s) {
			hits = append(hits, m)
		}
	}
	switch len(hits) {
	case 0:
		return server.APIMachine{}, userError("No machine has that name or id; list_machines shows them.")
	case 1:
		return hits[0], nil
	}
	ids := make([]string, 0, len(hits))
	slices.SortFunc(hits, func(a, b server.APIMachine) int { return int(a.ID - b.ID) })
	for _, m := range hits {
		ids = append(ids, strconv.FormatInt(m.ID, 10))
	}
	return server.APIMachine{}, userError("That matches more than one machine, ids " + strings.Join(ids, ", ") + ". Give the id.")
}

func ref(m server.APIMachine) machineRef {
	return machineRef{ID: m.ID, Name: escape.Terminal(m.Name)}
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func summary(code int) string {
	switch code {
	case 0:
		return "nothing found"
	case 1:
		return "notes or weak settings"
	case 2:
		return "tampering or backdoor signs"
	}
	return "could not run"
}

func metaOut(m server.APIReportMeta) reportMetaOut {
	return reportMetaOut{ID: m.ID, Time: fmtTime(m.Time), ExitCode: m.ExitCode, Summary: summary(m.ExitCode), Findings: m.Findings}
}

// serverEscaped passes on text the server already escaped with
// escape.Terminal (a machine's visit error), so it is not escaped twice.
// Text that holds anything escape.Terminal would change, apart from
// backslashes, was not escaped after all, and is escaped here.
func serverEscaped(s string) string {
	plain := strings.ReplaceAll(s, `\`, "")
	if escape.Terminal(plain) == plain {
		return s
	}
	return escape.Terminal(s)
}

func escapeAll(ss []string) []string {
	var out []string
	for _, s := range ss {
		out = append(out, escape.Terminal(s))
	}
	return out
}

func where(evs []model.Evidence) string {
	if len(evs) == 0 || evs[0].Path == "" {
		return ""
	}
	s := escape.Terminal(evs[0].Path)
	if evs[0].Line > 0 {
		s += ":" + strconv.Itoa(evs[0].Line)
	}
	return s
}

func brief(f model.Finding) findingBrief {
	return findingBrief{Key: escape.Terminal(f.Key), ID: escape.Terminal(f.ID), Severity: f.Severity.String(), Title: escape.Terminal(f.Title), Where: where(f.Evidence)}
}

// briefs ranks findings most severe first (the report's order within a
// severity) and keeps at most max; the rest are counted.
func briefs(fs []model.Finding, max int) ([]findingBrief, int) {
	ranked := slices.Clone(fs)
	slices.SortStableFunc(ranked, func(a, b model.Finding) int { return int(b.Severity) - int(a.Severity) })
	out := []findingBrief{}
	for i, f := range ranked {
		if i == max {
			return out, len(ranked) - max
		}
		out = append(out, brief(f))
	}
	return out, 0
}

func (t *tools) listMachines(ctx context.Context, _ *mcp.CallToolRequest, _ noArgs) (*mcp.CallToolResult, any, error) {
	ms, err := t.c.Machines(ctx)
	if err != nil {
		return fail(err)
	}
	out := listMachinesOut{Note: UntrustedNote, Machines: []machineOut{}}
	for _, m := range ms {
		mo := machineOut{ID: m.ID, Name: escape.Terminal(m.Name), Address: escape.Terminal(m.Addr), Schedule: escape.Terminal(m.Schedule), HasSnapshot: m.Snapshot, VisitRunning: m.Visiting, VisitError: serverEscaped(m.VisitError)}
		if m.LastVisit != nil {
			mo.LastVisit = fmtTime(*m.LastVisit)
		}
		if m.Latest != nil {
			lm := metaOut(*m.Latest)
			mo.LatestReport = &lm
		}
		if w := m.Worst; w != nil {
			mo.WorstFinding = &findingBrief{Key: escape.Terminal(w.Key), Severity: w.Severity.String(), Title: escape.Terminal(w.Title)}
		}
		out.Machines = append(out.Machines, mo)
	}
	return respond(out)
}

func reportView(r *server.APIReport) reportOut {
	rep := r.Report
	if rep == nil {
		rep = &model.Report{}
	}
	h := rep.Host
	out := reportOut{
		ID: r.ID, Time: fmtTime(rep.Time), ExitCode: rep.ExitCode, Summary: summary(rep.ExitCode),
		Host:            hostOut{Hostname: escape.Terminal(h.Hostname), OS: escape.Terminal(h.OSPretty), Arch: escape.Terminal(h.Arch), Kernel: escape.Terminal(h.Kernel)},
		ComparedAgainst: escapeAll(rep.ComparedAgainst),
		CouldNotRuleOut: escapeAll(rep.CouldNotRuleOut),
	}
	out.Findings, out.FindingsNotShown = briefs(rep.Findings, maxListed)
	if len(rep.Explained) > 0 {
		out.Explained, out.ExplainedNotShown = briefs(rep.Explained, maxListed)
	}
	for _, s := range rep.Skipped {
		out.Skipped = append(out.Skipped, skipOut{Check: escape.Terminal(s.Check), Reason: escape.Terminal(s.Reason)})
	}
	for _, e := range rep.Exceptions {
		out.Exceptions = append(out.Exceptions, exceptionOut{Key: escape.Terminal(e.FindingKey), AcceptedValue: escape.Terminal(e.AcceptedValue), OwnerNote: escape.Terminal(e.Note), Accepted: fmtTime(e.At)})
	}
	return out
}

func (t *tools) latestReport(ctx context.Context, _ *mcp.CallToolRequest, in machineArgs) (*mcp.CallToolResult, any, error) {
	m, err := t.machine(ctx, in.Machine)
	if err != nil {
		return fail(err)
	}
	r, err := t.c.LatestReport(ctx, m.ID)
	if err != nil {
		return fail(err)
	}
	return respond(latestReportOut{Note: UntrustedNote, Machine: ref(m), Report: reportView(r)})
}

func findingView(f model.Finding) findingOut {
	out := findingOut{Key: escape.Terminal(f.Key), ID: escape.Terminal(f.ID), Severity: f.Severity.String(), Title: escape.Terminal(f.Title), Why: escape.Terminal(f.Why), Refs: escapeAll(f.Refs)}
	for _, e := range f.Evidence {
		ev := evidenceOut{Path: escape.Terminal(e.Path), Line: e.Line, Before: escape.Terminal(e.Before), After: escape.Terminal(e.After), Detail: escape.Terminal(e.Detail)}
		if e.When != nil {
			ev.When = fmtTime(*e.When)
		}
		out.Evidence = append(out.Evidence, ev)
	}
	if f.Fix != "" {
		out.Fix, out.FixSafeToCopy = report.FixText(f.Fix), !escape.HasUnsafe(f.Fix)
	}
	return out
}

func (t *tools) explainFinding(ctx context.Context, _ *mcp.CallToolRequest, in explainArgs) (*mcp.CallToolResult, any, error) {
	if strings.TrimSpace(in.Key) == "" {
		return fail(userError("Give the finding's key, as latest_report shows it."))
	}
	m, err := t.machine(ctx, in.Machine)
	if err != nil {
		return fail(err)
	}
	var r *server.APIReport
	if in.ReportID > 0 {
		r, err = t.c.Report(ctx, in.ReportID)
		if err == nil && r.MachineID != m.ID {
			err = userError("That report is not one of this machine's.")
		}
	} else {
		r, err = t.c.LatestReport(ctx, m.ID)
	}
	if err != nil {
		return fail(err)
	}
	var lists [][]model.Finding
	if r.Report != nil {
		lists = [][]model.Finding{r.Report.Findings, r.Report.Explained}
	}
	// The key as stored, or as the tools showed it (escaped).
	for _, list := range lists {
		for _, f := range list {
			if f.Key == in.Key || escape.Terminal(f.Key) == in.Key {
				return respond(explainOut{Note: UntrustedNote, Fixes: NeverRunsFixes, Machine: ref(m), ReportID: r.ID, Finding: findingView(f)}, NeverRunsFixes)
			}
		}
	}
	return fail(userError(fmt.Sprintf("There is no finding with that key in report %d; latest_report lists the keys.", r.ID)))
}

func (t *tools) compareReports(ctx context.Context, _ *mcp.CallToolRequest, in compareArgs) (*mcp.CallToolResult, any, error) {
	m, err := t.machine(ctx, in.Machine)
	if err != nil {
		return fail(err)
	}
	c, err := t.c.Compare(ctx, m.ID, in.A, in.B)
	if err != nil {
		return fail(err)
	}
	out := compareOut{Note: UntrustedNote, Machine: ref(m), A: metaOut(c.A), B: metaOut(c.B)}
	var n1, n2, n3 int
	out.New, n1 = briefs(c.New, maxListed)
	out.Resolved, n2 = briefs(c.Resolved, maxListed)
	out.Still, n3 = briefs(c.Still, maxListed)
	out.NotShown = n1 + n2 + n3
	return respond(out)
}

func (t *tools) checkNow(ctx context.Context, _ *mcp.CallToolRequest, in machineArgs) (*mcp.CallToolResult, any, error) {
	m, err := t.machine(ctx, in.Machine)
	if err != nil {
		return fail(err)
	}
	v, err := t.c.Visit(ctx, m.ID)
	if err != nil {
		return fail(err)
	}
	return respond(checkNowOut{Note: UntrustedNote, Machine: ref(m), Status: escape.Terminal(v.Status), ReportID: v.ReportID, ServerMessage: escape.Terminal(v.Message)})
}
