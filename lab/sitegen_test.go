//go:build lab && site

package lab

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"unicode"

	"github.com/donaldsteele/telltale/internal/escape"
	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/lab/labkit"
)

// The project site shows real telltale reports of lab machines, not
// mock-ups. TestGenerateSiteReports makes them: it runs the two break-in
// scenarios, a clean machine and a scan without a snapshot on Debian 12, and
// writes each report as telltale itself wrote it (the HTML report, the
// terminal output and the JSON) to site/reports, or to
// $TELLTALE_SITE_REPORTS, with index.json holding each report's story.
// scripts/site-reports.sh runs it, and the Pages workflow runs that script
// for every release, so the site always shows what the current version
// prints.
//
// The machines have fixed made-up names (web01, files02, build03). Nothing
// from the computer running the lab may reach the site: the test fails when
// a file it wrote holds this computer's host name, user name, home
// directory or network addresses.

// siteReports are the reports the site shows, in the order it shows them.
var siteReports = []siteReport{
	{Name: "weak-password-to-root", Machine: "files02", Kind: "scenario", Scenario: "weak-password-to-root", Snapshot: true},
	{Name: "no-snapshot", Machine: "files02", Kind: "no-snapshot", Scenario: "weak-password-to-root"},
	{Name: "web-shell-persistence", Machine: "web01", Kind: "scenario", Scenario: "web-shell-persistence", Snapshot: true},
	{Name: "clean", Machine: "build03", Kind: "clean", Snapshot: true},
}

// siteReport is one report's entry in index.json.
type siteReport struct {
	Name     string `json:"name"`
	Machine  string `json:"machine"`
	Kind     string `json:"kind"` // "scenario", "no-snapshot" or "clean"
	Scenario string `json:"scenario,omitempty"`
	Snapshot bool   `json:"snapshot"`
	Title    string `json:"title"`
	Summary  string `json:"summary"`
	// Story is what was done to the machine, one step each.
	Story []string `json:"story"`
	// What the report says, for the page's summary of it.
	ComparedAgainst []string       `json:"compared_against"`
	ExitCode        int            `json:"exit_code"`
	Counts          map[string]int `json:"counts"`
	Found           []siteFinding  `json:"found"`
	Files           siteFiles      `json:"files"`
}

type siteFinding struct {
	Severity string `json:"severity"`
	Title    string `json:"title"`
}

type siteFiles struct {
	HTML string `json:"html"`
	Text string `json:"text"`
	JSON string `json:"json"`
}

// siteIndex is index.json.
type siteIndex struct {
	Version string       `json:"version"`
	Distro  string       `json:"distro"`
	Reports []siteReport `json:"reports"`
}

func TestGenerateSiteReports(t *testing.T) {
	out := os.Getenv("TELLTALE_SITE_REPORTS")
	if out == "" {
		out = filepath.Join("..", "site", "reports")
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	// Last run's files must not stand in for this run's.
	for _, f := range siteFileNames() {
		if err := os.Remove(filepath.Join(out, f)); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	generateSiteReports(t, out)
	checkSiteReports(t, out)
}

// siteFileNames are the files the test writes.
func siteFileNames() []string {
	names := []string{"index.json"}
	for _, r := range siteReports {
		names = append(names, r.Name+".html", r.Name+".txt", r.Name+".json")
	}
	return names
}

// siteDistro is the distribution of the site's machines.
const siteDistro = "debian12"

// The words the site uses for what has no apply.sh to tell it.
var (
	siteTitles = map[string]string{
		"weak-password-to-root": "A guessed password, then root",
		"no-snapshot":           "The same machine, without a snapshot",
		"web-shell-persistence": "A web upload that stays",
		"clean":                 "A clean machine",
	}
	siteSummaries = map[string]string{
		"weak-password-to-root": "files02 was snapshotted while it was clean. Then the attacker got in and set up their ways back. telltale compares the machine with that snapshot.",
		"no-snapshot":           "The same break-in on files02, scanned as if telltale had never seen the machine: no snapshot, only the signed packages, the checklist and what is suspicious on any machine.",
		"web-shell-persistence": "web01 was snapshotted while it was clean. Then the attacker came in through the web site and stayed. telltale compares the machine with that snapshot.",
		"clean":                 "build03 was snapshotted while it was clean, and nothing has changed since. The checklist items it does not meet were looked at and accepted as exceptions, which every report lists.",
	}
)

// leftOut are the checklist items about packages the lab's image leaves
// out, by the package each wants installed.
var leftOut = map[string]string{"TT-SVC-005": "auditd", "TT-SVC-007": "unattended-upgrades"}

// cleanNote is the note the owner of build03 accepts an unmet checklist
// item with, from the item's ID and observed value, or "" for an item the
// site cannot explain (then the clean machine is not clean, and the test
// fails). A lab machine is a container: its kernel settings are its host's,
// or Docker's for its own network, and its image leaves some packages out.
func cleanNote(id, observed string) string {
	switch {
	case strings.HasPrefix(id, "TT-KERN-") && strings.HasPrefix(observed, "net."):
		return "set by Docker for this container's network; the machine cannot change it"
	case strings.HasPrefix(id, "TT-KERN-"):
		return "a setting of the host's kernel, which this container shares"
	case leftOut[id] != "":
		return "left out of the lab's machine image"
	}
	return ""
}

// cleanStory tells what happened to build03, with the items its owner
// accepted.
func cleanStory(accepted []model.Finding) []string {
	kernel := 0
	var left []string
	for _, f := range accepted {
		if strings.HasPrefix(f.ID, "TT-KERN-") {
			kernel++
		} else {
			left = append(left, leftOut[f.ID])
		}
	}
	var what []string
	if kernel > 0 {
		what = append(what, fmt.Sprintf("%d kernel %s, which a container shares with its host or gets from Docker", kernel, plural(kernel, "setting", "settings")))
	}
	if len(left) > 0 {
		what = append(what, strings.Join(left, " and ")+", which the lab's image leaves out")
	}
	accept := "The first check against the snapshot finds nothing to accept."
	if len(accepted) > 0 {
		accept = fmt.Sprintf("The first check against the snapshot finds %d checklist %s it does not meet: %s. The owner looks at each and accepts it as an exception, with a note saying why.",
			len(accepted), plural(len(accepted), "item", "items"), strings.Join(what, "; "))
	}
	return []string{
		"build03 is set up to pass the hardening checklist.",
		"A snapshot is taken while it is clean, and kept off the machine.",
		accept,
		"Nothing else changes, and telltale checks it against the snapshot again.",
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// shellQuote quotes s for sh.
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func generateSiteReports(t *testing.T, out string) {
	var (
		mu      sync.Mutex
		reports = map[string]*model.Report{}
		version string
		story   []string // build03's
	)
	keep := func(name string, r *model.Report) {
		mu.Lock()
		defer mu.Unlock()
		reports[name] = r
	}
	t.Run("machines", func(t *testing.T) {
		t.Run("files02", func(t *testing.T) {
			slot(t)
			m := siteMachine(t, "clean", "files02")
			v := strings.TrimSpace(mustExec(t, m, "telltale version"))
			mu.Lock()
			version = v
			mu.Unlock()
			with := siteScenario(t, m, out, "weak-password-to-root")
			keep("weak-password-to-root", with)
			man := siteManifest(t, "weak-password-to-root")
			plain, _ := refsFor(t, m)
			without := siteScan(t, m, out, "no-snapshot", "--refs", plain)
			checkReport(t, man, without, false)
			keep("no-snapshot", without)
		})
		t.Run("web01", func(t *testing.T) {
			slot(t)
			m := siteMachine(t, "clean", "web01")
			with := siteScenario(t, m, out, "web-shell-persistence")
			keep("web-shell-persistence", with)
		})
		t.Run("build03", func(t *testing.T) {
			slot(t)
			m := siteMachine(t, "hardened", "build03")
			snap := takeSnapshot(t, m)
			putSnapshot(t, m, snap)
			refs, _ := refsWith(t, m, snap)
			// The owner's first check, and the exceptions they accept after
			// reading it (accept reads the report the scan saved next to the
			// snapshot).
			first, _ := scan(t, m, "--snapshot", snapInside, "--refs", refs)
			var accepted []model.Finding
			for _, f := range first.Findings {
				if f.Severity <= model.SevNote || !strings.HasPrefix(f.Key, "check:") || len(f.Evidence) == 0 {
					continue
				}
				note := cleanNote(f.ID, f.Evidence[0].After)
				if note == "" {
					continue // left in the report: the clean check fails on it
				}
				mustExec(t, m, "telltale accept "+shellQuote(f.Key)+" --snapshot "+snapInside+" --note "+shellQuote(note))
				accepted = append(accepted, f)
			}
			mu.Lock()
			story = cleanStory(accepted)
			mu.Unlock()
			r := siteScan(t, m, out, "clean", "--snapshot", snapInside, "--refs", refs)
			man, err := LoadManifestFile(filepath.Join("variants", "hardened.manifest.json"))
			if err != nil {
				t.Fatal(err)
			}
			checkReport(t, man, r, true)
			if len(r.Exceptions) != len(accepted) {
				t.Errorf("%d exceptions accepted, the report lists %d", len(accepted), len(r.Exceptions))
			}
			keep("clean", r)
		})
	})
	if len(reports) != len(siteReports) {
		return // checkSiteReports says what is missing
	}

	idx := siteIndex{Version: version}
	for _, want := range siteReports {
		r := reports[want.Name]
		if idx.Distro == "" {
			idx.Distro = escape.Terminal(r.Host.OSPretty + ", " + r.Host.Arch)
		}
		e := want
		e.Title, e.Summary = siteTitles[want.Name], siteSummaries[want.Name]
		if want.Scenario != "" {
			e.Story = scenarioStory(t, want.Scenario)
		} else {
			e.Story = story
		}
		for _, s := range r.ComparedAgainst {
			e.ComparedAgainst = append(e.ComparedAgainst, escape.Terminal(s))
		}
		e.ExitCode = r.ExitCode
		e.Counts = map[string]int{"explained": len(r.Explained)}
		for s := model.SevNote; s <= model.SevTampering; s++ {
			e.Counts[s.String()] = 0
		}
		for _, f := range r.Findings {
			e.Counts[f.Severity.String()]++
			if len(e.Found) < 6 {
				e.Found = append(e.Found, siteFinding{Severity: f.Severity.String(), Title: escape.Terminal(f.Title)})
			}
		}
		e.Files = siteFiles{HTML: want.Name + ".html", Text: want.Name + ".txt", JSON: want.Name + ".json"}
		idx.Reports = append(idx.Reports, e)
	}
	data, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "index.json"), append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

// siteMachine starts a lab machine under one of the site's made-up names.
// $TELLTALE_SITE_BIN, when set, is the telltale it runs (the release build
// scripts/site-reports.sh makes, with its version); otherwise the lab's own
// build.
func siteMachine(t *testing.T, variant, name string) *labkit.Machine {
	t.Helper()
	m := start(t, labkit.Build(t, siteDistro, variant), labkit.Opts{Hostname: name})
	if bin := os.Getenv("TELLTALE_SITE_BIN"); bin != "" {
		m.CopyIn(t, bin, "/usr/local/bin/telltale")
		mustExec(t, m, "chmod 755 /usr/local/bin/telltale")
	}
	if got := strings.TrimSpace(mustExec(t, m, "hostname")); got != name {
		t.Fatalf("the machine calls itself %q, want %s", got, name)
	}
	return m
}

func siteManifest(t *testing.T, scenario string) *Manifest {
	t.Helper()
	man, err := LoadManifest(filepath.Join("scenarios", scenario))
	if err != nil {
		t.Fatal(err)
	}
	return man
}

// siteScenario is runCase for the site: snapshot the clean machine, play the
// scenario, and scan against the snapshot. The report must match the
// scenario's manifest.
func siteScenario(t *testing.T, m *labkit.Machine, out, scenario string) *model.Report {
	t.Helper()
	plant(t, m)
	snap := takeSnapshot(t, m)
	mustExec(t, m, "sh /lab/scenarios/"+scenario+"/apply.sh >/run/telltale-lab/apply.log 2>&1 || { cat /run/telltale-lab/apply.log; exit 1; }")
	putSnapshot(t, m, snap)
	refs, _ := refsWith(t, m, snap)
	r := siteScan(t, m, out, scenario, "--snapshot", snapInside, "--refs", refs)
	checkReport(t, siteManifest(t, scenario), r, true)
	return r
}

// siteScan runs one scan in the machine, as an owner would, and keeps what
// telltale wrote: the terminal output, the HTML report and the JSON, each
// byte for byte, as out/name.txt, .html and .json.
func siteScan(t *testing.T, m *labkit.Machine, out, name string, args ...string) *model.Report {
	t.Helper()
	const dir = "/run/telltale-lab/site"
	cmd := "mkdir -p " + dir + " && telltale scan " + strings.Join(args, " ") +
		" --json " + dir + "/report.json --html " + dir + "/report.html >" + dir + "/report.txt 2>" + errInside
	_, code := m.Exec(t, "sh", "-c", cmd)
	if code < 0 || code > 2 {
		errs, _ := m.Exec(t, "cat", errInside)
		t.Fatalf("%s: `%s` exit %d:\n%s", m.Name, cmd, code, errs)
	}
	files := map[string]string{}
	for _, ext := range []string{"txt", "html", "json"} {
		data, c := m.Exec(t, "cat", dir+"/report."+ext)
		if c != 0 || data == "" {
			t.Fatalf("%s: no %s report (exit %d)", m.Name, ext, c)
		}
		files[ext] = data
	}
	var r model.Report
	if err := json.Unmarshal([]byte(files["json"]), &r); err != nil {
		t.Fatalf("%s: the JSON report does not parse: %v", m.Name, err)
	}
	if r.ExitCode != code {
		t.Errorf("%s: scan exit code %d, the report says %d", m.Name, code, r.ExitCode)
	}
	for ext, data := range files {
		if err := os.WriteFile(filepath.Join(out, name+"."+ext), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mustExec(t, m, "rm -rf "+dir)
	return &r
}

// scenarioStory reads the steps an apply.sh header tells its story in: a
// line "# - " starts a step, and lines "#   " continue it.
func scenarioStory(t *testing.T, scenario string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("scenarios", scenario, "apply.sh"))
	if err != nil {
		t.Fatal(err)
	}
	var steps []string
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "#") {
			if strings.TrimSpace(line) != "" && len(steps) > 0 {
				break // the header is over
			}
			continue
		}
		text := strings.TrimPrefix(line, "#")
		switch {
		case strings.HasPrefix(text, " - "):
			steps = append(steps, strings.TrimSpace(text[3:]))
		case strings.HasPrefix(text, "   ") && len(steps) > 0 && strings.TrimSpace(text) != "":
			steps[len(steps)-1] += " " + strings.TrimSpace(text)
		}
	}
	return steps
}

// checkSiteReports checks what the site will show: every file there, each
// report the one its machine printed, every break-in story found, the clean
// machine quiet, and nothing of this computer anywhere.
func checkSiteReports(t *testing.T, out string) {
	for _, f := range siteFileNames() {
		fi, err := os.Stat(filepath.Join(out, f))
		if err != nil || fi.Size() == 0 {
			t.Errorf("site report %s is missing or empty (%v)", f, err)
		}
	}
	var idx siteIndex
	if data, err := os.ReadFile(filepath.Join(out, "index.json")); err != nil {
		t.Errorf("index.json: %v", err)
	} else if err := json.Unmarshal(data, &idx); err != nil {
		t.Errorf("index.json does not parse: %v", err)
	}
	if !strings.HasPrefix(idx.Version, "telltale ") {
		t.Errorf("index.json names no telltale version: %q", idx.Version)
	}
	if len(idx.Reports) != len(siteReports) {
		t.Errorf("index.json lists %d reports, want %d", len(idx.Reports), len(siteReports))
	}
	for i, want := range siteReports {
		if i < len(idx.Reports) {
			got := idx.Reports[i]
			if got.Name != want.Name || got.Machine != want.Machine || got.Kind != want.Kind {
				t.Errorf("index.json report %d is %s on %s (%s), want %s on %s (%s)", i, got.Name, got.Machine, got.Kind, want.Name, want.Machine, want.Kind)
			}
			if len(got.Story) < 2 || got.Title == "" || got.Summary == "" {
				t.Errorf("index.json: %s has no story (title %q, summary %q, %d steps)", want.Name, got.Title, got.Summary, len(got.Story))
			}
		}
		data, err := os.ReadFile(filepath.Join(out, want.Name+".json"))
		if err != nil {
			continue // reported above
		}
		var r model.Report
		if err := json.Unmarshal(data, &r); err != nil {
			t.Errorf("%s.json does not parse: %v", want.Name, err)
			continue
		}
		if r.Host.Hostname != want.Machine {
			t.Errorf("%s was made on %q, want the lab machine %s", want.Name, r.Host.Hostname, want.Machine)
		}
		if text, _ := os.ReadFile(filepath.Join(out, want.Name+".txt")); !bytes.HasPrefix(text, []byte("telltale: "+want.Machine+" (")) {
			t.Errorf("%s.txt is not the terminal report of %s: %.80q", want.Name, want.Machine, text)
		}
		if html, _ := os.ReadFile(filepath.Join(out, want.Name+".html")); !bytes.Contains(html, []byte("<title>telltale report: "+want.Machine+"</title>")) {
			t.Errorf("%s.html is not the HTML report of %s", want.Name, want.Machine)
		}
		switch want.Kind {
		case "clean":
			for _, f := range r.Findings {
				if f.Severity > model.SevNote {
					t.Errorf("the clean machine's report has %q: %s (%s)", f.Severity, f.Title, f.Key)
				}
			}
		default:
			// A break-in must be found as one: a finding that the machine
			// was tampered with (tampering or a backdoor sign, the two
			// severities of exit code 2).
			found := false
			for _, f := range r.Findings {
				found = found || f.Severity >= model.SevBackdoor
			}
			if !found || r.ExitCode != 2 {
				t.Errorf("%s: the break-in is not reported as tampering or a backdoor sign (exit %d):\n%s", want.Name, r.ExitCode, summary(&r))
			}
		}
	}
	checkPrivate(t, out)
}

// checkPrivate fails the test when a file in dir holds anything of the
// computer running the lab: its host name, its user's name and home
// directory, the parts of those names (split at anything that is not a
// letter or digit, four characters or longer, with a letter), its network
// addresses, and the words in
// $TELLTALE_SITE_PRIVATE (comma separated). They are worked out here rather
// than written down, so the repository does not hold them either.
func checkPrivate(t *testing.T, dir string) {
	t.Helper()
	words, ips := privateWords(t)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		checked++
		low := bytes.ToLower(data)
		for i, w := range words {
			if bytes.Contains(low, []byte(strings.ToLower(w))) {
				t.Errorf("%s holds something of this computer (private word %d of %d): it must never reach the site", e.Name(), i+1, len(words))
			}
		}
		for _, re := range ips {
			if re.Match(data) {
				t.Errorf("%s holds one of this computer's network addresses: it must never reach the site", e.Name())
			}
		}
	}
	t.Logf("privacy: %d files checked against %d private words and %d addresses of this computer", checked, len(words), len(ips))
}

// privateWords works out what identifies the computer running the test.
func privateWords(t *testing.T) ([]string, []*regexp.Regexp) {
	t.Helper()
	host, err := os.Hostname()
	if err != nil || host == "" {
		t.Fatalf("cannot tell this computer's host name (%v), so the privacy check cannot run", err)
	}
	seen := map[string]bool{}
	var words []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if len(s) < 3 || seen[strings.ToLower(s)] {
			return
		}
		// Names every Linux machine has, the lab's included.
		switch strings.ToLower(s) {
		case "root", "localhost", "/root", "debian", "ubuntu", "user", "admin", "home":
			return
		}
		seen[strings.ToLower(s)] = true
		words = append(words, s)
	}
	parts := func(s string) {
		for _, p := range strings.FieldsFunc(s, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) {
			if len(p) >= 4 && strings.ContainsFunc(p, unicode.IsLetter) {
				add(p)
			}
		}
	}
	add(host)
	parts(host)
	if u, err := user.Current(); err == nil {
		add(u.Username)
		parts(u.Username)
		if strings.HasPrefix(u.HomeDir, "/home/") {
			add(u.HomeDir)
		}
	}
	if home, err := os.UserHomeDir(); err == nil && strings.HasPrefix(home, "/home/") {
		add(home)
	}
	for _, w := range strings.Split(os.Getenv("TELLTALE_SITE_PRIVATE"), ",") {
		add(w)
	}
	var ips []*regexp.Regexp
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatalf("cannot list this computer's addresses (%v), so the privacy check cannot run", err)
	}
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok || n.IP.IsLoopback() || n.IP.IsLinkLocalUnicast() {
			continue
		}
		ips = append(ips, regexp.MustCompile(fmt.Sprintf(`(^|[^0-9a-fA-F.:])%s($|[^0-9a-fA-F])`, regexp.QuoteMeta(n.IP.String()))))
	}
	return words, ips
}
