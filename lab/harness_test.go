//go:build lab

package lab

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/lab/labkit"
)

var binPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "telltale-lab-bin")
	if err != nil {
		panic(err)
	}
	binPath = filepath.Join(dir, "telltale")
	cmd := exec.Command("go", "build", "-o", binPath, "./cmd/telltale")
	cmd.Dir = ".."
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
	if out, err := cmd.CombinedOutput(); err != nil {
		os.RemoveAll(dir)
		println("build telltale:", err.Error(), string(out))
		os.Exit(1)
	}
	code := labkit.Main(m)
	labGate.report()
	os.RemoveAll(dir)
	if standinsDir != "" {
		os.RemoveAll(standinsDir)
	}
	os.Exit(code)
}

// The Docker disk is shared and small, so the lab works through one distro at
// a time: every test that goes over the distros joins the gate, all of them do
// debian12 together, its images are removed, and only then does anyone start
// on debian13. TELLTALE_LAB_DISTROS (comma separated) limits the distros;
// TELLTALE_LAB_KEEP_IMAGES=1 keeps the images.
type distroGate struct {
	mu      sync.Mutex
	cond    *sync.Cond
	users   map[*testing.T]int // the last distro index each joined test has finished
	cur     int
	started map[int]time.Time
	took    map[string]time.Duration
}

var labGate = func() *distroGate {
	g := &distroGate{users: map[*testing.T]int{}, started: map[int]time.Time{}, took: map[string]time.Duration{}}
	g.cond = sync.NewCond(&g.mu)
	return g
}()

// join registers a test. It must be called before t.Parallel: Go resumes
// parallel tests only when every top-level test has reached that call, so by
// then every test that will take part has joined.
func (g *distroGate) join(t *testing.T) {
	g.mu.Lock()
	g.users[t] = -1
	g.mu.Unlock()
	t.Cleanup(func() {
		g.mu.Lock()
		delete(g.users, t)
		g.advance()
		g.mu.Unlock()
	})
}

func (g *distroGate) enter(i int) {
	g.mu.Lock()
	for g.cur < i {
		g.cond.Wait()
	}
	if _, ok := g.started[i]; !ok {
		g.started[i] = time.Now()
	}
	g.mu.Unlock()
}

func (g *distroGate) leave(t *testing.T, i int) {
	g.mu.Lock()
	if g.users[t] < i {
		g.users[t] = i
	}
	g.advance()
	g.mu.Unlock()
}

// advance moves on when every joined test has finished the current distro.
func (g *distroGate) advance() {
	for g.cur < len(labkit.Distros) {
		for _, done := range g.users {
			if done < g.cur {
				return
			}
		}
		distro := labkit.Distros[g.cur]
		if st, ok := g.started[g.cur]; ok {
			g.took[distro] = time.Since(st)
		}
		labkit.ReleaseImages(distro)
		g.cur++
		g.cond.Broadcast()
	}
}

func (g *distroGate) report() {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, d := range labkit.Distros {
		if took, ok := g.took[d]; ok && took > time.Second {
			fmt.Fprintf(os.Stderr, "lab: %s took %v\n", d, took.Round(time.Second))
		}
	}
}

func wantDistro(distro string) bool {
	only := os.Getenv("TELLTALE_LAB_DISTROS")
	if only == "" {
		return true
	}
	for _, d := range strings.Split(only, ",") {
		if strings.TrimSpace(d) == distro {
			return true
		}
	}
	return false
}

// eachDistro runs fn as a subtest per distro, one distro at a time across the
// whole test binary. Subtests of fn may run in parallel.
func eachDistro(t *testing.T, fn func(t *testing.T, distro string)) {
	onDistros(t, labkit.Distros, fn)
}

// onDistros is eachDistro for some of the distros.
func onDistros(t *testing.T, only []string, fn func(t *testing.T, distro string)) {
	labGate.join(t)
	t.Parallel()
	for i, distro := range labkit.Distros {
		func() {
			labGate.enter(i)
			defer labGate.leave(t, i)
			if !slices.Contains(only, distro) || !wantDistro(distro) {
				return
			}
			t.Run(distro, func(t *testing.T) {
				labkit.RequireFree(t)
				fn(t, distro)
			})
		}()
	}
}

// machineSlots bounds how many lab machines run at once.
var machineSlots = make(chan struct{}, 8)

// slot makes a parallel leaf test wait for a free machine slot.
func slot(t *testing.T) {
	t.Parallel()
	machineSlots <- struct{}{}
	t.Cleanup(func() { <-machineSlots })
}

// standinsDir is the temporary directory standins made, removed by TestMain.
var standinsDir string

// standins extracts the right-architecture stand-ins from their image (built
// from lab/standins when missing) into a host directory, once per run.
var standins = sync.OnceValues(func() (string, error) {
	src := "standins"
	h := sha256.New()
	names, err := filepath.Glob(filepath.Join(src, "*"))
	if err != nil {
		return "", err
	}
	sort.Strings(names)
	for _, n := range names {
		data, err := os.ReadFile(n)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(h, "%s\x00%d\x00", filepath.Base(n), len(data))
		h.Write(data)
	}
	tag := "telltale-lab/standins:" + hex.EncodeToString(h.Sum(nil))[:12]
	run := func(args ...string) (string, error) {
		out, err := exec.Command("docker", args...).CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return strings.TrimSpace(string(out)), nil
	}
	if _, err := run("image", "inspect", "--format", "{{.Id}}", tag); err != nil {
		if _, err := run("build", "-q", "--label", labkit.Label, "-f", filepath.Join(src, "Dockerfile.build"), "-t", tag, src); err != nil {
			return "", err
		}
	}
	// The image is FROM scratch: a container needs some command to be created.
	id, err := run("create", "--label", labkit.Label, tag, "/none")
	if err != nil {
		return "", err
	}
	defer run("rm", "-f", id)
	dir, err := os.MkdirTemp("", "telltale-lab-standins")
	if err != nil {
		return "", err
	}
	standinsDir = dir
	if _, err := run("cp", id+":/standins/amd64", filepath.Join(dir, "standins")); err != nil {
		return "", err
	}
	return filepath.Join(dir, "standins"), nil
})

// start runs a machine with the telltale binary installed and the bundle
// cache mounted.
func start(t *testing.T, image string, opts labkit.Opts) *labkit.Machine {
	t.Helper()
	opts.Binds = append(opts.Binds, RefsBind())
	m := labkit.Start(t, image, opts)
	m.CopyIn(t, binPath, "/usr/local/bin/telltale")
	mustExec(t, m, "chmod 755 /usr/local/bin/telltale && mkdir -p /run/telltale-lab")
	return m
}

// plant copies the break and scenario scripts and the stand-ins into a
// machine. Machines with a route out never get them.
func plant(t *testing.T, m *labkit.Machine) {
	t.Helper()
	if m.Egress {
		t.Fatalf("%s has a route out: nothing may be planted on it", m.Name)
	}
	si, err := standins()
	if err != nil {
		t.Fatalf("stand-ins: %v", err)
	}
	m.CopyIn(t, si, "/lab/standins")
	m.CopyIn(t, "breaks", "/lab/breaks")
	m.CopyIn(t, "scenarios", "/lab/scenarios")
}

// mustExec runs a shell command in the machine and fails the test when it fails.
func mustExec(t *testing.T, m *labkit.Machine, script string) string {
	t.Helper()
	out, code := m.Exec(t, "sh", "-c", script+" 2>&1")
	if code != 0 {
		t.Fatalf("%s: `%s` exit %d:\n%s", m.Name, script, code, out)
	}
	return out
}

const (
	snapInside = "/run/telltale-lab/snap"
	errInside  = "/run/telltale-lab/stderr"
)

// takeSnapshot records the machine as it is now and takes the snapshot off
// the machine, as an owner would; putSnapshot brings it back for a scan.
func takeSnapshot(t *testing.T, m *labkit.Machine) string {
	t.Helper()
	mustExec(t, m, "telltale snapshot --out /tmp/snap --no-encrypt")
	// Read through the machine, not with docker cp: /tmp can be a tmpfs
	// mount, which docker cp does not see.
	data, code := m.Exec(t, "cat", "/tmp/snap")
	if code != 0 || len(data) == 0 {
		t.Fatalf("%s: cannot read the snapshot back (exit %d, %d bytes)", m.Name, code, len(data))
	}
	host := filepath.Join(t.TempDir(), "snap")
	if err := os.WriteFile(host, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	mustExec(t, m, "rm -f /tmp/snap")
	return host
}

func putSnapshot(t *testing.T, m *labkit.Machine, host string) {
	t.Helper()
	// By way of /lab, because docker cp cannot write into a tmpfs /run.
	m.CopyIn(t, host, "/lab/snap.in")
	mustExec(t, m, "mv /lab/snap.in "+snapInside)
}

// refsFor collects the machine as it is now and returns the path, inside the
// machine, of the reference bundle for it.
func refsFor(t *testing.T, m *labkit.Machine) string {
	t.Helper()
	out, code := m.Exec(t, "sh", "-c", "telltale collect 2>"+errInside)
	if code != 0 {
		errs, _ := m.Exec(t, "cat", errInside)
		t.Fatalf("%s: telltale collect exit %d: %s", m.Name, code, errs)
	}
	dir, err := EnsureBundle(binPath, []byte(out))
	if err != nil {
		t.Fatalf("%s: reference bundle: %v", m.Name, err)
	}
	return dir
}

// scan runs "telltale scan ARGS --json -" in the machine.
func scan(t *testing.T, m *labkit.Machine, args ...string) (*model.Report, int) {
	t.Helper()
	cmd := "telltale scan " + strings.Join(args, " ") + " --json - 2>" + errInside
	out, code := m.Exec(t, "sh", "-c", cmd)
	var r model.Report
	dec := json.NewDecoder(bytes.NewReader([]byte(out)))
	if err := dec.Decode(&r); err != nil || code < 0 || code > 2 {
		errs, _ := m.Exec(t, "cat", errInside)
		t.Fatalf("%s: `%s` exit %d (%v):\n%s", m.Name, cmd, code, err, errs)
	}
	if r.ExitCode != code {
		t.Errorf("%s: scan exit code %d, the report says %d", m.Name, code, r.ExitCode)
	}
	return &r, code
}

// saveReport keeps a report under $TELLTALE_LAB_REPORTS when that is set.
func saveReport(t *testing.T, distro, name string, r *model.Report) {
	dir := os.Getenv("TELLTALE_LAB_REPORTS")
	if dir == "" {
		return
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		t.Errorf("save report: %v", err)
		return
	}
	_ = os.MkdirAll(filepath.Join(dir, distro), 0o755)
	if err := os.WriteFile(filepath.Join(dir, distro, name+".json"), data, 0o644); err != nil {
		t.Errorf("save report: %v", err)
	}
}

// summary lists a report's findings, most severe first, for failure messages.
func summary(r *model.Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "exit %d, compared against %q\n", r.ExitCode, r.ComparedAgainst)
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "  %-14s %s\n      %s\n", f.Severity, f.Key, f.Title)
	}
	fmt.Fprintf(&b, "  (%d explained groups)\n", len(r.Explained))
	return b.String()
}

// checkReport compares a report with a manifest section and fails the test
// with every mismatch.
func checkReport(t *testing.T, man *Manifest, r *model.Report, withSnapshot bool) {
	t.Helper()
	if problems := Check(man, r, withSnapshot); len(problems) > 0 {
		t.Errorf("the report does not match the manifest:\n  %s\nreport: %s", strings.Join(problems, "\n  "), summary(r))
	}
}
