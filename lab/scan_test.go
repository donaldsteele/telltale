//go:build lab

package lab

import (
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/donaldsteele/telltale/internal/judge"
	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/lab/labkit"
)

// The scan suite runs the real static binary inside lab machines and compares
// every report with the committed manifests. Each case is scanned twice, with
// a snapshot of the machine taken before anything was planted and without
// one. Packages are verified with reference bundles (see refs.go).

// labCase is one machine to scan: a break, a scenario or a plain variant.
type labCase struct {
	id   string
	dir  string // holds apply.sh and manifest.json; "" for a variant baseline
	man  *Manifest
	kind string // "variant", "break" or "scenario"
}

func loadCases(t *testing.T, kind, parent string) []labCase {
	t.Helper()
	dirs, err := filepath.Glob(filepath.Join(parent, "*", "manifest.json"))
	if err != nil || len(dirs) == 0 {
		t.Fatalf("no manifests under %s (%v)", parent, err)
	}
	sort.Strings(dirs)
	var cases []labCase
	for _, f := range dirs {
		dir := filepath.Dir(f)
		man, err := LoadManifest(dir)
		if err != nil {
			t.Fatal(err)
		}
		cases = append(cases, labCase{id: filepath.Base(dir), dir: dir, man: man, kind: kind})
	}
	return cases
}

// machineFor starts the machine a case asks for.
func machineFor(t *testing.T, distro string, c labCase) *labkit.Machine {
	t.Helper()
	req := c.man.Requires
	if req.NativeExe && labkit.Emulated() {
		t.Skipf("%s is detected from the program a process runs, and under emulation the kernel reports qemu as every process's program; it is checked on %s machines that are not emulated", c.id, labkit.Arch)
	}
	if len(req.Distros) > 0 && !slices.Contains(req.Distros, distro) {
		t.Skipf("%s does not apply to %s", c.id, distro)
	}
	variant := req.Variant
	if variant == "" {
		variant = "clean"
	}
	image := labkit.BuildWith(t, distro, variant, labkit.BuildOpts{Newer: req.NewerSnapshot, Systemd: req.Systemd})
	if variant == "thirdparty" {
		// Its APT sources name the lab's repository.
		ensureRepo(t)
	}
	return start(t, image, labkit.Opts{
		Noexec:     variant == "noexec",
		Privileged: req.Privileged,
		Caps:       req.Caps,
		Ext4Volume: req.Ext4,
		Systemd:    req.Systemd,
		ExecShm:    req.ExecShm,
	})
}

// runCase is the flow every case follows: snapshot the machine while it is
// clean and take the snapshot away, plant the break, bring the snapshot back,
// then scan with it and without it and compare both reports with the manifest.
func runCase(t *testing.T, distro string, c labCase) (with, without *model.Report) {
	t.Helper()
	m := machineFor(t, distro, c)
	if c.dir != "" {
		plant(t, m)
	}
	snap := takeSnapshot(t, m)
	if c.dir != "" {
		// Nothing a script leaves running may hold the exec session open.
		mustExec(t, m, "sh /lab/"+filepath.Base(filepath.Dir(c.dir))+"/"+c.id+"/apply.sh >/run/telltale-lab/apply.log 2>&1 || { cat /run/telltale-lab/apply.log; exit 1; }")
	}
	putSnapshot(t, m, snap)
	// With a snapshot the bundle also carries the third-party repositories
	// whose keys the snapshot recorded; without one, only the distribution.
	refsSnap, _ := refsWith(t, m, snap)
	with, _ = scan(t, m, "--snapshot", snapInside, "--refs", refsSnap)
	saveReport(t, distro, c.id+".with-snapshot", with)
	checkReport(t, c.man, with, true)

	refs, _ := refsFor(t, m)
	without, _ = scan(t, m, "--refs", refs)
	saveReport(t, distro, c.id+".without-snapshot", without)
	checkReport(t, c.man, without, false)
	return with, without
}

// TestCleanMachinesAreClean scans every variant of every distro with nothing
// planted. A clean machine must be quiet: no tampering and no backdoor sign
// without a snapshot, and nothing above a note against its own snapshot.
func TestCleanMachinesAreClean(t *testing.T) {
	eachDistro(t, func(t *testing.T, distro string) {
		for _, variant := range labkit.Variants {
			t.Run(variant, func(t *testing.T) {
				slot(t)
				man, err := LoadManifestFile(filepath.Join("variants", variant+".manifest.json"))
				if err != nil {
					t.Fatal(err)
				}
				with, without := runCase(t, distro, labCase{id: variant, man: man, kind: "variant"})
				for _, r := range []*model.Report{with, without} {
					for _, f := range r.Findings {
						if f.Severity >= model.SevBackdoor {
							t.Errorf("clean %s %s reports %q: %s (%s)", distro, variant, f.Severity, f.Key, f.Title)
						}
					}
				}
				// Against its own snapshot nothing has changed: the only
				// things above a note are checklist items that were not met
				// when the snapshot was taken either.
				for _, f := range with.Findings {
					if f.Severity > model.SevNote && (!strings.HasPrefix(f.Key, "check:") || findKey(without, f.Key) == nil) {
						t.Errorf("clean %s %s against its own snapshot reports %q: %s (%s)", distro, variant, f.Severity, f.Key, f.Title)
					}
				}
				if variant == "localsoft" {
					// Locally built software is the owner's business: it is
					// shown, and never as more than a note.
					seen := false
					for _, f := range without.Findings {
						if !strings.Contains(f.Key, "/usr/local/") {
							continue
						}
						seen = true
						if f.Severity > model.SevNote {
							t.Errorf("local software is reported as %q, want a note: %s", f.Severity, f.Key)
						}
					}
					if !seen {
						t.Errorf("the local setuid helper is not mentioned at all:\n%s", summary(without))
					}
				}
			})
		}
	})
}

// TestEveryBreakDetected plants each break on each distro and checks that the
// report names it, with and without the clean snapshot.
func TestEveryBreakDetected(t *testing.T) {
	cases := loadCases(t, "break", "breaks")
	eachDistro(t, func(t *testing.T, distro string) {
		for _, c := range cases {
			t.Run(c.id, func(t *testing.T) {
				slot(t)
				runCase(t, distro, c)
			})
		}
	})
}

// TestScenarios runs the whole-story machines.
func TestScenarios(t *testing.T) {
	cases := loadCases(t, "scenario", "scenarios")
	eachDistro(t, func(t *testing.T, distro string) {
		for _, c := range cases {
			t.Run(c.id, func(t *testing.T) {
				slot(t)
				runCase(t, distro, c)
			})
		}
	})
}

// TestUpdateNoiseIsExplained upgrades a snapshotted clean machine to the
// newer pinned package versions and scans it: an ordinary update must not
// raise anything. The machine has nothing planted and is the only one with a
// route out (it needs the package archive).
//
// To reach the newer versions the test itself points the machine's APT
// source at a later archive snapshot. Changing where packages come from is
// a backdoor sign, and must be reported as one here; it is the one finding
// above a note that the test expects.
func TestUpdateNoiseIsExplained(t *testing.T) {
	eachDistro(t, func(t *testing.T, distro string) {
		t.Run("upgrade", func(t *testing.T) {
			slot(t)
			m := start(t, labkit.Build(t, distro, "clean"), labkit.Opts{Egress: true})
			snap := takeSnapshot(t, m)
			const versions = `dpkg-query -W -f '${Package} ${Version}\n'`
			before := mustExec(t, m, versions)
			mustExec(t, m, `. /lab/os; . /lab/common/pins.env; `+
				`if [ "$LAB_FAMILY" = debian ]; then ts=$DEBIAN_SNAPSHOT_NEWER; else ts=$UBUNTU_SNAPSHOT_NEWER; fi; `+
				`/lab/common/set-snapshot.sh "$ts" && apt-get update >/dev/null && `+
				`DEBIAN_FRONTEND=noninteractive apt-get -y upgrade >/run/telltale-lab/upgrade.log`)
			after := mustExec(t, m, versions)
			changed := 0
			was := map[string]bool{}
			for _, l := range strings.Split(before, "\n") {
				was[l] = true
			}
			for _, l := range strings.Split(after, "\n") {
				if !was[l] {
					changed++
				}
			}
			if changed == 0 {
				t.Fatalf("the upgrade changed no package: the two pinned snapshots do not differ for %s", distro)
			}
			t.Logf("%s: the upgrade changed %d packages", distro, changed)
			putSnapshot(t, m, snap)
			refs, col := refsFor(t, m)
			r, code := scan(t, m, "--snapshot", snapInside, "--refs", refs)
			saveReport(t, distro, "update-noise.with-snapshot", r)
			const labSource = "snap.file_modified:/etc/apt/sources.list.d/lab-snapshot.sources"
			if f := findKey(r, labSource); f == nil || f.Key != labSource || f.Severity != model.SevBackdoor {
				t.Errorf("the APT source the test repointed is not a backdoor sign: %+v", f)
			}
			// 2 is for that finding; nothing may say tampering (3).
			if code != 2 {
				t.Errorf("exit code %d after an ordinary upgrade from a repointed APT source, want 2", code)
			}
			if findKey(r, "explained:") == nil {
				t.Errorf("no upgraded package is in the explained group")
			}
			// Checklist items that were not met before the upgrade either
			// stay weak settings; nothing else may rank above a note.
			for _, f := range r.Findings {
				if f.Key == labSource {
					continue
				}
				if f.Severity > model.SevNote && !(f.Severity == model.SevWeak && strings.HasPrefix(f.Key, "check:")) {
					t.Errorf("an ordinary upgrade raised %q: %s (%s)", f.Severity, f.Key, f.Title)
				}
			}
			// Every changed package-owned file has to be in the explained
			// group, not in the ranked list under its own name. Owners knows
			// both spellings of a merged-/usr path (/lib/x and /usr/lib/x).
			owners := col.Packages.Owners()
			if len(owners) < 1000 {
				t.Fatalf("only %d package-owned paths in the collection", len(owners))
			}
			for _, f := range r.Findings {
				for _, family := range []string{"snap.file_modified:", "snap.file_added:", "snap.file_removed:", "snap.persist:", "pkg.mismatch:", "pkg.unverifiable:"} {
					if p, ok := strings.CutPrefix(f.Key, family); ok && owners[p] != "" {
						t.Errorf("a file of package %s changed by the upgrade is not explained: %s is %q", owners[p], f.Key, f.Severity)
					}
				}
			}
			if len(r.Explained) == 0 {
				t.Errorf("nothing was explained after an upgrade of %d packages", changed)
			}
			if t.Failed() {
				t.Logf("report: %s", summary(r))
			}
		})
	})
}

// TestOfflineFallbackWarns scans a clean machine with --offline, the one case
// that trusts the machine's own package checksums: the report has to say so.
func TestOfflineFallbackWarns(t *testing.T) {
	eachDistro(t, func(t *testing.T, distro string) {
		t.Run("offline", func(t *testing.T) {
			slot(t)
			m := start(t, labkit.Build(t, distro, "clean"), labkit.Opts{})
			r, _ := scan(t, m, "--offline")
			saveReport(t, distro, "offline.without-snapshot", r)
			if !slices.Contains(r.ComparedAgainst, judge.OfflineReference) {
				t.Errorf("compared_against does not name the machine's own checksums: %q", r.ComparedAgainst)
			}
			warned := false
			for _, l := range r.CouldNotRuleOut {
				warned = warned || strings.Contains(l, "own package checksums")
			}
			if !warned {
				t.Errorf("could_not_rule_out does not say that the machine's own checksums are trusted: %q", r.CouldNotRuleOut)
			}
			for _, f := range r.Findings {
				if f.Severity > model.SevWeak {
					t.Errorf("clean %s scanned offline reports %q: %s (%s)", distro, f.Severity, f.Key, f.Title)
				}
			}
		})
	})
}

// TestSystemdLiveUnit runs the one machine with systemd as PID 1 (in its own
// cgroup namespace), plants the systemd callback, starts its timer for real
// and scans: the unit, the enabled link and what the unit runs are reported.
func TestSystemdLiveUnit(t *testing.T) {
	onDistros(t, []string{"debian12"}, func(t *testing.T, distro string) {
		t.Run("systemd-callback", func(t *testing.T) {
			slot(t)
			man, err := LoadManifest(filepath.Join("breaks", "systemd-callback"))
			if err != nil {
				t.Fatal(err)
			}
			sink := labkit.StartSink(t)
			image := labkit.BuildWith(t, distro, "clean", labkit.BuildOpts{Systemd: true})
			m := start(t, image, labkit.Opts{Systemd: true})
			if out := mustExec(t, m, "cat /proc/1/comm"); strings.TrimSpace(out) != "systemd" {
				t.Fatalf("PID 1 is %q, want systemd", strings.TrimSpace(out))
			}
			if out := mustExec(t, m, "cat /proc/1/cgroup"); strings.TrimSpace(out) != "0::/" && !strings.HasPrefix(strings.TrimSpace(out), "0::/init.scope") {
				t.Fatalf("the machine sees a cgroup path of the host (%q): its cgroup namespace is not private", strings.TrimSpace(out))
			}
			waitFor(t, 60*time.Second, "systemd to finish starting", func() bool {
				out, _ := m.Exec(t, "systemctl", "is-system-running")
				s := strings.TrimSpace(out)
				return s == "running" || s == "degraded"
			})
			plant(t, m)
			snap := takeSnapshot(t, m)
			mustExec(t, m, "sh /lab/breaks/systemd-callback/apply.sh >/run/telltale-lab/apply.log 2>&1 || { cat /run/telltale-lab/apply.log; exit 1; }")
			// Live: systemd loads the units and the timer fires the service.
			mustExec(t, m, "systemctl daemon-reload && systemctl start lab-sync.timer && systemctl start lab-sync.service")
			if out := mustExec(t, m, "systemctl is-active lab-sync.timer"); strings.TrimSpace(out) != "active" {
				t.Fatalf("lab-sync.timer is %q, want active", strings.TrimSpace(out))
			}
			if !sink.WaitFor(t, "lab-callback", 20*time.Second) {
				t.Fatalf("the unit never called the sink; sink log:\n%s", sink.Log(t))
			}
			putSnapshot(t, m, snap)
			refs, _ := refsFor(t, m)
			with, _ := scan(t, m, "--snapshot", snapInside, "--refs", refs)
			saveReport(t, distro, "systemd-live.with-snapshot", with)
			checkReport(t, man, with, true)
			without, _ := scan(t, m, "--refs", refs)
			saveReport(t, distro, "systemd-live.without-snapshot", without)
			checkReport(t, man, without, false)

			const link = "/etc/systemd/system/timers.target.wants/lab-sync.timer"
			wantKey(t, with, "snap.persist:"+link, model.SevBackdoor)
			// What the unit runs: the callback command, in the finding's evidence.
			for _, r := range []*model.Report{with, without} {
				f := findKey(r, "heur.persist_callback:/etc/systemd/system/lab-sync.service")
				if f == nil {
					continue // already reported by the manifest check
				}
				shown := false
				for _, e := range f.Evidence {
					shown = shown || strings.Contains(e.After+e.Detail, "/dev/tcp/")
				}
				if !shown {
					t.Errorf("the callback finding does not show the command the unit runs: %+v", f.Evidence)
				}
			}
			t.Run("running-process", func(t *testing.T) {
				t.Skip("concern, not fixed here: no rule reports a process for having been started by a unit. " +
					"The unit runs the packaged /bin/bash for an instant; telltale reports the unit, its timer and the enabled link, " +
					"and the command the unit runs, but not a live process. Reporting one needs a new rule and a spec decision.")
			})
		})
	})
}

func findKey(r *model.Report, prefix string) *model.Finding {
	for _, l := range [][]model.Finding{r.Findings, r.Explained} {
		for i := range l {
			if strings.HasPrefix(l[i].Key, prefix) {
				return &l[i]
			}
		}
	}
	return nil
}

func wantKey(t *testing.T, r *model.Report, prefix string, sev model.Severity) {
	t.Helper()
	f := findKey(r, prefix)
	switch {
	case f == nil:
		t.Errorf("no finding %q:\n%s", prefix, summary(r))
	case f.Severity != sev:
		t.Errorf("finding %s is %q, want %q", f.Key, f.Severity, sev)
	}
}

func waitFor(t *testing.T, timeout time.Duration, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v waiting for %s", timeout, what)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func init() {
	// The lab's paths are relative to this directory.
	if _, err := os.Stat("breaks"); err != nil {
		panic("lab tests must run from the lab directory: " + err.Error())
	}
}
