package crossview

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/donaldsteele/telltale/internal/model"
)

var distros = []string{"debian12", "debian13", "ubuntu2204", "ubuntu2404"}

func readFixture(t *testing.T, distro, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", distro, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestParsePSOutput(t *testing.T) {
	for _, d := range distros {
		pids, err := parsePSOutput(readFixture(t, d, "ps.txt"))
		if err != nil || len(pids) < 2 || pids[0] != 1 {
			t.Errorf("%s: pids=%v err=%v", d, pids, err)
		}
	}
	if _, err := parsePSOutput("12\nabc\n"); err == nil {
		t.Error("garbage accepted")
	}
}

func TestParseSSOutput(t *testing.T) {
	for _, d := range distros {
		p, err := parseSSOutput(readFixture(t, d, "ss-tcp.txt"))
		if err != nil || !reflect.DeepEqual(p, []ssListener{{"4", 31337}}) {
			t.Errorf("%s tcp: %v %v", d, p, err)
		}
		p, err = parseSSOutput(readFixture(t, d, "ss-udp.txt"))
		if err != nil || !reflect.DeepEqual(p, []ssListener{{"4", 31338}}) {
			t.Errorf("%s udp: %v %v", d, p, err)
		}
	}
	p, err := parseSSOutput("LISTEN 0 4096 [::]:22 [::]:*\nLISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:*\nLISTEN 0 1 *:80 *:*\nLISTEN 0 1 :::81 :::*\nESTAB 0 0 1.2.3.4:80 5.6.7.8:9\n")
	want := []ssListener{{"6", 22}, {"4", 53}, {"", 80}, {"6", 81}}
	if err != nil || !reflect.DeepEqual(p, want) {
		t.Errorf("ipv6/zone: %v %v", p, err)
	}
}

func TestParseLsmod(t *testing.T) {
	for _, d := range distros {
		n, err := parseLsmod(readFixture(t, d, "lsmod.txt"))
		if err != nil || len(n) < 5 {
			t.Fatalf("%s: %v %v", d, n, err)
		}
		for _, m := range n {
			if m == "Module" || strings.Contains(m, "-") {
				t.Errorf("%s: bad name %q", d, m)
			}
		}
	}
	if _, err := parseLsmod("nope\n"); err == nil {
		t.Error("garbage accepted")
	}
}

func TestParseLs(t *testing.T) {
	for _, d := range distros {
		n, err := parseLs(readFixture(t, d, "ls-etc.txt"))
		if err != nil || len(n) < 10 {
			t.Fatalf("%s: %d names, %v", d, len(n), err)
		}
		for _, x := range n {
			if x == "." || x == ".." {
				t.Errorf("%s: kept %q", d, x)
			}
		}
	}
}

func TestParseLsHostileNames(t *testing.T) {
	for _, d := range []string{"debian12", "ubuntu2404"} {
		n, err := parseLs(readFixture(t, d, "ls-hostile.txt"))
		if err != nil {
			t.Fatal(err)
		}
		got := toSet(n)
		for _, w := range []string{"x\ny", "a b", `back\slash`, "hi\xff", "plain"} {
			if !got[w] {
				t.Errorf("%s: missing %q in %q", d, w, n)
			}
		}
		if len(n) != 5 {
			t.Errorf("%s: %q", d, n)
		}
	}
	if _, err := parseLs("bad\\q\n"); err == nil {
		t.Error("undecodable name accepted")
	}
	if _, err := parseLs("bad\\\n"); err == nil {
		t.Error("trailing backslash accepted")
	}
}

func TestCompareListeners(t *testing.T) {
	before := map[string]bool{"tcp 22": true, "tcp6 22": true, "tcp 99": true}
	after := map[string]bool{"tcp 22": true, "tcp6 22": true}
	// ss shows only the v4 listener on 22; 99 closed during the run.
	hidden, extra := compareListeners("tcp", before, after, []ssListener{{"4", 22}})
	if !reflect.DeepEqual(hidden, []string{"tcp6 port 22"}) || len(extra) != 0 {
		t.Errorf("hidden=%v extra=%v", hidden, extra)
	}
	// wildcard satisfies both families; unknown port is extra
	hidden, extra = compareListeners("tcp", before, after, []ssListener{{"", 22}, {"4", 7000}})
	if len(hidden) != 0 || !reflect.DeepEqual(extra, []string{"tcp port 7000"}) {
		t.Errorf("hidden=%v extra=%v", hidden, extra)
	}
	// a listener that appeared during the run is not extra
	hidden, extra = compareListeners("udp", map[string]bool{}, map[string]bool{"udp 53": true}, []ssListener{{"4", 53}})
	if len(hidden) != 0 || len(extra) != 0 {
		t.Errorf("hidden=%v extra=%v", hidden, extra)
	}
}

func TestDiffSetsRaces(t *testing.T) {
	id := func(s string) string { return s }
	// present before only (exited): not hidden; tool-only but in after: not extra
	h, e := diffSets(map[string]bool{"1": true, "2": true}, map[string]bool{"1": true, "5": true},
		map[string]bool{"1": true, "5": true}, id)
	if len(h) != 0 || len(e) != 0 {
		t.Errorf("h=%v e=%v", h, e)
	}
	h, e = diffSets(map[string]bool{"1": true, "2": true}, map[string]bool{"1": true, "2": true},
		map[string]bool{"1": true, "9": true}, id)
	if !reflect.DeepEqual(h, []string{"2"}) || !reflect.DeepEqual(e, []string{"9"}) {
		t.Errorf("h=%v e=%v", h, e)
	}
}

func fakeTools(t *testing.T, scripts map[string]string) {
	t.Helper()
	dir := t.TempDir()
	for n, body := range scripts {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	old := toolDirs
	toolDirs = []string{dir}
	t.Cleanup(func() { toolDirs = old })
}

func fakeProc(t *testing.T, pids map[string]string, modules, tcp string) {
	t.Helper()
	proc := t.TempDir()
	for p, comm := range pids {
		must(t, os.Mkdir(filepath.Join(proc, p), 0o755))
		must(t, os.WriteFile(filepath.Join(proc, p, "comm"), []byte(comm+"\n"), 0o644))
	}
	must(t, os.WriteFile(filepath.Join(proc, "modules"), []byte(modules), 0o644))
	must(t, os.Mkdir(filepath.Join(proc, "net"), 0o755))
	must(t, os.WriteFile(filepath.Join(proc, "net", "tcp"), []byte(tcp), 0o644))
	old := procRoot
	procRoot = proc
	t.Cleanup(func() { procRoot = old })
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestMissingToolSkipped(t *testing.T) {
	fakeTools(t, nil)
	res := Collect(model.Runtime{}, t.TempDir(), []string{"/etc"})
	if len(res) != 5 {
		t.Fatalf("%d results", len(res))
	}
	for _, r := range res {
		if r.Ran || !strings.HasSuffix(r.SkipReason, "not installed") {
			t.Errorf("%+v", r)
		}
	}
	if res[0].Tool != "ps" || res[0].SkipReason != "ps not installed" {
		t.Errorf("%+v", res[0])
	}
}

func TestSkipAll(t *testing.T) {
	res := SkipAll("why", []string{"/etc"})
	if len(res) != 5 {
		t.Fatalf("%d", len(res))
	}
	for _, r := range res {
		if r.Ran || r.SkipReason != "why" || r.Tool == "" {
			t.Errorf("%+v", r)
		}
	}
}

func TestEnvironmentIsClean(t *testing.T) {
	fakeTools(t, map[string]string{"ps": "cat /proc/$$/environ"})
	t.Setenv("LD_PRELOAD", "/nonexistent.so")
	t.Setenv("SECRET_TOKEN", "x")
	out, _, reason := runTool("ps")
	if reason != "" {
		t.Fatal(reason)
	}
	got := strings.Split(strings.TrimRight(out, "\x00"), "\x00")
	want := []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("environment %q, want %q", got, want)
	}
}

func TestToolFailureAndOutputCap(t *testing.T) {
	fakeTools(t, map[string]string{"ps": "echo 1; exit 3", "lsmod": "yes | head -c 40000000"})
	if _, _, r := runTool("ps"); !strings.Contains(r, "exit status 3") {
		t.Errorf("reason %q", r)
	}
	if _, _, r := runTool("lsmod"); !strings.Contains(r, "32 MiB") {
		t.Errorf("reason %q", r)
	}
}

func TestToolTimeoutKillsGroup(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "child-alive")
	fakeTools(t, map[string]string{"ps": "(sleep 2; touch " + marker + ") &\nsleep 30"})
	old := toolTimeout
	toolTimeout = 300 * time.Millisecond
	t.Cleanup(func() { toolTimeout = old })
	start := time.Now()
	_, _, r := runTool("ps")
	if !strings.Contains(r, "timed out") {
		t.Errorf("reason %q", r)
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("took %s", time.Since(start))
	}
	time.Sleep(2500 * time.Millisecond)
	if _, err := os.Stat(marker); err == nil {
		t.Error("child survived the timeout")
	}
}

const tcpHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

// 0.0.0.0:22 and 0.0.0.0:31337 (0x7A69) listening.
const tcpRows = "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 100 0 0 10 0\n" +
	"   1: 00000000:7A69 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2 1 0000000000000000 100 0 0 10 0\n"

func TestCollectEndToEnd(t *testing.T) {
	root := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(root, "etc"), 0o755))
	for _, n := range []string{"a", "hidden-by-rootkit"} {
		must(t, os.WriteFile(filepath.Join(root, "etc", n), nil, 0o644))
	}
	fakeProc(t, map[string]string{"1": "init", "4242": "evil"},
		"nf_tables 1 0 - Live 0x0\nrk 1 0 - Live 0x0\n", tcpHeader+tcpRows)
	fakeTools(t, map[string]string{
		"ps":    "echo 1",
		"ss":    "echo 'LISTEN 0 5 0.0.0.0:22 0.0.0.0:*'",
		"lsmod": "echo 'Module Size Used by'; echo nf_tables 1 0",
		"ls":    `printf '.\n..\na\nx\\ny\n'`,
	})
	res := Collect(model.Runtime{}, root, []string{"/etc"})
	want := map[string][2][]string{
		"ps":      {{"pid 4242 (evil)"}, nil},
		"lsmod":   {{"module rk"}, nil},
		"ss -t":   {{"tcp port 31337"}, nil},
		"ss -u":   {nil, {"udp port 22"}},
		"ls /etc": {{"/etc/hidden-by-rootkit"}, {"/etc/x\ny"}},
	}
	if len(res) != len(want) {
		t.Fatalf("%d results: %+v", len(res), res)
	}
	for _, r := range res {
		w := want[r.Tool]
		if !r.Ran || !reflect.DeepEqual(r.HiddenFromTool, w[0]) || !reflect.DeepEqual(r.ExtraInTool, w[1]) {
			t.Errorf("%s: %+v", r.Tool, r)
		}
	}
}

func TestLsChurnNotHidden(t *testing.T) {
	root := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(root, "d"), 0o755))
	f := filepath.Join(root, "d", "moved")
	must(t, os.WriteFile(f, nil, 0o644))
	// The fake ls renames the file away and back (changes ctime) and lists nothing.
	fakeTools(t, map[string]string{"ls": "mv " + f + " " + f + ".x; sleep 0.05; mv " + f + ".x " + f + "; echo ."})
	res := crossLs(root, "/d")
	if !res.Ran || len(res.HiddenFromTool) != 0 {
		t.Errorf("%+v", res)
	}
}
