package crossview

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

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
		if err != nil || !reflect.DeepEqual(p, []int{31337}) {
			t.Errorf("%s tcp: %v %v", d, p, err)
		}
		p, err = parseSSOutput(readFixture(t, d, "ss-udp.txt"))
		if err != nil || !reflect.DeepEqual(p, []int{31338}) {
			t.Errorf("%s udp: %v %v", d, p, err)
		}
	}
	p, err := parseSSOutput("LISTEN 0 4096 [::]:22 [::]:*\nLISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:*\nESTAB 0 0 1.2.3.4:80 5.6.7.8:9\n")
	if err != nil || !reflect.DeepEqual(p, []int{22, 53}) {
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
		n := parseLs(readFixture(t, d, "ls-etc.txt"))
		if len(n) < 10 {
			t.Fatalf("%s: %d names", d, len(n))
		}
		for _, x := range n {
			if x == "." || x == ".." {
				t.Errorf("%s: kept %q", d, x)
			}
		}
	}
}

func TestCompareHiddenProcess(t *testing.T) {
	before := []model.Process{{PID: 1, Comm: "init"}, {PID: 4242, Comm: "evil"}}
	hidden, extra := comparePIDs(before, []int{1}, map[int]bool{1: true, 4242: true}, 999)
	if !reflect.DeepEqual(hidden, []string{"pid 4242 (evil)"}) || len(extra) != 0 {
		t.Errorf("hidden=%v extra=%v", hidden, extra)
	}
}

func TestCompareIgnoresRaces(t *testing.T) {
	before := []model.Process{{PID: 1, Comm: "init"}, {PID: 4242, Comm: "gone"}}
	// 4242 exited before the second read; 77 appeared and exited unseen
	// by telltale; 78 is the tool's own pid.
	hidden, extra := comparePIDs(before, []int{1, 77, 78}, map[int]bool{1: true, 77: true}, 78)
	if len(hidden) != 0 || len(extra) != 0 {
		t.Errorf("hidden=%v extra=%v", hidden, extra)
	}
	// A pid only the tool knows and that is gone everywhere is extra.
	_, extra = comparePIDs(before, []int{1, 5000}, map[int]bool{1: true}, 78)
	if !reflect.DeepEqual(extra, []string{"pid 5000"}) {
		t.Errorf("extra=%v", extra)
	}
}

func fakeTools(t *testing.T, root string, scripts map[string]string) string {
	t.Helper()
	dir := filepath.Join(root, "fakebin")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for n, body := range scripts {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	old := toolDirs
	toolDirs = []string{"/fakebin"}
	t.Cleanup(func() { toolDirs = old })
	return dir
}

func TestMissingToolSkipped(t *testing.T) {
	root := t.TempDir()
	fakeTools(t, root, nil)
	res := Collect(model.Runtime{}, root, []string{})
	if len(res) == 0 {
		t.Fatal("no results")
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

func TestEnvironmentIsClean(t *testing.T) {
	root := t.TempDir()
	fakeTools(t, root, map[string]string{"ps": "env"})
	t.Setenv("LD_PRELOAD", "/nonexistent.so")
	t.Setenv("SECRET_TOKEN", "x")
	out, _, reason := runTool(root, "ps")
	if reason != "" {
		t.Fatal(reason)
	}
	got := strings.Fields(out)
	// Some shells add PWD/SHLVL/_ themselves; those are not ours.
	for _, l := range got {
		if strings.HasPrefix(l, "LD_PRELOAD") || strings.HasPrefix(l, "SECRET") || strings.HasPrefix(l, "HOME") {
			t.Errorf("leaked %q", l)
		}
	}
	joined := "\n" + strings.Join(got, "\n") + "\n"
	for _, w := range []string{"\nPATH=/usr/sbin:/usr/bin:/sbin:/bin\n", "\nLC_ALL=C\n"} {
		if !strings.Contains(joined, w) {
			t.Errorf("missing %q in %q", w, got)
		}
	}
}

func TestToolFailureAndOutputCap(t *testing.T) {
	root := t.TempDir()
	fakeTools(t, root, map[string]string{"ps": "echo 1; exit 3", "lsmod": "yes | head -c 40000000"})
	if _, _, r := runTool(root, "ps"); !strings.Contains(r, "exit status 3") {
		t.Errorf("reason %q", r)
	}
	if _, _, r := runTool(root, "lsmod"); !strings.Contains(r, "32 MiB") {
		t.Errorf("reason %q", r)
	}
}

func TestCollectEndToEnd(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"a", "hidden-by-rootkit"} {
		if err := os.WriteFile(filepath.Join(root, "etc", n), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	proc := t.TempDir()
	for _, n := range []string{"1", "4242"} {
		os.Mkdir(filepath.Join(proc, n), 0o755)
	}
	oldProc := procRoot
	procRoot = proc
	t.Cleanup(func() { procRoot = oldProc })
	fakeTools(t, root, map[string]string{
		"ps":    "echo 1",
		"ss":    "echo 'LISTEN 0 5 0.0.0.0:22 0.0.0.0:*'",
		"lsmod": "echo 'Module Size Used by'; echo nf_tables 1 0",
		"ls":    `printf '.\n..\na\n'`,
	})
	rt := model.Runtime{
		Processes: []model.Process{{PID: 1, Comm: "init"}, {PID: 4242, Comm: "evil"}},
		Sockets: []model.Socket{
			{Proto: "tcp", Local: "0.0.0.0:22", Listening: true},
			{Proto: "tcp", Local: "0.0.0.0:31337", Listening: true},
		},
		Modules: []model.KernelModule{{Name: "nf_tables"}, {Name: "rk"}},
	}
	res := Collect(rt, root, []string{"/etc"})
	want := map[string][2][]string{
		"ps":      {{"pid 4242 (evil)"}, nil},
		"ss -t":   {{"tcp port 31337"}, nil},
		"ss -u":   {nil, {"udp port 22"}},
		"lsmod":   {{"module rk"}, nil},
		"ls /etc": {{"/etc/hidden-by-rootkit"}, nil},
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
