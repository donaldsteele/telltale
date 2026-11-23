//go:build lab && vm

// Package vm runs the kernel checks that a container cannot exercise, because
// a container shares the host's kernel: loaded modules, the kernel command
// line and the live firewall. It boots a real Debian 12 machine in QEMU.
//
// Run it with a generous timeout, because the first run downloads the image
// and installs packages in the VM:
//
//	go test -tags "lab vm" -timeout 30m ./lab/vm/
//
// It needs read and write access to /dev/kvm (else it is skipped) and network
// access. A VM left behind by a killed test ends itself after an hour.
package vm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/donaldsteele/telltale/internal/checklist"
	"github.com/donaldsteele/telltale/internal/model"
)

// run.sh up exit codes: no usable /dev/kvm, and the forwarded port is taken.
const (
	exitSkip      = 77
	exitPortTaken = 78
)

// machine is the running VM and how to reach it.
type machine struct {
	t    *testing.T
	dir  string
	key  string
	port int
}

func (m *machine) sshArgs() []string {
	return []string{
		"-i", m.key, "-p", strconv.Itoa(m.port),
		"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
		"-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "LogLevel=ERROR",
		"-o", "ConnectTimeout=10",
	}
}

// ssh runs a command in the VM and returns its stdout and exit code (-1 when
// ssh itself did not run it).
func (m *machine) ssh(timeout time.Duration, command string) (string, string, int) {
	m.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ssh", append(m.sshArgs(), "debian@127.0.0.1", command)...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return out.String(), errb.String(), 0
	case errors.As(err, &ee):
		return out.String(), errb.String(), ee.ExitCode()
	default:
		return out.String(), errb.String() + err.Error(), -1
	}
}

func (m *machine) copyTo(local, remote string) {
	m.t.Helper()
	args := []string{"-i", m.key, "-P", strconv.Itoa(m.port),
		"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
		"-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "LogLevel=ERROR",
		local, "debian@127.0.0.1:" + remote}
	if out, err := exec.Command("scp", args...).CombinedOutput(); err != nil {
		m.t.Fatalf("scp %s: %v\n%s", local, err, out)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// Every VM that is running, by working directory, so that a signal can stop
// them all. (A -timeout panic cannot be caught: the tests keep inside the
// deadline instead, and run.sh's watchdog ends a VM that is left behind.)
var (
	regMu sync.Mutex
	reg   = map[string]string{} // working directory -> run.sh
)

func TestMain(m *testing.M) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		regMu.Lock()
		for dir, runSh := range reg {
			teardown(runSh, dir)
		}
		regMu.Unlock()
		os.Exit(130)
	}()
	os.Exit(m.Run())
}

// teardown stops QEMU through run.sh, then through its pidfile, and removes
// the working directory.
func teardown(runSh, dir string) {
	exec.Command(runSh, "down", dir).Run()
	if b, err := os.ReadFile(filepath.Join(dir, "qemu.pid")); err == nil {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && pid > 1 {
			if p, err := os.FindProcess(pid); err == nil {
				p.Kill()
			}
		}
	}
	os.RemoveAll(dir)
}

// budget is how long a wait may take: want, but never past the test's
// -timeout (less a margin), so that the test fails, and cleans up, before the
// testing package panics.
func budget(t *testing.T, want time.Duration) time.Duration {
	t.Helper()
	if dl, ok := t.Deadline(); ok {
		if left := time.Until(dl) - 45*time.Second; left < want {
			if left <= 0 {
				t.Fatal("no time left before the test timeout (run with -timeout 30m)")
			}
			return left
		}
	}
	return want
}

// boot starts the VM with run.sh and registers its teardown before anything
// can fail, whether the test passes, fails or panics.
func boot(t *testing.T) *machine {
	t.Helper()
	dir, err := os.MkdirTemp("", "telltale-vm-")
	if err != nil {
		t.Fatal(err)
	}
	m := &machine{t: t, dir: dir, key: filepath.Join(dir, "id_ed25519")}
	runSh, err := filepath.Abs("run.sh")
	if err != nil {
		t.Fatal(err)
	}
	regMu.Lock()
	reg[dir] = runSh
	regMu.Unlock()
	t.Cleanup(func() {
		if t.Failed() {
			if b, err := os.ReadFile(filepath.Join(dir, "console.log")); err == nil {
				tail := string(b)
				if len(tail) > 6000 {
					tail = tail[len(tail)-6000:]
				}
				t.Logf("VM console (tail):\n%s", tail)
			}
		}
		regMu.Lock()
		delete(reg, dir)
		regMu.Unlock()
		teardown(runSh, dir)
	})

	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "telltale-lab", "-f", m.key).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v\n%s", err, out)
	}
	start := time.Now()
	// The first run downloads the image. A port that someone else took
	// between freePort and QEMU's start (exit 78) is retried with another.
	for attempt := 1; ; attempt++ {
		m.port = freePort(t)
		ctx, cancel := context.WithTimeout(context.Background(), budget(t, 20*time.Minute))
		cmd := exec.CommandContext(ctx, runSh, "up", dir, m.key+".pub", strconv.Itoa(m.port))
		var errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = os.Stderr, &errb
		err = cmd.Run()
		cancel()
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == exitSkip {
			t.Skip(strings.TrimSpace(errb.String()))
		}
		if errors.As(err, &ee) && ee.ExitCode() == exitPortTaken && attempt < 4 {
			t.Logf("port %d taken, retrying: %s", m.port, strings.TrimSpace(errb.String()))
			continue
		}
		if err != nil {
			t.Fatalf("run.sh up: %v\n%s", err, errb.String())
		}
		break
	}
	t.Logf("run.sh up took %s", time.Since(start).Round(time.Second))

	// SSH answers early; cloud-init then installs the packages and builds and
	// loads the module, so wait for it to finish as well.
	sshBy := time.Now().Add(budget(t, 10*time.Minute))
	for {
		if _, _, code := m.ssh(30*time.Second, "true"); code == 0 {
			break
		}
		if time.Now().After(sshBy) {
			t.Fatal("the VM did not accept SSH in time")
		}
		time.Sleep(5 * time.Second)
	}
	t.Logf("ssh up after %s", time.Since(start).Round(time.Second))
	out, serr, code := m.ssh(budget(t, 25*time.Minute), "sudo cloud-init status --wait --long")
	t.Logf("cloud-init: %s%s (exit %d), %s", out, serr, code, time.Since(start).Round(time.Second))
	_, _, ready := m.ssh(30*time.Second, "test -e /var/lib/telltale-lab-ready")
	if ready != 0 {
		// user-data's setup script names the stage that failed.
		stage, _, _ := m.ssh(30*time.Second, "cat /var/lib/telltale-lab-failed 2>/dev/null")
		logTail, _, _ := m.ssh(30*time.Second, "sudo tail -n 40 /var/log/cloud-init-output.log")
		if stage = strings.TrimSpace(stage); stage != "" {
			t.Fatalf("lab setup failed at stage %q (sources/apt: installing build-essential, nftables and the kernel headers from snapshot.debian.org; make: building labmod; insmod: loading it; nftables: the ruleset)\n%s", stage, logTail)
		}
		t.Fatalf("lab setup did not finish: cloud-init status exit %d (not a setup stage failure; cloud-init itself or a timeout)\n%s\n%s", code, out, logTail)
	}
	return m
}

func buildTelltale(t *testing.T, dir string) string {
	t.Helper()
	bin := filepath.Join(dir, "telltale")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/telltale")
	cmd.Dir = filepath.Join("..", "..")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build telltale: %v\n%s", err, out)
	}
	return bin
}

func TestVMUnownedKernelModule(t *testing.T) {
	m := boot(t)
	bin := buildTelltale(t, m.dir)
	m.copyTo(bin, "/tmp/telltale")

	if out, _, code := m.ssh(30*time.Second, "lsmod"); code != 0 || !strings.Contains(out, "labmod") {
		t.Fatalf("labmod is not loaded in the VM (exit %d): %s", code, out)
	}

	// The scan: exit code 2, and the module reported as a backdoor sign.
	start := time.Now()
	out, serr, code := m.ssh(10*time.Minute, "sudo /tmp/telltale scan --json -")
	t.Logf("scan took %s", time.Since(start).Round(time.Second))
	if code != 2 {
		t.Fatalf("scan exit code = %d, want 2\nstderr: %s\nstdout: %.2000s", code, serr, out)
	}
	var rep model.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("scan JSON: %v\n%.2000s", err, out)
	}
	if rep.ExitCode != 2 {
		t.Errorf("report exit_code = %d, want 2", rep.ExitCode)
	}
	var found bool
	for _, f := range rep.Findings {
		if f.Key == "heur.module:labmod" {
			found = true
			if f.Severity != model.SevBackdoor {
				t.Errorf("heur.module:labmod severity = %v, want %v", f.Severity, model.SevBackdoor)
			}
		}
	}
	if !found {
		keys := make([]string, 0, len(rep.Findings))
		for _, f := range rep.Findings {
			keys = append(keys, f.Key)
		}
		t.Fatalf("no heur.module:labmod finding; findings: %v", keys)
	}

	// The raw collection: the kernel command line, the module and the
	// firewall, which only a real kernel can answer.
	out, serr, code = m.ssh(10*time.Minute, "sudo /tmp/telltale collect")
	if code != 0 {
		t.Fatalf("collect exit code = %d: %s", code, serr)
	}
	var c model.Collection
	if err := json.Unmarshal([]byte(out), &c); err != nil {
		t.Fatalf("collect JSON: %v", err)
	}
	if c.Runtime.Cmdline == "" {
		t.Error("Runtime.Cmdline is empty")
	}
	if c.Runtime.SharedKernel {
		t.Error("the VM was taken for a container (Runtime.SharedKernel)")
	}
	var mod bool
	for _, km := range c.Runtime.Modules {
		mod = mod || km.Name == "labmod"
	}
	if !mod {
		t.Error("labmod is not in Runtime.Modules")
	}

	// The firewall reader ran for real: not skipped for lack of privilege,
	// and TT-FW-001 reads the ruleset that cloud-init loaded.
	for _, s := range c.Skipped {
		if s.Check == "firewall" || strings.Contains(s.Reason, "operation not permitted") {
			t.Errorf("skipped: %s: %s", s.Check, s.Reason)
		}
	}
	if c.Firewall.Backend != "nftables" || c.Firewall.InputPolicy != "drop" || c.Firewall.InputRules == 0 {
		t.Errorf("firewall = %+v, want nftables with input policy drop and input rules", c.Firewall)
	}
	var fw *model.CheckResult
	for _, r := range checklist.Evaluate(&c, model.ScanContext{}) {
		if r.ID == "TT-FW-001" {
			r := r
			fw = &r
		}
	}
	switch {
	case fw == nil:
		t.Error("TT-FW-001 was not evaluated")
	case fw.Skipped != "":
		t.Errorf("TT-FW-001 skipped: %s", fw.Skipped)
	case !fw.Pass || !strings.Contains(fw.Observed, "input policy drop"):
		t.Errorf("TT-FW-001 = %+v, want a pass that reads the input policy drop", *fw)
	}
	t.Logf("scan and collect took %s", time.Since(start).Round(time.Second))
}
