//go:build lab && vm

// Package vm runs the kernel checks that a container cannot exercise, because
// a container shares the host's kernel: loaded modules, the kernel command
// line and the live firewall. It boots a real Debian 12 machine in QEMU.
package vm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/donaldsteele/telltale/internal/checklist"
	"github.com/donaldsteele/telltale/internal/model"
)

const exitSkip = 77

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

// boot starts the VM with run.sh and registers its teardown before anything
// can fail: QEMU is stopped through run.sh, then through its pidfile, and the
// temporary directory is removed, whether the test passes, fails or panics.
func boot(t *testing.T) *machine {
	t.Helper()
	dir, err := os.MkdirTemp("", "telltale-vm-")
	if err != nil {
		t.Fatal(err)
	}
	m := &machine{t: t, dir: dir, key: filepath.Join(dir, "id_ed25519"), port: freePort(t)}
	runSh, err := filepath.Abs("run.sh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		exec.Command(runSh, "down", dir).Run()
		if b, err := os.ReadFile(filepath.Join(dir, "qemu.pid")); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && pid > 1 {
				if p, err := os.FindProcess(pid); err == nil {
					p.Kill()
				}
			}
		}
		if t.Failed() {
			if b, err := os.ReadFile(filepath.Join(dir, "console.log")); err == nil {
				tail := string(b)
				if len(tail) > 6000 {
					tail = tail[len(tail)-6000:]
				}
				t.Logf("VM console (tail):\n%s", tail)
			}
		}
		os.RemoveAll(dir)
	})

	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "telltale-lab", "-f", m.key).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v\n%s", err, out)
	}
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, runSh, "up", dir, m.key+".pub", strconv.Itoa(m.port))
	var errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = os.Stderr, &errb
	err = cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() == exitSkip {
		t.Skip(strings.TrimSpace(errb.String()))
	}
	if err != nil {
		t.Fatalf("run.sh up: %v\n%s", err, errb.String())
	}
	t.Logf("run.sh up took %s", time.Since(start).Round(time.Second))

	// SSH answers early; cloud-init then installs the packages and builds and
	// loads the module, so wait for it to finish as well.
	deadline := time.Now().Add(10 * time.Minute)
	for {
		if _, _, code := m.ssh(30*time.Second, "true"); code == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the VM did not accept SSH within 10 minutes")
		}
		time.Sleep(5 * time.Second)
	}
	t.Logf("ssh up after %s", time.Since(start).Round(time.Second))
	out, serr, code := m.ssh(25*time.Minute, "sudo cloud-init status --wait --long")
	t.Logf("cloud-init: %s%s (exit %d), %s", out, serr, code, time.Since(start).Round(time.Second))
	if _, _, ready := m.ssh(30*time.Second, "test -e /var/lib/telltale-lab-ready"); ready != 0 {
		t.Fatalf("cloud-init did not finish the lab setup (exit %d):\n%s", code, out)
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
	fmt.Fprintln(os.Stderr, "vm: total", time.Since(start).Round(time.Second))
}
