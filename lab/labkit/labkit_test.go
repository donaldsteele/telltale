//go:build lab

package labkit_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/donaldsteele/telltale/lab/labkit"
)

var wantOS = map[string][2]string{
	"debian12":   {"debian", "12"},
	"debian13":   {"debian", "13"},
	"ubuntu2204": {"ubuntu", "22.04"},
	"ubuntu2404": {"ubuntu", "24.04"},
}

func TestCleanMachinesBoot(t *testing.T) {
	for _, distro := range labkit.Distros {
		t.Run(distro, func(t *testing.T) {
			t.Parallel()
			m := labkit.Start(t, labkit.Build(t, distro, "clean"), labkit.Opts{})
			out, code := m.Exec(t, "ss", "-ltn")
			if code != 0 || !strings.Contains(out, ":22 ") {
				t.Fatalf("sshd not listening on 22 (exit %d):\n%s", code, out)
			}
			out, _ = m.Exec(t, "sh", "-c", ". /etc/os-release; echo $ID $VERSION_ID")
			want := wantOS[distro]
			if got := strings.TrimSpace(out); got != want[0]+" "+want[1] {
				t.Fatalf("os-release = %q, want %q", got, want[0]+" "+want[1])
			}
			if out, _ := m.Exec(t, "sh", "-c", "pgrep -x cron >/dev/null && echo yes"); strings.TrimSpace(out) != "yes" {
				t.Fatalf("cron not running")
			}
			if m.IP() == "" {
				t.Fatalf("no IP on the lab network")
			}
		})
	}
}

func TestLabNetworkHasNoRouteOut(t *testing.T) {
	m := labkit.Start(t, labkit.Build(t, "debian12", "clean"), labkit.Opts{})
	if _, code := m.Exec(t, "getent", "hosts", "deb.debian.org"); code == 0 {
		t.Fatalf("deb.debian.org resolved from inside the lab network")
	}
	start := time.Now()
	_, code := m.Exec(t, "timeout", "3", "bash", "-c", "exec 3<>/dev/tcp/1.1.1.1/443")
	if code == 0 {
		t.Fatalf("connected to 1.1.1.1:443 from inside the lab network")
	}
	if d := time.Since(start); d > 6*time.Second {
		t.Fatalf("connect attempt took %v, want under 6s", d)
	}
	if !labkit.NetworkInternal(t) {
		t.Fatalf("telltale-lab network is not internal")
	}
}

func TestSinkReachableFromMachines(t *testing.T) {
	sink := labkit.StartSink(t)
	m := labkit.Start(t, labkit.Build(t, "debian12", "clean"), labkit.Opts{})
	for _, port := range []int{4444, 8443} {
		token := fmt.Sprintf("hello-%d-%d", port, time.Now().UnixNano())
		cmd := fmt.Sprintf("echo %s > /dev/tcp/%s/%d", token, sink.IP(), port)
		if _, code := m.Exec(t, "bash", "-c", cmd); code != 0 {
			t.Fatalf("connect to sink port %d failed", port)
		}
		if !sink.WaitFor(t, token, 5*time.Second) {
			t.Fatalf("sink never logged %q on port %d; log:\n%s", token, port, sink.Log(t))
		}
	}
	// Reachable by name as well.
	if _, code := m.Exec(t, "bash", "-c", "echo by-name > /dev/tcp/sink/4444"); code != 0 {
		t.Fatalf("sink not reachable by the name sink")
	}
}

func TestNoexecVariantRefusesExecInTmp(t *testing.T) {
	m := labkit.Start(t, labkit.Build(t, "debian12", "noexec"), labkit.Opts{Noexec: true})
	for _, dir := range []string{"/tmp", "/dev/shm"} {
		out, code := m.Exec(t, "sh", "-c", fmt.Sprintf("cp /bin/true %s/x && %s/x", dir, dir))
		if code == 0 {
			t.Fatalf("executed a binary from %s on a noexec mount: %s", dir, out)
		}
	}
	// Control: a normal directory still allows execution.
	if _, code := m.Exec(t, "sh", "-c", "cp /bin/true /var/tmp/x && /var/tmp/x"); code != 0 {
		t.Fatalf("exec from /var/tmp should work")
	}
}

func TestVariants(t *testing.T) {
	t.Run("hardened", func(t *testing.T) {
		t.Parallel()
		m := labkit.Start(t, labkit.Build(t, "debian12", "hardened"), labkit.Opts{})
		out, _ := m.Exec(t, "/usr/sbin/sshd", "-T")
		for _, want := range []string{"permitrootlogin no", "passwordauthentication no", "x11forwarding no", "maxauthtries 3"} {
			if !strings.Contains(out, want) {
				t.Errorf("sshd -T lacks %q", want)
			}
		}
	})
	t.Run("thirdparty", func(t *testing.T) {
		t.Parallel()
		m := labkit.Start(t, labkit.Build(t, "debian13", "thirdparty"), labkit.Opts{})
		if _, code := m.Exec(t, "sh", "-c", "test -x /usr/sbin/tailscaled && ls /etc/apt/sources.list.d/tailscale.list && ls /usr/share/keyrings/tailscale-archive-keyring.gpg"); code != 0 {
			t.Fatalf("tailscale source, key or package missing")
		}
	})
	t.Run("localsoft", func(t *testing.T) {
		t.Parallel()
		m := labkit.Start(t, labkit.Build(t, "ubuntu2404", "localsoft"), labkit.Opts{})
		out, code := m.Exec(t, "sh", "-c", "/usr/local/bin/lab-hello && stat -c '%a %U' /usr/local/sbin/lab-helper")
		if code != 0 || !strings.Contains(out, "4755 root") {
			t.Fatalf("local software wrong (exit %d): %s", code, out)
		}
	})
}

func TestExt4Volume(t *testing.T) {
	m := labkit.Start(t, labkit.Build(t, "debian12", "clean"), labkit.Opts{Ext4Volume: true})
	if out, _ := m.Exec(t, "stat", "-f", "-c", "%T", "/lab-ext4"); strings.TrimSpace(out) != "ext2/ext3" {
		t.Fatalf("/lab-ext4 is %q, want ext2/ext3 (ext4)", strings.TrimSpace(out))
	}
	if out, code := m.Exec(t, "sh", "-c", "touch /lab-ext4/f && chattr +i /lab-ext4/f"); code != 0 {
		t.Fatalf("chattr +i failed (exit %d): %s", code, out)
	}
	out, _ := m.Exec(t, "lsattr", "/lab-ext4/f")
	flags := strings.Fields(out)
	// Clear the flag first so cleanup can unmount and remove.
	m.Exec(t, "chattr", "-i", "/lab-ext4/f")
	if len(flags) < 1 || !strings.Contains(flags[0], "i") {
		t.Fatalf("lsattr shows no immutable flag: %q", out)
	}
}
