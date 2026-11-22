//go:build lab

package lab

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

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
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

var wantOS = map[string][2]string{
	"debian12":   {"debian", "12"},
	"debian13":   {"debian", "13"},
	"ubuntu2204": {"ubuntu", "22.04"},
	"ubuntu2404": {"ubuntu", "24.04"},
}

func TestCollectInEveryCleanDistro(t *testing.T) {
	for _, distro := range labkit.Distros {
		t.Run(distro, func(t *testing.T) {
			t.Parallel()
			m := labkit.Start(t, labkit.Build(t, distro, "clean"), labkit.Opts{})
			m.CopyIn(t, binPath, "/usr/local/bin/telltale")
			m.Exec(t, "chmod", "755", "/usr/local/bin/telltale")
			_, code := m.Exec(t, "sh", "-c", "telltale collect > /tmp/c.json 2>/tmp/c.err")
			if code != 0 {
				errs, _ := m.Exec(t, "cat", "/tmp/c.err")
				t.Fatalf("collect exit %d: %s", code, errs)
			}
			js, _ := m.Exec(t, "cat", "/tmp/c.json")
			var c model.Collection
			if err := json.Unmarshal([]byte(js), &c); err != nil {
				t.Fatalf("parse: %v (len %d)", err, len(js))
			}
			if !c.AsRoot {
				t.Error("AsRoot false")
			}
			if len(c.Files) < 4000 {
				t.Errorf("files = %d, want >= 4000", len(c.Files))
			}
			if want := wantOS[distro]; c.Host.OSID != want[0] || c.Host.OSVersionID != want[1] {
				t.Errorf("os = %s %s, want %v", c.Host.OSID, c.Host.OSVersionID, want)
			}
			root := false
			for _, u := range c.Accounts.Users {
				root = root || u.Name == "root"
			}
			if !root {
				t.Error("no root user")
			}
			comm := map[int]string{}
			for _, p := range c.Runtime.Processes {
				comm[p.PID] = p.Comm
			}
			ssh := false
			for _, s := range c.Runtime.Sockets {
				if s.Listening && strings.HasSuffix(s.Local, ":22") && comm[s.PID] == "sshd" {
					ssh = true
				}
			}
			if !ssh {
				t.Errorf("no listening sshd socket on :22 (%d sockets)", len(c.Runtime.Sockets))
			}
			pkg := false
			for _, p := range c.Packages.Installed {
				pkg = pkg || p.Name == "openssh-server"
			}
			if !pkg {
				t.Error("no openssh-server package")
			}
		})
	}
}
