//go:build lab

package lab

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/lab/labkit"
)

var wantOS = map[string][2]string{
	"debian12":   {"debian", "12"},
	"debian13":   {"debian", "13"},
	"ubuntu2204": {"ubuntu", "22.04"},
	"ubuntu2404": {"ubuntu", "24.04"},
}

func TestCollectInEveryCleanDistro(t *testing.T) {
	eachDistro(t, func(t *testing.T, distro string) {
		t.Run("clean", func(t *testing.T) {
			slot(t)
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
	})
}
