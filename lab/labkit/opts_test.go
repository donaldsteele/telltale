//go:build lab

package labkit

import "testing"

func TestTmpfsOnOtherOptionsDirsRefused(t *testing.T) {
	for _, tc := range []struct {
		opts Opts
		ok   bool
	}{
		{Opts{Tmpfs: []string{"/var/tmp:noexec", "/run:noexec"}}, true},
		{Opts{Tmpfs: []string{"/tmp:noexec"}}, false},
		{Opts{Tmpfs: []string{"/tmp/"}}, false},
		{Opts{Tmpfs: []string{"/dev/shm:exec"}}, false},
		{Opts{Tmpfs: []string{"/run:noexec"}, Systemd: true}, false},
		{Opts{Tmpfs: []string{"/var/tmp"}, Systemd: true}, true},
	} {
		if err := checkTmpfs(tc.opts); (err == nil) != tc.ok {
			t.Errorf("checkTmpfs(%+v) = %v, want ok %v", tc.opts, err, tc.ok)
		}
	}
}
