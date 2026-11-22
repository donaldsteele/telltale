package collect

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/donaldsteele/telltale/internal/diff"
	"github.com/donaldsteele/telltale/internal/heuristics"
	"github.com/donaldsteele/telltale/internal/model"
	"golang.org/x/sys/unix"
)

func plant(t *testing.T, root, mp string, mode os.FileMode) {
	t.Helper()
	p := filepath.Join(root, mp)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

func TestSweepFindsSetuidOutsideSystemPaths(t *testing.T) {
	root := t.TempDir()
	plant(t, root, "var/tmp/.s", os.ModeSetuid|0o755)
	plant(t, root, "var/tmp/plain", 0o755)
	plant(t, root, "opt/app/helper", os.ModeSetgid|0o755)
	plant(t, root, "usr/local/bin/mine", os.ModeSetuid|0o755)
	plant(t, root, "dev/shm/x", os.ModeSetuid|0o755)
	mounts := []model.Mount{
		{Path: "/", FSType: "ext4"},
		{Path: "/var/tmp", FSType: "ext4"},
		{Path: "/dev/shm", FSType: "tmpfs"},
		{Path: "/dev", FSType: "devtmpfs"},
	}
	// the system-path walk already holds /usr/local/bin/mine
	have, _ := Files(root, []string{"/usr"}, FileOptions{})
	got, skips := Sweep(root, mounts, have, FileOptions{MaxHashBytes: defaultMaxHash})
	m := byPath(got)
	for _, p := range []string{"/var/tmp/.s", "/opt/app/helper", "/dev/shm/x"} {
		e, ok := m[p]
		if !ok {
			t.Errorf("%s not swept; got %v (skips %v)", p, got, skips)
			continue
		}
		if e.Supplementary || e.SHA256 == "" || e.Type != "file" || e.Mode&0o6000 == 0 {
			t.Errorf("%s: %+v", p, e)
		}
	}
	for _, p := range []string{"/var/tmp/plain", "/usr/local/bin/mine"} {
		if _, ok := m[p]; ok {
			t.Errorf("%s must not be swept (plain or already collected)", p)
		}
	}
	if len(got) != 3 {
		t.Errorf("entries: %v", got)
	}

	// heuristics: /var/tmp/.s is a backdoor sign
	c := &model.Collection{Files: append(append([]model.FileEntry{}, have...), got...)}
	fs := heuristics.Run(c, model.ScanContext{}, map[string]string{})
	var sev model.Severity = -1
	for _, f := range fs {
		if f.Key == "heur.unowned_setuid:/var/tmp/.s" {
			sev = f.Severity
		}
	}
	if sev != model.SevBackdoor {
		t.Errorf("severity %v; findings %d", sev, len(fs))
	}
}

func TestSweepSkipsPseudoAndNetworkFS(t *testing.T) {
	root := t.TempDir()
	types := []string{"proc", "sysfs", "devtmpfs", "devpts", "cgroup", "cgroup2", "securityfs", "debugfs", "tracefs", "bpf", "pstore", "configfs", "autofs", "efivarfs", "mqueue", "binfmt_misc", "nfs", "nfs4", "cifs", "smb3", "fuse", "fuse.sshfs", "fusectl"}
	mounts := []model.Mount{{Path: "/", FSType: "ext4"}}
	for i, ft := range types {
		mp := fmt.Sprintf("/mnt/m%d", i)
		plant(t, root, mp+"/hidden", os.ModeSetuid|0o755)
		mounts = append(mounts, model.Mount{Path: mp, FSType: ft})
	}
	// a local filesystem next to them is walked
	plant(t, root, "mnt/local/ok", os.ModeSetuid|0o755)
	mounts = append(mounts, model.Mount{Path: "/mnt/local", FSType: "xfs"})
	// a local mount nested under a pseudo one is still walked
	plant(t, root, "mnt/m0/inner/deep", os.ModeSetuid|0o755)
	mounts = append(mounts, model.Mount{Path: "/mnt/m0/inner", FSType: "tmpfs"})

	got, _ := Sweep(root, mounts, nil, FileOptions{})
	m := byPath(got)
	for p := range m {
		if strings.HasSuffix(p, "/hidden") {
			t.Errorf("descended into a pseudo or network mount: %s", p)
		}
	}
	if _, ok := m["/mnt/local/ok"]; !ok {
		t.Errorf("local mount not walked: %v", got)
	}
	if _, ok := m["/mnt/m0/inner/deep"]; !ok {
		t.Errorf("tmpfs under a pseudo mount not walked: %v", got)
	}
}

func TestSweepCapabilityXattr(t *testing.T) {
	root := t.TempDir()
	plant(t, root, "var/tmp/cap", 0o755)
	plant(t, root, "var/tmp/nocap", 0o755)
	// a minimal v1 security.capability value (cap_net_raw in the permitted set)
	val := []byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if err := unix.Lsetxattr(filepath.Join(root, "var/tmp/cap"), "security.capability", val, 0); err != nil {
		t.Skipf("security.capability xattr cannot be set here: %v", err)
	}
	got, _ := Sweep(root, []model.Mount{{Path: "/", FSType: "ext4"}}, nil, FileOptions{})
	m := byPath(got)
	e, ok := m["/var/tmp/cap"]
	if !ok || e.Caps == "" || e.Supplementary {
		t.Fatalf("capability file: %v", got)
	}
	if _, ok := m["/var/tmp/nocap"]; ok {
		t.Error("file without capabilities swept")
	}
	fs := heuristics.Run(&model.Collection{Files: got}, model.ScanContext{}, map[string]string{})
	found := false
	for _, f := range fs {
		if f.Key == "heur.unowned_caps:/var/tmp/cap" && f.Severity == model.SevBackdoor {
			found = true
		}
	}
	if !found {
		t.Errorf("no unowned_caps finding")
	}
}

func TestSweepEntriesDiffNormally(t *testing.T) {
	root := t.TempDir()
	mounts := []model.Mount{{Path: "/", FSType: "ext4"}}
	before, _ := Sweep(root, mounts, nil, FileOptions{})
	old := &model.Snapshot{Collection: &model.Collection{Files: before}}
	plant(t, root, "var/tmp/.s", os.ModeSetuid|0o755)
	after, _ := Sweep(root, mounts, nil, FileOptions{})
	cs := diff.Compare(old, &model.Collection{Files: after}, nil)
	found := false
	for _, c := range cs {
		if c.Kind == diff.FileAdded && c.Subject == "/var/tmp/.s" {
			found = true
		}
	}
	if !found {
		t.Errorf("no file_added: %+v", cs)
	}
}

func TestSweepBoundsAndRecordsSkips(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 20; i++ {
		plant(t, root, fmt.Sprintf("srv/d/f%02d", i), 0o755)
	}
	old := sweepMaxEntries
	sweepMaxEntries = 10
	defer func() { sweepMaxEntries = old }()
	_, skips := Sweep(root, []model.Mount{{Path: "/", FSType: "ext4"}}, nil, FileOptions{})
	found := false
	for _, s := range skips {
		if s.Check == checkName && strings.Contains(s.Reason, "stopped after") {
			found = true
		}
	}
	if !found {
		t.Errorf("no bound skip: %v", skips)
	}
}

func TestSweepUnreadableDirIsOneSkip(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads everything")
	}
	root := t.TempDir()
	plant(t, root, "srv/locked/a", os.ModeSetuid|0o755)
	plant(t, root, "srv/locked/sub/b", os.ModeSetuid|0o755)
	plant(t, root, "srv/open/c", os.ModeSetuid|0o755)
	if err := os.Chmod(filepath.Join(root, "srv/locked"), 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(filepath.Join(root, "srv/locked"), 0o755)
	got, skips := Sweep(root, []model.Mount{{Path: "/", FSType: "ext4"}}, nil, FileOptions{})
	if _, ok := byPath(got)["/srv/open/c"]; !ok {
		t.Errorf("readable dir lost: %v", got)
	}
	n := 0
	for _, s := range skips {
		if strings.Contains(s.Reason, "/srv/locked") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("want one skip for the locked directory, got %d: %v", n, skips)
	}
}

func TestSweepSkipsImageStoresAndImageFilesystems(t *testing.T) {
	root := t.TempDir()
	plant(t, root, "var/lib/docker/overlay2/abc/diff/usr/bin/su", os.ModeSetuid|0o755)
	plant(t, root, "snap/core/1/usr/bin/sudo", os.ModeSetuid|0o755)
	plant(t, root, "mnt/img/usr/bin/su", os.ModeSetuid|0o755)
	plant(t, root, "srv/real", os.ModeSetuid|0o755)
	mounts := []model.Mount{{Path: "/", FSType: "ext4"}, {Path: "/mnt/img", FSType: "squashfs"}, {Path: "/var/lib/docker", FSType: "ext4"}}
	got, skips := Sweep(root, mounts, nil, FileOptions{})
	if m := byPath(got); len(m) != 1 || m["/srv/real"].Path == "" {
		t.Errorf("got %v", got)
	}
	noted := false
	for _, s := range skips {
		noted = noted || strings.Contains(s.Reason, "/var/lib/docker")
	}
	if !noted {
		t.Errorf("image store skip not recorded: %v", skips)
	}
}

func TestSweepReachesTempDirsBeforeTheBoundRunsOut(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 30; i++ {
		plant(t, root, fmt.Sprintf("aaa/f%02d", i), 0o644)
		plant(t, root, fmt.Sprintf("home/u/f%02d", i), 0o644)
	}
	plant(t, root, "var/tmp/.s", os.ModeSetuid|0o755)
	plant(t, root, "home/u/z", os.ModeSetuid|0o755)
	old := sweepMaxEntries
	sweepMaxEntries = 15
	defer func() { sweepMaxEntries = old }()
	got, _ := Sweep(root, []model.Mount{{Path: "/", FSType: "ext4"}}, nil, FileOptions{})
	if _, ok := byPath(got)["/var/tmp/.s"]; !ok {
		t.Errorf("/var/tmp not reached: %v", got)
	}
}
