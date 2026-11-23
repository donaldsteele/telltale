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
		plant(t, root, fmt.Sprintf("data/d/f%02d", i), 0o644)
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

func TestSweepOverlayRootIsSearched(t *testing.T) {
	// a container or lab machine: the root filesystem is overlay
	root := t.TempDir()
	plant(t, root, "var/tmp/.s", os.ModeSetuid|0o755)
	got, _ := Sweep(root, []model.Mount{{Path: "/", FSType: "overlay"}}, nil, FileOptions{})
	if _, ok := byPath(got)["/var/tmp/.s"]; !ok {
		t.Errorf("overlay root not searched: %v", got)
	}
	// even a squashfs root (a live system) is the system being examined
	got, _ = Sweep(root, []model.Mount{{Path: "/", FSType: "squashfs"}}, nil, FileOptions{})
	if _, ok := byPath(got)["/var/tmp/.s"]; !ok {
		t.Errorf("root mount skipped by type: %v", got)
	}
}

func TestSweepSkipsOverlayUnderImageStoreAndSquashfsUnderSnap(t *testing.T) {
	root := t.TempDir()
	plant(t, root, "var/lib/docker/overlay2/x/merged/usr/bin/su", os.ModeSetuid|0o755)
	plant(t, root, "var/lib/containerd/io/y/usr/bin/su", os.ModeSetuid|0o755)
	plant(t, root, "snap/core22/1/usr/bin/sudo", os.ModeSetuid|0o755)
	plant(t, root, "home/u/.local/share/containers/storage/overlay/z/usr/bin/su", os.ModeSetuid|0o755)
	plant(t, root, "opt/real", os.ModeSetuid|0o755)
	mounts := []model.Mount{
		{Path: "/", FSType: "ext4"},
		{Path: "/var/lib/docker/overlay2/x/merged", FSType: "overlay"},
		{Path: "/snap/core22/1", FSType: "squashfs"},
	}
	got, _ := Sweep(root, mounts, nil, FileOptions{})
	if m := byPath(got); len(m) != 1 || m["/opt/real"].Path == "" {
		t.Errorf("got %v", got)
	}
	// an overlay mount elsewhere (not an image store) is searched
	plant(t, root, "srv/ov/.s", os.ModeSetuid|0o755)
	got, _ = Sweep(root, append(mounts, model.Mount{Path: "/srv/ov", FSType: "overlay"}), nil, FileOptions{})
	if _, ok := byPath(got)["/srv/ov/.s"]; !ok {
		t.Errorf("ordinary overlay mount skipped: %v", got)
	}
}

func TestSweepSkipsSnapshotAndChrootStores(t *testing.T) {
	root := t.TempDir()
	for _, p := range []string{
		"run/containerd/io.containerd.runtime.v2.task/k8s.io/abc/rootfs/usr/bin/su",
		"run/docker/netns/x",
		"var/lib/kubelet/pods/p1/volumes/v/su",
		"var/snap/lxd/common/lxd/storage-pools/default/containers/c1/rootfs/usr/bin/su",
		"var/lib/rancher/k3s/agent/containerd/snapshots/1/fs/usr/bin/su",
		"timeshift/snapshots/2026-11-01_00-00-01/localhost/usr/bin/sudo",
		".snapshots/1/snapshot/usr/bin/su",
		"var/cache/pbuilder/base.cow/usr/bin/su",
		"srv/chroot/sid/usr/bin/su",
	} {
		plant(t, root, p, os.ModeSetuid|0o755)
	}
	// /snap and /var/lib/snapd are not hiding places
	plant(t, root, "snap/.s", os.ModeSetuid|0o755)
	plant(t, root, "var/lib/snapd/.s", os.ModeSetuid|0o755)
	plant(t, root, "srv/real", os.ModeSetuid|0o755)
	plant(t, root, "media/u/Win/x", os.ModeSetuid|0o755)
	mounts := []model.Mount{
		{Path: "/", FSType: "ext4"},
		{Path: "/run", FSType: "tmpfs"},
		{Path: "/run/containerd/io.containerd.runtime.v2.task/k8s.io/abc/rootfs", FSType: "overlay"},
		{Path: "/.snapshots", FSType: "btrfs"},
		{Path: "/media/u/Win", FSType: "fuseblk"},
	}
	got, _ := Sweep(root, mounts, nil, FileOptions{})
	m := byPath(got)
	for _, p := range []string{"/snap/.s", "/var/lib/snapd/.s", "/srv/real"} {
		if _, ok := m[p]; !ok {
			t.Errorf("%s missing: %v", p, got)
		}
	}
	if len(m) != 3 {
		t.Errorf("stores were searched: %v", got)
	}
	if !sweepSkipType("fuseblk") {
		t.Error("fuseblk not skipped by type")
	}
}

func TestSweepEachPriorityDirHasItsOwnBudget(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 40; i++ {
		plant(t, root, fmt.Sprintf("tmp/.x/f%02d", i), 0o644)
	}
	plant(t, root, "tmp/.x/zz", os.ModeSetuid|0o755)
	plant(t, root, "var/tmp/.s", os.ModeSetuid|0o755)
	old, oldMax := sweepFirstBudget, sweepMaxEntries
	sweepFirstBudget = 10
	defer func() { sweepFirstBudget, sweepMaxEntries = old, oldMax }()
	got, skips := Sweep(root, []model.Mount{{Path: "/", FSType: "ext4"}}, nil, FileOptions{})
	if _, ok := byPath(got)["/var/tmp/.s"]; !ok {
		t.Errorf("/var/tmp starved by /tmp: %v", got)
	}
	noted := false
	for _, s := range skips {
		noted = noted || (strings.Contains(s.Reason, "/tmp: stopped after 10 entries"))
	}
	if !noted {
		t.Errorf("budget skip not recorded: %v", skips)
	}
}

func TestSweepMountsAndMediaAreWalkedLast(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 30; i++ {
		plant(t, root, fmt.Sprintf("mnt/d/f%02d", i), 0o644)
	}
	plant(t, root, "var/tmp/.s", os.ModeSetuid|0o755)
	old := sweepMaxEntries
	sweepMaxEntries = 15
	defer func() { sweepMaxEntries = old }()
	got, _ := Sweep(root, []model.Mount{{Path: "/", FSType: "ext4"}}, nil, FileOptions{})
	if _, ok := byPath(got)["/var/tmp/.s"]; !ok {
		t.Errorf("late group walked early: %v", got)
	}
}

func TestSweepIsStableWhenTmpGrows(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 5; i++ {
		plant(t, root, fmt.Sprintf("tmp/f%02d", i), 0o644)
	}
	plant(t, root, "var/tmp/.s", os.ModeSetuid|0o755)
	for i := 0; i < 10; i++ {
		plant(t, root, fmt.Sprintf("home/a/f%02d", i), 0o644)
	}
	plant(t, root, "home/z/.s", os.ModeSetuid|0o755)
	ob, om := sweepFirstBudget, sweepMaxEntries
	sweepFirstBudget, sweepMaxEntries = 10, 24
	defer func() { sweepFirstBudget, sweepMaxEntries = ob, om }()
	m := []model.Mount{{Path: "/", FSType: "ext4"}}
	a, _ := Sweep(root, m, nil, FileOptions{})
	for i := 5; i < 9; i++ {
		plant(t, root, fmt.Sprintf("tmp/f%02d", i), 0o644)
	}
	b, _ := Sweep(root, m, nil, FileOptions{})
	for name, got := range map[string][]model.FileEntry{"first": a, "second": b} {
		if _, ok := byPath(got)["/home/z/.s"]; !ok {
			t.Errorf("%s scan lost /home/z/.s: %v", name, got)
		}
		for _, e := range got {
			if !e.Swept || e.Supplementary {
				t.Errorf("%s: entry flags: %+v", name, e)
			}
		}
	}
}

func TestSweepRecordsWhereItStoppedAndDiffIgnoresIt(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 30; i++ {
		plant(t, root, fmt.Sprintf("home/u/f%02d", i), 0o644)
	}
	plant(t, root, "home/u/zz-late", os.ModeSetuid|0o755)
	plant(t, root, "var/tmp/.s", os.ModeSetuid|0o755)
	old := sweepMaxEntries
	sweepMaxEntries = 10
	defer func() { sweepMaxEntries = old }()
	m := []model.Mount{{Path: "/", FSType: "ext4"}}
	got, _, incomplete := sweepFull(root, m, nil, FileOptions{})
	if len(incomplete) == 0 {
		t.Fatal("no incomplete region recorded")
	}
	covered := false
	for _, p := range incomplete {
		covered = covered || p == "/home/u/zz-late" || p == "/home/u" || strings.HasPrefix("/home/u/zz-late", p+"/")
	}
	if !covered || incompleteHas(incomplete, "/var/tmp") {
		t.Errorf("incomplete: %v", incomplete)
	}
	// An earlier snapshot that saw /home/u/zz-late; this scan did not reach it.
	e := model.FileEntry{Path: "/home/u/zz-late", Type: "file", Mode: 0o104755, Swept: true}
	oldSnap := &model.Snapshot{Collection: &model.Collection{Files: []model.FileEntry{e}}}
	cur := &model.Collection{Files: got, SweepIncomplete: incomplete}
	for _, c := range diff.Compare(oldSnap, cur, nil) {
		if c.Subject == "/home/u/zz-late" {
			t.Errorf("one-sided swept entry under an incomplete region reported: %+v", c)
		}
	}
	// and the reverse: now seen, but the old snapshot was incomplete there
	oldSnap = &model.Snapshot{Collection: &model.Collection{SweepIncomplete: []string{"/home/u"}}}
	cur = &model.Collection{Files: []model.FileEntry{e}}
	for _, c := range diff.Compare(oldSnap, cur, nil) {
		if c.Subject == "/home/u/zz-late" {
			t.Errorf("added entry under the old scan's incomplete region reported: %+v", c)
		}
	}
	// a complete scan still reports it
	oldSnap = &model.Snapshot{Collection: &model.Collection{}}
	found := false
	for _, c := range diff.Compare(oldSnap, &model.Collection{Files: []model.FileEntry{e}}, nil) {
		found = found || c.Subject == "/home/u/zz-late"
	}
	if !found {
		t.Error("complete scans no longer report added swept files")
	}
}

func incompleteHas(l []string, p string) bool {
	for _, x := range l {
		if x == p || strings.HasPrefix(x, p+"/") {
			return true
		}
	}
	return false
}

func TestSweepRealisticMountTableOnPAMEnsure(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"etc/pam.d", "dev/shm", "tmp", "run/user/1000", "opt"} {
		os.MkdirAll(filepath.Join(root, d), 0o755)
	}
	for _, f := range []string{"dev/shm/x.so", "tmp/y.so", "run/user/1000/z.so", "opt/o.so"} {
		os.WriteFile(filepath.Join(root, f), []byte(f), 0o644)
	}
	os.WriteFile(filepath.Join(root, "etc/pam.d/sshd"), []byte(strings.Join([]string{
		"auth optional /dev/shm/x.so", "auth optional /tmp/y.so", "auth optional /run/user/1000/z.so",
		"auth optional /opt/o.so", "auth optional /dev/zero", "auth optional /proc/kmsg",
	}, "\n")+"\n"), 0o644)
	mounts := []model.Mount{
		{Path: "/", FSType: "ext4"}, {Path: "/dev", FSType: "devtmpfs"}, {Path: "/dev/shm", FSType: "tmpfs"},
		{Path: "/tmp", FSType: "tmpfs"}, {Path: "/run", FSType: "tmpfs"}, {Path: "/run/user/1000", FSType: "tmpfs"},
	}
	persist, _ := Persistence(root, nil, []byte("k"))
	files, _ := ensurePAMEntries(root, nil, mounts, persist, defaultMaxHash)
	got := byPath(files)
	for _, p := range []string{"/dev/shm/x.so", "/tmp/y.so", "/run/user/1000/z.so", "/opt/o.so"} {
		if _, ok := got[p]; !ok {
			t.Errorf("%s not collected", p)
		}
	}
	for _, p := range []string{"/dev/zero", "/proc/kmsg"} {
		if _, ok := got[p]; ok {
			t.Errorf("%s must not be opened", p)
		}
	}
	// the nearest mount decides: /dev/shm is tmpfs, not the devtmpfs above it
	if underMountOf("/dev/shm/x.so", mounts, func(t string) bool { return t == "devtmpfs" }) {
		t.Error("judged by an ancestor mount")
	}
	if !underSkippedMount("/tmp/y.so", mounts) || underSkippedMount("/opt/o.so", mounts) {
		t.Error("ordinary scan rule changed")
	}
}

// A priority directory whose budget ran out is named, so the report can say
// so in a finding and not only among the skipped checks.
func TestSweepNamesFloodedDirectories(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 40; i++ {
		plant(t, root, fmt.Sprintf("tmp/.x/f%02d", i), 0o644)
	}
	plant(t, root, "var/tmp/.s", os.ModeSetuid|0o755)
	old := sweepFirstBudget
	sweepFirstBudget = 10
	defer func() { sweepFirstBudget = old }()
	_, _, _, flooded := sweepAll(root, []model.Mount{{Path: "/", FSType: "ext4"}}, nil, FileOptions{})
	if len(flooded) != 1 || flooded[0] != "/tmp" {
		t.Errorf("flooded = %v, want [/tmp]", flooded)
	}
	sweepFirstBudget = old
	if _, _, _, flooded := sweepAll(root, []model.Mount{{Path: "/", FSType: "ext4"}}, nil, FileOptions{}); len(flooded) != 0 {
		t.Errorf("flooded = %v within the budget", flooded)
	}
}
