//go:build lab

package labkit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// MinFreeBytes is the free space the Docker root must have for the lab to run.
const MinFreeBytes = 3 << 30

// Main runs a lab test binary. It holds a host-wide lock (lab packages never
// run side by side, so the clean-up below cannot hit a running test), skips
// everything when the Docker root is short of space, removes what an earlier
// killed run left behind, runs the tests, and leaves no container or network.
// Only objects labelled telltale-lab=1 are ever removed.
func Main(m *testing.M) int {
	unlock, err := lockHost()
	if err != nil {
		fmt.Fprintln(os.Stderr, "lab: cannot take the lab lock:", err)
		return 1
	}
	defer unlock()
	free, root, err := DockerFree()
	if err != nil {
		fmt.Fprintln(os.Stderr, "lab: SKIP: Docker is not usable here:", err)
		return 0
	}
	if free < MinFreeBytes {
		fmt.Fprintf(os.Stderr, "lab: SKIP: %s has %.1f GB free; the lab needs at least %d GB. Nothing was run.\n",
			root, float64(free)/(1<<30), MinFreeBytes>>30)
		return 0
	}
	Reap()
	stop := watchDisk()
	code := m.Run()
	low := stop()
	Reap()
	for _, d := range Distros {
		ReleaseImages(d)
	}
	fmt.Fprintf(os.Stderr, "lab: Docker root free space: %.2f GB at the start, %.2f GB at the lowest point (other users of the disk included)\n",
		float64(free)/(1<<30), float64(low)/(1<<30))
	return code
}

// lockHost takes an exclusive lock on a file in the user's cache directory
// and waits for another lab run to finish first.
func lockHost() (func(), error) {
	f, err := os.OpenFile(filepath.Join(CacheDir(), "lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { f.Close() }, nil
}

// CacheDir is the lab's cache outside the repository (reference bundles and
// the lock file): $TELLTALE_LAB_CACHE or <user cache dir>/telltale-lab.
func CacheDir() string {
	dir := os.Getenv("TELLTALE_LAB_CACHE")
	if dir == "" {
		base, err := os.UserCacheDir()
		if err != nil {
			base = os.TempDir()
		}
		dir = filepath.Join(base, "telltale-lab")
	}
	_ = os.MkdirAll(dir, 0o755)
	return dir
}

// DockerFree returns the free bytes on the filesystem holding Docker's root
// directory, and that directory.
func DockerFree() (uint64, string, error) {
	out, se, code := docker("info", "--format", "{{.DockerRootDir}}")
	root := strings.TrimSpace(out)
	if code != 0 || root == "" {
		return 0, "", fmt.Errorf("docker info: %s", strings.TrimSpace(se))
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(root, &st); err != nil {
		return 0, root, fmt.Errorf("statfs %s: %w", root, err)
	}
	return st.Bavail * uint64(st.Bsize), root, nil
}

// RequireFree skips the test when the Docker root is short of space.
func RequireFree(t testing.TB) {
	t.Helper()
	if free, root, err := DockerFree(); err == nil && free < MinFreeBytes {
		t.Skipf("%s has %.1f GB free; the lab needs at least %d GB", root, float64(free)/(1<<30), MinFreeBytes>>30)
	}
}

// ReleaseImages is RemoveImages unless TELLTALE_LAB_KEEP_IMAGES=1 asks to keep
// the images for the next run.
func ReleaseImages(distro string) {
	if os.Getenv("TELLTALE_LAB_KEEP_IMAGES") != "1" {
		RemoveImages(distro)
	}
}

// Reap removes the containers, volumes and networks labelled telltale-lab=1,
// and nothing else. Images stay: they are a cache (see RemoveImages).
func Reap() {
	if out, _, _ := docker("ps", "-aq", "--filter", "label="+Label); strings.TrimSpace(out) != "" {
		docker(append([]string{"rm", "-f", "-v"}, strings.Fields(out)...)...)
	}
	if out, _, _ := docker("volume", "ls", "-q", "--filter", "label="+Label); strings.TrimSpace(out) != "" {
		docker(append([]string{"volume", "rm", "-f"}, strings.Fields(out)...)...)
	}
	if out, _, _ := docker("network", "ls", "-q", "--filter", "label="+Label); strings.TrimSpace(out) != "" {
		docker(append([]string{"network", "rm"}, strings.Fields(out)...)...)
	}
	netMu.Lock()
	netReady, egressReady = false, false
	netMu.Unlock()
}

// watchDisk samples the Docker root's free space until stopped and returns
// the lowest value seen.
func watchDisk() func() uint64 {
	var low atomic.Uint64
	low.Store(^uint64(0))
	sample := func() {
		if free, _, err := DockerFree(); err == nil && free < low.Load() {
			low.Store(free)
		}
	}
	sample()
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-done:
				return
			case <-tick.C:
				sample()
			}
		}
	}()
	return func() uint64 {
		close(done)
		wg.Wait()
		sample()
		return low.Load()
	}
}
