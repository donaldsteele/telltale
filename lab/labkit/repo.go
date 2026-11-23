//go:build lab

package labkit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// The lab's signed third-party APT repository (lab/repo): lab-vendor 1.0 and
// 2.0, signed with a key generated when the image is built. Machines of the
// thirdparty variant have it in their APT sources under RepoURL, with the
// key in a signed-by keyring, and install lab-vendor from it.
const (
	// RepoHost is the name the repository has on the lab network.
	RepoHost = "telltale-lab-repo"
	// RepoSwappedHost serves the same repository signed with another key.
	RepoSwappedHost = "telltale-lab-repo-swapped"
	// RepoURL is the repository's address in a machine's APT sources.
	RepoURL = "http://" + RepoHost + "/lab-vendor"
)

var (
	repoMu    sync.Mutex
	repoTag   string
	repoID    string
	repoErr   error
	repoBuilt bool
)

// RepoImage builds (or reuses) the repository image and returns its tag,
// telltale-lab/repo:<hash of inputs>, and its image ID. The ID changes with
// every build, because the signing keys are generated in it: whatever holds a
// copy of the repository's key depends on the ID, not on the tag.
func RepoImage() (tag, id string, err error) {
	repoMu.Lock()
	defer repoMu.Unlock()
	if repoBuilt {
		return repoTag, repoID, repoErr
	}
	repoBuilt = true
	repoTag, repoID, repoErr = buildRepoImage()
	return repoTag, repoID, repoErr
}

func buildRepoImage() (string, string, error) {
	src := filepath.Join(labDir, "repo")
	var files []string
	for _, pat := range []string{"Dockerfile", "build.sh", "server/*.go", "vendord/*.go"} {
		m, err := filepath.Glob(filepath.Join(src, pat))
		if err != nil {
			return "", "", err
		}
		files = append(files, m...)
	}
	sort.Strings(files)
	h := sha256.New()
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return "", "", err
		}
		rel, _ := filepath.Rel(src, f)
		fmt.Fprintf(h, "%s\x00%d\x00", rel, len(data))
		h.Write(data)
	}
	tag := "telltale-lab/repo:" + hex.EncodeToString(h.Sum(nil))[:12]
	imageID := func() string {
		out, _, code := docker("image", "inspect", "--format", "{{.Id}}", tag)
		if code != 0 {
			return ""
		}
		return strings.TrimSpace(out)
	}
	if id := imageID(); id != "" {
		return tag, id, nil
	}
	dir, err := os.MkdirTemp("", "telltale-lab-repo")
	if err != nil {
		return "", "", err
	}
	defer os.RemoveAll(dir)
	for bin, pkg := range map[string]string{"repo-server": "server", "lab-vendord": "vendord"} {
		cmd := exec.Command("go", "build", "-tags", "lab", "-trimpath", "-ldflags", "-s -w", "-o", filepath.Join(dir, bin), filepath.Join(src, pkg))
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
		if out, err := cmd.CombinedOutput(); err != nil {
			return "", "", fmt.Errorf("build %s: %v\n%s", bin, err, out)
		}
	}
	for _, f := range []string{"Dockerfile", "build.sh"} {
		data, err := os.ReadFile(filepath.Join(src, f))
		if err != nil {
			return "", "", err
		}
		if err := os.WriteFile(filepath.Join(dir, f), data, 0o755); err != nil {
			return "", "", err
		}
	}
	start := time.Now()
	if so, se, code := docker("build", "-q", "--label", Label, "-t", tag, dir); code != 0 {
		return "", "", fmt.Errorf("docker build %s: exit %d\n%s%s", tag, code, so, se)
	}
	fmt.Fprintf(os.Stderr, "lab: built %s in %v\n", tag, time.Since(start).Round(time.Second))
	id := imageID()
	if id == "" {
		return "", "", fmt.Errorf("%s was built but cannot be inspected", tag)
	}
	return tag, id, nil
}

// withBuildRepo runs the repository on Docker's default network for the time
// of an image build, which happens there (apt needs the internet), and calls
// fn with its address. The variant's build reaches it by name through
// "docker build --add-host".
func withBuildRepo(t testing.TB, fn func(ip string)) {
	t.Helper()
	tag, _, err := RepoImage()
	if err != nil {
		t.Fatalf("repository image: %v", err)
	}
	name := "telltale-lab-repo-build-" + randHex()
	defer docker("rm", "-f", name)
	mustDocker(t, "run", "-d", "--name", name, "--label", Label, tag)
	out := mustDocker(t, "inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", name)
	ips := strings.Fields(out)
	if len(ips) == 0 {
		t.Fatalf("%s has no address on the default network", name)
	}
	fn(ips[0])
}

// Repo is the running repository: one server signed with the vendor's key
// and one with the replacement key.
type Repo struct {
	name, swapped string
}

// StartRepo starts the repository's two servers on the lab network, under
// the names RepoHost and RepoSwappedHost. They are not tied to a test: start
// them once per run; Reap removes them.
func StartRepo(t testing.TB) *Repo {
	t.Helper()
	ensureNetwork(t)
	tag, _, err := RepoImage()
	if err != nil {
		t.Fatalf("repository image: %v", err)
	}
	r := &Repo{name: "telltale-lab-repo-" + randHex(), swapped: "telltale-lab-repo-swapped-" + randHex()}
	mustDocker(t, "run", "-d", "--name", r.name, "--network", NetworkName, "--network-alias", RepoHost, "--label", Label, tag, "-tree", "a")
	mustDocker(t, "run", "-d", "--name", r.swapped, "--network", NetworkName, "--network-alias", RepoSwappedHost, "--label", Label, tag, "-tree", "b")
	return r
}

// IP is the address of the server signed with the vendor's key; SwappedIP of
// the one signed with the replacement key.
func (r *Repo) IP() string        { return containerIP(r.name, NetworkName) }
func (r *Repo) SwappedIP() string { return containerIP(r.swapped, NetworkName) }

// Log returns what both servers have logged.
func (r *Repo) Log() string {
	a, ae, _ := docker("logs", r.name)
	b, be, _ := docker("logs", r.swapped)
	return a + ae + b + be
}
