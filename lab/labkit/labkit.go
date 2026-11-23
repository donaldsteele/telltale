//go:build lab

// Package labkit drives the Docker test lab: it builds the machine images,
// starts them on the isolated telltale-lab network and runs commands in them.
// It shells out to the docker CLI. Everything it creates is named telltale-lab*
// and nothing else on the host is touched.
package labkit

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// Distros are the lab's machine families; Variants the flavours of each.
var (
	Distros  = []string{"debian12", "debian13", "ubuntu2204", "ubuntu2404"}
	Variants = []string{"clean", "hardened", "noexec", "thirdparty", "localsoft"}
)

// NetworkName is the internal Docker network every lab container joins.
const NetworkName = "telltale-lab"

// EgressNetworkName is the lab's one network with a route out. Only machines
// with nothing planted may join it.
const EgressNetworkName = "telltale-lab-egress"

// Label marks every container, network, volume and image the lab creates.
const Label = "telltale-lab=1"

// Opts tunes how a machine is started.
type Opts struct {
	Noexec     bool     // /tmp and /dev/shm mounted noexec
	Privileged bool     // docker run --privileged
	Systemd    bool     // run /sbin/init as PID 1 (the image must contain systemd)
	Caps       []string // extra capabilities, e.g. "LINUX_IMMUTABLE"
	Ext4Volume bool     // loop-mounted ext4 image at /lab-ext4; implies Privileged (test skips if the mount fails)
	Hostname   string   // container hostname; default <distro>-<variant>
	// Egress puts the machine on the telltale-lab-egress network, which has a
	// route out, instead of the internal one. Only for machines with nothing
	// planted (the update-noise test needs the package archive).
	Egress bool
	// ExecShm mounts /dev/shm without noexec, as on a real machine (Docker's
	// own /dev/shm is noexec). Ignored with Noexec.
	ExecShm bool
	// Binds are extra read-only bind mounts, "hostdir:containerdir".
	Binds []string
	// Tmpfs are extra tmpfs mounts as docker run --tmpfs takes them,
	// "dir:options" (for example "/var/tmp:noexec"). Not /tmp or /dev/shm,
	// which Noexec and ExecShm own, nor /run with Systemd; Start refuses them.
	Tmpfs []string
}

// BuildOpts picks a flavour of an image.
type BuildOpts struct {
	Newer   bool // built at the *_NEWER package snapshot (then upgraded, with openssl installed)
	Systemd bool // systemd installed, for Opts.Systemd
}

// Machine is a running lab container.
type Machine struct {
	Name     string
	Image    string
	Hostname string
	// Egress is true when the machine has a route out (see Opts.Egress).
	Egress  bool
	network string
}

var (
	labDir      string
	buildMu     sync.Mutex
	built       = map[string]bool{}
	netMu       sync.Mutex
	netReady    bool
	egressReady bool
)

func init() {
	_, file, _, _ := runtime.Caller(0)
	labDir = filepath.Join(filepath.Dir(file), "..")
}

func randHex() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// docker runs the docker CLI and returns stdout, stderr and the exit code.
func docker(args ...string) (string, string, int) {
	cmd := exec.Command("docker", args...)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else {
			code = -1
			se.WriteString(err.Error())
		}
	}
	return so.String(), se.String(), code
}

func mustDocker(t testing.TB, args ...string) string {
	t.Helper()
	so, se, code := docker(args...)
	if code != 0 {
		t.Fatalf("docker %s: exit %d\n%s%s", strings.Join(args, " "), code, so, se)
	}
	return so
}

// ensureNetwork creates the internal lab network if it does not exist.
func ensureNetwork(t testing.TB) {
	t.Helper()
	netMu.Lock()
	defer netMu.Unlock()
	if netReady {
		return
	}
	createNetwork(t, NetworkName, true)
	if !NetworkInternal(t) {
		t.Fatalf("network %s exists but is not internal; refusing to use it", NetworkName)
	}
	netReady = true
}

// ensureEgressNetwork creates the lab's network with a route out.
func ensureEgressNetwork(t testing.TB) {
	t.Helper()
	netMu.Lock()
	defer netMu.Unlock()
	if egressReady {
		return
	}
	createNetwork(t, EgressNetworkName, false)
	egressReady = true
}

// createNetwork makes a labelled lab network. A network of that name without
// the label is not the lab's to use or to remove: the test fails and says so.
func createNetwork(t testing.TB, name string, internal bool) {
	t.Helper()
	if lbl, _, code := docker("network", "inspect", "--format", `{{index .Labels "telltale-lab"}}`, name); code == 0 {
		if strings.TrimSpace(lbl) == "1" {
			return
		}
		t.Fatalf("a Docker network named %s exists without the label %s, so the lab did not create it and will not touch it; remove or rename it (docker network rm %s) and run again", name, Label, name)
	}
	args := []string{"network", "create", "--label", Label}
	if internal {
		args = append(args, "--internal")
	}
	if _, se, code := docker(append(args, name)...); code != 0 && !strings.Contains(se, "already exists") {
		t.Fatalf("create network %s: %s", name, se)
	}
}

// NetworkInternal reports whether the lab network has no route out.
func NetworkInternal(t testing.TB) bool {
	t.Helper()
	out := mustDocker(t, "network", "inspect", "--format", "{{.Internal}}", NetworkName)
	return strings.TrimSpace(out) == "true"
}

// stageContext assembles a build context (Dockerfile, common/, variant.sh) in
// dir and returns a hash of its contents. variantNote, when not empty, is
// appended to variant.sh as a comment: it makes the image, its tag and
// Docker's cached layer of the variant step depend on something outside the
// lab's files.
func stageContext(dir, distro, variant, variantNote string) (string, error) {
	h := sha256.New()
	add := func(src, dst string) error {
		data, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		if dst == "variant.sh" && variantNote != "" {
			data = append(data, []byte("\n# "+variantNote+"\n")...)
		}
		fmt.Fprintf(h, "%s\x00%d\x00", dst, len(data))
		h.Write(data)
		out := filepath.Join(dir, dst)
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			return err
		}
		return os.WriteFile(out, data, 0o755)
	}
	if err := add(filepath.Join(labDir, "images", distro, "Dockerfile"), "Dockerfile"); err != nil {
		return "", err
	}
	if err := add(filepath.Join(labDir, "variants", variant+".sh"), "variant.sh"); err != nil {
		return "", err
	}
	var files []string
	common := filepath.Join(labDir, "images", "common")
	err := filepath.WalkDir(common, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			files = append(files, p)
		}
		return err
	})
	if err != nil {
		return "", err
	}
	sort.Strings(files)
	for _, f := range files {
		rel, _ := filepath.Rel(common, f)
		if err := add(f, filepath.Join("common", rel)); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil))[:12], nil
}

// Build builds (or reuses) the image for a distro and variant and returns its
// tag, telltale-lab/<distro>-<variant>:<hash of inputs>.
func Build(t testing.TB, distro, variant string) string {
	t.Helper()
	return BuildWith(t, distro, variant, BuildOpts{})
}

// BuildWith is Build for a flavour of the image; the flavour is part of the
// tag (telltale-lab/<distro>-<variant>-newer:<hash>, ...-systemd:<hash>).
func BuildWith(t testing.TB, distro, variant string, bo BuildOpts) string {
	t.Helper()
	if !contains(Distros, distro) || !contains(Variants, variant) {
		t.Fatalf("unknown distro %q or variant %q", distro, variant)
	}
	usesRepo := variant == "thirdparty"
	note := ""
	if usesRepo {
		// The image holds the repository's public key and a package
		// installed from it, so it belongs to one build of the repository
		// image: the keys are made anew with each.
		_, id, err := RepoImage()
		if err != nil {
			t.Fatalf("repository image: %v", err)
		}
		note = "built against the lab repository image " + id
	}
	dir := t.TempDir()
	hash, err := stageContext(dir, distro, variant, note)
	if err != nil {
		t.Fatalf("stage build context: %v", err)
	}
	name := distro + "-" + variant
	args := []string{"build", "-q", "--label", Label, "--build-arg", "VARIANT=" + variant}
	if bo.Newer {
		name += "-newer"
		args = append(args, "--build-arg", "LAB_NEWER=1")
	}
	if bo.Systemd {
		name += "-systemd"
		args = append(args, "--build-arg", "LAB_SYSTEMD=1")
	}
	tag := fmt.Sprintf("telltale-lab/%s:%s", name, hash)
	buildMu.Lock()
	defer buildMu.Unlock()
	if built[tag] {
		return tag
	}
	if _, _, code := docker("image", "inspect", tag); code != 0 {
		build := func(extra ...string) {
			start := time.Now()
			so, se, code := docker(append(append(args, extra...), "-t", tag, dir)...)
			if code != 0 {
				t.Fatalf("build %s failed (exit %d):\n%s%s", tag, code, so, se)
			}
			t.Logf("built %s in %v", tag, time.Since(start).Round(time.Second))
		}
		if usesRepo {
			withBuildRepo(t, func(ip string) { build("--add-host", RepoHost+":"+ip) })
		} else {
			build()
		}
	}
	built[tag] = true
	return tag
}

// RemoveImages removes every image of one distro that is both named
// telltale-lab/<distro>-* and labelled telltale-lab=1, and forgets that they
// were built. Images of other projects are never touched.
func RemoveImages(distro string) {
	buildMu.Lock()
	defer buildMu.Unlock()
	out, _, _ := docker("image", "ls", "--format", "{{.Repository}}:{{.Tag}}",
		"--filter", "reference=telltale-lab/"+distro+"-*", "--filter", "label="+Label)
	for _, tag := range strings.Fields(out) {
		if strings.HasPrefix(tag, "telltale-lab/"+distro+"-") {
			docker("image", "rm", tag)
			delete(built, tag)
		}
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// Start runs image on the lab network. The container is removed by t.Cleanup.
func Start(t testing.TB, image string, opts Opts) *Machine {
	t.Helper()
	if err := checkTmpfs(opts); err != nil {
		t.Fatal(err)
	}
	network := NetworkName
	if opts.Egress {
		if opts.Privileged || opts.Ext4Volume || opts.Systemd || len(opts.Caps) > 0 {
			t.Fatalf("a machine with a route out gets no extra privileges")
		}
		network = EgressNetworkName
		ensureEgressNetwork(t)
	} else {
		ensureNetwork(t)
	}
	short := strings.TrimPrefix(strings.SplitN(image, ":", 2)[0], "telltale-lab/")
	name := fmt.Sprintf("telltale-lab-%s-%s", short, randHex())
	host := opts.Hostname
	if host == "" {
		host = short
	}
	// SYS_PTRACE is what lets root see the programs of other accounts'
	// processes (/proc/PID/exe), as root on a real machine can.
	args := []string{"run", "-d", "--name", name, "--network", network, "--hostname", host,
		"--label", Label, "--cap-add", "SYS_PTRACE"}
	for _, b := range opts.Binds {
		args = append(args, "-v", b+":ro")
	}
	if lbl, _, _ := docker("image", "inspect", "--format", `{{index .Config.Labels "lab.variant"}}`, image); strings.TrimSpace(lbl) == "noexec" {
		opts.Noexec = true
	}
	if opts.Noexec {
		args = append(args, "--tmpfs", "/tmp:noexec", "--tmpfs", "/dev/shm:noexec")
	} else if opts.ExecShm {
		args = append(args, "--tmpfs", "/dev/shm:exec,nosuid,nodev,size=64m")
	}
	for _, mnt := range opts.Tmpfs {
		args = append(args, "--tmpfs", mnt)
	}
	if opts.Privileged {
		args = append(args, "--privileged")
	}
	for _, c := range opts.Caps {
		args = append(args, "--cap-add", c)
	}
	if opts.Systemd {
		// systemd needs a cgroup tree it may write. It gets its own: a private
		// cgroup namespace, never the host's tree.
		args = append(args, "--entrypoint", "/sbin/init", "--tmpfs", "/run", "--tmpfs", "/run/lock",
			"--privileged", "--cgroupns", "private", "--stop-signal", "SIGRTMIN+3")
	}
	if opts.Ext4Volume {
		// A loop mount inside the container needs privileges; the image file is
		// bind-mounted and mounted at /lab-ext4 after start.
		args = append(args, "--privileged", "-v", ext4Volume(t)+":/lab-ext4.img")
	}
	args = append(args, image)

	m := &Machine{Name: name, Image: image, Hostname: host, Egress: opts.Egress, network: network}
	t.Cleanup(func() {
		if t.Failed() {
			so, _, _ := docker("logs", "--tail", "40", name)
			t.Logf("last output of %s:\n%s", name, so)
		}
		if opts.Ext4Volume {
			docker("exec", name, "umount", "/lab-ext4") // best effort
		}
		docker("rm", "-f", "-v", name)
	})
	if so, se, code := docker(args...); code != 0 {
		t.Fatalf("docker run: exit %d\n%s%s", code, so, se)
	}
	m.waitSSH(t)
	if opts.Ext4Volume {
		var so, se string
		var code int
		for try := 0; try < 4; try++ { // loop device allocation can race with other users of the host
			so, se, code = docker("exec", name, "sh", "-c", "mkdir -p /lab-ext4 && mount -o loop /lab-ext4.img /lab-ext4")
			if code == 0 {
				break
			}
			time.Sleep(time.Second)
		}
		if code != 0 {
			t.Skipf("privileged loop mount of the ext4 image failed on this host (exit %d): %s%s", code, so, se)
		}
	}
	return m
}

// checkTmpfs refuses Opts.Tmpfs mounts on the directories other options
// own: /tmp and /dev/shm (Noexec, ExecShm; Noexec can also come from the
// image's label), and /run with Systemd.
func checkTmpfs(opts Opts) error {
	for _, mnt := range opts.Tmpfs {
		dir := path.Clean(strings.SplitN(mnt, ":", 2)[0])
		if dir == "/tmp" || dir == "/dev/shm" || (opts.Systemd && dir == "/run") {
			return fmt.Errorf("labkit: Opts.Tmpfs %q: %s is mounted by another option", mnt, dir)
		}
	}
	return nil
}

// ext4Volume creates a sparse ext4 image file on the host (no sudo needed) and
// returns its path. Start bind-mounts it and loop-mounts it inside the container.
func ext4Volume(t testing.TB) string {
	t.Helper()
	mkfs, err := exec.LookPath("mkfs.ext4")
	if err != nil {
		for _, p := range []string{"/usr/sbin/mkfs.ext4", "/sbin/mkfs.ext4"} {
			if _, e := os.Stat(p); e == nil {
				mkfs, err = p, nil
				break
			}
		}
	}
	if err != nil {
		t.Skip("mkfs.ext4 not found; skipping test that needs an ext4 volume")
	}
	img := filepath.Join(t.TempDir(), "ext4.img")
	f, err := os.Create(img)
	if err != nil {
		t.Fatalf("create ext4 image: %v", err)
	}
	f.Close()
	if err := os.Truncate(img, 64<<20); err != nil {
		t.Fatalf("size ext4 image: %v", err)
	}
	if out, err := exec.Command(mkfs, "-F", "-q", img).CombinedOutput(); err != nil {
		t.Skipf("mkfs.ext4 failed: %v\n%s", err, out)
	}
	return img
}

func (m *Machine) waitSSH(t testing.TB) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		out, _, code := docker("exec", m.Name, "ss", "-ltn")
		if code == 0 && strings.Contains(out, ":22 ") {
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("%s: sshd not listening after 30s", m.Name)
}

// Exec runs a command in the machine as root and returns stdout and the exit code.
func (m *Machine) Exec(t testing.TB, cmd ...string) (string, int) {
	t.Helper()
	so, se, code := docker(append([]string{"exec", m.Name}, cmd...)...)
	if code == -1 {
		t.Fatalf("docker exec: %s", se)
	}
	return so, code
}

// CopyIn copies a host file or directory into the machine.
func (m *Machine) CopyIn(t testing.TB, hostPath, path string) {
	t.Helper()
	mustDocker(t, "cp", hostPath, m.Name+":"+path)
}

// CopyOut copies a file or directory out of the machine.
func (m *Machine) CopyOut(t testing.TB, path, hostPath string) {
	t.Helper()
	mustDocker(t, "cp", m.Name+":"+path, hostPath)
}

// IP is the machine's address on the lab network.
func (m *Machine) IP() string {
	return containerIP(m.Name, m.network)
}

func containerIP(name, network string) string {
	out, _, _ := docker("inspect", "--format", `{{(index .NetworkSettings.Networks "`+network+`").IPAddress}}`, name)
	return strings.TrimSpace(out)
}

// Sink is the attacker's remote end: it logs connections to 4444 and 8443.
type Sink struct{ name string }

// StartSink builds the sink image (cached by hash of its source) and starts one
// on the lab network with the alias "sink".
func StartSink(t testing.TB) *Sink {
	t.Helper()
	ensureNetwork(t)
	src, err := os.ReadFile(filepath.Join(labDir, "sink", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	df, err := os.ReadFile(filepath.Join(labDir, "sink", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(append(append([]byte{}, src...), df...))
	tag := "telltale-lab/sink:" + hex.EncodeToString(sum[:])[:12]
	buildMu.Lock()
	if _, _, code := docker("image", "inspect", tag); code != 0 {
		dir := t.TempDir()
		bin := filepath.Join(dir, "sink")
		cmd := exec.Command("go", "build", "-tags", "lab", "-o", bin, filepath.Join(labDir, "sink"))
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			buildMu.Unlock()
			t.Fatalf("build sink: %v\n%s", err, out)
		}
		if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), df, 0o644); err != nil {
			buildMu.Unlock()
			t.Fatal(err)
		}
		if so, se, code := docker("build", "-q", "--label", Label, "-t", tag, dir); code != 0 {
			buildMu.Unlock()
			t.Fatalf("docker build sink: %s%s", so, se)
		}
	}
	buildMu.Unlock()

	name := "telltale-lab-sink-" + randHex()
	t.Cleanup(func() { docker("rm", "-f", name) })
	mustDocker(t, "run", "-d", "--name", name, "--network", NetworkName, "--network-alias", "sink",
		"--label", Label, tag)
	return &Sink{name: name}
}

// IP is the sink's address on the lab network.
func (s *Sink) IP() string { return containerIP(s.name, NetworkName) }

// Log returns everything the sink has logged so far.
func (s *Sink) Log(t testing.TB) string {
	t.Helper()
	so, se, _ := docker("logs", s.name)
	return so + se
}

// WaitFor polls the sink's log for text until the timeout.
func (s *Sink) WaitFor(t testing.TB, text string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if strings.Contains(s.Log(t), text) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(200 * time.Millisecond)
	}
}
