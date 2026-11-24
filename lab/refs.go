//go:build lab

package lab

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/lab/labkit"
)

// Lab machines have no route out, so their packages are verified the way an
// isolated machine's are: "telltale collect" on the machine, "telltale
// fetch-refs" on the host (which has network), and "telltale scan --refs" on
// the machine again. Bundles are cached outside the repository, one per
// release and set of installed packages, so machines started from the same
// image share one and a rerun downloads nothing.

// RefsMount is where the bundle cache is mounted (read-only) in a machine.
const RefsMount = "/lab-refs"

// RefsRoot is the host directory holding the cached bundles.
func RefsRoot() string {
	dir := filepath.Join(labkit.CacheDir(), "refs")
	_ = os.MkdirAll(dir, 0o755)
	return dir
}

// RefsBind is the labkit.Opts.Binds entry that makes the bundles visible.
func RefsBind() string { return RefsRoot() + ":" + RefsMount }

type bundle struct {
	once sync.Once
	err  error
}

var (
	bundleMu sync.Mutex
	bundles  = map[string]*bundle{}
	// The archives are shared services: build at most two bundles at a time.
	fetchSlots = make(chan struct{}, 2)
)

// BundleTrust says what a bundle is built with besides the distribution's
// archives: the snapshot whose recorded repository keys third-party sources
// are fetched and verified with. The zero value is a bundle of the
// distribution's packages only.
type BundleTrust struct {
	// Snapshot is the host path of the machine's snapshot (unencrypted).
	Snapshot string
	// Proxy, when set, is the address ("ip:port") plain-HTTP requests for
	// hosts outside the distributions' archives go through: the lab's own
	// repository, which the host cannot resolve by name. It is the server
	// the machine itself reaches under that name.
	Proxy string
	// ID tells apart bundles of the same packages built with different
	// trust: the recorded keys and which server answered.
	ID string
}

// bundleKey names the bundle a collection needs. A bundle depends on the
// release, on which package versions are installed and, for a machine with
// third-party repositories a snapshot vouches for, on that trust.
func bundleKey(c *model.Collection, trust BundleTrust) string {
	key := packagesKey(c)
	if trust.ID != "" {
		sum := sha256.Sum256([]byte(trust.ID))
		key += "-t" + hex.EncodeToString(sum[:])[:12]
	}
	return key
}

func packagesKey(c *model.Collection) string {
	pkgs := make([]string, 0, len(c.Packages.Installed))
	for _, p := range c.Packages.Installed {
		pkgs = append(pkgs, p.Name+"\x00"+p.Version+"\x00"+p.Arch+"\x00"+p.Status)
	}
	sort.Strings(pkgs)
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00%s\x00", c.Host.OSID, c.Host.OSVersionID, c.Host.Arch)
	for _, p := range pkgs {
		h.Write([]byte(p + "\n"))
	}
	return fmt.Sprintf("%s%s-%s", c.Host.OSID, c.Host.OSVersionID, hex.EncodeToString(h.Sum(nil))[:16])
}

// EnsureBundle returns the path, inside a machine, of the reference bundle
// for the collection in collectionJSON (the output of "telltale collect"),
// building it on the host with bin ("telltale fetch-refs") when the cache
// does not have it yet. trust adds the third-party repositories a snapshot
// vouches for ("fetch-refs --snapshot").
func EnsureBundle(bin string, collectionJSON []byte, trust BundleTrust) (string, error) {
	var c model.Collection
	if err := json.Unmarshal(collectionJSON, &c); err != nil {
		return "", fmt.Errorf("parse collection: %w", err)
	}
	if len(c.Packages.Installed) == 0 {
		return "", fmt.Errorf("the collection lists no packages")
	}
	key := bundleKey(&c, trust)
	bundleMu.Lock()
	b := bundles[key]
	if b == nil {
		b = &bundle{}
		bundles[key] = b
	}
	bundleMu.Unlock()
	b.once.Do(func() { b.err = buildBundle(bin, key, collectionJSON, trust) })
	if b.err != nil {
		return "", b.err
	}
	return RefsMount + "/" + key, nil
}

// directHosts are the hosts fetch-refs reaches over plain HTTP without the
// proxy: the distributions' archives.
const directHosts = ".debian.org,.ubuntu.com,.launchpad.net,.canonical.com"

// staleBuildDirs lists the build directories in root that an earlier build
// of this bundle left: ".building-<key>-" followed by the digits
// os.MkdirTemp adds, and nothing else. A glob on ".building-<key>-*" would
// also match the build directory of a bundle whose key extends this one
// (the same packages with "-t<trust>"), which may be building right now.
func staleBuildDirs(root, key string) []string {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	prefix := ".building-" + key + "-"
	var out []string
	for _, e := range entries {
		rest, ok := strings.CutPrefix(e.Name(), prefix)
		if ok && rest != "" && strings.Trim(rest, "0123456789") == "" {
			out = append(out, filepath.Join(root, e.Name()))
		}
	}
	return out
}

func buildBundle(bin, key string, collectionJSON []byte, trust BundleTrust) error {
	dst := filepath.Join(RefsRoot(), key)
	if _, err := os.Stat(filepath.Join(dst, "bundle.json")); err == nil {
		return nil
	}
	// A directory without bundle.json is what a killed run left: it would
	// block the rename below for ever. The same goes for old build
	// directories of this bundle (the lab lock means no one else is
	// building it now).
	if err := os.RemoveAll(dst); err != nil {
		return err
	}
	for _, d := range staleBuildDirs(RefsRoot(), key) {
		_ = os.RemoveAll(d)
	}
	fetchSlots <- struct{}{}
	defer func() { <-fetchSlots }()
	tmp, err := os.MkdirTemp(RefsRoot(), ".building-"+key+"-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	scan := filepath.Join(tmp, "collection.json")
	if err := os.WriteFile(scan, collectionJSON, 0o600); err != nil {
		return err
	}
	out := filepath.Join(tmp, "bundle")
	start := time.Now()
	args := []string{"fetch-refs", "--for", scan, "--out", out}
	if trust.Snapshot != "" {
		args = append(args, "--snapshot", trust.Snapshot)
	}
	cmd := exec.Command(bin, args...)
	if trust.Proxy != "" {
		cmd.Env = append(os.Environ(), "HTTP_PROXY=http://"+trust.Proxy, "http_proxy=http://"+trust.Proxy, "NO_PROXY="+directHosts, "no_proxy="+directHosts)
	}
	res, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("telltale fetch-refs for %s: %v\n%s", key, err, res)
	}
	// Bundles are read through a bind mount by root in the machine and must
	// stay readable by this user.
	_ = filepath.WalkDir(out, func(p string, d os.DirEntry, err error) error {
		if err == nil {
			if d.IsDir() {
				_ = os.Chmod(p, 0o755)
			} else {
				_ = os.Chmod(p, 0o644)
			}
		}
		return nil
	})
	if err := os.WriteFile(filepath.Join(RefsRoot(), key+".log"), res, 0o644); err != nil {
		return err
	}
	if err := os.Rename(out, dst); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "lab: built reference bundle %s in %v\n", key, time.Since(start).Round(time.Second))
	return nil
}
