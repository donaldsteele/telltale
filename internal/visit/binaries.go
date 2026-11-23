package visit

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/donaldsteele/telltale/internal/escape"
)

// Binaries finds the collector binary to copy to a machine. Nothing is
// embedded: scripts/build.sh writes telltale-linux-amd64 and
// telltale-linux-arm64 (to dist/bin), and the server finds them in Dir.
type Binaries struct {
	// Dir holds telltale-linux-<arch> (the server's --bin-dir). When it is
	// empty, the binaries are looked for next to the running executable,
	// and the running executable itself serves its own architecture.
	Dir string
}

// goarchOf maps what uname -m prints to Go's architecture names.
var goarchOf = map[string]string{"x86_64": "amd64", "aarch64": "arm64"}

// For returns the path of the collector for a machine whose uname -m
// printed arch.
func (b Binaries) For(arch string) (string, error) {
	goarch, ok := goarchOf[arch]
	if !ok {
		return "", fmt.Errorf("no collector for the machine's architecture \"%s\" (telltale is built for x86_64 and aarch64)", escape.Terminal(arch))
	}
	name := "telltale-linux-" + goarch
	if b.Dir != "" {
		p := filepath.Join(b.Dir, name)
		if err := usable(p); err != nil {
			return "", fmt.Errorf("no collector for %s: %w", arch, err)
		}
		return p, nil
	}
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		return "", fmt.Errorf("find the running executable: %w", err)
	}
	p := filepath.Join(filepath.Dir(exe), name)
	if usable(p) == nil {
		return p, nil
	}
	if runtime.GOOS == "linux" && runtime.GOARCH == goarch {
		return exe, nil
	}
	return "", fmt.Errorf("no collector for %s: %s is missing and this server is %s/%s; build it with scripts/build.sh and give its directory as the bin directory", arch, p, runtime.GOOS, runtime.GOARCH)
}

// usable checks that p is a regular, non-empty file.
func usable(p string) error {
	fi, err := os.Stat(p)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() || fi.Size() == 0 {
		return fmt.Errorf("%s is not a regular non-empty file", p)
	}
	return nil
}
