package visit

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/donaldsteele/telltale/internal/escape"
)

// Binaries finds the collector binary to copy to a machine. Nothing is
// embedded: scripts/build.sh writes the collector build of telltale as
// telltale-linux-amd64 and telltale-linux-arm64 (to dist/collector), the
// .deb installs them in /usr/lib/telltale, and the server finds them in
// Dir.
type Binaries struct {
	// Dir holds telltale-linux-<arch> (the server's bin_dir). When it is
	// empty, the binaries are looked for next to the running executable,
	// then in ../lib/telltale beside it (/usr/lib/telltale for
	// /usr/bin/telltale), and the running executable itself serves its own
	// architecture.
	Dir string
	// Log is the server log, which hears when the running executable
	// stands in for a missing collector; nil means the standard logger.
	Log *log.Logger
}

func (b Binaries) logf(format string, args ...any) {
	if b.Log != nil {
		b.Log.Printf(format, args...)
		return
	}
	log.Printf(format, args...)
}

// fallbackWarned makes the warning about the full binary standing in for a
// collector come once per process. A pointer, so tests can start afresh.
var fallbackWarned = new(sync.Once)

// executable is os.Executable, a variable for tests.
var executable = os.Executable

// goarchOf maps what uname -m prints to Go's architecture names.
var goarchOf = map[string]string{"x86_64": "amd64", "aarch64": "arm64"}

// For returns the path of the collector for a machine whose uname -m
// printed arch.
func (b Binaries) For(arch string) (string, error) {
	goarch, ok := goarchOf[arch]
	if !ok {
		return "", fmt.Errorf("%w: no collector for the machine's architecture \"%s\" (telltale is built for x86_64 and aarch64)", errOdd, escape.Terminal(arch))
	}
	name := "telltale-linux-" + goarch
	if b.Dir != "" {
		p := filepath.Join(b.Dir, name)
		if err := usable(p); err != nil {
			return "", fmt.Errorf("no collector for %s: %w", arch, err)
		}
		return p, nil
	}
	exe, err := executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		return "", fmt.Errorf("find the running executable: %w", err)
	}
	dir := filepath.Dir(exe)
	tried := []string{filepath.Join(dir, name), filepath.Join(filepath.Dir(dir), "lib", "telltale", name)}
	for _, p := range tried {
		if usable(p) == nil {
			return p, nil
		}
	}
	if runtime.GOOS == "linux" && runtime.GOARCH == goarch {
		// Every visit to such a machine comes here: the log says it once.
		fallbackWarned.Do(func() {
			b.logf("telltale server: warning: no collector for %s (neither %s nor %s is there); copying this server's full binary to the machine instead, which works but is larger and has the server in it. Install the collectors (the .deb has them) or set bin_dir.", arch, tried[0], tried[1])
		})
		return exe, nil
	}
	return "", fmt.Errorf("no collector for %s: neither %s nor %s is there and this server is %s/%s; build them with scripts/build.sh and give their directory as bin_dir", arch, tried[0], tried[1], runtime.GOOS, runtime.GOARCH)
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
