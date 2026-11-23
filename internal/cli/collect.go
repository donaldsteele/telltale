package cli

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/donaldsteele/telltale/internal/collect"
	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/visit"
)

const (
	maxContextBytes = 64 << 10
	minKeyBytes     = 16
)

func init() {
	Register(Command{Name: "collect", Summary: "write this machine's raw collection as JSON, for fetch-refs or offline analysis", Run: runCollect})
}

func runCollect(ctx *Context) int {
	fail := func(err error) int {
		fmt.Fprintf(ctx.Stderr, "telltale collect: %v\n", err)
		return ExitUsage
	}
	fs := flag.NewFlagSet("collect", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	root := fs.String("root", "/", "the examined machine's root filesystem")
	procRoot := fs.String("proc-root", "/proc", "its /proc")
	sysRoot := fs.String("sys-root", "/sys", "its /sys")
	ctxStdin := fs.Bool("context-stdin", false, "read a scan context (JSON with the digest key) from stdin")
	gz := fs.Bool("gzip", false, "gzip the output")
	noCross := fs.Bool("no-cross-view", false, "skip comparing with the machine's own tools")
	if err := fs.Parse(ctx.Args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(ctx.Stdout, "usage: telltale collect [flags] > SCAN.json\n\nWrites this machine's raw collection as JSON, for fetch-refs or offline analysis.\n\nFlags:")
			fs.SetOutput(ctx.Stdout)
			fs.PrintDefaults()
			return 0
		}
		return fail(err)
	}
	opt := collect.Options{Root: *root, ProcRoot: *procRoot, SysRoot: *sysRoot, CrossView: !*noCross}
	if *ctxStdin {
		b, err := io.ReadAll(io.LimitReader(ctx.Stdin, maxContextBytes+1))
		if err != nil {
			return fail(fmt.Errorf("read scan context: %w", err))
		}
		if len(b) > maxContextBytes {
			return fail(fmt.Errorf("scan context larger than %d bytes", maxContextBytes))
		}
		var sc model.ScanContext
		if err := json.Unmarshal(b, &sc); err != nil {
			return fail(fmt.Errorf("read scan context: %w", err))
		}
		if len(sc.DigestKey) < minKeyBytes {
			return fail(fmt.Errorf("digest key too short: %d bytes, need at least %d", len(sc.DigestKey), minKeyBytes))
		}
		opt.DigestKey = sc.DigestKey
		// A server visit runs the collector from a temporary directory it
		// made for it. When that directory checks out as the collector's
		// own (root's, 0700, holding only the running binary), the binary
		// is left out of the inventory; anything else there is not.
		if exe, err := os.Executable(); err == nil && filepath.Clean(*root) == "/" {
			if d, ok := visitDir(exe); ok {
				opt.Self, _ = collect.FindSelf(d, "/proc/self/exe", 0)
			}
		}
	}
	c, err := collect.All(opt)
	if err != nil {
		return fail(err)
	}
	var w io.Writer = ctx.Stdout
	var zw *gzip.Writer
	if *gz {
		zw = gzip.NewWriter(ctx.Stdout)
		w = zw
	}
	if err := json.NewEncoder(w).Encode(c); err != nil {
		return fail(err)
	}
	if zw != nil {
		if err := zw.Close(); err != nil {
			return fail(err)
		}
	}
	return 0
}

// visitDir is the directory of the collector at exe when it is one a server
// visit made for it (visit.IsTempDir: telltale.XXXXXXXX in /run, /var/tmp,
// /root or /tmp).
func visitDir(exe string) (string, bool) {
	d := filepath.Dir(exe)
	return d, visit.IsTempDir(d)
}
