package cli

import (
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/donaldsteele/telltale/internal/collect"
	"github.com/donaldsteele/telltale/internal/model"
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
	root := fs.String("root", "/", "")
	procRoot := fs.String("proc-root", "/proc", "")
	sysRoot := fs.String("sys-root", "/sys", "")
	ctxStdin := fs.Bool("context-stdin", false, "")
	gz := fs.Bool("gzip", false, "")
	noCross := fs.Bool("no-cross-view", false, "")
	if err := fs.Parse(ctx.Args); err != nil {
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
