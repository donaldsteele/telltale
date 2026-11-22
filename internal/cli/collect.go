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

func init() {
	Register(Command{Name: "collect", Summary: "collect machine facts (internal)", Hidden: true, Run: runCollect})
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
	if err := fs.Parse(ctx.Args); err != nil {
		return fail(err)
	}
	opt := collect.Options{Root: *root, ProcRoot: *procRoot, SysRoot: *sysRoot}
	if *ctxStdin {
		var sc model.ScanContext
		if err := json.NewDecoder(ctx.Stdin).Decode(&sc); err != nil {
			return fail(fmt.Errorf("read scan context: %w", err))
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
