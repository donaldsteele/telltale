package cli

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/donaldsteele/telltale/internal/checklist"
	"github.com/donaldsteele/telltale/internal/collect"
	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/snapshot"
)

func init() {
	Register(Command{Name: "snapshot", Summary: "record a known-good snapshot of this machine", Run: runSnapshot})
}

func runSnapshot(ctx *Context) int {
	fail := func(err error) int {
		fmt.Fprintf(ctx.Stderr, "telltale snapshot: %v\n", err)
		return ExitUsage
	}
	fs := flag.NewFlagSet("snapshot", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	out := fs.String("out", "", "")
	noEnc := fs.Bool("no-encrypt", false, "")
	nonRoot := fs.Bool("allow-non-root", false, "")
	force := fs.Bool("force", false, "")
	root := fs.String("root", "/", "")
	procRoot := fs.String("proc-root", "/proc", "")
	sysRoot := fs.String("sys-root", "/sys", "")
	if err := fs.Parse(ctx.Args); err != nil {
		return fail(err)
	}
	if *out == "" {
		return fail(fmt.Errorf("--out FILE is required"))
	}
	if os.Geteuid() != 0 && !*nonRoot {
		return fail(fmt.Errorf("not running as root, so the snapshot would miss files and processes only root can see; run with sudo, or pass --allow-non-root to accept an incomplete snapshot"))
	}
	if _, err := os.Lstat(*out); err == nil && !*force {
		return fail(fmt.Errorf("%s already exists; pass --force to overwrite it", *out))
	}
	pass := ""
	if !*noEnc {
		p, err := getPassphrase(ctx, true)
		if err != nil {
			return fail(err)
		}
		pass = p
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return fail(err)
	}
	c, err := collect.All(collect.Options{Root: *root, ProcRoot: *procRoot, SysRoot: *sysRoot, DigestKey: key, CrossView: false})
	if err != nil {
		return fail(err)
	}
	checks := checklist.Evaluate(c, model.ScanContext{DigestKey: key})
	if err := snapshot.WriteFile(*out, snapshot.New(c, checks, key), pass); err != nil {
		return fail(err)
	}
	fmt.Fprintf(ctx.Stdout, "Snapshot written to %s\n", *out)
	fmt.Fprintln(ctx.Stdout, "Copy this file off the machine and delete the local copy: a snapshot kept here can be edited by an attacker, which would hide their changes.")
	return 0
}
