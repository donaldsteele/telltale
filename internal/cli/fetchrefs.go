package cli

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"

	"github.com/donaldsteele/telltale/internal/escape"
	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/pkgverify"
)

// maxScanJSON bounds a decompressed collection read by fetch-refs.
const maxScanJSON = 1 << 30

const fetchRefsUsage = `usage: telltale fetch-refs --for SCAN.json --out DIR [--full] [--keys DIR]

Builds a reference bundle on a machine with network access, so that an
isolated machine's packages can be verified properly with
"telltale scan --refs DIR".

  --for SCAN.json  the isolated machine's collection: what "telltale collect"
                   writes there (plain or with --gzip). Reports carry no
                   package list and cannot be used.
  --out DIR        a new or empty directory for the bundle
  --full           include every package, not only those owning executables,
                   libraries, PAM and kernel modules and /boot
  --keys DIR       public keys of third-party repositories to trust

Everything in the bundle is checked again with telltale's built-in archive
keys when it is used, so the bundle can travel by any means.`

func init() {
	Register(Command{Name: "fetch-refs", Summary: "build a reference bundle for verifying an isolated machine", Run: runFetchRefs})
}

func runFetchRefs(ctx *Context) int {
	fail := func(err error) int {
		fmt.Fprintf(ctx.Stderr, "telltale fetch-refs: %v\n", err)
		return ExitUsage
	}
	fs := flag.NewFlagSet("fetch-refs", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	scan := fs.String("for", "", "")
	out := fs.String("out", "", "")
	full := fs.Bool("full", false, "")
	keys := fs.String("keys", "", "")
	if err := fs.Parse(ctx.Args); err != nil || fs.NArg() > 0 || *scan == "" || *out == "" {
		if err != nil && !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintf(ctx.Stderr, "telltale fetch-refs: %v\n", err)
		}
		fmt.Fprintln(ctx.Stderr, fetchRefsUsage)
		return ExitUsage
	}
	c, err := readCollectionFile(*scan)
	if err != nil {
		return fail(err)
	}
	opt := pkgverify.Options{Full: *full}
	if *keys != "" {
		if opt.ExtraKeys, err = pkgverify.LoadKeys(*keys); err != nil {
			return fail(err)
		}
	}
	sctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	werr := pkgverify.WriteBundle(sctx, c, *out, opt)
	if m, err := pkgverify.ReadBundleManifest(*out); err == nil {
		printBundleSummary(ctx.Stdout, *out, m)
	}
	if werr != nil {
		return fail(werr)
	}
	return 0
}

func printBundleSummary(w io.Writer, dir string, m *pkgverify.BundleManifest) {
	fmt.Fprintf(w, "Reference bundle for %s %s (%s) written to %s: %d packages.\n",
		escape.Terminal(m.Host.OSID), escape.Terminal(m.Host.OSVersionID), escape.Terminal(m.Host.Arch), escape.Terminal(dir), len(m.Packages))
	if n := len(m.Unavailable); n > 0 {
		fmt.Fprintf(w, "%d packages could not be included; their files will show as not verified:\n", n)
		for i, u := range m.Unavailable {
			if i == 50 {
				fmt.Fprintf(w, "  ... and %d more (see bundle.json)\n", n-i)
				break
			}
			fmt.Fprintf(w, "  %s %s %s: %s\n", escape.Terminal(u.Name), escape.Terminal(u.Version), escape.Terminal(u.Arch), escape.Terminal(u.Reason))
		}
	}
	for _, e := range m.Errors {
		fmt.Fprintf(w, "! %s\n", escape.Terminal(e))
	}
	fmt.Fprintf(w, "Carry the directory to the isolated machine and run: telltale scan --refs %s\n", escape.Terminal(dir))
}

// readCollectionFile reads a collection written by "telltale collect",
// gzip-compressed or not.
func readCollectionFile(path string) (*model.Collection, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	br := bufio.NewReader(f)
	var r io.Reader = br
	if magic, _ := br.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		zr, err := gzip.NewReader(br)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		r = zr
	}
	lr := &io.LimitedReader{R: r, N: maxScanJSON + 1}
	var c model.Collection
	if err := json.NewDecoder(lr).Decode(&c); err != nil {
		if lr.N <= 0 {
			return nil, fmt.Errorf("%s: larger than %d bytes", path, maxScanJSON)
		}
		return nil, fmt.Errorf("%s is not a collection: %w", path, err)
	}
	if c.Schema != model.CollectionSchema {
		return nil, fmt.Errorf("%s: collection schema %d, this telltale reads %d", path, c.Schema, model.CollectionSchema)
	}
	if len(c.Packages.Installed) == 0 || c.Host.OSID == "" {
		return nil, fmt.Errorf("%s lists no installed packages; give the output of \"telltale collect\" from the isolated machine (a report has no package list)", path)
	}
	return &c, nil
}
