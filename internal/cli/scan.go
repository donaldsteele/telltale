package cli

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/donaldsteele/telltale/internal/collect"
	"github.com/donaldsteele/telltale/internal/escape"
	"github.com/donaldsteele/telltale/internal/judge"
	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/pkgverify"
	"github.com/donaldsteele/telltale/internal/report"
	"github.com/donaldsteele/telltale/internal/snapshot"
	"golang.org/x/sys/unix"
)

const scanUsage = `usage: telltale scan [flags]

Collects this machine, compares it with a snapshot when one is given, verifies
the files of installed packages, and prints a ranked report. Exit code: 0 clean,
1 notes or weak settings only, 2 tampering or a backdoor sign, 3 the scan could
not run.

Flags:
  --snapshot FILE   compare with this snapshot (the passphrase comes from
                    TELLTALE_PASSPHRASE or a prompt); the report is also
                    saved next to it as FILE.last-report.json
  --refs DIR        reference bundle from "telltale fetch-refs"; nothing is
                    downloaded
  --keys DIR        public keys of third-party repositories to trust. Without
                    it a third-party repository is verified with the key the
                    snapshot recorded for it, or with telltale's built-in key
                    for a well-known vendor; never with a key from this machine
  --offline         compare with the machine's own package checksums (root
                    can edit these) instead of downloading from the archive
  --full            verify every package file, not only the security-relevant ones
  --json FILE|-     also write the report as JSON ("-" prints only the JSON)
  --html FILE       also write the report as one self-contained HTML file
  --no-color        no colour in the text report (also off unless stdout is a terminal)`

func init() {
	Register(Command{Name: "scan", Summary: "check this machine against a snapshot and the hardening checklist", Run: runScan})
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
}

func runScan(ctx *Context) int {
	fail := func(err error) int {
		fmt.Fprintf(ctx.Stderr, "telltale scan: %s\n", escape.Terminal(err.Error()))
		return ExitUsage
	}
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	snapPath := fs.String("snapshot", "", "")
	refs := fs.String("refs", "", "")
	keys := fs.String("keys", "", "")
	offline := fs.Bool("offline", false, "")
	full := fs.Bool("full", false, "")
	jsonOut := fs.String("json", "", "")
	htmlOut := fs.String("html", "", "")
	noColor := fs.Bool("no-color", false, "")
	root := fs.String("root", "/", "")
	procRoot := fs.String("proc-root", "/proc", "")
	sysRoot := fs.String("sys-root", "/sys", "")
	if err := fs.Parse(ctx.Args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(ctx.Stdout, scanUsage)
			return 0
		}
		fmt.Fprintf(ctx.Stderr, "telltale scan: %v\n%s\n", err, scanUsage)
		return ExitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(ctx.Stderr, "telltale scan: unexpected argument %q\n%s\n", fs.Arg(0), scanUsage)
		return ExitUsage
	}

	var snap *model.Snapshot
	if *snapPath != "" {
		pass, err := getPassphraseIfEncrypted(ctx, *snapPath)
		if err != nil {
			return fail(err)
		}
		if snap, err = snapshot.ReadFile(*snapPath, pass); err != nil {
			return fail(fmt.Errorf("read snapshot %s: %w", *snapPath, err))
		}
	}
	var extra openpgp.EntityList
	if *keys != "" {
		var err error
		if extra, err = pkgverify.LoadKeys(*keys); err != nil {
			return fail(err)
		}
	}

	sctx := model.ScanContext{}
	if snap != nil && len(snap.DigestKey) > 0 {
		sctx.DigestKey = snap.DigestKey
	} else {
		sctx.DigestKey = make([]byte, 32)
		if _, err := rand.Read(sctx.DigestKey); err != nil {
			return fail(err)
		}
	}

	runCtx, stop := scanContext()
	defer stop()

	fmt.Fprintln(ctx.Stderr, "Collecting this machine...")
	c, err := collect.All(collect.Options{Root: *root, ProcRoot: *procRoot, SysRoot: *sysRoot, DigestKey: sctx.DigestKey, CrossView: true})
	if err != nil {
		return fail(err)
	}

	opt := pkgverify.Options{Full: *full, Offline: *offline, RefsDir: *refs, ExtraKeys: extra, Root: *root}
	// What to verify (the package files changed since the snapshot, startup
	// link targets) and which recorded keys vouch for third-party
	// repositories (the snapshot's, never the collection's). The server
	// uses the same function.
	judge.VerifyScope(&opt, snap, c)
	opt.SignedOnly = signedSourcesOnly(*root, *refs, *offline)
	if *refs == "" && !*offline {
		// Never leave a package cache on the machine being examined.
		// Written before the directory exists: a closed stderr (SIGPIPE) then
		// leaves nothing behind.
		fmt.Fprintln(ctx.Stderr, "Verifying packages against the archive (this can take a while)...")
		dir, err := os.MkdirTemp("", "telltale-cache-")
		if err != nil {
			return fail(err)
		}
		defer os.RemoveAll(dir)
		opt.CacheDir = dir
	}
	pkg := verifyPackages(runCtx, c, opt)
	// The cache is not needed any more: remove it before anything is written,
	// so a closed pipe (SIGPIPE) cannot leave it behind.
	if opt.CacheDir != "" {
		os.RemoveAll(opt.CacheDir)
	}
	if runCtx.Err() != nil {
		return fail(errors.New("interrupted"))
	}

	rep := judge.Judge(judge.Input{Collection: c, Snapshot: snap, Context: sctx, Pkg: pkg, Now: time.Now()})

	jsonToStdout := *jsonOut == "-"
	if !jsonToStdout {
		color := !*noColor && os.Getenv("NO_COLOR") == "" && isTerminal(ctx.Stdout)
		report.Text(ctx.Stdout, rep, report.TextOptions{Color: color})
	}
	if *jsonOut != "" {
		var err error
		if jsonToStdout {
			err = report.JSON(ctx.Stdout, rep)
		} else {
			err = writeTo(*jsonOut, func(w io.Writer) error { return report.JSON(w, rep) })
		}
		if err != nil {
			return fail(err)
		}
	}
	if *htmlOut != "" {
		if err := writeTo(*htmlOut, func(w io.Writer) error { return report.HTML(w, rep) }); err != nil {
			return fail(err)
		}
	}
	if *snapPath != "" {
		// accept reads this file to find the finding a key names.
		if err := writeTo(snapshot.LastReportPath(*snapPath), func(w io.Writer) error { return report.JSON(w, rep) }); err != nil {
			fmt.Fprintf(ctx.Stderr, "telltale scan: could not save the report for accept: %s\n", escape.Terminal(err.Error()))
		}
	}
	return rep.ExitCode
}

// writeTo writes a file (mode 0600) by way of a temporary file in the same
// directory, so a failed write never leaves half a report.
func writeTo(path string, fill func(io.Writer) error) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".telltale-report-*")
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	if err := fill(tmp); err != nil {
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	ok = true
	return nil
}

// scanContext is cancelled by an interrupt, a terminate or a hangup (a dropped
// SSH session), so the deferred clean-up of the temporary cache always runs.
var scanContext = func() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
}

// signedSourcesOnly reports whether a scan may use only sources whose
// signed indexes telltale's keys verify: when it examines the machine it
// runs on and fetches from the archives itself. HTTPS is then checked with
// the examined machine's own CA store and names are resolved by its own
// resolver, and root on that machine controls both, so a source trusted
// through HTTPS alone (snapshot.debian.org's file API, Launchpad) proves
// nothing there. The server, a reference bundle (--refs) built on another
// machine, and a filesystem mounted on the machine that examines it are
// not affected. Tests replace it.
var signedSourcesOnly = func(root, refs string, offline bool) bool {
	return refs == "" && !offline && filepath.Clean("/"+root) == "/"
}

// verifyPackages is pkgverify.Verify; tests replace it.
var verifyPackages = pkgverify.Verify
