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
	"strings"
	"syscall"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/donaldsteele/telltale/internal/collect"
	"github.com/donaldsteele/telltale/internal/diff"
	"github.com/donaldsteele/telltale/internal/escape"
	"github.com/donaldsteele/telltale/internal/heuristics"
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
	// Startup links into package-owned files outside the system directories
	// are only notes; the target is verified so a tampered one still shows.
	// A target is named where it really is, which is the path package
	// verification reports a file under.
	opt.ExtraPaths = append(opt.ExtraPaths, heuristics.PackageLinkTargets(c, c.Packages.Owners())...)
	if snap != nil {
		opt.OnlyPaths = changedOwnedPaths(snap, c)
		// The keys third-party repositories were signed with when the
		// machine was clean. The collection just taken holds the same kind
		// of record (c.Packages.RepoTrust); that one is the examined
		// machine's word and is never passed here.
		if snap.Collection != nil {
			opt.RepoTrust = snap.Collection.Packages.RepoTrust
		}
	}
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

const dpkgInfo = "/var/lib/dpkg/info/"

// changedOwnedPaths is what package verification must look at when a
// snapshot says what the machine looked like before: the package-owned paths
// that changed, plus every changed or added dpkg maintainer script.
func changedOwnedPaths(snap *model.Snapshot, cur *model.Collection) map[string]bool {
	owned := map[string]bool{}
	for _, col := range []*model.Collection{cur, snap.Collection} {
		if col == nil {
			continue
		}
		// Owners applies the merged-/usr aliases (/bin/ls is /usr/bin/ls).
		// A package path behind a directory that is a link is recorded,
		// and so changes, where it really is: those paths are verified too.
		// Asking for more to be verified can only find more.
		owners, _ := col.Packages.PhysicalOwners(model.Inventory(col.Files))
		for p := range owners {
			owned[p] = true
		}
	}
	only := map[string]bool{}
	for _, ch := range diff.Compare(snap, cur, nil) {
		switch ch.Kind {
		case diff.FileModified, diff.FileAdded, diff.FileRemoved, diff.PersistChanged:
			if owned[ch.Subject] {
				only[ch.Subject] = true
			}
		}
		if ch.Kind == diff.FileModified || ch.Kind == diff.FileAdded {
			if isMaintainerScript(ch.Subject) {
				only[ch.Subject] = true
			}
		}
	}
	return only
}

func isMaintainerScript(p string) bool {
	if !strings.HasPrefix(p, dpkgInfo) || strings.Contains(p[len(dpkgInfo):], "/") {
		return false
	}
	for _, ext := range pkgverify.MaintainerScripts {
		if strings.HasSuffix(p, "."+ext) {
			return true
		}
	}
	return false
}

// scanContext is cancelled by an interrupt, a terminate or a hangup (a dropped
// SSH session), so the deferred clean-up of the temporary cache always runs.
var scanContext = func() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
}

// verifyPackages is pkgverify.Verify; tests replace it.
var verifyPackages = pkgverify.Verify
