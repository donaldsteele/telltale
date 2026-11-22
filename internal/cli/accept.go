package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/donaldsteele/telltale/internal/snapshot"
)

func init() {
	Register(Command{Name: "accept", Summary: "accept reviewed changes into the snapshot", Run: runAccept})
}

func runAccept(ctx *Context) int {
	fail := func(err error) int {
		fmt.Fprintf(ctx.Stderr, "telltale accept: %v\n", err)
		return ExitUsage
	}
	fs := flag.NewFlagSet("accept", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	snap := fs.String("snapshot", "", "")
	note := fs.String("note", "", "")
	// Allow the key before or after the flags.
	args := ctx.Args
	var key string
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		key, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return fail(err)
	}
	if key == "" && fs.NArg() == 1 {
		key = fs.Arg(0)
	} else if fs.NArg() > 0 {
		return fail(fmt.Errorf("usage: telltale accept FINDING-KEY --snapshot FILE [--note TEXT]"))
	}
	if key == "" || *snap == "" {
		return fail(fmt.Errorf("usage: telltale accept FINDING-KEY --snapshot FILE [--note TEXT]"))
	}
	pass := ""
	if p, err := getPassphraseIfEncrypted(ctx, *snap); err != nil {
		return fail(err)
	} else {
		pass = p
	}
	if err := snapshot.Accept(*snap, pass, key, *note, time.Now()); err != nil {
		if errors.Is(err, snapshot.ErrUnknownFinding) {
			return fail(fmt.Errorf("no finding with that key in the last report"))
		}
		return fail(err)
	}
	fmt.Fprintln(ctx.Stdout, "Accepted. Future scans will treat this value as expected.")
	return 0
}

// getPassphraseIfEncrypted asks for a passphrase only when the file needs one.
func getPassphraseIfEncrypted(ctx *Context, path string) (string, error) {
	enc, err := snapshot.IsEncrypted(path)
	if err != nil {
		return "", err
	}
	if !enc {
		return "", nil
	}
	return getPassphrase(ctx, false)
}
