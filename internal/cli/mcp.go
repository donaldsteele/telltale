package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/donaldsteele/telltale/internal/escape"
	"github.com/donaldsteele/telltale/internal/mcpserver"
)

const mcpUsage = `usage: telltale mcp --server https://ADDRESS:PORT --token-file FILE --fingerprint SHA256:...

Runs an MCP server on stdin and stdout for an AI assistant. Its tools read a
running telltale server's machines and reports and can ask it for a visit:
list_machines, latest_report, explain_finding, compare_reports and check_now.
They cannot take a snapshot, accept changes or add exceptions, and telltale
never runs a fix command.

Flags:
  --server URL        the server's web UI address, https://ADDRESS:PORT
  --token-file FILE   a file that holds a token made in the web UI's settings
                      (MCP access tokens); only you may be able to read it
  --fingerprint FP    the server's HTTPS certificate fingerprint, as its
                      settings page and console show it; telltale mcp talks
                      to no other certificate`

// mcpCheckTimeout bounds the check of the server, the certificate and the
// token at start.
const mcpCheckTimeout = 30 * time.Second

func init() {
	Register(Command{Name: "mcp", Summary: "serve read-only MCP tools over stdio, from a running server", Run: runMCP})
}

func runMCP(ctx *Context) int {
	fail := func(err error) int {
		fmt.Fprintf(ctx.Stderr, "telltale mcp: %s\n", escape.Terminal(err.Error()))
		return ExitUsage
	}
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	srv := fs.String("server", "", "")
	tokenFile := fs.String("token-file", "", "")
	fp := fs.String("fingerprint", "", "")
	if err := fs.Parse(ctx.Args); err != nil || *srv == "" || *tokenFile == "" || *fp == "" || fs.NArg() > 0 {
		if err != nil && !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintf(ctx.Stderr, "telltale mcp: %s\n", escape.Terminal(err.Error()))
		}
		fmt.Fprintln(ctx.Stderr, mcpUsage)
		return ExitUsage
	}
	tok, err := mcpserver.ReadTokenFile(*tokenFile)
	if err != nil {
		return fail(err)
	}
	c, err := mcpserver.NewClient(mcpserver.ClientOptions{Server: *srv, Token: tok, Fingerprint: *fp})
	if err != nil {
		return fail(err)
	}
	runCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// A wrong fingerprint or token is a hard error at start. A server that
	// is down is not: the tools report it until it is back.
	check, cancel := context.WithTimeout(runCtx, mcpCheckTimeout)
	_, err = c.Machines(check)
	cancel()
	var fe *mcpserver.FingerprintError
	var se *mcpserver.ServerError
	switch {
	case errors.As(err, &fe):
		return fail(err)
	case errors.As(err, &se) && (se.Status == http.StatusUnauthorized || se.Status == http.StatusTooManyRequests):
		return fail(fmt.Errorf("the server refused the token: %s", se.Message))
	case err != nil:
		fmt.Fprintf(ctx.Stderr, "telltale mcp: warning: %s; the tools will say so until it answers\n", escape.Terminal(err.Error()))
	}
	// stdout carries the MCP protocol and nothing else.
	if err := mcpserver.Serve(runCtx, c, ctx.Stdin, ctx.Stdout); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
		return fail(err)
	}
	return 0
}
