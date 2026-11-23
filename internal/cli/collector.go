//go:build collector

package cli

import "fmt"

// The collector build (go build -tags collector) is what a server copies to
// a machine on each visit and what carry mode needs: version, collect,
// scan, snapshot, accept and fetch-refs. It leaves out the server and mcp
// commands and everything only they use (the web UI, the database, alerts
// and the MCP SDK), so it is smaller and runs none of their start-up code.
// Asked for one of them, it says where to get it.

func init() {
	flavour = " (collector build)"
	for _, name := range []string{"server", "mcp"} {
		Register(Command{Name: name, Hidden: true, Run: func(ctx *Context) int {
			fmt.Fprintf(ctx.Stderr, "telltale %s: this is the collector build of telltale, which has no %s command; it is in the full build (the telltale_<version>_linux_<arch>.tar.gz release or the .deb package)\n", name, name)
			return ExitUsage
		}})
	}
}
