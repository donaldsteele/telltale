// Package cli dispatches telltale subcommands.
package cli

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/donaldsteele/telltale/internal/version"
)

// Exit codes shared by all subcommands.
const ExitUsage = 3

// Context is what a subcommand receives.
type Context struct {
	Args   []string
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// Command is one subcommand.
type Command struct {
	Name    string
	Summary string
	Hidden  bool
	Run     func(ctx *Context) int
}

var registry = map[string]Command{}

// Register adds or replaces a command. Each command's file calls it from
// init().
func Register(c Command) { registry[c.Name] = c }

// flavour follows the version when this is not the full build (see
// collector.go).
var flavour = ""

// all returns the registered commands plus version and help.
func all() []Command {
	m := map[string]Command{}
	for n, c := range registry {
		m[n] = c
	}
	m["version"] = Command{Name: "version", Summary: "print the version", Run: func(ctx *Context) int {
		fmt.Fprintf(ctx.Stdout, "telltale %s%s\n", version.Version, flavour)
		return 0
	}}
	m["help"] = Command{Name: "help", Summary: "show this help", Run: func(ctx *Context) int {
		usage(ctx.Stdout)
		return 0
	}}
	out := make([]Command, 0, len(m))
	for _, c := range m {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func usage(w io.Writer) {
	var b strings.Builder
	b.WriteString("Usage: telltale <command> [flags]\n\nCommands:\n")
	for _, c := range all() {
		if !c.Hidden {
			fmt.Fprintf(&b, "  %-11s %s\n", c.Name, c.Summary)
		}
	}
	io.WriteString(w, b.String())
}

// Run executes the subcommand named by args[0] and returns the exit code.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return ExitUsage
	}
	for _, c := range all() {
		if c.Name == args[0] {
			return c.Run(&Context{Args: args[1:], Stdin: stdin, Stdout: stdout, Stderr: stderr})
		}
	}
	fmt.Fprintf(stderr, "telltale: unknown command %q\n", args[0])
	usage(stderr)
	return ExitUsage
}
