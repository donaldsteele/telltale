// Command telltale detects backdoors and tampering on Linux machines.
package main

import (
	"os"

	"github.com/donaldsteele/telltale/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
