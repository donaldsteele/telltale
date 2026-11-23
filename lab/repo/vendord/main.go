//go:build lab

// Command lab-vendord is the program the lab's stand-in vendor package ships:
// a long-running process that does nothing. "lab-vendord SECONDS" sleeps that
// long and exits. It is built static, so the one package installs on every
// lab distro.
package main

import (
	"os"
	"strconv"
	"time"
)

func main() {
	secs := 3600
	if len(os.Args) > 1 {
		if n, err := strconv.Atoi(os.Args[1]); err == nil && n >= 0 {
			secs = n
		}
	}
	time.Sleep(time.Duration(secs) * time.Second)
}
