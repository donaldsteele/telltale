//go:build ignore

// Command listener is a lab stand-in for a backdoor listening port: it listens
// on the given TCP port, accepts each connection and closes it at once. It reads
// nothing, writes nothing and runs nothing.
//
//	listener PORT
package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: listener PORT")
		os.Exit(2)
	}
	port, err := strconv.Atoi(os.Args[1])
	if err != nil || port < 1 || port > 65535 {
		fmt.Fprintln(os.Stderr, "listener: bad port")
		os.Exit(2)
	}
	l, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		fmt.Fprintln(os.Stderr, "listener:", err)
		os.Exit(1)
	}
	for {
		c, err := l.Accept()
		if err != nil {
			continue
		}
		c.Close()
	}
}
