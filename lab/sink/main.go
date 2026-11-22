//go:build lab

// Command sink plays the attacker's remote end in the lab: it accepts TCP
// connections on 4444 and 8443 and logs them. It sends nothing back.
package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	log.SetFlags(0)
	ports := []int{4444, 8443}
	for _, p := range ports {
		l, err := net.Listen("tcp", ":"+strconv.Itoa(p))
		if err != nil {
			log.Fatalf("listen %d: %v", p, err)
		}
		go serve(l, p)
	}
	fmt.Fprintln(os.Stdout, "sink ready")
	select {}
}

func serve(l net.Listener, port int) {
	for {
		c, err := l.Accept()
		if err != nil {
			log.Printf("accept %d: %v", port, err)
			return
		}
		fmt.Printf("accept port=%d from=%s\n", port, c.RemoteAddr())
		go func() {
			defer c.Close()
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			buf, _ := io.ReadAll(io.LimitReader(c, 512))
			fmt.Printf("conn port=%d from=%s data=%q\n", port, c.RemoteAddr(), strings.TrimSpace(string(buf)))
		}()
	}
}
