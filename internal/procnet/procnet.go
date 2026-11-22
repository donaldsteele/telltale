// Package procnet parses the /proc/net/{tcp,tcp6,udp,udp6} socket tables.
package procnet

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// States maps the hex state column to its name.
var States = map[string]string{
	"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
	"05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
	"09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING", "0C": "NEW_SYN_RECV",
}

// Row is one parsed line of a socket table.
type Row struct {
	Local      string // "ip:port" or "[ip6]:port"
	Remote     string
	LocalPort  int
	RemoteZero bool   // remote address is all zero
	State      string // upper-case hex state
	Inode      uint64
}

// Listening reports whether the row is a listening socket for the table
// proto ("tcp", "tcp6", "udp", "udp6").
func (r Row) Listening(proto string) bool {
	if strings.HasPrefix(proto, "tcp") {
		return r.State == "0A"
	}
	return r.RemoteZero && r.LocalPort != 0
}

// ParseAddr decodes a hex "ADDR:PORT". The address words are in host
// (little-endian) order. zero reports an all-zero address.
func ParseAddr(s string) (text string, port int, zero bool, err error) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return "", 0, false, fmt.Errorf("bad address %q", s)
	}
	p, err := strconv.ParseUint(s[i+1:], 16, 16)
	if err != nil {
		return "", 0, false, err
	}
	h := s[:i]
	if len(h) != 8 && len(h) != 32 {
		return "", 0, false, fmt.Errorf("bad address %q", s)
	}
	ip := make(net.IP, len(h)/2)
	zero = true
	for w := 0; w < len(h)/8; w++ {
		v, err := strconv.ParseUint(h[w*8:w*8+8], 16, 32)
		if err != nil {
			return "", 0, false, err
		}
		if v != 0 {
			zero = false
		}
		binary.LittleEndian.PutUint32(ip[w*4:], uint32(v))
	}
	if len(ip) == 4 {
		return fmt.Sprintf("%s:%d", ip, p), int(p), zero, nil
	}
	return fmt.Sprintf("[%s]:%d", ip, p), int(p), zero, nil
}

// Parse reads the text of one table. Unparseable lines are skipped.
func Parse(data string) []Row {
	lines := strings.Split(data, "\n")
	var out []Row
	for _, ln := range lines[min(1, len(lines)):] {
		f := strings.Fields(ln)
		if len(f) < 10 {
			continue
		}
		local, lport, _, err1 := ParseAddr(f[1])
		remote, _, rzero, err2 := ParseAddr(f[2])
		inode, err3 := strconv.ParseUint(f[9], 10, 64)
		if err1 != nil || err2 != nil || err3 != nil {
			continue
		}
		out = append(out, Row{Local: local, Remote: remote, LocalPort: lport, RemoteZero: rzero,
			State: strings.ToUpper(f[3]), Inode: inode})
	}
	return out
}
