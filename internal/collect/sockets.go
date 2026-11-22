package collect

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/donaldsteele/telltale/internal/model"
)

var tcpStates = map[string]string{
	"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
	"05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
	"09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING", "0C": "NEW_SYN_RECV",
}

// parseAddr decodes a /proc/net hex "ADDR:PORT". The address words are in host
// (little-endian) order. zero reports an all-zero address.
func parseAddr(s string) (text string, port int, zero bool, err error) {
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

// parseSockets reads one /proc/net table. Unparseable lines are skipped.
func parseSockets(procRoot, proto string, owners map[uint64]int, skips *[]model.Skip) []model.Socket {
	data, err := readBounded(filepath.Join(procRoot, "net", proto), 64<<20)
	if err != nil {
		if !os.IsNotExist(err) {
			*skips = append(*skips, model.Skip{Check: runtimeCheck, Reason: "net/" + proto + ": " + err.Error()})
		}
		return nil
	}
	var out []model.Socket
	lines := strings.Split(string(data), "\n")
	for _, ln := range lines[min(1, len(lines)):] {
		f := strings.Fields(ln)
		if len(f) < 10 {
			continue
		}
		local, lport, _, err1 := parseAddr(f[1])
		remote, _, rzero, err2 := parseAddr(f[2])
		inode, err3 := strconv.ParseUint(f[9], 10, 64)
		if err1 != nil || err2 != nil || err3 != nil {
			continue
		}
		st := strings.ToUpper(f[3])
		s := model.Socket{Proto: proto, Local: local, Remote: remote, State: tcpStates[st], Inode: inode, PID: owners[inode]}
		if strings.HasPrefix(proto, "tcp") {
			s.Listening = st == "0A"
		} else {
			s.Listening = rzero && lport != 0
			if s.Listening && st == "07" {
				s.State = "UNCONN"
			} else if s.State == "CLOSE" {
				s.State = "UNCONN"
			}
		}
		if s.State == "" {
			s.State = st
		}
		out = append(out, s)
	}
	return out
}

// socketOwners maps socket inodes to the first (lowest) pid holding them.
// Unreadable fd directories are counted, not reported individually.
func socketOwners(procRoot string, pids []int) (map[uint64]int, int) {
	owners := make(map[uint64]int)
	denied := 0
	for _, pid := range pids {
		dir := filepath.Join(procRoot, strconv.Itoa(pid), "fd")
		ents, err := os.ReadDir(dir)
		if err != nil {
			if !os.IsNotExist(err) {
				denied++
			}
			continue
		}
		for _, e := range ents {
			t, err := os.Readlink(filepath.Join(dir, e.Name()))
			if err != nil {
				continue
			}
			if !strings.HasPrefix(t, "socket:[") || !strings.HasSuffix(t, "]") {
				continue
			}
			ino, err := strconv.ParseUint(t[8:len(t)-1], 10, 64)
			if err != nil {
				continue
			}
			if _, ok := owners[ino]; !ok {
				owners[ino] = pid
			}
		}
	}
	return owners, denied
}
