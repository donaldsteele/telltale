package collect

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/procnet"
)

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
	for _, r := range procnet.Parse(string(data)) {
		st := r.State
		s := model.Socket{Proto: proto, Local: r.Local, Remote: r.Remote, State: procnet.States[st], Inode: r.Inode, PID: owners[r.Inode]}
		s.Listening = r.Listening(proto)
		if !strings.HasPrefix(proto, "tcp") {
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
