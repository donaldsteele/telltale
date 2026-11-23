package visit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// A machine that is no longer trusted writes its own collection. The bound
// on its size (maxOutput) does not bound what it costs to decode: an entry
// can be three bytes of JSON ("{},") and a few hundred bytes once decoded,
// so a collection well under the size limit could ask for gigabytes. The
// entries are therefore counted on the raw text first, in one pass that
// keeps nothing, and a collection over a cap is refused before any of it is
// decoded.

// ErrOversized means a collection holds more entries of some kind than any
// machine has; nothing of it was decoded.
var ErrOversized = errors.New("the collection is oversized")

// ErrCollectorFailed means the server logged in and the collector then did
// not hand over a collection it could use: it was killed or failed, sent
// more than the bound, or sent something that is not a collection. A
// connection that broke and a visit that ran out of time are not this.
var ErrCollectorFailed = errors.New("the collector on the machine did not return a usable collection")

// entryCaps are the most entries a collection may hold, by kind.
type entryCaps struct {
	Files     int // files[]
	Persist   int // persist[]
	Processes int // runtime.processes[]
	Sockets   int // runtime.sockets[]
	Packages  int // packages.installed[] and packages.residual[]
	// Other is every other array element that is an object or an array
	// (accounts, mounts, modules, sources, ...), all together.
	Other int
	// Strings is every array element that is a string or a number (kept
	// lines, package file lists, ...), all together.
	Strings int
	// MapMembers is the members of the objects decoded into maps (sysctl,
	// a package's checksums and conffiles), all together.
	MapMembers int
	// Depth is how deep values may nest.
	Depth int
}

// maxEntries is far above what a real machine has (a large server has a few
// hundred thousand files and a few thousand packages). It bounds how many
// entries the decoder creates. It does not bound the server's memory: a
// collection at the caps decodes to several hundred MiB, and judging it
// (package verification, the comparison with the snapshot) takes several
// times that again, so a hostile machine can still make the server use
// several GiB and be killed. What then holds is outside this package: the
// service's memory limit, its restart, and the server reporting the machine
// after three visits that ended that way.
var maxEntries = entryCaps{
	Files: 1_000_000, Persist: 20_000, Processes: 100_000, Sockets: 200_000, Packages: 20_000,
	Other: 500_000, Strings: 6_000_000, MapMembers: 1_500_000, Depth: 16,
}

// mapPaths are the objects the collection decodes into maps.
var mapPaths = map[string]bool{
	"sysctl":                       true,
	"packages.installed.conffiles": true, "packages.installed.local_md5": true,
	"packages.residual.conffiles": true, "packages.residual.local_md5": true,
}

func oversized(limit int, what string) error {
	return fmt.Errorf("%w: more than %d %s", ErrOversized, limit, what)
}

// checkEntries counts the entries of the collection in data against caps
// without decoding it. Text that is not JSON is not its business: it
// returns nil and the decoder says what is wrong.
func checkEntries(data []byte, caps entryCaps) error {
	type frame struct {
		arr     bool
		path    string
		wantKey bool
		key     string
	}
	var stack []frame
	var files, persist, procs, socks, pkgs, other, strs, members int
	// start is called for each value as it begins; nested says it is an
	// object or an array.
	start := func(nested bool) (string, error) {
		if len(stack) == 0 {
			return "", nil
		}
		top := &stack[len(stack)-1]
		if !top.arr {
			p := top.key
			if top.path != "" {
				p = top.path + "." + top.key
			}
			top.wantKey = true
			return p, nil
		}
		switch {
		case top.path == "files" && nested:
			if files++; files > caps.Files {
				return "", oversized(caps.Files, "files")
			}
		case top.path == "persist" && nested:
			if persist++; persist > caps.Persist {
				return "", oversized(caps.Persist, "startup files")
			}
		case top.path == "runtime.processes" && nested:
			if procs++; procs > caps.Processes {
				return "", oversized(caps.Processes, "processes")
			}
		case top.path == "runtime.sockets" && nested:
			if socks++; socks > caps.Sockets {
				return "", oversized(caps.Sockets, "sockets")
			}
		case (top.path == "packages.installed" || top.path == "packages.residual") && nested:
			if pkgs++; pkgs > caps.Packages {
				return "", oversized(caps.Packages, "packages")
			}
		case nested:
			if other++; other > caps.Other {
				return "", oversized(caps.Other, "entries in its other lists")
			}
		default:
			if strs++; strs > caps.Strings {
				return "", oversized(caps.Strings, "lines and names in its lists")
			}
		}
		return top.path, nil
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil // io.EOF, or not JSON: the decoder reports that
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				p, err := start(true)
				if err != nil {
					return err
				}
				if len(stack) >= caps.Depth {
					return oversized(caps.Depth, "levels of nesting")
				}
				stack = append(stack, frame{arr: d == '[', path: p, wantKey: d == '{'})
			default:
				if len(stack) > 0 {
					stack = stack[:len(stack)-1]
				}
			}
			continue
		}
		if len(stack) > 0 {
			if top := &stack[len(stack)-1]; !top.arr && top.wantKey {
				top.key, _ = tok.(string)
				top.wantKey = false
				if mapPaths[top.path] {
					if members++; members > caps.MapMembers {
						return oversized(caps.MapMembers, "entries in its tables")
					}
				}
				continue
			}
		}
		if _, err := start(false); err != nil {
			return err
		}
	}
}

// readBounded reads all of r, which must not hold more than max bytes.
func readBounded(r io.Reader, max int64, what string) ([]byte, error) {
	return io.ReadAll(&capReader{r: r, max: max, what: what})
}
