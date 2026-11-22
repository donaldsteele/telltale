package collect

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io/fs"
	"path/filepath"
	"slices"

	"github.com/donaldsteele/telltale/internal/model"
)

// The dynamic linker's cache maps library names to files. ldconfig rewrites
// it whenever a package with libraries is installed, so its hash changes with
// ordinary updates; what matters is which files it sends programs to.

const (
	linkerCachePath   = "/etc/ld.so.cache"
	linkerCacheMagic  = "glibc-ld.so.cache1.1"
	linkerCacheHeader = 48 // magic, entry count, string size, flags, extension offset, padding
	linkerCacheEntry  = 24 // flags, name offset, path offset, OS version, hardware capabilities
	linkerCacheMax    = 64 << 20
	linkerPathMax     = 4096
)

// LinkerCache returns every file path the linker's cache lists, sorted, or
// nil when the machine has no cache. A cache that cannot be read or parsed
// gives a Skip and nil.
func LinkerCache(root string) ([]string, []model.Skip) {
	b, err := readBounded(filepath.Join(root, linkerCachePath), linkerCacheMax)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, []model.Skip{{Check: model.SkipCheckLinkerCache, Reason: err.Error()}}
	}
	paths, ok := parseLinkerCache(b)
	if !ok {
		return nil, []model.Skip{{Check: model.SkipCheckLinkerCache, Reason: linkerCachePath + ": not in a format telltale reads, so the libraries it lists were not checked"}}
	}
	return paths, nil
}

// parseLinkerCache reads the glibc 2.2+ cache format (an older-format table
// may precede it in the same file). Offsets in it count from its own header.
func parseLinkerCache(b []byte) ([]string, bool) {
	i := bytes.Index(b, []byte(linkerCacheMagic))
	if i < 0 {
		return nil, false
	}
	h := b[i:]
	if len(h) < linkerCacheHeader {
		return nil, false
	}
	n := int(binary.LittleEndian.Uint32(h[len(linkerCacheMagic):]))
	if n < 0 || n > (len(h)-linkerCacheHeader)/linkerCacheEntry {
		return nil, false
	}
	paths := make([]string, 0, n)
	for k := 0; k < n; k++ {
		e := h[linkerCacheHeader+k*linkerCacheEntry:]
		off := int(binary.LittleEndian.Uint32(e[8:]))
		if off < 0 || off >= len(h) {
			return nil, false
		}
		end := bytes.IndexByte(h[off:], 0)
		if end <= 0 || end > linkerPathMax {
			return nil, false
		}
		paths = append(paths, string(h[off:off+end]))
	}
	slices.Sort(paths)
	paths = slices.Compact(paths)
	if paths == nil {
		paths = []string{}
	}
	return paths, true
}
