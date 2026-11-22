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
	// Real caches list a few thousand libraries. A count beyond this is not
	// a cache telltale reads: a root-writable file must not be able to make
	// the collector allocate without bound.
	linkerCacheMaxEntries = 65536

	// The format before glibc 2.2, which may still come first in the file:
	// an 11-byte magic, padding, a 32-bit entry count at offset 12, then
	// 12-byte entries from offset 16.
	linkerCacheOldMagic  = "ld.so-1.7.0"
	linkerCacheOldHeader = 16
	linkerCacheOldEntry  = 12
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

// parseLinkerCache finds the cache table exactly where glibc's loader does
// (elf/dl-cache.c), and nowhere else: at the start of the file, or, when the
// file starts with an old-format table, right after that table's entries,
// rounded up to 8 bytes. Searching for the magic instead would let a decoy
// table placed among the old entries hide the one the loader really uses.
// A file with only an old-format table is not parsed. Offsets inside the
// table count from its own header.
func parseLinkerCache(b []byte) ([]string, bool) {
	h := b
	if !bytes.HasPrefix(b, []byte(linkerCacheMagic)) {
		if !bytes.HasPrefix(b, []byte(linkerCacheOldMagic)) || len(b) < linkerCacheOldHeader {
			return nil, false
		}
		old := uint64(binary.LittleEndian.Uint32(b[12:]))
		at := (linkerCacheOldHeader + old*linkerCacheOldEntry + 7) &^ 7
		if at > uint64(len(b)) {
			return nil, false
		}
		h = b[at:]
		if !bytes.HasPrefix(h, []byte(linkerCacheMagic)) {
			return nil, false
		}
	}
	if len(h) < linkerCacheHeader {
		return nil, false
	}
	n := int(binary.LittleEndian.Uint32(h[len(linkerCacheMagic):]))
	if n > linkerCacheMaxEntries || n > (len(h)-linkerCacheHeader)/linkerCacheEntry {
		return nil, false
	}
	// Many entries may share one string: read each offset once.
	seen := make(map[uint32]bool, n)
	paths := make([]string, 0, n)
	for k := 0; k < n; k++ {
		e := h[linkerCacheHeader+k*linkerCacheEntry:]
		off := binary.LittleEndian.Uint32(e[8:])
		if seen[off] {
			continue
		}
		seen[off] = true
		if uint64(off) >= uint64(len(h)) {
			return nil, false
		}
		end := bytes.IndexByte(h[off:], 0)
		if end <= 0 || end > linkerPathMax {
			return nil, false
		}
		paths = append(paths, string(h[off:off+uint32(end)]))
	}
	slices.Sort(paths)
	paths = slices.Compact(paths)
	return paths, true
}
