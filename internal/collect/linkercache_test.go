package collect

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// compatLinkerCache is the layout glibc writes in compatibility mode and its
// loader reads: an old-format header whose entry count says where the
// current-format table starts (after the old entries, rounded up to 8 bytes).
// oldEntries fills the old-entry region and decides that count.
func compatLinkerCache(oldEntries []byte, table []byte) []byte {
	for len(oldEntries)%linkerCacheOldEntry != 0 {
		oldEntries = append(oldEntries, 0)
	}
	b := make([]byte, linkerCacheOldHeader)
	copy(b, linkerCacheOldMagic)
	binary.LittleEndian.PutUint32(b[12:], uint32(len(oldEntries)/linkerCacheOldEntry))
	b = append(b, oldEntries...)
	for len(b)%8 != 0 {
		b = append(b, 0)
	}
	return append(b, table...)
}

// buildLinkerCache writes a cache table in glibc's current format: header,
// entries, strings. prefix is put in front as it is.
func buildLinkerCache(prefix string, libs [][2]string) []byte {
	head := make([]byte, linkerCacheHeader)
	copy(head, linkerCacheMagic)
	binary.LittleEndian.PutUint32(head[len(linkerCacheMagic):], uint32(len(libs)))
	entries := make([]byte, len(libs)*linkerCacheEntry)
	var strs []byte
	base := linkerCacheHeader + len(entries)
	for i, l := range libs {
		e := entries[i*linkerCacheEntry:]
		binary.LittleEndian.PutUint32(e[4:], uint32(base+len(strs)))
		strs = append(append(strs, l[0]...), 0)
		binary.LittleEndian.PutUint32(e[8:], uint32(base+len(strs)))
		strs = append(append(strs, l[1]...), 0)
	}
	return append(append(append([]byte(prefix), head...), entries...), strs...)
}

func TestLinkerCacheListsLibraryPaths(t *testing.T) {
	libs := [][2]string{
		{"libc.so.6", "/lib/x86_64-linux-gnu/libc.so.6"},
		{"libz.so.1", "/lib/x86_64-linux-gnu/libz.so.1"},
		{"libevil.so.1", "/var/tmp/.x/libevil.so.1"},
		{"libc.so.6", "/lib/x86_64-linux-gnu/libc.so.6"},
	}
	want := []string{"/lib/x86_64-linux-gnu/libc.so.6", "/lib/x86_64-linux-gnu/libz.so.1", "/var/tmp/.x/libevil.so.1"}
	table := buildLinkerCache("", libs)
	for name, data := range map[string][]byte{
		"current format":                  table,
		"old-format table in front":       compatLinkerCache(make([]byte, 5*linkerCacheOldEntry), table),
		"old table of odd length (align)": compatLinkerCache(make([]byte, 3*linkerCacheOldEntry), table),
		"empty old table":                 compatLinkerCache(nil, table),
	} {
		root := t.TempDir()
		os.MkdirAll(filepath.Join(root, "etc"), 0o755)
		os.WriteFile(filepath.Join(root, "etc/ld.so.cache"), data, 0o644)
		got, skips := LinkerCache(root)
		if len(skips) != 0 || !slices.Equal(got, want) {
			t.Errorf("%s: got %q, skips %+v", name, got, skips)
		}
	}
}

// A table planted among the old-format entries is never read by the loader,
// which goes straight to the offset the old header gives. The collector must
// list what the loader uses, not the decoy.
func TestLinkerCacheIgnoresDecoyTable(t *testing.T) {
	decoy := buildLinkerCache("", [][2]string{{"libc.so.6", "/lib/x86_64-linux-gnu/libc.so.6"}})
	real := buildLinkerCache("", [][2]string{{"libc.so.6", "/var/tmp/.x/libc.so.6"}})
	got, ok := parseLinkerCache(compatLinkerCache(decoy, real))
	if !ok || !slices.Equal(got, []string{"/var/tmp/.x/libc.so.6"}) {
		t.Fatalf("got %q (parsed %v), want the table the loader reads", got, ok)
	}
	// The old header points at nothing that is a table: not parsed, even
	// though a table can be found by searching.
	for name, data := range map[string][]byte{
		"table one entry too early":   append(compatLinkerCache(make([]byte, 2*linkerCacheOldEntry), nil), append(make([]byte, 8), real...)...),
		"junk in front of a table":    append([]byte("junk"), real...),
		"old header, count too large": compatLinkerCache(nil, real)[:linkerCacheOldHeader],
	} {
		if name == "old header, count too large" {
			binary.LittleEndian.PutUint32(data[12:], 1<<31)
		}
		if got, ok := parseLinkerCache(data); ok {
			t.Errorf("%s: parsed as %q, want not parsed", name, got)
		}
	}
}

// The file is root-writable: its size, not its claims, bounds the work.
func TestLinkerCacheBoundsWork(t *testing.T) {
	// Many entries sharing one long string are read once.
	const n = 60000
	long := "/" + strings.Repeat("a", 4000)
	head := make([]byte, linkerCacheHeader)
	copy(head, linkerCacheMagic)
	binary.LittleEndian.PutUint32(head[len(linkerCacheMagic):], n)
	entries := make([]byte, n*linkerCacheEntry)
	for i := 0; i < n; i++ {
		binary.LittleEndian.PutUint32(entries[i*linkerCacheEntry+8:], uint32(linkerCacheHeader+len(entries)))
	}
	data := append(append(append(head, entries...), long...), 0)
	allocs := testing.AllocsPerRun(1, func() {
		got, ok := parseLinkerCache(data)
		if !ok || len(got) != 1 || got[0] != long {
			t.Fatalf("parsed %v, %d paths", ok, len(got))
		}
	})
	if allocs > 1000 {
		t.Errorf("%v allocations for %d entries that share one string", allocs, n)
	}
	// More entries than any real cache has: not parsed.
	binary.LittleEndian.PutUint32(head[len(linkerCacheMagic):], linkerCacheMaxEntries+1)
	big := append(append(head, make([]byte, (linkerCacheMaxEntries+1)*linkerCacheEntry)...), "/x\x00"...)
	if _, ok := parseLinkerCache(big); ok {
		t.Errorf("a cache with %d entries was parsed", linkerCacheMaxEntries+1)
	}
}

func TestLinkerCacheMissingAndDamaged(t *testing.T) {
	root := t.TempDir()
	if got, skips := LinkerCache(root); got != nil || len(skips) != 0 {
		t.Fatalf("no cache: got %q, skips %+v", got, skips)
	}
	os.MkdirAll(filepath.Join(root, "etc"), 0o755)
	good := buildLinkerCache("", [][2]string{{"libc.so.6", "/lib/libc.so.6"}})
	damaged := map[string][]byte{
		"not a cache":      []byte("hello"),
		"cut in the table": good[:linkerCacheHeader+10],
		"cut in a string":  good[:len(good)-1],
	}
	// An entry count far beyond the file.
	huge := append([]byte{}, good...)
	binary.LittleEndian.PutUint32(huge[len(linkerCacheMagic):], 1<<30)
	damaged["entry count too large"] = huge
	// A path offset outside the file.
	wild := append([]byte{}, good...)
	binary.LittleEndian.PutUint32(wild[linkerCacheHeader+8:], 1<<30)
	damaged["offset outside the file"] = wild
	for name, data := range damaged {
		os.WriteFile(filepath.Join(root, "etc/ld.so.cache"), data, 0o644)
		if got, skips := LinkerCache(root); got != nil || len(skips) != 1 {
			t.Errorf("%s: got %q, skips %+v; want nil and one skip", name, got, skips)
		}
	}
}

func TestLinkerCacheReadsThisMachines(t *testing.T) {
	if _, err := os.Stat("/etc/ld.so.cache"); err != nil {
		t.Skip("no /etc/ld.so.cache here")
	}
	got, skips := LinkerCache("/")
	if len(skips) != 0 || len(got) == 0 {
		t.Fatalf("got %d paths, skips %+v", len(got), skips)
	}
	for _, p := range got {
		if !filepath.IsAbs(p) {
			t.Fatalf("not a path: %q", p)
		}
	}
}
