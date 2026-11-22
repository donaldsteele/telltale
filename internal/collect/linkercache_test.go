package collect

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// buildLinkerCache writes a cache in glibc's format: header, entries, strings.
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
	// The second form has an old-format table in front, as older glibc wrote.
	for _, prefix := range []string{"", "ld.so-1.7.0\x00\x00\x00\x00\x00old table"} {
		root := t.TempDir()
		os.MkdirAll(filepath.Join(root, "etc"), 0o755)
		os.WriteFile(filepath.Join(root, "etc/ld.so.cache"), buildLinkerCache(prefix, libs), 0o644)
		got, skips := LinkerCache(root)
		if len(skips) != 0 || !slices.Equal(got, want) {
			t.Errorf("prefix %q: got %q, skips %+v", prefix, got, skips)
		}
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
