package pkgverify

import (
	"bytes"
	"encoding/json"
	"path"
	"path/filepath"
	"strings"
)

// The file table cache keeps, per package build, the per-file SHA-256 table
// read from a verified .deb, keyed by that .deb's SHA-256. A table is trusted
// because its key is the hash a signed index gave for the .deb it came from;
// the cache is therefore only as trustworthy as the directory holding it,
// which must not be on the machine being examined. A server keeps one cache
// for all its machines.

const (
	// tableSchema changes whenever DebFiles would produce a different table
	// for the same .deb, so older tables are not reused.
	tableSchema  = 2 // 2: ScriptModes
	maxTableFile = 256 << 20
)

type cachedTable struct {
	Schema    int                `json:"schema"`
	DebSHA256 string             `json:"deb_sha256"`
	Files     map[string]DebFile `json:"files"`
}

func tablePath(dir, debSHA string) string {
	if dir == "" || !isHexLen(debSHA, 64) {
		return ""
	}
	return filepath.Join(dir, "debfiles-"+strings.ToLower(debSHA)+".json")
}

// loadTable returns the cached table for the .deb with SHA-256 debSHA, or
// false when there is none or it does not pass every check.
func loadTable(dir, debSHA string) (map[string]DebFile, bool) {
	b := readCache(tablePath(dir, debSHA), maxTableFile)
	if b == nil {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var t cachedTable
	if err := dec.Decode(&t); err != nil || dec.More() {
		return nil, false
	}
	if t.Schema != tableSchema || t.DebSHA256 != strings.ToLower(debSHA) || t.Files == nil {
		return nil, false
	}
	for p, f := range t.Files {
		if !validTablePath(p) || !isHexLen(f.SHA256, 64) || f.Mode > 0o7777 || len(f.Text) > maxConffileText || (f.Text != nil && !f.Conffile) || len(f.ScriptModes) > 16 {
			return nil, false
		}
		for _, m := range f.ScriptModes {
			if m > 0o7777 {
				return nil, false
			}
		}
	}
	return t.Files, true
}

// storeTable caches the table for the .deb with SHA-256 debSHA. Failures
// only cost a later download.
func storeTable(dir, debSHA string, files map[string]DebFile) {
	p := tablePath(dir, debSHA)
	if p == "" {
		return
	}
	b, err := json.Marshal(cachedTable{Schema: tableSchema, DebSHA256: strings.ToLower(debSHA), Files: files})
	if err != nil {
		return
	}
	writeCache(p, b)
}

// validTablePath accepts what debPath produces.
func validTablePath(p string) bool {
	return len(p) > 1 && p[0] == '/' && path.Clean(p) == p && !strings.ContainsRune(p, 0)
}
