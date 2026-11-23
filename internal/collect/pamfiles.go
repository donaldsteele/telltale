package collect

import (
	"path/filepath"
	"strings"

	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/pamconf"
)

// pamModulePaths returns the module files the PAM configuration can load
// that the system-path walk does not cover: absolute paths elsewhere, and
// bare names that PAM's own directories reach through "..". They are
// collected like startup-link targets, so a module planted in /opt or
// /dev/shm is seen (and judged unowned) rather than reported as missing.
//
// A module directory may itself be a symbolic link now (root moved it away
// and left a link): each candidate is looked for where it really is, by the
// inventory files, so a module behind such a link is recorded even when no
// package's file list names it any more.
func pamModulePaths(persist []model.PersistFile, files []model.FileEntry) []string {
	var out []string
	seen := map[string]bool{}
	phys := model.NewPhysicalResolver(model.Inventory(files))
	multi := pamconf.MultiarchDirs(files)
	for _, r := range pamconf.Refs(persist) {
		for _, p := range pamconf.Candidates(r.Module, multi) {
			if at, ok := phys.Path(p); ok {
				p = at
			}
			if seen[p] || inSystemPaths(p) {
				continue
			}
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

func inSystemPaths(p string) bool {
	for _, s := range SystemPaths {
		if hasPathPrefix(p, filepath.Clean("/"+s)) {
			return true
		}
	}
	return false
}

// pamNever is the never-opened rule for PAM modules: /proc, /sys and the
// device nodes under /dev, but not /dev/shm, where a module can be planted.
func pamNever(p string) bool {
	if p == "/dev/shm" || strings.HasPrefix(p, "/dev/shm/") {
		return false
	}
	return underNeverRead(p)
}

// ensurePAMEntries adds supplementary entries for module files. tmpfs is
// opened (modules are often planted there); the descriptor-level kernel
// filesystem check still applies.
func ensurePAMEntries(root string, files []model.FileEntry, mounts []model.Mount, persist []model.PersistFile, maxHash int64) ([]model.FileEntry, []model.Skip) {
	// tmpfs is allowed, judged by the nearest mount
	skip := func(t string) bool { return t != "tmpfs" && skipFS(t) }
	return ensureEntriesIn(root, files, pamModulePaths(persist, files), mounts, maxHash, pamNever, skip)
}
