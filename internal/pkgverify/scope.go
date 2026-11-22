package pkgverify

import (
	"path"
	"slices"
	"strings"
)

// scopeDirs are trees whose every file is security-relevant: PAM modules,
// kernel modules and the boot files.
var scopeDirs = []string{"/lib/security", "/lib/modules", "/usr/lib/modules", "/boot"}

// InScope reports whether a package-owned file belongs to the default check
// without a snapshot: executables (any execute bit, which includes setuid and
// setgid programs), shared libraries ("*.so", "*.so.*"), and everything below
// /lib/security, /usr/lib/<triplet>/security, /lib/modules, /usr/lib/modules
// and /boot. Both spellings of merged-/usr paths are considered. mode is a
// stat mode or bare permission bits.
func InScope(p string, mode uint32) bool {
	if mode&0o111 != 0 {
		return true
	}
	base := path.Base(p)
	if strings.HasSuffix(base, ".so") || strings.Contains(base, ".so.") {
		return true
	}
	for _, q := range []string{p, usrAlias(p)} {
		if q == "" {
			continue
		}
		for _, d := range scopeDirs {
			if q == d || strings.HasPrefix(q, d+"/") {
				return true
			}
		}
		// /usr/lib/<triplet>/security/...
		if rest, ok := strings.CutPrefix(q, "/usr/lib/"); ok {
			if seg := strings.SplitN(rest, "/", 3); len(seg) >= 2 && seg[0] != "" && seg[1] == "security" {
				return true
			}
		}
	}
	return false
}

var mergedDirs = []string{"bin", "sbin", "lib", "lib32", "lib64", "libx32"}

// usrAlias returns the other spelling of p on merged-/usr systems, where
// /bin is /usr/bin and so on, or "" when there is none. It follows the same
// rule as model.Packages.Owners.
func usrAlias(p string) string {
	for _, d := range mergedDirs {
		if strings.HasPrefix(p, "/"+d+"/") {
			return "/usr" + p
		}
		if strings.HasPrefix(p, "/usr/"+d+"/") {
			return strings.TrimPrefix(p, "/usr")
		}
	}
	return ""
}

// candidate reports whether the file at collected path cp, listed by its
// package as p, is checked: with OnlyPaths (a snapshot) exactly the changed
// paths; with Full everything; otherwise what InScope selects by the mode on
// disk or, once the package is at hand, by the mode the package gives it.
// diskMode is 0 for entries that are not regular files.
func (o *Options) candidate(cp, p string, diskMode uint32, deb *DebFile) bool {
	if o.isExtra(cp) || o.isExtra(p) {
		return true
	}
	if o.OnlyPaths != nil {
		return o.OnlyPaths[cp] || o.OnlyPaths[p]
	}
	if o.Full {
		return true
	}
	if InScope(cp, diskMode) || InScope(p, diskMode) {
		return true
	}
	return deb != nil && InScope(p, deb.Mode)
}

// isExtra reports whether p is one of ExtraPaths.
func (o *Options) isExtra(p string) bool {
	return slices.Contains(o.ExtraPaths, p)
}
