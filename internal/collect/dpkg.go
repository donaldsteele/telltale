package collect

import (
	"bufio"
	"fmt"
	"io"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/donaldsteele/telltale/internal/model"
)

const dpkgCheck = "packages"

// maxDpkgList caps one dpkg status, .list or .md5sums file.
var maxDpkgList int64 = 64 << 20

// scanLines streams the lines of a regular file under root, failing with
// errTooLarge once more than max bytes have been read.
func scanLines(root, mp string, max int64, fn func(line string)) error {
	f, _, err := openRegular(root, mp)
	if err != nil {
		return err
	}
	defer f.Close()
	lr := &io.LimitedReader{R: f, N: max + 1}
	sc := bufio.NewScanner(lr)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		fn(strings.TrimSuffix(sc.Text(), "\r"))
	}
	if lr.N <= 0 {
		return errTooLarge
	}
	return sc.Err()
}

// installedStatus reports whether a dpkg status means the package's files
// are on disk. That is its third word, the package's state. The first word
// is only what was last asked for (install, hold, deinstall, purge), which
// dpkg --set-selections changes without touching a file, so it decides
// nothing here; neither does a package being caught mid-configuration.
func installedStatus(s string) bool {
	f := strings.Fields(s)
	if len(f) != 3 {
		return false
	}
	switch f[2] {
	case "installed", "triggers-pending", "triggers-awaited", "half-configured", "unpacked", "half-installed":
		return true
	}
	return false
}

// residualStatus reports whether a dpkg status is that of a package removed
// but not purged: its files are gone, its postrm waits for the purge.
func residualStatus(s string) bool {
	f := strings.Fields(s)
	return len(f) == 3 && f[2] == "config-files"
}

type dpkgEntry struct {
	p         model.Package
	multiArch bool
	inConf    bool
}

// Packages reads the dpkg database and APT sources under root.
func Packages(root string) (model.Packages, []model.Skip) {
	var skips []model.Skip
	skip := func(f string, a ...any) {
		skips = append(skips, model.Skip{Check: dpkgCheck, Reason: fmt.Sprintf(f, a...)})
	}
	var ents []dpkgEntry
	var residual []model.Package
	var cur dpkgEntry
	flush := func() {
		switch p := cur.p; {
		case p.Name == "":
		case installedStatus(p.Status):
			ents = append(ents, cur)
		case residualStatus(p.Status) && safePkgToken(p.Name) && (p.Arch == "" || safePkgToken(p.Arch)):
			residual = append(residual, model.Package{Name: p.Name, Version: p.Version, Arch: p.Arch, Status: p.Status})
		}
		cur = dpkgEntry{}
	}
	err := scanLines(root, "/var/lib/dpkg/status", maxDpkgList, func(l string) {
		if l == "" {
			flush()
			return
		}
		if l[0] == ' ' || l[0] == '\t' {
			if cur.inConf {
				if f := strings.Fields(l); len(f) >= 2 {
					if cur.p.Conffiles == nil {
						cur.p.Conffiles = map[string]string{}
					}
					cur.p.Conffiles[f[0]] = f[1]
					// Flags follow the hash: "obsolete", "remove-on-upgrade".
					if slices.Contains(f[2:], "obsolete") {
						cur.p.ObsoleteConffiles = append(cur.p.ObsoleteConffiles, f[0])
					}
				}
			}
			return
		}
		cur.inConf = false
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			return
		}
		v = strings.TrimSpace(v)
		switch k {
		case "Package":
			cur.p.Name = v
		case "Status":
			cur.p.Status = v
		case "Architecture":
			cur.p.Arch = v
		case "Version":
			cur.p.Version = v
		case "Multi-Arch":
			cur.multiArch = v == "same"
		case "Conffiles":
			cur.inConf = true
		}
	})
	flush()
	if err != nil {
		skip("/var/lib/dpkg/status: %v", err)
	}
	sort.SliceStable(ents, func(i, j int) bool {
		if ents[i].p.Name != ents[j].p.Name {
			return ents[i].p.Name < ents[j].p.Name
		}
		return ents[i].p.Arch < ents[j].p.Arch
	})

	sort.SliceStable(residual, func(i, j int) bool {
		if residual[i].Name != residual[j].Name {
			return residual[i].Name < residual[j].Name
		}
		return residual[i].Arch < residual[j].Arch
	})

	pk := model.Packages{Installed: make([]model.Package, 0, len(ents)), Residual: residual}
	for _, e := range ents {
		p := e.p
		if !safePkgToken(p.Name) || (p.Arch != "" && !safePkgToken(p.Arch)) {
			skip("package %q (arch %q): unsafe name, file lists not read", p.Name, p.Arch)
			pk.Installed = append(pk.Installed, p)
			continue
		}
		base := "/var/lib/dpkg/info/" + p.Name
		if e.multiArch && p.Arch != "" {
			base += ":" + p.Arch
		}
		lerr := scanLines(root, base+".list", maxDpkgList, func(l string) {
			if l != "" {
				p.Files = append(p.Files, l)
			}
		})
		if lerr != nil && !isNotExist(lerr) {
			skip("%s.list: %v", base, lerr)
		}
		merr := scanLines(root, base+".md5sums", maxDpkgList, func(l string) {
			sum, path, ok := strings.Cut(l, " ")
			if !ok {
				return
			}
			path = strings.TrimLeft(path, " *")
			if path == "" {
				return
			}
			if p.LocalMD5 == nil {
				p.LocalMD5 = map[string]string{}
			}
			p.LocalMD5["/"+strings.TrimPrefix(path, "/")] = sum
		})
		if merr != nil && !isNotExist(merr) {
			skip("%s.md5sums: %v", base, merr)
		}
		pk.Installed = append(pk.Installed, p)
	}
	pk.Diversions = diversions(root, skip)
	pk.StatOverrides = statOverrides(root, skip)
	var s2 []model.Skip
	pk.Sources, s2 = aptSources(root)
	return pk, append(skips, s2...)
}

// diversions reads /var/lib/dpkg/diversions: stanzas of three lines, the
// original path, the path it is diverted to, and the diverting package or
// ":" for a local diversion. Malformed stanzas are skipped and reported.
func diversions(root string, skip func(string, ...any)) []model.Diversion {
	const name = "/var/lib/dpkg/diversions"
	var out []model.Diversion
	var stanza []string
	bad := 0
	err := scanLines(root, name, maxDpkgList, func(l string) {
		if stanza = append(stanza, l); len(stanza) < 3 {
			return
		}
		d := model.Diversion{Path: stanza[0], DivertTo: stanza[1], Package: stanza[2]}
		stanza = stanza[:0]
		if !absPath(d.Path) || !absPath(d.DivertTo) || (d.Package != model.LocalDiversion && !safePkgToken(d.Package)) {
			bad++
			return
		}
		out = append(out, d)
	})
	if err != nil && !isNotExist(err) {
		skip("%s: %v", name, err)
	}
	if len(stanza) > 0 {
		bad++
	}
	if bad > 0 {
		skip("%s: %d malformed diversions skipped", name, bad)
	}
	return out
}

// statOverrides reads /var/lib/dpkg/statoverride: "owner group mode path",
// where the path may contain spaces.
func statOverrides(root string, skip func(string, ...any)) []model.StatOverride {
	const name = "/var/lib/dpkg/statoverride"
	var out []model.StatOverride
	bad := 0
	err := scanLines(root, name, maxDpkgList, func(l string) {
		f := strings.SplitN(l, " ", 4)
		if len(f) != 4 {
			bad++
			return
		}
		mode, err := strconv.ParseUint(f[2], 8, 32)
		if err != nil || mode > 0o7777 || !absPath(f[3]) || f[0] == "" || f[1] == "" {
			bad++
			return
		}
		out = append(out, model.StatOverride{Path: f[3], Owner: f[0], Group: f[1], Mode: uint32(mode)})
	})
	if err != nil && !isNotExist(err) {
		skip("%s: %v", name, err)
	}
	if bad > 0 {
		skip("%s: %d malformed entries skipped", name, bad)
	}
	return out
}

// absPath accepts a clean absolute path.
func absPath(p string) bool {
	return len(p) > 1 && p[0] == '/' && path.Clean(p) == p && !strings.ContainsRune(p, 0)
}

// safePkgToken accepts only [a-z0-9][a-z0-9+.-]* with no "..".
func safePkgToken(s string) bool {
	if s == "" || strings.Contains(s, "..") {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case i > 0 && (r == '+' || r == '.' || r == '-'):
		default:
			return false
		}
	}
	return true
}
