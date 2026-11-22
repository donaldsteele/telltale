package collect

import (
	"bufio"
	"fmt"
	"io"
	"sort"
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

func installedStatus(s string) bool {
	return s == "install ok installed" || s == "hold ok installed"
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
	var cur dpkgEntry
	flush := func() {
		if cur.p.Name != "" && installedStatus(cur.p.Status) {
			ents = append(ents, cur)
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

	pk := model.Packages{Installed: make([]model.Package, 0, len(ents))}
	for _, e := range ents {
		p := e.p
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
	var s2 []model.Skip
	pk.Sources, s2 = aptSources(root)
	return pk, append(skips, s2...)
}
