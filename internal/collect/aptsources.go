package collect

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/donaldsteele/telltale/internal/model"
)

const maxAptFile = 1 << 20

func stripComment(l string) string {
	if i := strings.Index(l, "#"); i >= 0 {
		l = l[:i]
	}
	return strings.TrimSpace(l)
}

func aptSources(root string) ([]model.AptSource, []model.Skip) {
	var out []model.AptSource
	var skips []model.Skip
	files := []string{"/etc/apt/sources.list"}
	ents, err := os.ReadDir(filepath.Join(root, "etc/apt/sources.list.d"))
	if err != nil && !isNotExist(err) {
		skips = append(skips, model.Skip{Check: dpkgCheck, Reason: "/etc/apt/sources.list.d: " + err.Error()})
	}
	var extra []string
	for _, e := range ents {
		n := e.Name()
		if strings.HasSuffix(n, ".list") || strings.HasSuffix(n, ".sources") {
			extra = append(extra, "/etc/apt/sources.list.d/"+n)
		}
	}
	sort.Strings(extra)
	files = append(files, extra...)
	for _, mp := range files {
		b, err := readRaw(root, mp, maxAptFile)
		if err != nil {
			if !isNotExist(err) {
				skips = append(skips, model.Skip{Check: dpkgCheck, Reason: fmt.Sprintf("%s: %v", mp, err)})
			}
			continue
		}
		lines := splitLines(b)
		if strings.HasSuffix(mp, ".sources") {
			out = append(out, parseDeb822(mp, lines)...)
		} else {
			out = append(out, parseOneLine(mp, lines)...)
		}
	}
	return out, skips
}

func parseOneLine(file string, lines []string) []model.AptSource {
	var out []model.AptSource
	for _, l := range lines {
		f := strings.Fields(stripComment(l))
		if len(f) < 3 || (f[0] != "deb" && f[0] != "deb-src") {
			continue
		}
		s := model.AptSource{File: file, Types: []string{f[0]}}
		rest := f[1:]
		if strings.HasPrefix(rest[0], "[") {
			j := 0
			var opts []string
			for ; j < len(rest); j++ {
				opts = append(opts, rest[j])
				if strings.HasSuffix(rest[j], "]") {
					break
				}
			}
			if j >= len(rest) {
				continue
			}
			rest = rest[j+1:]
			for _, o := range strings.Fields(strings.Trim(strings.Join(opts, " "), "[]")) {
				if k, v, ok := strings.Cut(o, "="); ok && (k == "signed-by" || k == "signed_by") {
					s.SignedBy = v
				}
			}
		}
		if len(rest) < 2 {
			continue
		}
		s.URIs = []string{rest[0]}
		s.Suites = []string{rest[1]}
		s.Components = append([]string{}, rest[2:]...)
		out = append(out, s)
	}
	return out
}

func parseDeb822(file string, lines []string) []model.AptSource {
	var out []model.AptSource
	var cur model.AptSource
	var have, disabled, inSigned bool
	flush := func() {
		if have && !disabled {
			cur.File = file
			out = append(out, cur)
		}
		cur, have, disabled, inSigned = model.AptSource{}, false, false, false
	}
	for _, l := range lines {
		if strings.TrimSpace(l) == "" {
			flush()
			continue
		}
		if l[0] == '#' {
			continue
		}
		if l[0] == ' ' || l[0] == '\t' {
			if inSigned && cur.SignedBy == "" {
				cur.SignedBy = "inline"
			}
			continue
		}
		inSigned = false
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		have = true
		switch strings.ToLower(k) {
		case "types":
			cur.Types = strings.Fields(v)
		case "uris":
			cur.URIs = strings.Fields(v)
		case "suites":
			cur.Suites = strings.Fields(v)
		case "components":
			cur.Components = strings.Fields(v)
		case "signed-by":
			cur.SignedBy = v
			inSigned = v == ""
		case "enabled":
			disabled = strings.EqualFold(v, "no") || strings.EqualFold(v, "false")
		}
	}
	flush()
	return out
}
