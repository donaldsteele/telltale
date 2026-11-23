// Command linkcheck checks the project site before it is published. Every
// local link in its pages (href, src and srcset) and in its style (url() in
// a style sheet, a style element or a style attribute) must lead to a file
// in the site, and every #fragment to an id on its page. And no file in it
// except images may hold anything that identifies the computer linkcheck
// runs on (tools/sitecheck: its host name, user name, home directory and
// addresses, and the words in $TELLTALE_SITE_PRIVATE, comma separated). The
// site shows reports made in the lab, and nothing of the computer that made
// them may reach it. A problem says what kind of thing it found, never the
// thing itself.
//
// Usage, from the repository root:
//
//	go run ./tools/linkcheck site                   # after scripts/site-reports.sh
//	go run ./tools/linkcheck -skip reports/ site    # the pages alone
//
// Links starting with -base (default /telltale/, where GitHub Pages serves
// the site) lead into the site; other absolute paths are problems. It reads
// pages with simple patterns, so attributes must be quoted with ". It exits
// 1 when it finds a problem.
package main

import (
	"flag"
	"fmt"
	"html"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/donaldsteele/telltale/tools/sitecheck"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("linkcheck", flag.ContinueOnError)
	fl.SetOutput(stderr)
	base := fl.String("base", "/telltale/", "the path the site is served under")
	skip := fl.String("skip", "", "leave out links into this directory of the site (one made later)")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if fl.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: linkcheck [-base PATH] [-skip DIR/] SITE")
		return 2
	}
	private, err := sitecheck.This(strings.Split(os.Getenv("TELLTALE_SITE_PRIVATE"), ","))
	if err != nil {
		fmt.Fprintf(stderr, "linkcheck: %v\n", err)
		return 2
	}
	c := &checker{root: fl.Arg(0), base: *base, skip: *skip, ids: map[string]map[string]bool{}}
	if err := c.walk(private); err != nil {
		fmt.Fprintf(stderr, "linkcheck: %v\n", err)
		return 2
	}
	sort.Strings(c.problems)
	for _, p := range c.problems {
		fmt.Fprintln(stdout, p)
	}
	fmt.Fprintf(stdout, "linkcheck: %d pages, %d local links, %d files checked against %d private words and addresses: %d problems\n",
		c.pages, c.links, c.read, len(private), len(c.problems))
	if len(c.problems) > 0 {
		return 1
	}
	return 0
}

type checker struct {
	root, base, skip string
	ids              map[string]map[string]bool // page (slash path) -> its ids
	problems         []string
	pages, links     int
	read             int
}

func (c *checker) problem(file, format string, a ...any) {
	c.problems = append(c.problems, file+": "+fmt.Sprintf(format, a...))
}

// imageExt are the files not read for private words: their bytes are no
// text. Everything else is read, whatever its name.
var imageExt = map[string]bool{".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true, ".avif": true, ".ico": true, ".bmp": true}

func (c *checker) walk(private []sitecheck.Private) error {
	return filepath.WalkDir(c.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(c.root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		ext := strings.ToLower(path.Ext(rel))
		if imageExt[ext] {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		c.read++
		found := map[string]bool{}
		for _, w := range private {
			if !found[w.Kind] && w.In(data) {
				found[w.Kind] = true
				c.problem(rel, "holds %s", w.Kind)
			}
		}
		switch ext {
		case ".html", ".htm":
			c.pages++
			c.page(rel, string(data))
			c.style(rel, string(data))
		case ".css":
			c.style(rel, string(data))
		}
		return nil
	})
}

var (
	attrRE   = regexp.MustCompile(`\s(href|src|srcset)="([^"]*)"`)
	idRE     = regexp.MustCompile(`\sid="([^"]*)"`)
	urlRE    = regexp.MustCompile(`url\(\s*(?:"([^"]*)"|'([^']*)'|([^)'"\s]*))\s*\)`)
	schemeRE = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*:`)
)

// page checks the local links of one page.
func (c *checker) page(rel, text string) {
	for _, m := range attrRE.FindAllStringSubmatch(text, -1) {
		values := []string{m[2]}
		if m[1] == "srcset" {
			values = nil
			for _, part := range strings.Split(m[2], ",") {
				if f := strings.Fields(part); len(f) > 0 {
					values = append(values, f[0])
				}
			}
		}
		for _, v := range values {
			c.link(rel, html.UnescapeString(v))
		}
	}
}

// style checks the url() references in a style sheet, or in the style of a
// page; they are relative to the file they are in.
func (c *checker) style(rel, text string) {
	for _, m := range urlRE.FindAllStringSubmatch(text, -1) {
		c.link(rel, html.UnescapeString(m[1]+m[2]+m[3]))
	}
}

func (c *checker) link(page, link string) {
	if link == "" || strings.HasPrefix(link, "//") || schemeRE.MatchString(link) {
		return // external, mail, data
	}
	c.links++
	target, frag, _ := strings.Cut(link, "#")
	target, _, _ = strings.Cut(target, "?")
	var p string
	switch {
	case target == "":
		p = page
	case strings.HasPrefix(target, c.base):
		p = path.Clean(strings.TrimPrefix(target, c.base))
	case strings.HasPrefix(target, "/"):
		c.problem(page, "%s: an absolute link outside %s", link, c.base)
		return
	default:
		p = path.Join(path.Dir(page), target)
	}
	if p == ".." || strings.HasPrefix(p, "../") {
		c.problem(page, "%s: leads out of the site", link)
		return
	}
	if p == "." {
		p = ""
	}
	if c.skip != "" && strings.HasPrefix(p+"/", c.skip) {
		return
	}
	full := filepath.Join(c.root, filepath.FromSlash(p))
	fi, err := os.Stat(full)
	if err == nil && fi.IsDir() {
		p = path.Join(p, "index.html")
		full = filepath.Join(full, "index.html")
		fi, err = os.Stat(full)
	}
	if err != nil || fi.IsDir() {
		c.problem(page, "%s: no such file", link)
		return
	}
	if frag == "" {
		return
	}
	ids, err := c.idsOf(p)
	if err != nil {
		c.problem(page, "%s: %v", link, err)
		return
	}
	if !ids[frag] {
		c.problem(page, "%s: no such id in %s", link, p)
	}
}

func (c *checker) idsOf(p string) (map[string]bool, error) {
	if ids, ok := c.ids[p]; ok {
		return ids, nil
	}
	data, err := os.ReadFile(filepath.Join(c.root, filepath.FromSlash(p)))
	if err != nil {
		return nil, err
	}
	ids := map[string]bool{}
	for _, m := range idRE.FindAllStringSubmatch(string(data), -1) {
		ids[html.UnescapeString(m[1])] = true
	}
	c.ids[p] = ids
	return ids, nil
}
