// Command linkcheck checks the project site before it is published. Every
// local link in its pages (href, src and srcset) must lead to a file in the
// site, and every #fragment to an id on its page. And no text file in it
// may hold anything of the computer linkcheck runs on: its host name, its
// user's name and home directory, the parts of those names, its network
// addresses, or a word in $TELLTALE_SITE_PRIVATE (comma separated). The
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
	"net"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
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
	words, err := privateWords()
	if err != nil {
		fmt.Fprintf(stderr, "linkcheck: %v\n", err)
		return 2
	}
	c := &checker{root: fl.Arg(0), base: *base, skip: *skip, ids: map[string]map[string]bool{}}
	if err := c.walk(words); err != nil {
		fmt.Fprintf(stderr, "linkcheck: %v\n", err)
		return 2
	}
	sort.Strings(c.problems)
	for _, p := range c.problems {
		fmt.Fprintln(stdout, p)
	}
	fmt.Fprintf(stdout, "linkcheck: %d pages, %d local links, %d text files checked against %d private words and addresses: %d problems\n",
		c.pages, c.links, c.texts, len(words), len(c.problems))
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
	texts            int
}

func (c *checker) problem(file, format string, a ...any) {
	c.problems = append(c.problems, file+": "+fmt.Sprintf(format, a...))
}

// textExt are the files read for private words; anything else (images,
// fonts) is not text.
var textExt = map[string]bool{".html": true, ".htm": true, ".css": true, ".js": true, ".json": true, ".txt": true, ".svg": true, ".xml": true, ".md": true}

func (c *checker) walk(words []private) error {
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
		if !textExt[ext] {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		c.texts++
		c.private(rel, data, words)
		if ext == ".html" || ext == ".htm" {
			c.pages++
			c.page(rel, string(data))
		}
		return nil
	})
}

var (
	attrRE   = regexp.MustCompile(`\s(href|src|srcset)="([^"]*)"`)
	idRE     = regexp.MustCompile(`\sid="([^"]*)"`)
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

// private is one thing of this computer that must not be in the site, and
// what kind of thing it is (for the problem, which never repeats it).
type private struct {
	kind  string
	word  string         // matched case-insensitively
	match *regexp.Regexp // for an address: the address and not a longer number
}

func (c *checker) private(rel string, data []byte, words []private) {
	low := strings.ToLower(string(data))
	found := map[string]bool{}
	for _, w := range words {
		hit := false
		if w.match != nil {
			hit = w.match.Match(data)
		} else {
			hit = strings.Contains(low, strings.ToLower(w.word))
		}
		if hit && !found[w.kind] {
			found[w.kind] = true
			c.problem(rel, "holds %s", w.kind)
		}
	}
}

// common are names every Linux machine has, the lab's machines too, so
// finding them says nothing about this computer.
var common = map[string]bool{"root": true, "localhost": true, "/root": true, "debian": true, "ubuntu": true, "user": true, "admin": true, "home": true}

// privateWords works out what identifies the computer linkcheck runs on.
func privateWords() ([]private, error) {
	host, err := os.Hostname()
	if err != nil || host == "" {
		return nil, fmt.Errorf("cannot tell this computer's host name (%v), so the site cannot be checked for it", err)
	}
	var out []private
	seen := map[string]bool{}
	add := func(kind, w string) {
		w = strings.TrimSpace(w)
		if len(w) < 3 || common[strings.ToLower(w)] || seen[strings.ToLower(w)] {
			return
		}
		seen[strings.ToLower(w)] = true
		out = append(out, private{kind: kind, word: w})
	}
	add("this computer's host name", host)
	for _, p := range nameParts(host) {
		add("part of this computer's host name", p)
	}
	homes := []string{}
	if u, err := user.Current(); err == nil {
		add("this computer's user name", u.Username)
		for _, p := range nameParts(u.Username) {
			add("part of this computer's user name", p)
		}
		homes = append(homes, u.HomeDir)
	}
	if h, err := os.UserHomeDir(); err == nil {
		homes = append(homes, h)
	}
	for _, h := range homes {
		if strings.HasPrefix(h, "/home/") {
			add("this computer's home directory", h)
		}
	}
	for _, w := range strings.Split(os.Getenv("TELLTALE_SITE_PRIVATE"), ",") {
		add("a word from TELLTALE_SITE_PRIVATE", w)
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, fmt.Errorf("cannot list this computer's addresses (%v), so the site cannot be checked for them", err)
	}
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok || n.IP.IsLoopback() || n.IP.IsLinkLocalUnicast() || n.IP.IsUnspecified() {
			continue
		}
		ip := n.IP.String()
		if seen[ip] {
			continue
		}
		seen[ip] = true
		out = append(out, private{kind: "this computer's address", match: regexp.MustCompile(`(^|[^0-9a-fA-F.:])` + regexp.QuoteMeta(ip) + `($|[^0-9a-fA-F])`)})
	}
	return out, nil
}

// nameParts are the parts of a host or user name, split at anything that is
// not a letter or digit, that are four characters or longer and hold a
// letter: "lab-host01.example" gives "host01" and "example".
func nameParts(name string) []string {
	var parts []string
	for _, p := range strings.FieldsFunc(name, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) {
		if len(p) >= 4 && strings.ContainsFunc(p, unicode.IsLetter) {
			parts = append(parts, p)
		}
	}
	return parts
}
