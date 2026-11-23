// Package sitecheck says whether a file of the project site holds anything
// that identifies the computer that made it: its host name, its user's name
// and home directory, the telling parts of those names, its network
// addresses, and words the owner adds. The site shows reports made in the
// lab, and nothing of the computer running the lab may reach it.
// tools/linkcheck and the lab's TestGenerateSiteReports both use it.
//
// What is private is worked out where the check runs, never written down,
// so the repository does not hold it either. Names match as whole words
// (case ignored), and generic names that any machine might have do not
// count, so an ordinary report on an ordinary computer passes.
package sitecheck

import (
	"fmt"
	"net"
	"os"
	"os/user"
	"regexp"
	"strings"
	"unicode"
)

// Private is one thing of the computer, and what kind of thing it is. A
// finding names the kind, never the thing.
type Private struct {
	Kind string
	re   *regexp.Regexp
}

// In reports whether text holds the thing.
func (p Private) In(text []byte) bool { return p.re.Match(text) }

// Machine is what identifies a computer.
type Machine struct {
	Host, User, Home string
	Addrs            []net.IP
	// Extra are more words the owner counts as private.
	Extra []string
}

// This is For the computer it runs on, with extra words.
func This(extra []string) ([]Private, error) {
	host, err := os.Hostname()
	if err != nil || host == "" {
		return nil, fmt.Errorf("cannot tell this computer's host name (%v), so the site cannot be checked for it", err)
	}
	m := Machine{Host: host, Extra: extra}
	if u, err := user.Current(); err == nil {
		m.User, m.Home = u.Username, u.HomeDir
	}
	if m.Home == "" {
		m.Home, _ = os.UserHomeDir()
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, fmt.Errorf("cannot list this computer's addresses (%v), so the site cannot be checked for them", err)
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			m.Addrs = append(m.Addrs, n.IP)
		}
	}
	return For(m), nil
}

// common are names every Linux machine has, the lab's machines too.
var common = map[string]bool{
	"root": true, "localhost": true, "debian": true, "ubuntu": true, "user": true,
	"admin": true, "home": true, "lab": true, "server": true, "linux": true,
}

// generic are words that turn up in host and user names without saying
// which computer it is ("ubuntu-server", "build-runner-01").
var generic = map[string]bool{
	"server": true, "desktop": true, "laptop": true, "workstation": true, "linux": true,
	"debian": true, "ubuntu": true, "fedora": true, "local": true, "localdomain": true,
	"domain": true, "admin": true, "users": true, "build": true, "builder": true,
	"runner": true, "worker": true, "github": true, "azure": true, "cloud": true,
	"internal": true, "compute": true, "amazonaws": true, "virtual": true,
	"docker": true, "vagrant": true, "default": true, "example": true, "network": true,
	"office": true, "client": true, "machine": true, "devbox": true, "testing": true,
}

// For works out what identifies m.
func For(m Machine) []Private {
	var out []Private
	seen := map[string]bool{}
	add := func(kind, w string) {
		w = strings.TrimSpace(w)
		low := strings.ToLower(w)
		if len(w) < 3 || common[low] || seen[low] {
			return
		}
		seen[low] = true
		out = append(out, Private{Kind: kind, re: wordRE(w)})
	}
	add("this computer's host name", m.Host)
	for _, p := range NameParts(m.Host) {
		add("part of this computer's host name", p)
	}
	add("this computer's user name", m.User)
	for _, p := range NameParts(m.User) {
		add("part of this computer's user name", p)
	}
	if strings.HasPrefix(m.Home, "/home/") {
		add("this computer's home directory", m.Home)
	}
	for _, w := range m.Extra {
		add("a word from TELLTALE_SITE_PRIVATE", w)
	}
	for _, ip := range m.Addrs {
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			continue
		}
		s := ip.String()
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, Private{Kind: "this computer's address",
			re: regexp.MustCompile(`(^|[^0-9a-fA-F.:])` + regexp.QuoteMeta(s) + `($|[^0-9a-fA-F])`)})
	}
	return out
}

// wordRE matches w as a whole word, case ignored: where w starts or ends
// with a letter or digit, the text next to it must not be one.
func wordRE(w string) *regexp.Regexp {
	pre, post := "", ""
	if r := []rune(w); isWordRune(r[0]) {
		pre = `(?:^|[^\p{L}\p{N}])`
	}
	if r := []rune(w); isWordRune(r[len(r)-1]) {
		post = `(?:$|[^\p{L}\p{N}])`
	}
	return regexp.MustCompile(`(?i)` + pre + regexp.QuoteMeta(w) + post)
}

func isWordRune(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }

// NameParts are the telling parts of a host or user name: split at anything
// that is not a letter or digit, five characters or longer, with a letter,
// and not a generic word. "lab-host01.example" gives "host01".
func NameParts(name string) []string {
	var parts []string
	for _, p := range strings.FieldsFunc(name, func(r rune) bool { return !isWordRune(r) }) {
		if len(p) >= 5 && strings.ContainsFunc(p, unicode.IsLetter) && !generic[strings.ToLower(p)] && !common[strings.ToLower(p)] {
			parts = append(parts, p)
		}
	}
	return parts
}
