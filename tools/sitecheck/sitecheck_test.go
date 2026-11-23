package sitecheck

import (
	"net"
	"sort"
	"strings"
	"testing"
)

// hits is the kinds of private thing found in text.
func hits(ps []Private, text string) []string {
	var out []string
	for _, p := range ps {
		if p.In([]byte(text)) {
			out = append(out, p.Kind)
		}
	}
	sort.Strings(out)
	return out
}

func TestNames(t *testing.T) {
	ps := For(Machine{Host: "kestrel-dev", User: "kestrel-dev", Home: "/home/kestrel-dev"})
	for text, want := range map[string]string{
		"made on KESTREL-DEV today":         "part of this computer's host name,this computer's host name",
		"found in /home/kestrel-dev/code/x": "part of this computer's host name,this computer's home directory,this computer's host name",
		"owner kestrel, the host":           "part of this computer's host name",
		"kestrels nest; akestrel; kestrelx": "",
		"nothing here":                      "",
	} {
		if got := strings.Join(hits(ps, text), ","); got != want {
			t.Errorf("%q: %q, want %q", text, got, want)
		}
	}
}

// Generic names say nothing about a computer, and a short user name only
// counts as a whole word: neither may make an ordinary report fail.
func TestGenericNames(t *testing.T) {
	ps := For(Machine{Host: "ubuntu-server", User: "sam", Home: "/home/sam"})
	for text, want := range map[string]string{
		"SSH server configuration changed on an Ubuntu machine": "",
		"a sample of samba":     "",
		"sudo rule for sam.":    "this computer's user name",
		"made on ubuntu-server": "this computer's host name",
		"/home/sam/notes":       "this computer's home directory,this computer's user name",
		"/home/samuel":          "",
	} {
		if got := strings.Join(hits(ps, text), ","); got != want {
			t.Errorf("%q: %q, want %q", text, got, want)
		}
	}
	for _, p := range For(Machine{Host: "root", User: "root", Home: "/root"}) {
		t.Errorf("a name every machine has counts as private: %s", p.Kind)
	}
}

func TestNameParts(t *testing.T) {
	for name, want := range map[string]string{
		"lab-host01.example": "host01",
		"kestrel-dev":        "kestrel",
		"web-pc12":           "",
		"fv-az1234-56":       "az1234",
		"ubuntu-server":      "",
		"build-runner-01":    "",
	} {
		if got := strings.Join(NameParts(name), ","); got != want {
			t.Errorf("NameParts(%q) = %q, want %q (five or more characters, a letter, not a generic word)", name, got, want)
		}
	}
}

func TestAddressesAndExtra(t *testing.T) {
	ps := For(Machine{Host: "kestrel-dev", Addrs: []net.IP{net.ParseIP("10.1.2.3"), net.ParseIP("fd00::12"), net.ParseIP("127.0.0.1")}, Extra: []string{"Project-X", " ", "ab"}})
	for text, want := range map[string]string{
		"connected to 10.1.2.3.":   "this computer's address",
		"version 10.1.2.34":        "",
		"110.1.2.3":                "",
		"[fd00::12]:22":            "this computer's address",
		"fd00::123":                "",
		"from 127.0.0.1":           "",
		"the project-x plan":       "a word from TELLTALE_SITE_PRIVATE",
		"ab is too short to count": "",
	} {
		if got := strings.Join(hits(ps, text), ","); got != want {
			t.Errorf("%q: %q, want %q", text, got, want)
		}
	}
}

func TestThis(t *testing.T) {
	ps, err := This(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) == 0 {
		t.Error("nothing identifies this computer")
	}
}
