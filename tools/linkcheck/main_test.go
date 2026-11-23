package main

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func problems(t *testing.T, args ...string) ([]string, int) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(args, &out, &errOut)
	var got []string
	for _, l := range strings.Split(out.String(), "\n") {
		if l != "" && !strings.HasPrefix(l, "linkcheck: ") {
			got = append(got, l)
		}
	}
	sort.Strings(got)
	if errOut.Len() > 0 {
		t.Logf("stderr: %s", errOut.String())
	}
	return got, code
}

func TestLinks(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "index.html", `<!doctype html><title>x</title><body id="top">
<a href="a.html">ok</a> <a href="b.html">missing</a>
<a href="a.html#here">ok</a> <a href="a.html#nowhere">missing id</a>
<a href="#top">ok</a> <a href="#gone">missing id here</a>
<a href="/telltale/a.html">ok, under the base</a> <a href="/elsewhere/x.html">outside</a>
<a href="https://example.com/">external</a> <a href="mailto:x@example.com">mail</a>
<a href="sub/">a directory with index.html</a> <a href="sub/x.txt?v=1">query</a>
<img src="img.png" srcset="img.png 1x, big.png 2x" alt="">
<a href="../outside.html">leaves the site</a>
<a href="reports/one.html">generated later</a>
<a href="a.html?x=1&amp;y=2">escaped</a>
</body>`)
	write(t, dir, "a.html", `<p id="here">here</p>`)
	write(t, dir, "img.png", "png")
	write(t, dir, "sub/index.html", `<a href="../index.html#top">back</a>`)
	write(t, dir, "sub/x.txt", "x")

	got, code := problems(t, dir)
	want := []string{
		"index.html: #gone: no such id in index.html",
		"index.html: ../outside.html: leads out of the site",
		"index.html: /elsewhere/x.html: an absolute link outside /telltale/",
		"index.html: a.html#nowhere: no such id in a.html",
		"index.html: b.html: no such file",
		"index.html: big.png: no such file",
		"index.html: reports/one.html: no such file",
	}
	if code != 1 || strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("exit %d, problems:\n%s\nwant:\n%s", code, strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	// -skip leaves out what is made later.
	got, _ = problems(t, "-skip", "reports/", dir)
	for _, p := range got {
		if strings.Contains(p, "reports/") {
			t.Errorf("-skip reports/ still reports %q", p)
		}
	}

	clean := t.TempDir()
	write(t, clean, "index.html", `<a href="a.html#x">a</a>`)
	write(t, clean, "a.html", `<h2 id="x">x</h2>`)
	if got, code := problems(t, clean); code != 0 || len(got) != 0 {
		t.Errorf("a good site: exit %d, %q", code, got)
	}
}

func TestPrivate(t *testing.T) {
	host, err := os.Hostname()
	if err != nil || host == "" {
		t.Skip("no host name")
	}
	t.Setenv("TELLTALE_SITE_PRIVATE", "Secret-Word")
	dir := t.TempDir()
	write(t, dir, "index.html", `<p>made on `+strings.ToUpper(host)+`</p>`)
	write(t, dir, "data/report.json", `{"note": "a secret-word here"}`)
	write(t, dir, "ok.txt", "nothing of this computer")
	if home, err := os.UserHomeDir(); err == nil && strings.HasPrefix(home, "/home/") {
		write(t, dir, "home.txt", "found in "+home+"/code")
	}
	var ip string
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && !n.IP.IsLoopback() && !n.IP.IsLinkLocalUnicast() && n.IP.To4() != nil {
				ip = n.IP.String()
				break
			}
		}
	}
	if ip != "" {
		write(t, dir, "ip.txt", "connected to "+ip+".")
		write(t, dir, "notip.txt", "version "+ip+"5 is not the address")
	}
	// A binary file is not read: its bytes are no text.
	write(t, dir, "shot.png", host)

	got, code := problems(t, dir)
	joined := strings.Join(got, "\n")
	if code != 1 || !strings.Contains(joined, "index.html: holds this computer's host name") || !strings.Contains(joined, "data/report.json: holds a word from TELLTALE_SITE_PRIVATE") {
		t.Errorf("exit %d, problems:\n%s", code, joined)
	}
	if strings.Contains(joined, "ok.txt") || strings.Contains(joined, "shot.png") || strings.Contains(joined, "notip.txt") {
		t.Errorf("reports a file that holds nothing private:\n%s", joined)
	}
	if strings.HasPrefix(os.Getenv("HOME"), "/home/") && !strings.Contains(joined, "home.txt: holds this computer's home directory") {
		t.Errorf("the home directory is not found:\n%s", joined)
	}
	if ip != "" && !strings.Contains(joined, "ip.txt: holds this computer's address") {
		t.Errorf("the address %s is not found:\n%s", ip, joined)
	}
	// What is private is never printed: the problems say what kind of
	// thing was found, not the thing.
	if strings.Contains(strings.ToLower(joined), strings.ToLower(host)) || (ip != "" && strings.Contains(joined, ip)) {
		t.Errorf("the problems repeat what they found:\n%s", joined)
	}
}

func TestPrivateWordParts(t *testing.T) {
	words := nameParts("lab-host01.example")
	want := []string{"example", "host01"}
	sort.Strings(words)
	if strings.Join(words, ",") != strings.Join(want, ",") {
		t.Errorf("nameParts = %q, want %q (parts of four or more characters with a letter)", words, want)
	}
	if got := nameParts("fv-az1-3456"); len(got) != 0 {
		t.Errorf("nameParts of a name whose long parts are numbers = %q, want none", got)
	}
}

// The site in the repository: every link resolves, except the reports
// scripts/site-reports.sh makes, and nothing private is in it.
func TestRepositorySite(t *testing.T) {
	got, code := problems(t, "-skip", "reports/", filepath.Join("..", "..", "site"))
	if code != 0 {
		t.Errorf("site/ has problems:\n%s", strings.Join(got, "\n"))
	}
}
