// Command stigrefs regenerates internal/checklist/stig_refs.go from the public
// DISA STIG for Canonical Ubuntu 22.04 LTS.
//
// It downloads the STIG zip (or reads a local copy), parses the XCCDF
// benchmark inside it, checks that every Vuln ID in the mapping table below
// exists in that benchmark, and writes the table as Go source with each
// rule's STIG ID, rule ID and title, so the mapping can be audited.
//
// Usage, from the repository root:
//
//	go run ./tools/stigrefs                  # download from -url
//	go run ./tools/stigrefs -zip FILE.zip    # use a local copy of the zip
//	go run ./tools/stigrefs -list            # print every rule and exit
//
// DISA STIGs are works of the US government and are not under copyright.
// See third_party/stig/README.md.
package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"go/format"
	"io"
	"net/http"
	"os"
	"path"
	"sort"
	"strings"
	"time"
)

// defaultURL is the newest release published by DISA when this generator was
// last run (V2R10, benchmark date 30 Sep 2026). DISA's download host keeps
// one URL per release; bump the release number to pick up a newer one.
const defaultURL = "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CAN_Ubuntu_22-04_LTS_V2R10_STIG.zip"

const maxBytes = 64 << 20

// mapping ties each checklist item to the STIG rules that require the same
// setting, by Vuln ID. It was made by reading each rule's title and check
// text (go run ./tools/stigrefs -list prints them), not by keyword. Items
// with no matching rule are absent: this STIG has no rule for SSH root login,
// MaxAuthTries, host-based login, .rhosts, sshd_config permissions, the
// mode of /etc/shadow and friends, cron directories, most sysctls, TFTP,
// NIS or unattended-upgrades. Deliberately not mapped: TT-ACCT-001 to
// V-260543 (that rule is about duplicate UIDs in general, not UID 0) and
// TT-ACCT-004 to V-260572 (its check requires SHA-512; telltale also accepts
// yescrypt, the stronger Debian and Ubuntu default).
var mapping = map[string][]string{
	"TT-SSH-002": {"V-260526"}, // no unattended SSH login: PermitEmptyPasswords no
	"TT-SSH-004": {"V-260529"}, // X11Forwarding no
	"TT-SSH-010": {"V-260526"}, // no unattended SSH login: PermitUserEnvironment no

	"TT-ACCT-002": {"V-260571"}, // no blank passwords in /etc/shadow
	"TT-ACCT-003": {"V-288817"}, // no interactive shell for system accounts

	"TT-SUDO-001": {"V-274860"}, // no NOPASSWD in sudoers
	"TT-SUDO-002": {"V-260558"}, // no !authenticate in sudoers

	// world-writable commands, libraries and directories without the sticky bit
	"TT-FILE-005": {"V-260485", "V-260486", "V-260487", "V-260513"},

	"TT-FW-001": {"V-260516"}, // an application firewall is enabled (any, not only ufw)

	"TT-KERN-001": {"V-260474"}, // ASLR: kernel.randomize_va_space = 2
	"TT-KERN-004": {"V-260472"}, // kernel.dmesg_restrict = 1
	"TT-KERN-008": {"V-260522"}, // TCP syncookies

	"TT-SVC-001": {"V-260483"}, // telnetd not installed
	"TT-SVC-002": {"V-260482"}, // rsh-server not installed
	"TT-SVC-005": {"V-260590"}, // auditd installed
	"TT-SVC-006": {"V-260557"}, // AppArmor active
}

type rule struct {
	VulnID, RuleID, StigID, Severity, Title string
}

type benchmark struct {
	ID      string `xml:"id,attr"`
	Title   string `xml:"title"`
	Version string `xml:"version"`
	Status  struct {
		Date string `xml:"date,attr"`
	} `xml:"status"`
	PlainText []struct {
		ID   string `xml:"id,attr"`
		Text string `xml:",chardata"`
	} `xml:"plain-text"`
	Groups []struct {
		ID   string `xml:"id,attr"`
		Rule struct {
			ID       string `xml:"id,attr"`
			Severity string `xml:"severity,attr"`
			Version  string `xml:"version"`
			Title    string `xml:"title"`
		} `xml:"Rule"`
	} `xml:"Group"`
}

func main() {
	url := flag.String("url", defaultURL, "STIG zip to download")
	local := flag.String("zip", "", "read this local zip instead of downloading")
	out := flag.String("out", "internal/checklist/stig_refs.go", "file to write")
	list := flag.Bool("list", false, "print every rule in the benchmark and exit")
	flag.Parse()
	if err := run(*url, *local, *out, *list); err != nil {
		fmt.Fprintln(os.Stderr, "stigrefs:", err)
		os.Exit(1)
	}
}

func run(url, local, out string, list bool) error {
	var data []byte
	var err error
	source := url
	if local != "" {
		data, err = readLimited(local)
		source = path.Base(local)
	} else {
		data, err = download(url)
	}
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	name, xmlData, err := findXCCDF(data)
	if err != nil {
		return err
	}
	var b benchmark
	if err := xml.Unmarshal(xmlData, &b); err != nil {
		return fmt.Errorf("parse %s: %w", name, err)
	}
	rules := map[string]rule{}
	var order []string
	for _, g := range b.Groups {
		if !strings.HasPrefix(g.ID, "V-") {
			continue
		}
		rules[g.ID] = rule{VulnID: g.ID, RuleID: g.Rule.ID, StigID: g.Rule.Version, Severity: g.Rule.Severity, Title: oneLine(g.Rule.Title)}
		order = append(order, g.ID)
	}
	if len(rules) == 0 {
		return fmt.Errorf("%s: no rules found", name)
	}
	if list {
		for _, id := range order {
			r := rules[id]
			fmt.Printf("%s\t%s\t%s\t%s\t%s\n", r.VulnID, r.StigID, r.RuleID, r.Severity, r.Title)
		}
		return nil
	}
	release := ""
	for _, p := range b.PlainText {
		if p.ID == "release-info" {
			release = oneLine(p.Text)
		}
	}
	src, err := render(source, hex.EncodeToString(sum[:]), name, b, release, rules)
	if err != nil {
		return err
	}
	return os.WriteFile(out, src, 0o644)
}

func readLimited(p string) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return limitedRead(f)
}

func limitedRead(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxBytes {
		return nil, fmt.Errorf("larger than %d bytes", maxBytes)
	}
	return b, nil
}

func download(url string) ([]byte, error) {
	c := &http.Client{Timeout: 2 * time.Minute}
	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return limitedRead(resp.Body)
}

// findXCCDF returns the name and content of the manual XCCDF benchmark in
// the zip.
func findXCCDF(data []byte) (string, []byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", nil, err
	}
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, "-xccdf.xml") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return "", nil, err
		}
		b, err := limitedRead(rc)
		rc.Close()
		if err != nil {
			return "", nil, fmt.Errorf("%s: %w", f.Name, err)
		}
		return f.Name, b, nil
	}
	return "", nil, errors.New("no *-xccdf.xml file in the zip")
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

func render(source, sum, name string, b benchmark, release string, rules map[string]rule) ([]byte, error) {
	ids := make([]string, 0, len(mapping))
	for id := range mapping {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var w bytes.Buffer
	fmt.Fprintf(&w, "// Code generated by go run ./tools/stigrefs; DO NOT EDIT.\n\n")
	fmt.Fprintf(&w, "// Source: %s\n", source)
	fmt.Fprintf(&w, "// Zip SHA-256: %s\n", sum)
	fmt.Fprintf(&w, "// Benchmark file: %s\n", name)
	fmt.Fprintf(&w, "// Benchmark: %s (%s), version %s, %s, status date %s\n", oneLine(b.Title), b.ID, oneLine(b.Version), release, b.Status.Date)
	fmt.Fprintf(&w, "// Generated: %s\n", time.Now().UTC().Format("2006-01-02"))
	fmt.Fprintf(&w, "//\n// DISA STIGs are US government works, not under copyright.\n// See third_party/stig/README.md.\n\n")
	fmt.Fprintf(&w, "package checklist\n\n")
	fmt.Fprintf(&w, "// stigRefs maps a checklist item ID to the DISA STIG rules that require\n// the same setting.\n")
	fmt.Fprintf(&w, "var stigRefs = map[string][]string{\n")
	for _, id := range ids {
		fmt.Fprintf(&w, "\t%q: {\n", id)
		for _, v := range mapping[id] {
			r, ok := rules[v]
			if !ok {
				return nil, fmt.Errorf("%s maps to %s, which is not in %s", id, v, name)
			}
			fmt.Fprintf(&w, "\t\t// %s %s: %s\n", r.RuleID, r.Severity, r.Title)
			fmt.Fprintf(&w, "\t\t%q,\n", fmt.Sprintf("STIG %s (%s)", r.VulnID, r.StigID))
		}
		fmt.Fprintf(&w, "\t},\n")
	}
	fmt.Fprintf(&w, "}\n")
	return format.Source(w.Bytes())
}
