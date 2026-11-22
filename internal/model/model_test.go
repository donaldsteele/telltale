package model

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestSeverityStringsAndOrder(t *testing.T) {
	want := []string{"explained", "note", "weak setting", "backdoor sign", "tampering"}
	sevs := []Severity{SevExplained, SevNote, SevWeak, SevBackdoor, SevTampering}
	for i, s := range sevs {
		if got := s.String(); got != want[i] {
			t.Errorf("Severity(%d).String() = %q, want %q", int(s), got, want[i])
		}
	}
	if !(SevTampering > SevBackdoor && SevBackdoor > SevWeak && SevWeak > SevNote && SevNote > SevExplained) {
		t.Errorf("severity ordering broken")
	}
}

func TestPackagesOwners(t *testing.T) {
	p := Packages{Installed: []Package{
		{Name: "first", Files: []string{"/usr/bin/a", "/usr/bin/shared"}},
		{Name: "second", Files: []string{"/usr/bin/b", "/usr/bin/shared"}},
	}}
	owners := p.Owners()
	want := map[string]string{
		"/usr/bin/a":      "first",
		"/usr/bin/shared": "first",
		"/usr/bin/b":      "second",
	}
	if !reflect.DeepEqual(owners, want) {
		t.Fatalf("Owners() = %v, want %v", owners, want)
	}
	if got := (Packages{}).Owners(); got == nil || len(got) != 0 {
		t.Errorf("Owners() on empty Packages = %v, want empty non-nil map", got)
	}
}

func sampleCollection() *Collection {
	ts := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	ufw := true
	return &Collection{
		Schema:  CollectionSchema,
		Host:    Host{Hostname: "h", OSID: "debian", OSVersionID: "13", OSPretty: "Debian 13", Arch: "amd64", Kernel: "6.12"},
		Time:    ts,
		AsRoot:  true,
		Skipped: []Skip{{Check: "x", Reason: "y"}},
		Files: []FileEntry{{
			Path: "/etc/passwd", Type: "file", Target: "", SHA256: "abc", Caps: "",
			Mode: 0644, UID: 0, GID: 0, Flags: 0x10, Size: 42, MTime: ts, CTime: ts,
		}},
		Accounts: Accounts{
			Users:  []User{{Name: "root", UID: 0, GID: 0, Home: "/root", Shell: "/bin/bash", Password: PasswordState{Set: true, Algo: "yescrypt", Digest: "d", LastChange: 1, MaxDays: 90}}},
			Groups: []Group{{Name: "sudo", GID: 27, Members: []string{"alice"}}},
		},
		Persist: []PersistFile{{
			Path: "/etc/sudoers", Kind: PersistKindSudoers, SHA256: "s", Lines: []string{"root ALL=(ALL) ALL"},
			Redactions: 1, Mode: 0440, UID: 0, MTime: ts,
		}},
		Runtime: Runtime{
			Processes: []Process{{PID: 1, PPID: 0, UID: 0, Exe: "/sbin/init", ExeSHA256: "e", Cmdline: "init", Comm: "init", ExeDeleted: false}},
			Sockets:   []Socket{{Proto: "tcp", Local: "0.0.0.0:22", Remote: "", State: "LISTEN", Inode: 9, PID: 1, Listening: true}},
			Modules:   []KernelModule{{Name: "ext4", File: "/lib/modules/x/ext4.ko", Taint: "", Size: 100}},
			Cmdline:   "BOOT_IMAGE=/vmlinuz",
			Mounts:    []Mount{{Path: "/", FSType: "ext4", Options: "rw", Source: "/dev/sda1"}},
		},
		Packages: Packages{
			Installed: []Package{{
				Name: "openssh-server", Version: "1", Arch: "amd64", Status: "install ok installed",
				Files:     []string{"/usr/sbin/sshd"},
				Conffiles: map[string]string{"/etc/ssh/sshd_config": "md5"},
				LocalMD5:  map[string]string{"/usr/sbin/sshd": "md5b"},
			}},
			Sources: []AptSource{{File: "/etc/apt/sources.list", SignedBy: "k", Types: []string{"deb"}, URIs: []string{"http://deb"}, Suites: []string{"trixie"}, Components: []string{"main"}}},
		},
		Firewall: Firewall{Backend: "nft", InputPolicy: "drop", Tables: 1, Rules: 4, UFWEnabled: &ufw},
		CrossView: []CrossViewResult{{
			Tool: "ps", Ran: true, SkipReason: "", HiddenFromTool: []string{"1234"}, ExtraInTool: []string{"5678"},
		}},
		Sysctl: map[string]string{"net.ipv4.ip_forward": "0"},
	}
}

func TestCollectionJSONRoundTrip(t *testing.T) {
	in := sampleCollection()
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out Collection
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*in, out) {
		t.Fatalf("round trip mismatch\nin:  %+v\nout: %+v", *in, out)
	}
}

func TestSnapshotJSONRoundTrip(t *testing.T) {
	ts := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	in := &Snapshot{
		Schema:     SnapshotSchema,
		Taken:      ts,
		Collection: sampleCollection(),
		Checks:     []CheckResult{{ID: "ssh.root", Pass: false, Observed: "yes", Skipped: ""}},
		DigestKey:  []byte{1, 2, 3},
		Exceptions: []Exception{{FindingKey: "k", AcceptedValue: "v", Note: "n", At: ts}},
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out Snapshot
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*in, out) {
		t.Fatalf("round trip mismatch\nin:  %+v\nout: %+v", *in, out)
	}
}

func TestReportJSONFieldNamesSnakeCase(t *testing.T) {
	r := Report{
		Schema:          ReportSchema,
		Host:            Host{Hostname: "h"},
		Time:            time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC),
		ComparedAgainst: []string{"snap"},
		CouldNotRuleOut: []string{"kernel"},
		Findings:        []Finding{{Key: "k", ID: "id", Title: "t", Severity: SevBackdoor, Source: "snapshot"}},
		Explained:       []Finding{},
		ExitCode:        2,
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(b, &keys); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"compared_against", "could_not_rule_out", "exit_code", "schema", "host", "time", "findings", "explained"} {
		if _, ok := keys[k]; !ok {
			t.Errorf("Report JSON missing key %q; got %s", k, b)
		}
	}
	for _, k := range []string{"ComparedAgainst", "CouldNotRuleOut", "ExitCode"} {
		if strings.Contains(string(b), `"`+k+`"`) {
			t.Errorf("Report JSON contains Go field name %q", k)
		}
	}
}
