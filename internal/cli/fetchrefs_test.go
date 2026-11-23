package cli

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/pkgverify"
	"github.com/donaldsteele/telltale/internal/snapshot"
)

func writeCollection(t *testing.T, c *model.Collection, gz bool) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "scan.json")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var w interface {
		Write([]byte) (int, error)
	} = f
	var zw *gzip.Writer
	if gz {
		zw = gzip.NewWriter(f)
		w = zw
	}
	if err := json.NewEncoder(w).Encode(c); err != nil {
		t.Fatal(err)
	}
	if zw != nil {
		zw.Close()
	}
	return p
}

func oldDebianCollection() *model.Collection {
	return &model.Collection{
		Schema: model.CollectionSchema,
		Host:   model.Host{OSID: "debian", OSVersionID: "10", Arch: "amd64"},
		Files:  []model.FileEntry{{Path: "/usr/bin/tool", Type: "file", SHA256: strings.Repeat("a", 64), Mode: 0o100755}},
		Packages: model.Packages{Installed: []model.Package{
			{Name: "tool", Version: "1", Arch: "amd64", Status: "install ok installed", Files: []string{"/usr/bin/tool"}},
		}},
	}
}

func TestFetchRefsUsage(t *testing.T) {
	for _, args := range [][]string{{"fetch-refs"}, {"fetch-refs", "--for", "x.json"}, {"fetch-refs", "--out", "d"}, {"fetch-refs", "--bogus"}} {
		code, out, errs := run(args...)
		if code != ExitUsage || out != "" || !strings.Contains(errs, "usage: telltale fetch-refs --for SCAN.json --out DIR") {
			t.Errorf("%q: code=%d out=%q err=%q", args, code, out, errs)
		}
	}
}

func TestFetchRefsRejectsReports(t *testing.T) {
	// A report shares the schema and host fields but has no package list.
	b, err := json.Marshal(model.Report{Schema: model.ReportSchema, Host: model.Host{Hostname: "web01", OSID: "debian", OSVersionID: "12", Arch: "amd64"}, Findings: []model.Finding{}})
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "report.json")
	os.WriteFile(p, b, 0o600)
	code, _, errs := run("fetch-refs", "--for", p, "--out", filepath.Join(t.TempDir(), "refs"))
	if code != ExitUsage || !strings.Contains(errs, "fetch-refs needs the output of `telltale collect`, not a report") {
		t.Errorf("code=%d err=%q", code, errs)
	}

	// Anything else without packages is refused with the same pointer.
	os.WriteFile(p, []byte(`{"schema":1,"host":{"os_id":"debian"}}`), 0o600)
	code, _, errs = run("fetch-refs", "--for", p, "--out", filepath.Join(t.TempDir(), "refs"))
	if code != ExitUsage || !strings.Contains(errs, "telltale collect") {
		t.Errorf("code=%d err=%q", code, errs)
	}
}

func TestFetchRefsReadsGzipCollection(t *testing.T) {
	// An unsupported release fails before any network access, which shows
	// the gzip-compressed collection was read.
	p := writeCollection(t, oldDebianCollection(), true)
	out := filepath.Join(t.TempDir(), "refs")
	code, _, errs := run("fetch-refs", "--for", p, "--out", out)
	if code != ExitUsage || !strings.Contains(errs, "not supported") {
		t.Errorf("code=%d err=%q", code, errs)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Errorf("a failed run left %s behind (%v)", out, err)
	}
}

func TestFetchRefsRefusesNonEmptyDir(t *testing.T) {
	p := writeCollection(t, oldDebianCollection(), false)
	out := t.TempDir()
	os.WriteFile(filepath.Join(out, "keep"), []byte("x"), 0o600)
	code, _, errs := run("fetch-refs", "--for", p, "--out", out)
	if code != ExitUsage || !strings.Contains(errs, "not empty") {
		t.Errorf("code=%d err=%q", code, errs)
	}
	if b, _ := os.ReadFile(filepath.Join(out, "keep")); string(b) != "x" {
		t.Error("existing file touched")
	}
}

// fetch-refs fetches a third-party repository only for keys the snapshot
// recorded (or --keys, or a built-in vendor key): the keys listed in the
// collection it is given are the examined machine's word.
func TestFetchRefsTakesRepoKeysFromTheSnapshotOnly(t *testing.T) {
	machine := model.RepoTrust{URL: "https://repo.vendor.test/apt", Suite: "stable", Keys: []model.KeyBlob{{Fingerprint: "AA", Data: []byte("m")}}}
	clean := model.RepoTrust{URL: "https://repo.vendor.test/apt", Suite: "stable", Keys: []model.KeyBlob{{Fingerprint: "BB", Data: []byte("s")}}}
	c := oldDebianCollection()
	c.Packages.RepoTrust = []model.RepoTrust{machine}
	scan := writeCollection(t, c, false)
	sc := oldDebianCollection()
	sc.Packages.RepoTrust = []model.RepoTrust{clean}
	snap := filepath.Join(t.TempDir(), "snap")
	if err := snapshot.WriteFile(snap, snapshot.New(sc, nil, []byte("k")), ""); err != nil {
		t.Fatal(err)
	}
	var got []pkgverify.Options
	old := writeBundle
	writeBundle = func(_ context.Context, _ *model.Collection, _ string, opt pkgverify.Options) error {
		got = append(got, opt)
		return nil
	}
	t.Cleanup(func() { writeBundle = old })
	var out, errb strings.Builder
	Run([]string{"fetch-refs", "--for", scan, "--out", filepath.Join(t.TempDir(), "o1")}, strings.NewReader(""), &out, &errb)
	Run([]string{"fetch-refs", "--for", scan, "--out", filepath.Join(t.TempDir(), "o2"), "--snapshot", snap}, strings.NewReader(""), &out, &errb)
	if len(got) != 2 {
		t.Fatalf("bundle written %d times: %s", len(got), errb.String())
	}
	if len(got[0].RepoTrust) != 0 {
		t.Errorf("without a snapshot: RepoTrust = %+v", got[0].RepoTrust)
	}
	if len(got[1].RepoTrust) != 1 || got[1].RepoTrust[0].Keys[0].Fingerprint != "BB" {
		t.Errorf("with a snapshot: RepoTrust = %+v, want the snapshot's", got[1].RepoTrust)
	}
}
