package snapshot

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/donaldsteele/telltale/internal/model"
)

func sample() *model.Snapshot {
	return New(&model.Collection{Schema: model.CollectionSchema},
		[]model.CheckResult{{ID: "ssh-root", Pass: true}}, bytes.Repeat([]byte{7}, 32))
}

func TestSnapshotRoundTripEncrypted(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, sample(), "hunter2"); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(b.Bytes(), []byte("age-encryption.org/v1")) {
		t.Fatal("not an age file")
	}
	got, err := Read(&b, "hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if got.Schema != model.SnapshotSchema || len(got.Checks) != 1 || got.Checks[0].ID != "ssh-root" {
		t.Fatalf("bad round trip: %+v", got)
	}
}

func TestSnapshotRoundTripPlain(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, sample(), ""); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(b.Bytes(), []byte{0x1f, 0x8b}) {
		t.Fatal("not gzip")
	}
	got, err := Read(&b, "")
	if err != nil || got.Collection == nil {
		t.Fatalf("got %+v err %v", got, err)
	}
}

func TestSnapshotWrongPassphrase(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, sample(), "right"); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(&b, "wrong"); !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("err = %v", err)
	}
}

func TestSnapshotCarriesDigestKey(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, sample(), "p"); err != nil {
		t.Fatal(err)
	}
	got, err := Read(&b, "p")
	if err != nil || !bytes.Equal(got.DigestKey, bytes.Repeat([]byte{7}, 32)) {
		t.Fatalf("key = %x err %v", got.DigestKey, err)
	}
}

func TestAcceptAddsException(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snap.tt")
	if err := WriteFile(path, sample(), "pw"); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	rep := model.Report{Findings: []model.Finding{
		{Key: "k1", Title: "t1", Evidence: []model.Evidence{{After: "PermitRootLogin yes"}}},
		{Key: "k2", Title: "only title"},
	}}
	rb, _ := json.Marshal(rep)
	if err := os.WriteFile(LastReportPath(path), rb, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Accept(path, "pw", "k1", "reviewed", time.Unix(100, 0)); err != nil {
		t.Fatal(err)
	}
	if err := Accept(path, "pw", "k2", "", time.Unix(200, 0)); err != nil {
		t.Fatal(err)
	}
	s, err := ReadFile(path, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Exceptions) != 2 || s.Exceptions[0].AcceptedValue != "PermitRootLogin yes" ||
		s.Exceptions[0].Note != "reviewed" || s.Exceptions[1].AcceptedValue != "only title" {
		t.Fatalf("exceptions %+v", s.Exceptions)
	}
	if err := Accept(path, "pw", "nope", "", time.Now()); !errors.Is(err, ErrUnknownFinding) {
		t.Fatalf("err = %v", err)
	}
	if err := os.Remove(LastReportPath(path)); err != nil {
		t.Fatal(err)
	}
	if err := Accept(path, "pw", "k1", "", time.Now()); err == nil {
		t.Fatal("want error without report")
	}
}

func gz(t *testing.T, v string) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	zw.Write([]byte(v))
	zw.Close()
	return b.Bytes()
}

func TestReadRejectsHostileInput(t *testing.T) {
	cases := map[string][]byte{
		"garbage":        []byte("this is not a snapshot at all"),
		"empty json":     gz(t, "{}"),
		"future schema":  gz(t, `{"schema":99,"collection":{}}`),
		"no collection":  gz(t, `{"schema":1}`),
		"trailing data":  gz(t, `{"schema":1,"collection":{}} {"x":1}`),
		"truncated gzip": gz(t, `{"schema":1,"collection":{}}`)[:12],
	}
	for name, in := range cases {
		if _, err := Read(bytes.NewReader(in), ""); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	_, err := Read(bytes.NewReader(gz(t, `{"schema":99,"collection":{}}`)), "")
	if err == nil || !strings.Contains(err.Error(), "schema 99") || !strings.Contains(err.Error(), "schema 1") {
		t.Fatalf("schema error unclear: %v", err)
	}
}

func TestReadOversize(t *testing.T) {
	old := maxPlainSize
	maxPlainSize = 1 << 20
	defer func() { maxPlainSize = old }()
	big := `{"schema":1,"collection":{},"pad":"` + strings.Repeat("a", 2<<20) + `"}`
	_, err := Read(bytes.NewReader(gz(t, big)), "")
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("err = %v", err)
	}
}

func reportFor(t *testing.T, path string) {
	t.Helper()
	rb, _ := json.Marshal(model.Report{Findings: []model.Finding{{Key: "k", Title: "t"}}})
	if err := os.WriteFile(LastReportPath(path), rb, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAcceptWrongPassphraseLeavesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s")
	if err := WriteFile(path, sample(), "right"); err != nil {
		t.Fatal(err)
	}
	reportFor(t, path)
	before, _ := os.ReadFile(path)
	if err := Accept(path, "wrong", "k", "", time.Now()); !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("err = %v", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("file changed")
	}
}

func TestAcceptPlain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s")
	if err := WriteFile(path, sample(), ""); err != nil {
		t.Fatal(err)
	}
	reportFor(t, path)
	if err := Accept(path, "", "k", "n", time.Now()); err != nil {
		t.Fatal(err)
	}
	s, err := ReadFile(path, "")
	if err != nil || len(s.Exceptions) != 1 {
		t.Fatalf("%+v %v", s, err)
	}
}
