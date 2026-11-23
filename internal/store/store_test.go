package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/donaldsteele/telltale/internal/model"
)

const testHost = "marker-host-7f3a.example"

func init() { scryptWorkFactor = 10 }

func tmpDB(t *testing.T) string { return filepath.Join(t.TempDir(), "server.db") }

func openPass(t *testing.T, path, pass string) *Store {
	t.Helper()
	s, err := Open(path, Unlock{Passphrase: pass})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func testSnap() *model.Snapshot {
	return &model.Snapshot{
		Schema:     model.SnapshotSchema,
		Taken:      time.Now().UTC(),
		Collection: &model.Collection{Host: model.Host{Hostname: testHost}},
		DigestKey:  []byte("digestkey"),
	}
}

func addM(t *testing.T, s *Store, name string) int64 {
	t.Helper()
	id, err := s.AddMachine(Machine{Name: name, Addr: name + ":22", Arch: "amd64", Schedule: "daily"})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestOpenCreatesAndUnlocks(t *testing.T) {
	p := tmpDB(t)
	s, err := Open(p, Unlock{Passphrase: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetSetting("k", "v"); err != nil {
		t.Fatal(err)
	}
	id := addM(t, s, "alpha")
	s.Close()
	s2 := openPass(t, p, "pw")
	if v, _ := s2.Setting("k"); v != "v" {
		t.Fatalf("setting = %q", v)
	}
	m, err := s2.Machine(id)
	if err != nil || m.Name != "alpha" || m.Created.IsZero() {
		t.Fatalf("machine = %+v, %v", m, err)
	}
	if v, _ := s2.Setting("schema_version"); v == "" {
		t.Fatal("no schema version")
	}
}

func TestWrongPassphraseFails(t *testing.T) {
	p := tmpDB(t)
	s := openPass(t, p, "right")
	if err := s.SetSecretSetting("x", []byte("y")); err != nil {
		t.Fatal(err)
	}
	wrapped, _ := s.Setting("wrapped_key")
	s.Close()
	_, err := Open(p, Unlock{Passphrase: "wrong"})
	if err == nil || !strings.Contains(err.Error(), "wrong passphrase or key file") {
		t.Fatalf("err = %v", err)
	}
	s2 := openPass(t, p, "right")
	if w, _ := s2.Setting("wrapped_key"); w != wrapped {
		t.Fatal("a second key was created")
	}
	if v, err := s2.SecretSetting("x"); err != nil || string(v) != "y" {
		t.Fatalf("secret lost: %q %v", v, err)
	}
}

func TestKeyFileUnlock(t *testing.T) {
	dir := t.TempDir()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	kf := filepath.Join(dir, "key.txt")
	if err := os.WriteFile(kf, []byte("# comment\n"+id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "s.db")
	s, err := Open(p, Unlock{KeyFile: kf})
	if err != nil {
		t.Fatal(err)
	}
	s.SetSetting("a", "b")
	s.Close()
	s2, err := Open(p, Unlock{KeyFile: kf})
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := s2.Setting("a"); v != "b" {
		t.Fatal("not reopened")
	}
	s2.Close()
	other, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	kf2 := filepath.Join(dir, "other.txt")
	if err := os.WriteFile(kf2, []byte(other.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(p, Unlock{KeyFile: kf2}); err == nil {
		t.Fatal("other key file opened the store")
	}
	if _, err := Open(p, Unlock{Passphrase: "pw"}); err == nil {
		t.Fatal("passphrase opened a key-file store")
	}
}

func TestOpenRejectsBothOrNeither(t *testing.T) {
	p := tmpDB(t)
	if _, err := Open(p, Unlock{}); err == nil {
		t.Fatal("neither accepted")
	}
	if _, err := Open(p, Unlock{Passphrase: "a", KeyFile: "b"}); err == nil {
		t.Fatal("both accepted")
	}
	if _, err := os.Stat(p); err == nil {
		t.Fatal("db created despite bad unlock")
	}
}

func TestSnapshotRoundTripEncryptedAtRest(t *testing.T) {
	p := tmpDB(t)
	s := openPass(t, p, "pw")
	id := addM(t, s, "alpha")
	if got, err := s.Snapshot(id); err != nil || got != nil {
		t.Fatalf("empty snapshot = %v, %v", got, err)
	}
	if err := s.PutSnapshot(id, testSnap()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutReport(id, &model.Report{Host: model.Host{Hostname: testHost}}, &model.Collection{Host: model.Host{Hostname: testHost}}); err != nil {
		t.Fatal(err)
	}
	got, err := s.Snapshot(id)
	if err != nil || got == nil || got.Collection.Host.Hostname != testHost {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	check := func(when string) {
		t.Helper()
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, []byte(testHost)) {
			t.Fatalf("hostname in clear in db %s", when)
		}
		// The WAL may or may not exist (a checkpoint can remove it).
		if w, err := os.ReadFile(p + "-wal"); err == nil && bytes.Contains(w, []byte(testHost)) {
			t.Fatalf("hostname in clear in wal %s", when)
		}
	}
	check("before close")
	s.Close()
	check("after close")
}

func TestBlobBoundToRow(t *testing.T) {
	s := openPass(t, tmpDB(t), "pw")
	a, b := addM(t, s, "a"), addM(t, s, "b")
	s.PutSnapshot(a, testSnap())
	s.PutSnapshot(b, testSnap())
	if _, err := s.db.Exec(`UPDATE snapshots SET blob = (SELECT blob FROM snapshots WHERE machine_id = ?) WHERE machine_id = ?`, a, b); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Snapshot(b); err == nil {
		t.Fatal("blob copied into another row decrypted")
	}
	if got, err := s.Snapshot(a); err != nil || got == nil {
		t.Fatalf("original broken: %v", err)
	}
	// An exception blob copied over another row of the same machine fails.
	s.AddException(a, model.Exception{FindingKey: "k1"})
	s.AddException(a, model.Exception{FindingKey: "k2"})
	if _, err := s.db.Exec(`UPDATE exceptions SET blob = (SELECT blob FROM exceptions ORDER BY id LIMIT 1) WHERE id = (SELECT max(id) FROM exceptions)`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Exceptions(a); err == nil {
		t.Fatal("exception blob copied into another row decrypted")
	}
	// A report row moved to another machine fails to open.
	mid, _ := s.PutReport(a, &model.Report{}, &model.Collection{})
	s.db.Exec(`UPDATE reports SET machine_id = ? WHERE id = ?`, b, mid)
	if _, _, err := s.Report(mid); err == nil {
		t.Fatal("report moved to another machine opened")
	}
	if _, err := s.Reports(b, 10); err == nil {
		t.Fatal("report meta moved to another machine opened")
	}
	s.db.Exec(`UPDATE reports SET machine_id = ? WHERE id = ?`, a, mid)
	// Purpose binding: a report blob cannot be read as a collection.
	rid, _ := s.PutReport(a, &model.Report{}, &model.Collection{})
	s.db.Exec(`UPDATE reports SET collection_blob = report_blob WHERE id = ?`, rid)
	if _, _, err := s.Report(rid); err == nil {
		t.Fatal("report blob opened as collection")
	}
}

func TestReportOnly(t *testing.T) {
	s := openPass(t, tmpDB(t), "pw")
	id := addM(t, s, "a")
	rid, err := s.PutReport(id, &model.Report{ExitCode: 2, Host: model.Host{Hostname: "h"}}, &model.Collection{Host: model.Host{Hostname: "big"}})
	if err != nil {
		t.Fatal(err)
	}
	r, mid, err := s.ReportOnly(rid)
	if err != nil || mid != id || r.ExitCode != 2 || r.Host.Hostname != "h" {
		t.Fatalf("ReportOnly: %+v %d %v", r, mid, err)
	}
	if _, _, err := s.ReportOnly(rid + 100); err == nil {
		t.Error("a missing report opened")
	}
}

func TestReportsHistoryOrder(t *testing.T) {
	s := openPass(t, tmpDB(t), "pw")
	id := addM(t, s, "a")
	other := addM(t, s, "b")
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var ids []int64
	for i := 0; i < 3; i++ {
		r := &model.Report{Time: base.Add(time.Duration(i) * time.Hour), ExitCode: i, Findings: make([]model.Finding, i)}
		rid, err := s.PutReport(id, r, &model.Collection{Host: model.Host{Hostname: "h"}})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, rid)
	}
	s.PutReport(other, &model.Report{Time: base}, &model.Collection{})
	got, err := s.Reports(id, 10)
	if err != nil || len(got) != 3 {
		t.Fatalf("%v %v", got, err)
	}
	for i, m := range got {
		if m.ID != ids[2-i] || m.MachineID != id {
			t.Fatalf("order: %+v", got)
		}
	}
	if got[0].ExitCode != 2 || got[0].Findings != 2 {
		t.Fatalf("meta: %+v", got[0])
	}
	if l, _ := s.Reports(id, 2); len(l) != 2 {
		t.Fatal("limit ignored")
	}
	r, c, err := s.Report(ids[1])
	if err != nil || r.ExitCode != 1 || c.Host.Hostname != "h" {
		t.Fatalf("Report: %+v %+v %v", r, c, err)
	}
}

func TestAuditLog(t *testing.T) {
	s := openPass(t, tmpDB(t), "pw")
	for _, a := range []string{"enrol", "visit", "accept"} {
		if err := s.Audit("admin", a, "detail "+a); err != nil {
			t.Fatal(err)
		}
	}
	l, err := s.AuditLog(2)
	if err != nil || len(l) != 2 || l[0].Action != "accept" || l[1].Action != "visit" || l[0].Actor != "admin" || l[0].Time.IsZero() {
		t.Fatalf("%+v %v", l, err)
	}
	if _, err := s.db.Exec(`UPDATE audit SET detail = 'x'`); err == nil {
		t.Fatal("audit update allowed")
	}
	if _, err := s.db.Exec(`DELETE FROM audit`); err == nil {
		t.Fatal("audit delete allowed")
	}
}

func TestSecretSettings(t *testing.T) {
	p := tmpDB(t)
	s := openPass(t, p, "pw")
	if v, err := s.SecretSetting("ssh"); err != nil || v != nil {
		t.Fatalf("missing: %v %v", v, err)
	}
	if err := s.SetSecretSetting("ssh", []byte("TOPSECRET-KEY-MATERIAL")); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSecretSetting("ssh", []byte("TOPSECRET-KEY-MATERIAL")); err != nil {
		t.Fatal(err)
	}
	if v, err := s.SecretSetting("ssh"); err != nil || string(v) != "TOPSECRET-KEY-MATERIAL" {
		t.Fatalf("%q %v", v, err)
	}
	if err := s.SetSetting("wrapped_key", "x"); err == nil {
		t.Fatal("reserved setting writable")
	}
	s.Close()
	b, _ := os.ReadFile(p)
	if bytes.Contains(b, []byte("TOPSECRET")) {
		t.Fatal("secret in clear")
	}
}

func TestExceptionsAndMachines(t *testing.T) {
	s := openPass(t, tmpDB(t), "pw")
	id := addM(t, s, "a")
	if err := s.AddException(id, model.Exception{FindingKey: "k", AcceptedValue: "v", At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	ex, err := s.Exceptions(id)
	if err != nil || len(ex) != 1 || ex[0].AcceptedValue != "v" {
		t.Fatalf("%+v %v", ex, err)
	}
	m, _ := s.Machine(id)
	now := time.Now().UTC()
	m.Clean, m.LastVisit = true, &now
	if err := s.UpdateMachine(*m); err != nil {
		t.Fatal(err)
	}
	m2, _ := s.Machine(id)
	if !m2.Clean || m2.LastVisit == nil {
		t.Fatalf("%+v", m2)
	}
	if l, _ := s.Machines(); len(l) != 1 {
		t.Fatal("Machines")
	}
	if _, err := s.Machine(999); err == nil {
		t.Fatal("missing machine")
	}
}

func TestFileModes(t *testing.T) {
	p := tmpDB(t)
	s := openPass(t, p, "pw")
	id := addM(t, s, "a")
	s.PutSnapshot(id, testSnap())
	for _, suffix := range []string{"", "-wal", "-shm"} {
		fi, err := os.Stat(p + suffix)
		if err != nil {
			if suffix == "" {
				t.Fatal(err)
			}
			continue
		}
		if fi.Mode().Perm()&0o077 != 0 {
			t.Fatalf("%s mode %v", p+suffix, fi.Mode().Perm())
		}
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
}

func TestRelativePath(t *testing.T) {
	dir := t.TempDir()
	old, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)
	s, err := Open("rel.db", Unlock{Passphrase: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := os.Stat(filepath.Join(dir, "rel.db")); err != nil {
		t.Fatal(err)
	}
	openPass(t, "rel.db", "pw")
}

func TestFailedOpenLeavesNoFile(t *testing.T) {
	p := tmpDB(t)
	if _, err := Open(p, Unlock{KeyFile: filepath.Join(t.TempDir(), "no", "such", "key")}); err == nil {
		t.Fatal("expected error")
	}
	if _, err := os.Stat(p); err == nil {
		t.Fatal("empty db left behind")
	}
}

func TestMissingKeyWithDataRefused(t *testing.T) {
	p := tmpDB(t)
	s := openPass(t, p, "pw")
	addM(t, s, "a")
	if _, err := s.db.Exec(`DELETE FROM settings WHERE key='wrapped_key'`); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := Open(p, Unlock{Passphrase: "other"}); !errors.Is(err, ErrNoKeyButData) {
		t.Fatalf("err = %v", err)
	}
	if _, err := Open(p, Unlock{Passphrase: "pw"}); !errors.Is(err, ErrNoKeyButData) {
		t.Fatalf("err = %v", err)
	}
}

func TestSchemaVersionChecks(t *testing.T) {
	p := tmpDB(t)
	s := openPass(t, p, "pw")
	if _, err := s.db.Exec(`DELETE FROM settings WHERE key='schema_version'`); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s = openPass(t, p, "pw") // backfilled
	if v, _ := s.Setting("schema_version"); v != "1" {
		t.Fatalf("backfill = %q", v)
	}
	if _, err := s.db.Exec(`UPDATE settings SET value='99' WHERE key='schema_version'`); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := Open(p, Unlock{Passphrase: "pw"}); err == nil || !strings.Contains(err.Error(), "newer") {
		t.Fatalf("err = %v", err)
	}
}

func TestKeyFileCreateAndModes(t *testing.T) {
	dir := t.TempDir()
	kf := filepath.Join(dir, "new.key")
	p := filepath.Join(dir, "s.db")
	s, err := Open(p, Unlock{KeyFile: kf})
	if err != nil {
		t.Fatal(err)
	}
	s.SetSetting("a", "b")
	s.Close()
	fi, err := os.Stat(kf)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v %v", fi, err)
	}
	openKF := func() error {
		s, err := Open(p, Unlock{KeyFile: kf})
		if err == nil {
			s.Close()
		}
		return err
	}
	if err := openKF(); err != nil {
		t.Fatal(err)
	}
	os.Chmod(kf, 0o644)
	if err := openKF(); err == nil || !strings.Contains(err.Error(), "accessible by group or others") {
		t.Fatalf("err = %v", err)
	}
}

func TestZeroTimeStoredAsZero(t *testing.T) {
	s := openPass(t, tmpDB(t), "pw")
	id, err := s.AddMachine(Machine{Name: "z", Addr: "z"})
	if err != nil {
		t.Fatal(err)
	}
	var lv *int64
	if err := s.db.QueryRow(`SELECT last_visit FROM machines WHERE id=?`, id).Scan(&lv); err != nil || lv != nil {
		t.Fatalf("last_visit = %v %v", lv, err)
	}
	rid, _ := s.PutReport(id, &model.Report{}, &model.Collection{})
	l, err := s.Reports(id, 1)
	if err != nil || len(l) != 1 || l[0].ID != rid || !l[0].Time.IsZero() {
		t.Fatalf("%+v %v", l, err)
	}
}

func TestReportMetaSealed(t *testing.T) {
	s := openPass(t, tmpDB(t), "pw")
	id := addM(t, s, "a")
	s.PutReport(id, &model.Report{ExitCode: 7, Time: time.Now()}, &model.Collection{})
	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM pragma_table_info('reports') WHERE name IN ('time','exit_code','findings')`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("plaintext metadata columns: %d %v", n, err)
	}
}

func TestConcurrentFirstOpen(t *testing.T) {
	p := tmpDB(t)
	const n = 6
	type res struct {
		s   *Store
		err error
	}
	out := make(chan res, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		pw := "one"
		if i%2 == 1 {
			pw = "two"
		}
		go func() {
			<-start
			s, err := Open(p, Unlock{Passphrase: pw})
			out <- res{s, err}
		}()
	}
	close(start)
	ok := 0
	for i := 0; i < n; i++ {
		r := <-out
		switch {
		case r.err == nil:
			ok++
			defer r.s.Close()
		case strings.Contains(r.err.Error(), "disk I/O"), strings.Contains(r.err.Error(), "BUSY"), strings.Contains(r.err.Error(), "locked"):
			t.Errorf("opener failed: %v", r.err)
		case !errors.Is(r.err, ErrWrongUnlock):
			t.Errorf("unexpected error: %v", r.err)
		}
	}
	if ok == 0 {
		t.Fatal("nobody opened")
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal(err)
	}
	// Exactly one key: the survivors share it, and the stored one is single.
	db, err := Open(p, Unlock{Passphrase: "one"})
	if err != nil {
		db, err = Open(p, Unlock{Passphrase: "two"})
	}
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n2 int
	if err := db.db.QueryRow(`SELECT count(*) FROM settings WHERE key='wrapped_key'`).Scan(&n2); err != nil || n2 != 1 {
		t.Fatalf("keys = %d %v", n2, err)
	}
}

// writeMode writes an empty file and forces its mode past the umask.
func writeMode(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, nil, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func TestLockFileSymlinkRefused(t *testing.T) {
	for _, existing := range []bool{false, true} {
		p := tmpDB(t)
		target := filepath.Join(t.TempDir(), "elsewhere")
		if existing {
			writeMode(t, target, 0o644)
		}
		if err := os.Symlink(target, p+".lock"); err != nil {
			t.Fatal(err)
		}
		s, err := Open(p, Unlock{Passphrase: "pw"})
		if err == nil {
			s.Close()
			t.Fatalf("existing=%v: opened through a symlinked lock file", existing)
		}
		if !strings.Contains(err.Error(), p+".lock") || !strings.Contains(err.Error(), "symbolic link") {
			t.Fatalf("existing=%v: err = %v", existing, err)
		}
		fi, err := os.Lstat(target)
		switch {
		case !existing && !errors.Is(err, os.ErrNotExist):
			t.Fatalf("lock target created: %v", err)
		case existing && (err != nil || fi.Mode().Perm() != 0o644):
			t.Fatalf("lock target touched: %v %v", fi, err)
		}
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("existing=%v: database created: %v", existing, err)
		}
	}
}

func TestLockFileTightened(t *testing.T) {
	p := tmpDB(t)
	writeMode(t, p+".lock", 0o644)
	openPass(t, p, "pw")
	fi, err := os.Stat(p + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("lock mode %v", fi.Mode().Perm())
	}
}

func TestLockFileNotRegularRefused(t *testing.T) {
	p := tmpDB(t)
	if err := syscall.Mkfifo(p+".lock", 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(p, Unlock{Passphrase: "pw"})
	if err == nil {
		s.Close()
		t.Fatal("opened with a FIFO as the lock file")
	}
	if !strings.Contains(err.Error(), p+".lock") || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("database created: %v", err)
	}
}

func TestDBSymlinkRefused(t *testing.T) {
	for _, existing := range []bool{false, true} {
		p := tmpDB(t)
		target := filepath.Join(t.TempDir(), "elsewhere.db")
		if existing {
			writeMode(t, target, 0o644)
		}
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
		s, err := Open(p, Unlock{Passphrase: "pw"})
		if err == nil {
			s.Close()
			t.Fatalf("existing=%v: opened through a symlinked database", existing)
		}
		if !strings.Contains(err.Error(), p) || !strings.Contains(err.Error(), "symbolic link") {
			t.Fatalf("existing=%v: err = %v", existing, err)
		}
		fi, err := os.Lstat(target)
		switch {
		case !existing && !errors.Is(err, os.ErrNotExist):
			t.Fatalf("database target created: %v", err)
		case existing && (err != nil || fi.Mode().Perm() != 0o644 || fi.Size() != 0):
			t.Fatalf("database target touched: %v %v", fi, err)
		}
		if fi, err := os.Lstat(p); err != nil || fi.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("existing=%v: symlink replaced: %v %v", existing, fi, err)
		}
	}
}

func TestDBNotRegularRefused(t *testing.T) {
	p := tmpDB(t)
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(p, Unlock{Passphrase: "pw"})
	if err == nil {
		s.Close()
		t.Fatal("opened a FIFO as the database")
	}
	if !strings.Contains(err.Error(), p) || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("err = %v", err)
	}
}

func TestRemoveException(t *testing.T) {
	s := openPass(t, filepath.Join(t.TempDir(), "t.db"), "pw")
	a, b := addM(t, s, "a"), addM(t, s, "b")
	for _, k := range []string{"heur.one", "heur.two"} {
		if err := s.AddException(a, model.Exception{FindingKey: k, AcceptedValue: "v"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.AddException(b, model.Exception{FindingKey: "heur.other", AcceptedValue: "v"}); err != nil {
		t.Fatal(err)
	}
	rows, err := s.ExceptionRows(a)
	if err != nil || len(rows) != 2 || rows[0].ID == 0 || rows[0].ID == rows[1].ID || rows[0].FindingKey != "heur.one" {
		t.Fatalf("rows %+v: %v", rows, err)
	}
	// Another machine's exception is not this machine's to remove.
	if err := s.RemoveException(b, rows[0].ID); !errors.Is(err, ErrNoException) {
		t.Errorf("removing machine a's exception as machine b: %v", err)
	}
	if err := s.RemoveException(a, rows[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveException(a, rows[0].ID); !errors.Is(err, ErrNoException) {
		t.Errorf("removing it twice: %v", err)
	}
	left, _ := s.Exceptions(a)
	other, _ := s.Exceptions(b)
	if len(left) != 1 || left[0].FindingKey != "heur.two" || len(other) != 1 {
		t.Errorf("left %+v, other machine %+v", left, other)
	}
}
