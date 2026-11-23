// Package store is the server's SQLite database. Snapshots, reports,
// collections and secret settings are sealed with a data key that is kept in
// the database only wrapped with age under the admin's passphrase or key file.
//
// Open takes an advisory flock on <db>.lock while it sets the database up, so
// concurrent first opens cannot collide; the lock file is left in place and is
// harmless. Normal use does not take it.
//
// Not encrypted, on purpose: machine name, address and host key (the owner
// types them, and a host key is public), plain settings, and the audit log.
// Everything derived from a machine's contents, including report time, exit
// code and finding counts, is sealed.
package store

import (
	"database/sql"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	_ "modernc.org/sqlite"

	"github.com/donaldsteele/telltale/internal/model"
)

//go:embed schema.sql
var schemaSQL string

const schemaVersion = 1

// Settings keys the store owns; SetSetting refuses them.
// ErrNoKeyButData means the wrapped data key is gone while sealed data remains.
var ErrNoKeyButData = errors.New("the store holds data but its key is missing")

var reservedSettings = map[string]bool{"wrapped_key": true, "schema_version": true}

// Unlock says how the data key is opened. Exactly one field must be set.
type Unlock struct {
	Passphrase string
	KeyFile    string
}

// Store is an open, unlocked database.
type Store struct {
	db  *sql.DB
	key []byte
}

// Machine is an enrolled machine.
type Machine struct {
	ID                                  int64
	Name, Addr, Arch, HostKey, Schedule string
	Clean                               bool
	Created                             time.Time
	LastVisit                           *time.Time
}

// ReportMeta describes a stored report without opening it.
type ReportMeta struct {
	ID        int64
	MachineID int64
	Time      time.Time
	ExitCode  int
	Findings  int
}

// AuditEntry is one line of the append-only audit log.
type AuditEntry struct {
	ID                    int64
	Time                  time.Time
	Actor, Action, Detail string
}

// Open opens or creates the database at path and unlocks it. A wrong
// passphrase or key file is an error; a second data key is never created.
func Open(path string, u Unlock) (*Store, error) {
	if (u.Passphrase == "") == (u.KeyFile == "") {
		return nil, errors.New("store: set exactly one of passphrase or key file")
	}
	// An absolute path keeps the file: URI free of an authority part.
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	// Check the key file up front, so a bad one never costs us a half-made
	// database (and nothing has to be removed after another opener may be
	// using it).
	if err := checkKeyFile(u.KeyFile); err != nil {
		return nil, err
	}
	// Serialize setup (WAL switch, DDL, key creation) between processes:
	// SQLite can answer BUSY to the first rollback-to-WAL switch without
	// calling the busy handler. The lock file is never removed, and a symlink
	// in its place is refused, not followed out of the data directory.
	lock, err := openNoFollow(path+".lock", os.O_RDWR|os.O_CREATE, "lock file")
	if err != nil {
		return nil, err
	}
	defer lock.Close() // closing releases the flock
	if err := regular0600(lock, "lock file"); err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return nil, fmt.Errorf("store: lock %s.lock: %w", path, err)
	}
	// Create the file 0600 ourselves so SQLite (which gives -wal and -shm the
	// main file's mode) never makes a wider one. Only the opener whose
	// O_EXCL create succeeds owns the file and may remove it on failure.
	// O_CREATE|O_EXCL never follows a symlink (it fails with EEXIST), so only
	// the reopen of an existing file needs O_NOFOLLOW.
	created := true
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		created = false
		f, err = openNoFollow(path, os.O_RDWR, "database")
	}
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*Store, error) {
		// Only before any SQL ran, and only by the opener that created the file.
		if created {
			for _, suf := range []string{"", "-wal", "-shm"} {
				os.Remove(path + suf)
			}
		}
		return nil, err
	}
	err = regular0600(f, "database")
	f.Close()
	if err != nil {
		return fail(err)
	}
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_txlock", "immediate")
	dsn := (&url.URL{Scheme: "file", Path: path, RawQuery: q.Encode()}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return fail(err)
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.init(u); err != nil {
		// Other openers may already be using the file: never remove it here.
		db.Close()
		return nil, err
	}
	for _, suf := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(path + suf); err == nil {
			os.Chmod(path+suf, 0o600)
		}
	}
	return s, nil
}

// openNoFollow opens name without following a symlink in its last element.
func openNoFollow(name string, flag int, what string) (*os.File, error) {
	f, err := os.OpenFile(name, flag|syscall.O_NOFOLLOW, 0o600)
	if errors.Is(err, syscall.ELOOP) {
		return nil, fmt.Errorf("store: %s %s is a symbolic link; refusing to follow it", what, name)
	}
	return f, err
}

// regular0600 refuses anything but a regular file behind f and sets its mode
// to 0600 through the descriptor, so a path swapped since the open is never
// touched.
func regular0600(f *os.File, what string) error {
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("store: %s: %w", what, err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("store: %s %s is not a regular file", what, f.Name())
	}
	if fi.Mode().Perm() != 0o600 {
		if err := f.Chmod(0o600); err != nil {
			return fmt.Errorf("store: %s: %w", what, err)
		}
	}
	return nil
}

// dataTables are the tables whose rows are sealed with the data key.
var dataTables = []string{"machines", "secrets", "snapshots", "reports", "exceptions", "audit"}

func (s *Store) init(u Unlock) error {
	// Refuse a newer schema before running any DDL against it.
	var has int
	if err := s.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='settings'`).Scan(&has); err != nil {
		return err
	}
	if has > 0 {
		v, err := s.Setting("schema_version")
		if err != nil {
			return err
		}
		if n, _ := strconv.Atoi(v); n > schemaVersion {
			return fmt.Errorf("store: database schema %s is newer than this build (%d)", v, schemaVersion)
		}
	}
	if _, err := s.db.Exec(schemaSQL); err != nil {
		return fmt.Errorf("store: schema: %w", err)
	}
	tx, err := s.db.Begin() // immediate: no other opener can race the key creation
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var wrapped string
	err = tx.QueryRow(`SELECT value FROM settings WHERE key='wrapped_key'`).Scan(&wrapped)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		for _, t := range dataTables {
			var n int
			if err := tx.QueryRow(`SELECT count(*) FROM ` + t).Scan(&n); err != nil {
				return err
			}
			if n > 0 {
				return ErrNoKeyButData
			}
		}
		key, err := newDataKey()
		if err != nil {
			return err
		}
		w, err := wrapKey(key, u)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO settings(key, value) VALUES('wrapped_key', ?)`, base64.StdEncoding.EncodeToString(w)); err != nil {
			return err
		}
		s.key = key
	case err != nil:
		return err
	default:
		raw, err := base64.StdEncoding.DecodeString(wrapped)
		if err != nil {
			return fmt.Errorf("store: wrapped key is corrupt: %w", err)
		}
		if s.key, err = unwrapKey(raw, u); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO settings(key, value) VALUES('schema_version', ?)`, strconv.Itoa(schemaVersion)); err != nil {
		return err
	}
	return tx.Commit()
}

// Close closes the database and forgets the data key.
func (s *Store) Close() error {
	for i := range s.key {
		s.key[i] = 0
	}
	return s.db.Close()
}

// ts stores a zero time as 0 and anything else as UTC nanoseconds.
func ts(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UTC().UnixNano()
}

func fromTS(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n).UTC()
}

// AddMachine enrols a machine and returns its ID.
func (s *Store) AddMachine(m Machine) (int64, error) {
	created := m.Created
	if created.IsZero() {
		created = time.Now()
	}
	res, err := s.db.Exec(`INSERT INTO machines(name, addr, arch, host_key, schedule, clean, created) VALUES(?,?,?,?,?,?,?)`,
		m.Name, m.Addr, m.Arch, m.HostKey, m.Schedule, m.Clean, ts(created))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateMachine rewrites every field of the machine with m.ID except Created.
func (s *Store) UpdateMachine(m Machine) error {
	var lv any
	if m.LastVisit != nil {
		lv = ts(*m.LastVisit)
	}
	res, err := s.db.Exec(`UPDATE machines SET name=?, addr=?, arch=?, host_key=?, schedule=?, clean=?, last_visit=? WHERE id=?`,
		m.Name, m.Addr, m.Arch, m.HostKey, m.Schedule, m.Clean, lv, m.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("store: no machine %d", m.ID)
	}
	return nil
}

const machineCols = `id, name, addr, arch, host_key, schedule, clean, created, last_visit`

type scanner interface{ Scan(...any) error }

func scanMachine(r scanner) (*Machine, error) {
	var m Machine
	var created int64
	var lv sql.NullInt64
	if err := r.Scan(&m.ID, &m.Name, &m.Addr, &m.Arch, &m.HostKey, &m.Schedule, &m.Clean, &created, &lv); err != nil {
		return nil, err
	}
	m.Created = fromTS(created)
	if lv.Valid {
		t := fromTS(lv.Int64)
		m.LastVisit = &t
	}
	return &m, nil
}

// Machine returns one machine, or an error when there is none.
func (s *Store) Machine(id int64) (*Machine, error) {
	m, err := scanMachine(s.db.QueryRow(`SELECT `+machineCols+` FROM machines WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("store: no machine %d", id)
	}
	return m, err
}

// Machines lists all machines by name.
func (s *Store) Machines() ([]Machine, error) {
	rows, err := s.db.Query(`SELECT ` + machineCols + ` FROM machines ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Machine
	for rows.Next() {
		m, err := scanMachine(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *m)
	}
	return out, rows.Err()
}

func snapshotAAD(machineID int64) string { return "snapshot:" + strconv.FormatInt(machineID, 10) }

func rowAAD(purpose string, machineID, id int64) string {
	return purpose + ":" + strconv.FormatInt(machineID, 10) + ":" + strconv.FormatInt(id, 10)
}

// PutSnapshot replaces the machine's snapshot.
func (s *Store) PutSnapshot(machineID int64, snap *model.Snapshot) error {
	blob, err := s.sealJSON(snap, snapshotAAD(machineID))
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO snapshots(machine_id, taken, blob) VALUES(?,?,?)
		ON CONFLICT(machine_id) DO UPDATE SET taken=excluded.taken, blob=excluded.blob`,
		machineID, ts(snap.Taken), blob)
	return err
}

// Snapshot returns the machine's snapshot, or nil when it has none.
func (s *Store) Snapshot(machineID int64) (*model.Snapshot, error) {
	var blob []byte
	err := s.db.QueryRow(`SELECT blob FROM snapshots WHERE machine_id=?`, machineID).Scan(&blob)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var snap model.Snapshot
	if err := s.openJSON(blob, snapshotAAD(machineID), &snap); err != nil {
		return nil, err
	}
	return &snap, nil
}

// reportMeta is the part of a report the history list needs, sealed like the rest.
type reportMeta struct {
	Time     time.Time `json:"time"`
	ExitCode int       `json:"exit_code"`
	Findings int       `json:"findings"`
}

// PutReport stores a report and the collection it judged.
func (s *Store) PutReport(machineID int64, r *model.Report, c *model.Collection) (int64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	// The blobs are bound to the row ID, so insert first, then seal.
	res, err := tx.Exec(`INSERT INTO reports(machine_id, meta_blob, report_blob, collection_blob) VALUES(?,x'',x'',x'')`, machineID)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	mb, err := s.sealJSON(reportMeta{r.Time, r.ExitCode, len(r.Findings)}, rowAAD("reportmeta", machineID, id))
	if err != nil {
		return 0, err
	}
	rb, err := s.sealJSON(r, rowAAD("report", machineID, id))
	if err != nil {
		return 0, err
	}
	cb, err := s.sealJSON(c, rowAAD("collection", machineID, id))
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`UPDATE reports SET meta_blob=?, report_blob=?, collection_blob=? WHERE id=?`, mb, rb, cb, id); err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

// Reports lists the machine's reports, newest first (by insertion order).
func (s *Store) Reports(machineID int64, limit int) ([]ReportMeta, error) {
	if limit <= 0 {
		limit = -1
	}
	rows, err := s.db.Query(`SELECT id, meta_blob FROM reports WHERE machine_id=? ORDER BY id DESC LIMIT ?`, machineID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ReportMeta
	for rows.Next() {
		var id int64
		var blob []byte
		if err := rows.Scan(&id, &blob); err != nil {
			return nil, err
		}
		var m reportMeta
		if err := s.openJSON(blob, rowAAD("reportmeta", machineID, id), &m); err != nil {
			return nil, err
		}
		out = append(out, ReportMeta{ID: id, MachineID: machineID, Time: m.Time, ExitCode: m.ExitCode, Findings: m.Findings})
	}
	return out, rows.Err()
}

// Report opens one stored report and its collection.
func (s *Store) Report(reportID int64) (*model.Report, *model.Collection, error) {
	var machineID int64
	var rb, cb []byte
	err := s.db.QueryRow(`SELECT machine_id, report_blob, collection_blob FROM reports WHERE id=?`, reportID).Scan(&machineID, &rb, &cb)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, fmt.Errorf("store: no report %d", reportID)
	}
	if err != nil {
		return nil, nil, err
	}
	var r model.Report
	if err := s.openJSON(rb, rowAAD("report", machineID, reportID), &r); err != nil {
		return nil, nil, err
	}
	var c model.Collection
	if err := s.openJSON(cb, rowAAD("collection", machineID, reportID), &c); err != nil {
		return nil, nil, err
	}
	return &r, &c, nil
}

// ReportOnly opens one stored report without its collection, which can be
// far larger, and says which machine it belongs to.
func (s *Store) ReportOnly(reportID int64) (*model.Report, int64, error) {
	var machineID int64
	var rb []byte
	err := s.db.QueryRow(`SELECT machine_id, report_blob FROM reports WHERE id=?`, reportID).Scan(&machineID, &rb)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, 0, fmt.Errorf("store: no report %d", reportID)
	}
	if err != nil {
		return nil, 0, err
	}
	var r model.Report
	if err := s.openJSON(rb, rowAAD("report", machineID, reportID), &r); err != nil {
		return nil, 0, err
	}
	return &r, machineID, nil
}

// AddException records a lasting exception for the machine.
func (s *Store) AddException(machineID int64, e model.Exception) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`INSERT INTO exceptions(machine_id, blob) VALUES(?,x'')`, machineID)
	if err != nil {
		return err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	blob, err := s.sealJSON(e, rowAAD("exception", machineID, id))
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE exceptions SET blob=? WHERE id=?`, blob, id); err != nil {
		return err
	}
	return tx.Commit()
}

// Exceptions lists the machine's exceptions in the order they were added.
func (s *Store) Exceptions(machineID int64) ([]model.Exception, error) {
	rows, err := s.db.Query(`SELECT id, blob FROM exceptions WHERE machine_id=? ORDER BY id`, machineID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Exception
	for rows.Next() {
		var id int64
		var blob []byte
		if err := rows.Scan(&id, &blob); err != nil {
			return nil, err
		}
		var e model.Exception
		if err := s.openJSON(blob, rowAAD("exception", machineID, id), &e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ErrNoException means the machine has no exception with that ID.
var ErrNoException = errors.New("store: the machine has no such exception")

// ExceptionRow is an exception with the ID that names it for removal.
type ExceptionRow struct {
	ID int64
	model.Exception
}

// ExceptionRows lists the machine's exceptions with their IDs, in the order
// they were added.
func (s *Store) ExceptionRows(machineID int64) ([]ExceptionRow, error) {
	rows, err := s.db.Query(`SELECT id, blob FROM exceptions WHERE machine_id=? ORDER BY id`, machineID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ExceptionRow
	for rows.Next() {
		var id int64
		var blob []byte
		if err := rows.Scan(&id, &blob); err != nil {
			return nil, err
		}
		r := ExceptionRow{ID: id}
		if err := s.openJSON(blob, rowAAD("exception", machineID, id), &r.Exception); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RemoveException removes one of the machine's exceptions. It is
// ErrNoException when the machine has none with that ID: an exception of
// another machine is never removed.
func (s *Store) RemoveException(machineID, id int64) error {
	res, err := s.db.Exec(`DELETE FROM exceptions WHERE id=? AND machine_id=?`, id, machineID)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrNoException
	}
	return nil
}

// Audit appends an entry to the audit log. There is no way to change or remove
// one through this API, and the schema's triggers refuse it in SQL too.
//
// The audit columns are NOT encrypted. Callers must never put machine content
// (file text, findings, evidence) in actor, action or detail; names, IDs and
// verbs only.
func (s *Store) Audit(actor, action, detail string) error {
	_, err := s.db.Exec(`INSERT INTO audit(time, actor, action, detail) VALUES(?,?,?,?)`, ts(time.Now()), actor, action, detail)
	return err
}

// AuditLog returns the newest entries first.
func (s *Store) AuditLog(limit int) ([]AuditEntry, error) {
	if limit <= 0 {
		limit = -1
	}
	rows, err := s.db.Query(`SELECT id, time, actor, action, detail FROM audit ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var t int64
		if err := rows.Scan(&e.ID, &t, &e.Actor, &e.Action, &e.Detail); err != nil {
			return nil, err
		}
		e.Time = fromTS(t)
		out = append(out, e)
	}
	return out, rows.Err()
}

// Setting returns a plain setting, or "" when unset.
func (s *Store) Setting(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

// SetSetting stores a plain (unencrypted) setting. Keys the store owns are refused.
func (s *Store) SetSetting(key, value string) error {
	if reservedSettings[key] {
		return fmt.Errorf("store: setting %q is reserved", key)
	}
	_, err := s.db.Exec(`INSERT INTO settings(key, value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

func secretAAD(key string) string { return "secret:" + key }

// SecretSetting returns a decrypted secret, or nil when unset.
func (s *Store) SecretSetting(key string) ([]byte, error) {
	var blob []byte
	err := s.db.QueryRow(`SELECT blob FROM secrets WHERE key=?`, key).Scan(&blob)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return open(s.key, blob, secretAAD(key))
}

// SetSecretSetting stores v sealed with the data key.
func (s *Store) SetSecretSetting(key string, v []byte) error {
	blob, err := seal(s.key, v, secretAAD(key))
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO secrets(key, blob) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET blob=excluded.blob`, key, blob)
	return err
}
