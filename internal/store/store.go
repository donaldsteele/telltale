// Package store is the server's SQLite database. Snapshots, reports,
// collections and secret settings are sealed with a data key that is kept in
// the database only wrapped with age under the admin's passphrase or key file.
package store

import (
	"database/sql"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"time"

	_ "modernc.org/sqlite"

	"github.com/donaldsteele/telltale/internal/model"
)

//go:embed schema.sql
var schemaSQL string

const schemaVersion = 1

// Settings keys the store owns; SetSetting refuses them.
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
	// Create the file 0600 ourselves so SQLite (which gives -wal and -shm the
	// main file's mode) never makes a wider one.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	f.Close()
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, err
	}
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "journal_mode(WAL)")
	dsn := (&url.URL{Scheme: "file", Path: path, RawQuery: q.Encode()}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.init(u); err != nil {
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

func (s *Store) init(u Unlock) error {
	if _, err := s.db.Exec(schemaSQL); err != nil {
		return fmt.Errorf("store: schema: %w", err)
	}
	wrapped, err := s.Setting("wrapped_key")
	if err != nil {
		return err
	}
	if wrapped == "" {
		key, err := newDataKey()
		if err != nil {
			return err
		}
		w, err := wrapKey(key, u)
		if err != nil {
			return err
		}
		// INSERT OR IGNORE: if another opener won the race, read its key.
		res, err := s.db.Exec(`INSERT OR IGNORE INTO settings(key, value) VALUES('wrapped_key', ?)`, base64.StdEncoding.EncodeToString(w))
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 1 {
			s.key = key
			_, err = s.db.Exec(`INSERT OR IGNORE INTO settings(key, value) VALUES('schema_version', ?)`, strconv.Itoa(schemaVersion))
			return err
		}
		if wrapped, err = s.Setting("wrapped_key"); err != nil {
			return err
		}
	}
	raw, err := base64.StdEncoding.DecodeString(wrapped)
	if err != nil {
		return fmt.Errorf("store: wrapped key is corrupt: %w", err)
	}
	if s.key, err = unwrapKey(raw, u); err != nil {
		return err
	}
	v, _ := s.Setting("schema_version")
	if n, _ := strconv.Atoi(v); n > schemaVersion {
		return fmt.Errorf("store: database schema %s is newer than this build (%d)", v, schemaVersion)
	}
	return nil
}

// Close closes the database and forgets the data key.
func (s *Store) Close() error {
	for i := range s.key {
		s.key[i] = 0
	}
	return s.db.Close()
}

func ts(t time.Time) int64 { return t.UTC().UnixNano() }

func fromTS(n int64) time.Time { return time.Unix(0, n).UTC() }

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
func reportAAD(id int64) string          { return "report:" + strconv.FormatInt(id, 10) }
func collectionAAD(id int64) string      { return "collection:" + strconv.FormatInt(id, 10) }
func exceptionAAD(machineID int64) string {
	return "exception:" + strconv.FormatInt(machineID, 10)
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

// PutReport stores a report and the collection it judged.
func (s *Store) PutReport(machineID int64, r *model.Report, c *model.Collection) (int64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	// The blobs are bound to the row ID, so insert first, then seal.
	res, err := tx.Exec(`INSERT INTO reports(machine_id, time, exit_code, findings, report_blob, collection_blob) VALUES(?,?,?,?,x'',x'')`,
		machineID, ts(r.Time), r.ExitCode, len(r.Findings))
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	rb, err := s.sealJSON(r, reportAAD(id))
	if err != nil {
		return 0, err
	}
	cb, err := s.sealJSON(c, collectionAAD(id))
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`UPDATE reports SET report_blob=?, collection_blob=? WHERE id=?`, rb, cb, id); err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

// Reports lists the machine's reports, newest first.
func (s *Store) Reports(machineID int64, limit int) ([]ReportMeta, error) {
	if limit <= 0 {
		limit = -1
	}
	rows, err := s.db.Query(`SELECT id, machine_id, time, exit_code, findings FROM reports WHERE machine_id=? ORDER BY time DESC, id DESC LIMIT ?`, machineID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ReportMeta
	for rows.Next() {
		var m ReportMeta
		var t int64
		if err := rows.Scan(&m.ID, &m.MachineID, &t, &m.ExitCode, &m.Findings); err != nil {
			return nil, err
		}
		m.Time = fromTS(t)
		out = append(out, m)
	}
	return out, rows.Err()
}

// Report opens one stored report and its collection.
func (s *Store) Report(reportID int64) (*model.Report, *model.Collection, error) {
	var rb, cb []byte
	err := s.db.QueryRow(`SELECT report_blob, collection_blob FROM reports WHERE id=?`, reportID).Scan(&rb, &cb)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, fmt.Errorf("store: no report %d", reportID)
	}
	if err != nil {
		return nil, nil, err
	}
	var r model.Report
	if err := s.openJSON(rb, reportAAD(reportID), &r); err != nil {
		return nil, nil, err
	}
	var c model.Collection
	if err := s.openJSON(cb, collectionAAD(reportID), &c); err != nil {
		return nil, nil, err
	}
	return &r, &c, nil
}

// AddException records a lasting exception for the machine.
func (s *Store) AddException(machineID int64, e model.Exception) error {
	blob, err := s.sealJSON(e, exceptionAAD(machineID))
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO exceptions(machine_id, blob) VALUES(?,?)`, machineID, blob)
	return err
}

// Exceptions lists the machine's exceptions in the order they were added.
func (s *Store) Exceptions(machineID int64) ([]model.Exception, error) {
	rows, err := s.db.Query(`SELECT blob FROM exceptions WHERE machine_id=? ORDER BY id`, machineID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Exception
	for rows.Next() {
		var blob []byte
		if err := rows.Scan(&blob); err != nil {
			return nil, err
		}
		var e model.Exception
		if err := s.openJSON(blob, exceptionAAD(machineID), &e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Audit appends an entry to the audit log. There is no way to change or remove
// one through this API, and the schema's triggers refuse it in SQL too.
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
