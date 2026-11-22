// Package snapshot reads and writes known-good snapshot files and records
// exceptions in them.
package snapshot

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"filippo.io/age"

	"github.com/donaldsteele/telltale/internal/model"
)

// ErrBadPassphrase means the file is encrypted and the passphrase did not open it.
var ErrBadPassphrase = errors.New("wrong passphrase")

// ErrUnknownFinding means no finding in the last report has the given key.
var ErrUnknownFinding = errors.New("no finding with that key in the last report")

const (
	ageMagic     = "age-encryption.org/v1"
	maxPlainSize = 512 << 20
)

// New builds a snapshot from a collection taken with key.
func New(c *model.Collection, checks []model.CheckResult, key []byte) *model.Snapshot {
	return &model.Snapshot{
		Schema:     model.SnapshotSchema,
		Taken:      time.Now().UTC(),
		Collection: c,
		Checks:     checks,
		DigestKey:  key,
	}
}

// Write encodes s as gzip JSON, inside an age scrypt envelope when passphrase
// is not empty.
func Write(w io.Writer, s *model.Snapshot, passphrase string) error {
	var enc io.Writer = w
	var ageW io.WriteCloser
	if passphrase != "" {
		rcpt, err := age.NewScryptRecipient(passphrase)
		if err != nil {
			return err
		}
		ageW, err = age.Encrypt(w, rcpt)
		if err != nil {
			return err
		}
		enc = ageW
	}
	zw := gzip.NewWriter(enc)
	if err := json.NewEncoder(zw).Encode(s); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	if ageW != nil {
		return ageW.Close()
	}
	return nil
}

// Read decodes a snapshot, detecting an age envelope versus plain gzip.
func Read(r io.Reader, passphrase string) (*model.Snapshot, error) {
	br := bufio.NewReader(r)
	head, err := br.Peek(len(ageMagic))
	if err != nil && len(head) < 2 {
		return nil, fmt.Errorf("read snapshot: %w", err)
	}
	var src io.Reader = br
	if bytes.HasPrefix(head, []byte(ageMagic)) {
		if passphrase == "" {
			return nil, fmt.Errorf("snapshot is encrypted: %w", ErrBadPassphrase)
		}
		id, err := age.NewScryptIdentity(passphrase)
		if err != nil {
			return nil, err
		}
		src, err = age.Decrypt(br, id)
		if err != nil {
			var nm *age.NoIdentityMatchError
			if errors.As(err, &nm) {
				return nil, ErrBadPassphrase
			}
			return nil, fmt.Errorf("decrypt snapshot: %w", err)
		}
	} else if head[0] != 0x1f || head[1] != 0x8b {
		return nil, errors.New("not a telltale snapshot")
	}
	zr, err := gzip.NewReader(src)
	if err != nil {
		return nil, fmt.Errorf("read snapshot: %w", err)
	}
	var s model.Snapshot
	if err := json.NewDecoder(io.LimitReader(zr, maxPlainSize)).Decode(&s); err != nil {
		return nil, fmt.Errorf("read snapshot: %w", err)
	}
	return &s, nil
}

// WriteFile writes the snapshot atomically with mode 0600.
func WriteFile(path string, s *model.Snapshot, passphrase string) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".telltale-snapshot-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	bw := bufio.NewWriter(f)
	if err := Write(bw, s, passphrase); err != nil {
		return err
	}
	if err := bw.Flush(); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	return nil
}

// ReadFile reads a snapshot file.
func ReadFile(path, passphrase string) (*model.Snapshot, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Read(f, passphrase)
}

// LastReportPath is where scan leaves its most recent report for a snapshot.
func LastReportPath(snapshotPath string) string { return snapshotPath + ".last-report.json" }

// Accept records an exception for the finding with the given key, using the
// finding's current value from the last report, and rewrites the snapshot.
func Accept(path, passphrase, key, note string, at time.Time) error {
	rb, err := os.ReadFile(LastReportPath(path))
	if err != nil {
		return fmt.Errorf("no last report next to the snapshot (run a scan first): %w", err)
	}
	var rep model.Report
	if err := json.Unmarshal(rb, &rep); err != nil {
		return fmt.Errorf("read last report: %w", err)
	}
	var found *model.Finding
	for _, list := range [][]model.Finding{rep.Findings, rep.Explained} {
		for i := range list {
			if list[i].Key == key {
				found = &list[i]
				break
			}
		}
		if found != nil {
			break
		}
	}
	if found == nil {
		return ErrUnknownFinding
	}
	val := found.Title
	if len(found.Evidence) > 0 && found.Evidence[0].After != "" {
		val = found.Evidence[0].After
	}
	s, err := ReadFile(path, passphrase)
	if err != nil {
		return err
	}
	s.Exceptions = append(s.Exceptions, model.Exception{FindingKey: key, AcceptedValue: val, Note: note, At: at.UTC()})
	return WriteFile(path, s, passphrase)
}

// IsEncrypted reports whether the file at path is an age envelope.
func IsEncrypted(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	b := make([]byte, len(ageMagic))
	n, _ := io.ReadFull(f, b)
	return bytes.HasPrefix(b[:n], []byte(ageMagic)), nil
}
