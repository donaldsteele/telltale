//go:build lab

package lab

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/lab/labkit"
)

// Requires says what a machine needs for a break or scenario to apply. Task
// runners read it to pick the variant and the docker run flags.
type Requires struct {
	Variant       string   `json:"variant,omitempty"`        // one of labkit.Variants; "" means clean
	Ext4          bool     `json:"ext4,omitempty"`           // labkit Opts.Ext4Volume
	Privileged    bool     `json:"privileged,omitempty"`     // labkit Opts.Privileged
	Caps          []string `json:"caps,omitempty"`           // labkit Opts.Caps
	Systemd       bool     `json:"systemd,omitempty"`        // labkit Opts.Systemd
	ExecShm       bool     `json:"exec_shm,omitempty"`       // labkit Opts.ExecShm: /dev/shm allows running programs
	NewerSnapshot bool     `json:"newer_snapshot,omitempty"` // the image is built at the *_NEWER package snapshot
	Distros       []string `json:"distros,omitempty"`        // only these distros; empty means all
}

// Must is one finding the report has to contain: some finding whose key
// starts with KeyPrefix and whose severity is exactly Severity.
type Must struct {
	KeyPrefix string         `json:"key_prefix"`
	Severity  model.Severity `json:"severity"`
}

// Section is what a report must and must not contain. It applies to one of the
// two ways of scanning: with the clean snapshot, or without one.
type Section struct {
	// Comment says why a section is empty or unusual; the matcher ignores it.
	Comment string `json:"comment,omitempty"`
	Must    []Must `json:"must,omitempty"`
	// MustNotSeverityAbove, when set, fails the check if any finding ranks
	// above it (explained < note < weak setting < backdoor sign < tampering).
	MustNotSeverityAbove *model.Severity `json:"must_not_severity_above,omitempty"`
}

// Manifest is the expected outcome of scanning one lab machine. Both sections
// are required in the file (an empty {} says "nothing is expected"), so a
// forgotten one cannot pass silently.
type Manifest struct {
	Requires        Requires `json:"requires"`
	WithSnapshot    *Section `json:"with_snapshot"`
	WithoutSnapshot *Section `json:"without_snapshot"`
}

// LoadManifest reads dir/manifest.json.
func LoadManifest(dir string) (*Manifest, error) {
	return LoadManifestFile(filepath.Join(dir, "manifest.json"))
}

// LoadManifestFile reads and validates one manifest file. Unknown fields,
// unknown severities, empty key prefixes and unknown variants are errors.
func LoadManifestFile(file string) (*Manifest, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	if v := m.Requires.Variant; v != "" && !slices.Contains(labkit.Variants, v) {
		return nil, fmt.Errorf("%s: unknown variant %q", file, v)
	}
	for _, d := range m.Requires.Distros {
		if !slices.Contains(labkit.Distros, d) {
			return nil, fmt.Errorf("%s: unknown distro %q", file, d)
		}
	}
	for name, s := range map[string]*Section{"with_snapshot": m.WithSnapshot, "without_snapshot": m.WithoutSnapshot} {
		if s == nil {
			continue
		}
		for _, mu := range s.Must {
			if mu.KeyPrefix == "" {
				return nil, fmt.Errorf("%s: %s: a must entry has an empty key_prefix", file, name)
			}
		}
	}
	return &m, nil
}

// Section returns the section that applies to a scan with or without a snapshot.
func (m *Manifest) Section(withSnapshot bool) *Section {
	if withSnapshot {
		return m.WithSnapshot
	}
	return m.WithoutSnapshot
}

// Check compares a report with the manifest section that applies (with_snapshot
// when withSnapshot is true, else without_snapshot). It returns one line per
// mismatch; an empty result means the report matches.
//
// A must entry is met when some finding, in the ranked list or the explained
// group, has a key with that prefix and exactly that severity.
func Check(m *Manifest, r *model.Report, withSnapshot bool) []string {
	name := "without_snapshot"
	if withSnapshot {
		name = "with_snapshot"
	}
	s := m.Section(withSnapshot)
	if s == nil {
		return []string{"manifest has no " + name + " section"}
	}
	all := append(slices.Clone(r.Findings), r.Explained...)
	var problems []string
	for _, mu := range s.Must {
		var seen []string
		met := false
		for _, f := range all {
			if !strings.HasPrefix(f.Key, mu.KeyPrefix) {
				continue
			}
			if f.Severity == mu.Severity {
				met = true
				break
			}
			seen = append(seen, fmt.Sprintf("%s is %q", f.Key, f.Severity))
		}
		switch {
		case met:
		case len(seen) > 0:
			problems = append(problems, fmt.Sprintf("%s: want %q finding %q, found only: %s", name, mu.Severity, mu.KeyPrefix, strings.Join(seen, "; ")))
		default:
			problems = append(problems, fmt.Sprintf("%s: want %q finding %q, none with that key prefix", name, mu.Severity, mu.KeyPrefix))
		}
	}
	if s.MustNotSeverityAbove != nil {
		for _, f := range all {
			if f.Severity > *s.MustNotSeverityAbove {
				problems = append(problems, fmt.Sprintf("%s: finding %s is %q, above the allowed %q", name, f.Key, f.Severity, *s.MustNotSeverityAbove))
			}
		}
	}
	return problems
}
