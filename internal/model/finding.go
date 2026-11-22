package model

import (
	"fmt"
	"time"
)

// Severity ranks how concerning a finding is. Higher values are more severe.
type Severity int

// Severity levels, lowest to highest.
const (
	SevExplained Severity = iota
	SevNote
	SevWeak
	SevBackdoor
	SevTampering
)

// String returns the human-readable label for the severity.
func (s Severity) String() string {
	switch s {
	case SevExplained:
		return "explained"
	case SevNote:
		return "note"
	case SevWeak:
		return "weak setting"
	case SevBackdoor:
		return "backdoor sign"
	case SevTampering:
		return "tampering"
	}
	return "unknown"
}

// Evidence is one concrete observation supporting a finding.
type Evidence struct {
	Path   string     `json:"path"`
	Line   int        `json:"line"`
	Before string     `json:"before"`
	After  string     `json:"after"`
	Detail string     `json:"detail"`
	When   *time.Time `json:"when,omitempty"`
}

// Finding is one thing telltale reports about a host.
// Key: stable identity for exceptions and alert dedupe.
// Source: snapshot|checklist|heuristic|crossview|package.
type Finding struct {
	Key      string     `json:"key"`
	ID       string     `json:"id"`
	Title    string     `json:"title"`
	Why      string     `json:"why"`
	Fix      string     `json:"fix"`
	Source   string     `json:"source"`
	Severity Severity   `json:"severity"`
	Evidence []Evidence `json:"evidence,omitempty"`
	Refs     []string   `json:"refs,omitempty"`
}

// MarshalText encodes the severity as its String() name so JSON shows
// "tampering" rather than a number.
func (s Severity) MarshalText() ([]byte, error) {
	if s < SevExplained || s > SevTampering {
		return nil, fmt.Errorf("unknown severity %d", int(s))
	}
	return []byte(s.String()), nil
}

// UnmarshalText decodes a name produced by MarshalText and rejects any other.
func (s *Severity) UnmarshalText(b []byte) error {
	for v := SevExplained; v <= SevTampering; v++ {
		if v.String() == string(b) {
			*s = v
			return nil
		}
	}
	return fmt.Errorf("unknown severity %q", b)
}
