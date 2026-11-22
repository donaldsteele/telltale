package model

import "time"

// CheckResult is the outcome of one checklist check.
type CheckResult struct {
	ID       string `json:"id"`
	Pass     bool   `json:"pass"`
	Observed string `json:"observed"`
	Skipped  string `json:"skipped"`
}

// Exception accepts a finding's current value so it stops being reported.
type Exception struct {
	FindingKey    string    `json:"finding_key"`
	AcceptedValue string    `json:"accepted_value"`
	Note          string    `json:"note"`
	At            time.Time `json:"at"`
}

// ScanContext carries the server identity used to authenticate a scan.
type ScanContext struct {
	DigestKey            []byte `json:"digest_key"`
	ServerAddr           string `json:"server_addr"`
	ServerKeyLine        string `json:"server_key_line"`
	ServerKeyFingerprint string `json:"server_key_fingerprint"`
}

// Snapshot is a saved baseline: a collection plus check results and the key
// used to authenticate it.
type Snapshot struct {
	Schema     int           `json:"schema"`
	Taken      time.Time     `json:"taken"`
	Collection *Collection   `json:"collection"`
	Checks     []CheckResult `json:"checks"`
	DigestKey  []byte        `json:"digest_key"`
	Exceptions []Exception   `json:"exceptions,omitempty"`
}

// Report is the output of one scan.
type Report struct {
	Schema          int         `json:"schema"`
	Host            Host        `json:"host"`
	Time            time.Time   `json:"time"`
	ComparedAgainst []string    `json:"compared_against"`
	CouldNotRuleOut []string    `json:"could_not_rule_out"`
	Skipped         []Skip      `json:"skipped,omitempty"`
	Findings        []Finding   `json:"findings"`  // ranked, excludes explained
	Explained       []Finding   `json:"explained"` // grouped quiet items
	Exceptions      []Exception `json:"exceptions,omitempty"`
	ExitCode        int         `json:"exit_code"`
}
