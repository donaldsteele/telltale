package judge

import (
	"sort"
	"time"

	"github.com/donaldsteele/telltale/internal/model"
)

// Sources of findings, in ranking order within one severity: a cross-view
// mismatch is the strongest evidence a machine is lying, the signed packages
// are the most trustworthy reference, then the known-good snapshot, then
// signs that are suspicious anywhere, then the checklist.
const (
	srcCrossview = "crossview"
	srcPackage   = "package"
	srcSnapshot  = "snapshot"
	srcHeuristic = "heuristic"
	srcChecklist = "checklist"
)

var sourceRank = map[string]int{srcCrossview: 0, srcPackage: 1, srcSnapshot: 2, srcHeuristic: 3, srcChecklist: 4}

func rankOf(source string) int {
	if r, ok := sourceRank[source]; ok {
		return r
	}
	return len(sourceRank)
}

// newest is the latest evidence time of f, or the zero time.
func newest(f *model.Finding) time.Time {
	var t time.Time
	for _, e := range f.Evidence {
		if e.When != nil && e.When.After(t) {
			t = *e.When
		}
	}
	return t
}

// sortFindings ranks findings: severity (highest first), then source order,
// then newest evidence first, then key.
func sortFindings(fs []model.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := &fs[i], &fs[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if ra, rb := rankOf(a.Source), rankOf(b.Source); ra != rb {
			return ra < rb
		}
		if ta, tb := newest(a), newest(b); !ta.Equal(tb) {
			return ta.After(tb)
		}
		return a.Key < b.Key
	})
}

// exitCode follows the command-line contract: 0 nothing found (explained
// changes and accepted exceptions do not count), 1 findings below a backdoor
// sign, 2 any tampering or backdoor sign. 3 (could not run) is the caller's.
func exitCode(fs []model.Finding) int {
	code := 0
	for _, f := range fs {
		switch {
		case f.Severity >= model.SevBackdoor:
			return 2
		case f.Severity > model.SevExplained:
			code = 1
		}
	}
	return code
}

func sameEvidence(a, b model.Evidence) bool {
	if a.Path != b.Path || a.Line != b.Line || a.Before != b.Before || a.After != b.After || a.Detail != b.Detail {
		return false
	}
	if (a.When == nil) != (b.When == nil) {
		return false
	}
	return a.When == nil || a.When.Equal(*b.When)
}

// mergeEvidence appends the items of src that dst does not already hold.
func mergeEvidence(dst, src []model.Evidence) []model.Evidence {
	for _, e := range src {
		dup := false
		for _, d := range dst {
			if sameEvidence(d, e) {
				dup = true
				break
			}
		}
		if !dup {
			dst = append(dst, e)
		}
	}
	return dst
}

// add records f, merging it into an earlier finding with the same key: the
// more severe of the two wins, and the evidence of both is kept.
func (j *judge) add(f *model.Finding) *model.Finding {
	prev, ok := j.byKey[f.Key]
	if !ok {
		j.byKey[f.Key] = f
		j.findings = append(j.findings, f)
		return f
	}
	if f.Severity > prev.Severity {
		ev := prev.Evidence
		*prev = *f
		prev.Evidence = mergeEvidence(append([]model.Evidence(nil), f.Evidence...), ev)
	} else {
		prev.Evidence = mergeEvidence(prev.Evidence, f.Evidence)
	}
	return prev
}

// maxEvidence caps the evidence items kept on one finding; the rest are
// counted in a closing line.
const maxEvidence = 50

// maxExplainedEvidence is the cap for an explained group, which can hold a
// whole distribution upgrade.
const maxExplainedEvidence = 1000

// attach adds one item of evidence to f within limit.
func (j *judge) attach(f *model.Finding, e model.Evidence, limit int) {
	if len(f.Evidence) >= limit {
		j.omitted[f]++
		return
	}
	f.Evidence = append(f.Evidence, e)
}
