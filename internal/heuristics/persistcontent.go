package heuristics

import (
	"fmt"
	"path"
	"strings"

	"github.com/donaldsteele/telltale/internal/model"
	"github.com/donaldsteele/telltale/internal/persistsig"
)

const idPersistCallback = "TT-HEUR-015"

func isComment(s string) bool {
	return strings.HasPrefix(s, "#") || strings.HasPrefix(s, ";")
}

// persistCallbacks reports the callback and download-and-run commands the
// collector found in persistence files. The matching ran on the raw text
// before redaction (see persistsig); the evidence shows the redacted line.
func persistCallbacks(c *model.Collection) []model.Finding {
	var out []model.Finding
	for _, p := range c.Persist {
		if len(p.Signals) == 0 || p.Mode&0o170000 == 0o120000 {
			continue
		}
		first := p.Signals[0]
		logical := persistsig.Logical{First: first.Line, Last: first.Line}
		after := ""
		for _, l := range persistsig.Join(p.Lines) {
			if l.First == first.Line {
				logical, after = l, l.Text
				break
			}
		}
		ev := []model.Evidence{{Path: p.Path, Line: first.Line, After: after, Detail: "matched: " + first.Pattern}}
		if len(p.Signals) > 1 {
			ev[0].Detail += fmt.Sprintf("; %d more matching line(s) in this file, first at line %d", len(p.Signals)-1, p.Signals[1].Line)
		}
		out = append(out, model.Finding{
			Key: "heur.persist_callback:" + p.Path, ID: idPersistCallback, Source: source, Severity: model.SevBackdoor,
			Title:    fmt.Sprintf("%s line %d connects out or downloads and runs code", p.Path, first.Line),
			Why:      "This startup or scheduled command opens a connection to another machine and hands it a shell, or downloads code and runs it unseen. That is how a reverse shell or loader keeps coming back after a reboot. Some administrators do download-and-run on purpose; check that this one is yours.",
			Fix:      callbackFix(p, logical),
			Evidence: ev,
			Refs:     []string{"T1059.004", "T1053.003", "T1543.002", "T1037"},
		})
	}
	return out
}

func callbackFix(p model.PersistFile, l persistsig.Logical) string {
	if p.Kind == model.PersistKindSystemdUnit && strings.HasSuffix(p.Path, ".service") {
		return fix([]string{p.Path, path.Base(p.Path)}, func(q []string) string {
			return keep(q[0]) + " && systemctl disable --now " + q[1] + "   # then remove the Exec line (or the unit file) and run systemctl daemon-reload; only if the unit is not yours"
		})
	}
	return fix([]string{p.Path}, func(q []string) string {
		return fmt.Sprintf("%s && sed -i '%s' %s   # comments the line out, keeps the file; only if the line is not yours", keep(q[0]), sedRange(l), q[0])
	})
}

// sedRange is the sed script that comments out the physical lines of l.
func sedRange(l persistsig.Logical) string {
	if l.First == l.Last {
		return fmt.Sprintf("%ds/^/#/", l.First)
	}
	return fmt.Sprintf("%d,%ds/^/#/", l.First, l.Last)
}
