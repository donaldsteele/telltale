package heuristics

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/donaldsteele/telltale/internal/model"
)

const idPersistCallback = "TT-HEUR-015"

// shellName matches a shell program name after an optional directory.
const shellName = `(?:\S*/)?(?:ba|z|da|k|c|tc|a)?sh\b`

// callbackPatterns match one logical line of persistence content that opens a
// connection out of the machine or downloads code and runs it. Every pattern
// is case-insensitive. Redaction replaces values with a marker and never
// removes the program names, options or redirections matched here.
var callbackPatterns = []*regexp.Regexp{
	// bash's built-in sockets
	regexp.MustCompile(`(?i)/dev/(?:tcp|udp)/`),
	// interactive shell with a redirect to a socket or descriptor
	regexp.MustCompile(`(?i)\b(?:ba|z|da|k)?sh\s+-[a-z]*i[a-z]*\b.*(?:>&|&>|<>|<&|>\s*/dev/)`),
	// netcat with -e or -c (also in a flag cluster) or --exec
	regexp.MustCompile(`(?i)(?:^|[\s/;|&(` + "`" + `])(?:nc|ncat|netcat)(?:\.\w+)?\s(?:.*\s)?(?:-[a-z]*[ec][a-z]*|--(?:sh-)?exec)(?:\s|$)`),
	// socat running a program
	regexp.MustCompile(`(?i)\bsocat\b.*\b(?:exec|system):`),
	// fifo relay
	regexp.MustCompile(`(?i)\bmkfifo\b.*(?:^|[\s/;|&(` + "`" + `])(?:nc|ncat|netcat)(?:\.\w+)?\s`),
	regexp.MustCompile(`(?i)(?:^|[\s/;|&(` + "`" + `])(?:nc|ncat|netcat)(?:\.\w+)?\s.*\bmkfifo\b`),
	// download piped into a shell
	regexp.MustCompile(`(?i)\b(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+(?:-\S+\s+)*)?` + shellName),
	// shell, eval or source on the output of a download
	regexp.MustCompile("(?i)(?:" + shellName + `\s+(?:-[a-z]+\s+)*|\beval\s+|\bsource\s+|(?:^|\s)\.\s+)["']?(?:\$\(|<\(|` + "`" + `)\s*(?:curl|wget)\b`),
	// base64 decode piped into a shell
	regexp.MustCompile(`(?i)\bbase64\s+(?:-[a-z]*d[a-z]*|--decode)\b[^|]*\|\s*(?:sudo\s+)?` + shellName),
}

var (
	scriptInterp = regexp.MustCompile(`(?i)\b(?:python[\d.]*|perl|ruby|php)\s+(?:-\S+\s+)*-[a-z]*[cer]`)
	socketToken  = regexp.MustCompile(`(?i)socket|fsockopen`)
	spawnToken   = regexp.MustCompile(`(?i)\b(?:pty|subprocess|exec\w*|system|dup2|spawn\w*|popen)\b`)
)

// callbackLine reports whether one logical line holds a callback or
// download-and-run pattern.
func callbackLine(l string) bool {
	for _, re := range callbackPatterns {
		if re.MatchString(l) {
			return true
		}
	}
	if loc := scriptInterp.FindStringIndex(l); loc != nil {
		arg := l[loc[1]:]
		return socketToken.MatchString(arg) && spawnToken.MatchString(arg)
	}
	return false
}

// logicalLine is one command: the physical lines joined across trailing
// backslashes.
type logicalLine struct {
	first, last int // 1-based physical line numbers
	text        string
}

func isComment(s string) bool {
	return strings.HasPrefix(s, "#") || strings.HasPrefix(s, ";")
}

// joinContinuations joins lines that end in a backslash with the next line.
// A comment never continues.
func joinContinuations(lines []string) []logicalLine {
	var out []logicalLine
	for i := 0; i < len(lines); i++ {
		start := i
		text := strings.TrimSpace(lines[i])
		for !isComment(text) && strings.HasSuffix(text, `\`) && i+1 < len(lines) {
			i++
			text = strings.TrimSpace(strings.TrimSuffix(text, `\`)) + " " + strings.TrimSpace(lines[i])
		}
		out = append(out, logicalLine{first: start + 1, last: i + 1, text: text})
	}
	return out
}

var unitExecKeys = []string{"ExecStart=", "ExecStartPre=", "ExecStartPost=", "ExecStop=", "ExecStopPost=", "ExecReload=", "ExecCondition="}

func unitExecValue(s string) (string, bool) {
	for _, k := range unitExecKeys {
		if strings.HasPrefix(s, k) {
			return s[len(k):], true
		}
	}
	return "", false
}

// callbackKind reports whether files of this kind hold commands.
func callbackKind(k string) bool {
	switch k {
	case model.PersistKindCron, model.PersistKindAt, model.PersistKindSystemdUnit,
		model.PersistKindRC, model.PersistKindProfile, model.PersistKindShellRC:
		return true
	}
	return false
}

func persistCallbacks(c *model.Collection) []model.Finding {
	var out []model.Finding
	for _, p := range c.Persist {
		if !callbackKind(p.Kind) || p.Mode&0o170000 == 0o120000 {
			continue
		}
		var hits []logicalLine
		for _, l := range joinContinuations(p.Lines) {
			if l.text == "" || isComment(l.text) {
				continue
			}
			text := l.text
			if p.Kind == model.PersistKindSystemdUnit {
				v, ok := unitExecValue(text)
				if !ok {
					continue
				}
				text = v
			}
			if callbackLine(text) {
				hits = append(hits, l)
			}
		}
		if len(hits) == 0 {
			continue
		}
		first := hits[0]
		ev := []model.Evidence{{Path: p.Path, Line: first.first, After: first.text}}
		if len(hits) > 1 {
			ev[0].Detail = fmt.Sprintf("%d more matching line(s) in this file, first at line %d", len(hits)-1, hits[1].first)
		}
		out = append(out, model.Finding{
			Key: "heur.persist_callback:" + p.Path, ID: idPersistCallback, Source: source, Severity: model.SevBackdoor,
			Title:    fmt.Sprintf("%s line %d connects out or downloads and runs code", p.Path, first.first),
			Why:      "This startup or scheduled command opens a connection to another machine and hands it a shell, or downloads code and runs it unseen. That is how a reverse shell or loader keeps coming back after a reboot. Some administrators do download-and-run on purpose; check that this one is yours.",
			Fix:      callbackFix(p, first),
			Evidence: ev,
			Refs:     []string{"T1059.004", "T1053.003", "T1543.002", "T1037"},
		})
	}
	return out
}

func callbackFix(p model.PersistFile, l logicalLine) string {
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
func sedRange(l logicalLine) string {
	if l.first == l.last {
		return fmt.Sprintf("%ds/^/#/", l.first)
	}
	return fmt.Sprintf("%d,%ds/^/#/", l.first, l.last)
}
