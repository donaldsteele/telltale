// Package persistsig finds callback and download-and-run commands in the raw
// text of persistence files. It runs at collection time, before redaction,
// because redaction can swallow the rest of a line (a URL query string
// `?a=1` or a secret-like key hides what follows). Only pattern ids and line
// numbers leave this package, never the matched text.
package persistsig

import (
	"regexp"
	"strings"

	"github.com/donaldsteele/telltale/internal/model"
)

// Pattern ids stored in model.PersistSignal.Pattern.
const (
	DevTCP         = "dev_tcp"
	ShellRedirect  = "shell_interactive_redirect"
	NetcatExec     = "netcat_exec"
	SocatExec      = "socat_exec"
	FifoNetcat     = "mkfifo_netcat"
	DownloadPipe   = "download_piped_to_shell"
	DownloadSubst  = "download_run_by_shell"
	Base64Shell    = "base64_decode_to_shell"
	ScriptSockExec = "script_socket_and_spawn"
)

// shellName matches a shell program name after an optional directory.
const shellName = `(?:\S*/)?(?:ba|z|da|k|c|tc|a)?sh\b`

const ncWord = `(?:^|[\s/;|&(` + "`" + `])(?:nc|ncat|netcat)(?:\.\w+)?\s`

type named struct {
	id string
	re *regexp.Regexp
}

// Every pattern is case-insensitive.
var patterns = []named{
	{DevTCP, regexp.MustCompile(`(?i)/dev/(?:tcp|udp)/`)},
	{ShellRedirect, regexp.MustCompile(`(?i)\b(?:ba|z|da|k)?sh\s+-[a-z]*i[a-z]*\b.*(?:>&|&>|<>|<&|>\s*/dev/)`)},
	{NetcatExec, regexp.MustCompile(`(?i)` + ncWord + `(?:.*\s)?(?:-[a-z]*[ec][a-z]*|--(?:sh-)?exec)(?:\s|$)`)},
	{SocatExec, regexp.MustCompile(`(?i)\bsocat\b.*\b(?:exec|system):`)},
	{FifoNetcat, regexp.MustCompile(`(?i)\bmkfifo\b.*` + ncWord)},
	{FifoNetcat, regexp.MustCompile(`(?i)` + ncWord + `.*\bmkfifo\b`)},
	{DownloadPipe, regexp.MustCompile(`(?i)\b(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+(?:-\S+\s+)*)?` + shellName)},
	{DownloadSubst, regexp.MustCompile("(?i)(?:" + shellName + `\s+(?:-[a-z]+\s+)*|\beval\s+|\bsource\s+|(?:^|\s)\.\s+)["']?(?:\$\(|<\(|` + "`" + `)\s*(?:curl|wget)\b`)},
	{Base64Shell, regexp.MustCompile(`(?i)\bbase64\s+(?:-[a-z]*d[a-z]*|--decode)\b[^|]*\|\s*(?:sudo\s+)?` + shellName)},
}

var (
	scriptInterp = regexp.MustCompile(`(?i)\b(?:python[\d.]*|perl|ruby|php)\s+(?:-\S+\s+)*-[a-z]*[cer]`)
	socketToken  = regexp.MustCompile(`(?i)socket|fsockopen`)
	spawnToken   = regexp.MustCompile(`(?i)\b(?:pty|subprocess|exec\w*|system|dup2|spawn\w*|popen)\b`)
)

// MatchLine returns the id of the first pattern that matches one logical
// line, or "".
func MatchLine(l string) string {
	for _, p := range patterns {
		if p.re.MatchString(l) {
			return p.id
		}
	}
	if loc := scriptInterp.FindStringIndex(l); loc != nil {
		arg := l[loc[1]:]
		if socketToken.MatchString(arg) && spawnToken.MatchString(arg) {
			return ScriptSockExec
		}
	}
	return ""
}

// Kinds whose files hold commands.
func commandKind(k string) bool {
	switch k {
	case model.PersistKindCron, model.PersistKindAt, model.PersistKindSystemdUnit,
		model.PersistKindRC, model.PersistKindProfile, model.PersistKindShellRC:
		return true
	}
	return false
}

// Logical is one command: physical lines joined across trailing backslashes.
type Logical struct {
	First, Last int // 1-based physical line numbers
	Text        string
}

func isComment(s string) bool {
	return strings.HasPrefix(s, "#") || strings.HasPrefix(s, ";")
}

// Join joins lines that end in a backslash with the next line. A comment
// never continues.
func Join(lines []string) []Logical {
	var out []Logical
	for i := 0; i < len(lines); i++ {
		start := i
		text := strings.TrimSpace(lines[i])
		for !isComment(text) && strings.HasSuffix(text, `\`) && i+1 < len(lines) {
			i++
			text = strings.TrimSpace(strings.TrimSuffix(text, `\`)) + " " + strings.TrimSpace(lines[i])
		}
		out = append(out, Logical{First: start + 1, Last: i + 1, Text: text})
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

// Detect scans the raw lines of a persistence file of the given kind and
// returns one signal per matching command, in order. Signal.Line is the first
// physical line of the command.
func Detect(kind string, raw []string) []model.PersistSignal {
	if !commandKind(kind) {
		return nil
	}
	var out []model.PersistSignal
	for _, l := range Join(raw) {
		if l.Text == "" || isComment(l.Text) {
			continue
		}
		text := l.Text
		if kind == model.PersistKindSystemdUnit {
			v, ok := unitExecValue(text)
			if !ok {
				continue
			}
			text = v
		}
		if id := MatchLine(text); id != "" {
			out = append(out, model.PersistSignal{Line: l.First, Pattern: id})
		}
	}
	return out
}
