// Package persistsig finds callback and download-and-run commands in the raw
// text of persistence files. It runs at collection time, before redaction,
// because redaction can swallow the rest of a line (a URL query string
// `?a=1` or a secret-like key hides what follows). Only pattern ids and line
// numbers leave this package, never the matched text.
package persistsig

import (
	"path"
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
	DownloadExec   = "download_then_run"
)

// wrapper programs that may sit in front of a shell.
const wrap = `(?:sudo\s+(?:-\S+\s+)*)?(?:busybox\s+|env\s+(?:\S+=\S+\s+|-\S+\s+)*)?`

// shellName matches a shell program name after an optional directory.
const shellName = `(?:\S*/)?(?:ba|z|da|k|c|tc|a)?sh\b`

// ncWord is a netcat program name at the start of a command word; quotes,
// braces, "=" and "," may precede it (`sh -c 'nc ...'`, `X=nc`).
const ncWord = `(?:^|[\s/;|&(` + "`" + `"'{=,])(?:nc|ncat|netcat)(?:\.\w+)?\s`

// sameCommand is one character of the same command: anything but | ; and a
// lone &; an & next to < or > is a redirection (2>&1, 0<&1, &>).
const sameCommand = `(?:[^|;&]|[<>]&|&[<>])`

type named struct {
	id string
	re *regexp.Regexp
}

// Patterns are case-insensitive unless noted.
var patterns = []named{
	{DevTCP, regexp.MustCompile(`(?i)/dev/(?:tcp|udp)\b`)},
	{ShellRedirect, regexp.MustCompile(`(?i)\b(?:ba|z|da|k)?sh\s+-[a-z]*i[a-z]*\b.*(?:>&|&>|<>|<&|>\s*/dev/)`)},
	// The program name is case-insensitive; the flags are not (OpenBSD's -C
	// is CRLF, not -c), and the flag scan stops at the next command.
	{NetcatExec, regexp.MustCompile(`(?i:` + ncWord + `)(?:` + sameCommand + `*\s)?(?:-[a-zA-Z]*[ec][a-zA-Z]*(?:\s|$|["'/])|--(?:sh-)?exec(?:=|\s|$|["']))`)},
	{SocatExec, regexp.MustCompile(`(?i)\bsocat\b.*\b(?:exec|system):`)},
	{FifoNetcat, regexp.MustCompile(`(?i)\bmkfifo\b.*` + ncWord)},
	{FifoNetcat, regexp.MustCompile(`(?i)` + ncWord + `.*\bmkfifo\b`)},
	{DownloadPipe, regexp.MustCompile(`(?i)\b(?:curl|wget)\b[^|]*(?:\|\s*tee\b[^|]*)*\|\s*` + wrap + shellName)},
	{DownloadSubst, regexp.MustCompile("(?i)(?:" + shellName + `\s+(?:-[a-z]+\s+)*|\beval\s+|\bsource\s+|(?:^|\s)\.\s+)["']?(?:\$\(|<\(|` + "`" + `)\s*(?:curl|wget)\b`)},
	{Base64Shell, regexp.MustCompile(`(?i)\bbase64\s+(?:-[a-z]*d[a-z]*|--decode)\b[^|]*\|\s*` + wrap + shellName)},
}

var (
	scriptInterp = regexp.MustCompile(`(?i)\b(?:python[\d.]*|perl|ruby|php)\s+(?:-\S+\s+)*-[a-z]*[cer]`)
	socketToken  = regexp.MustCompile(`(?i)socket|fsockopen`)
	spawnToken   = regexp.MustCompile(`(?i)\b(?:pty|subprocess|exec\w*|system|dup2|spawn\w*|popen)\b`)

	fetcher     = regexp.MustCompile(`(?i)\b(?:curl|wget)\b`)
	outFlag     = regexp.MustCompile(`(?:^|\s)(?:-[a-zA-Z]*[oO]|--output|--output-document)(?:\s+|=)("[^"]+"|'[^']+'|[^\s;&|<>]+)`)
	redirOut    = regexp.MustCompile(`>\s*("[^"]+"|'[^']+'|[^\s;&|<>]+)`)
	cmdSplit    = regexp.MustCompile(`&&|\|\||[;&|(){}]`)
	runPrefixes = map[string]bool{"sudo": true, "nohup": true, "exec": true, "setsid": true, "time": true, "env": true, "nice": true}
	runWith     = map[string]bool{"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true, "ash": true, ".": true, "source": true}
)

func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}

// downloadThenRun reports a line in which curl or wget writes a file and a
// later command on the same line runs that file.
func downloadThenRun(l string) bool {
	loc := fetcher.FindStringIndex(l)
	if loc == nil {
		return false
	}
	rest := l[loc[0]:]
	var files []string
	for _, m := range outFlag.FindAllStringSubmatch(rest, -1) {
		files = append(files, unquote(m[1]))
	}
	for _, m := range redirOut.FindAllStringSubmatch(rest, -1) {
		files = append(files, unquote(m[1]))
	}
	for _, f := range files {
		if f == "" || f == "-" || strings.HasPrefix(f, "&") || f == "/dev/null" {
			continue
		}
		if i := strings.Index(rest, f); i >= 0 && runsFile(rest[i+len(f):], f) {
			return true
		}
	}
	return false
}

// runsFile reports whether any command in after (the text following the
// download's output name) runs f.
func runsFile(after, f string) bool {
	norm := func(s string) string { return strings.TrimPrefix(strings.Trim(s, `"'`), "./") }
	want := norm(f)
	for _, seg := range cmdSplit.Split(after, -1) {
		toks := strings.Fields(seg)
		for len(toks) > 0 && runPrefixes[toks[0]] {
			toks = toks[1:]
		}
		if len(toks) == 0 {
			continue
		}
		if norm(toks[0]) == want && (strings.Contains(toks[0], "/") || strings.HasPrefix(toks[0], "./")) {
			return true // the file itself as the command
		}
		if toks[0] == want && toks[0] == f && strings.HasPrefix(f, "/") {
			return true
		}
		if runWith[path.Base(toks[0])] {
			for _, t := range toks[1:] {
				if strings.HasPrefix(t, "-") {
					continue
				}
				if norm(t) == want {
					return true
				}
				break
			}
		}
	}
	return false
}

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
	if downloadThenRun(l) {
		return DownloadExec
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

var unitExecKeys = map[string]bool{"ExecStart": true, "ExecStartPre": true, "ExecStartPost": true, "ExecStop": true, "ExecStopPre": true, "ExecStopPost": true, "ExecReload": true, "ExecCondition": true}

// unitExecValue returns the value of an Exec* assignment, with the "=" split
// at its first occurrence and spaces around key and value ignored.
func unitExecValue(s string) (string, bool) {
	k, v, ok := strings.Cut(s, "=")
	if !ok || !unitExecKeys[strings.TrimSpace(k)] {
		return "", false
	}
	return strings.TrimLeft(strings.TrimSpace(v), "-@+!:"), true
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
