package report

import (
	_ "embed"
	"html/template"
	"io"
	"strconv"
	"strings"

	"github.com/donaldsteele/telltale/internal/escape"
	"github.com/donaldsteele/telltale/internal/model"
)

//go:embed report.html.tmpl
var htmlSource string

// Every machine-supplied string passes through escape.Terminal (which hides
// control bytes and look-alike characters) and then html/template's own
// context-aware escaping, which neutralises markup.
var htmlTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"esc":   escape.Terminal,
	"label": Label,
	"class": func(s model.Severity) string { return strings.ToLower(Label(s)) },
	"time":  func(t model.Report) string { return t.Time.UTC().Format(timeLayout) },
	"when":  func(e model.Evidence) string { return e.When.UTC().Format(timeLayout) },
	"day":   func(e model.Exception) string { return e.At.UTC().Format("2006-01-02") },
	"where": func(e model.Evidence) string {
		if e.Path == "" {
			return ""
		}
		s := escape.Terminal(e.Path)
		if e.Line > 0 {
			s += ":" + strconv.Itoa(e.Line)
		}
		return s
	},
	"joined": func(a []string) string {
		out := make([]string, len(a))
		for i, s := range a {
			out[i] = escape.Terminal(s)
		}
		return strings.Join(out, ", ")
	},
	"name": func(k string) string { return escape.Terminal(strings.TrimPrefix(k, "explained:")) },
}).Parse(htmlSource))

// HTML writes the report as one self-contained page: inline CSS with a light
// and a dark scheme, no scripts and no external requests.
func HTML(w io.Writer, r *model.Report) error {
	return htmlTemplate.Execute(w, r)
}
