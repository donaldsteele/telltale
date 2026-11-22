package cli

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"strings"
	"testing"

	"github.com/donaldsteele/telltale/internal/model"
)

func collectArgs(extra ...string) []string {
	return append([]string{"collect", "--root", "../collect/testdata/root1",
		"--proc-root", "../collect/testdata/proc1", "--sys-root", "../collect/testdata/root1", "--no-cross-view"}, extra...)
}

func TestCollectCommandWritesJSON(t *testing.T) {
	var out, errb bytes.Buffer
	code := Run(collectArgs(), strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("code=%d err=%q", code, errb.String())
	}
	var c model.Collection
	if err := json.Unmarshal(out.Bytes(), &c); err != nil {
		t.Fatal(err)
	}
	if c.Schema != 1 || len(c.Accounts.Users) == 0 {
		t.Fatalf("bad collection: schema=%d users=%d", c.Schema, len(c.Accounts.Users))
	}
}

func TestCollectCommandGzipAndContext(t *testing.T) {
	var out, errb bytes.Buffer
	ctx := `{"digest_key":"AAECAwQFBgcICQoLDA0ODw=="}`
	code := Run(collectArgs("--gzip", "--context-stdin"), strings.NewReader(ctx), &out, &errb)
	if code != 0 {
		t.Fatalf("code=%d err=%q", code, errb.String())
	}
	zr, err := gzip.NewReader(&out)
	if err != nil {
		t.Fatal(err)
	}
	var c model.Collection
	if err := json.NewDecoder(zr).Decode(&c); err != nil || c.Schema != 1 {
		t.Fatalf("decode: %v schema=%d", err, c.Schema)
	}
}

func TestCollectCommandBadContext(t *testing.T) {
	var out, errb bytes.Buffer
	code := Run(collectArgs("--context-stdin"), strings.NewReader("{nope"), &out, &errb)
	if code != 3 || out.Len() != 0 || strings.Count(errb.String(), "\n") != 1 {
		t.Fatalf("code=%d out=%d err=%q", code, out.Len(), errb.String())
	}
}

func TestCollectCommandRejectsBadContext(t *testing.T) {
	big := `{"digest_key":"` + strings.Repeat("A", 100<<10) + `"}`
	cases := map[string]string{
		"oversized": big,
		"short key": `{"digest_key":"AAECAwQFBgc="}`,
	}
	for name, in := range cases {
		var out, errb bytes.Buffer
		code := Run(collectArgs("--context-stdin"), strings.NewReader(in), &out, &errb)
		if code != 3 || out.Len() != 0 || strings.Count(errb.String(), "\n") != 1 {
			t.Errorf("%s: code=%d out=%d err=%q", name, code, out.Len(), errb.String())
		}
	}
}

func TestCollectCommand32ByteKey(t *testing.T) {
	var out, errb bytes.Buffer
	in := `{"digest_key":"` + strings.Repeat("A", 43) + `="}`
	if code := Run(collectArgs("--context-stdin"), strings.NewReader(in), &out, &errb); code != 0 {
		t.Fatalf("code=%d err=%q", code, errb.String())
	}
}

func TestCollectHelp(t *testing.T) {
	for _, arg := range []string{"--help", "-h"} {
		code, out, errs := run("collect", arg)
		if code != 0 || errs != "" {
			t.Fatalf("%s: code=%d err=%q", arg, code, errs)
		}
		for _, want := range []string{"usage: telltale collect", "-root", "-gzip", "-context-stdin", "fetch-refs"} {
			if !strings.Contains(out, want) {
				t.Errorf("%s: help lacks %q: %q", arg, want, out)
			}
		}
	}
}
