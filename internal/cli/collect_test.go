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
		"--proc-root", "../collect/testdata/proc1", "--sys-root", "../collect/testdata/root1"}, extra...)
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
