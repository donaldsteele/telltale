package redact

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"testing"
)

var testKey = []byte("test-key")

var digestRe = regexp.MustCompile(`<redacted h:[0-9a-f]{24}>`)

func TestDigestFormat(t *testing.T) {
	got := Digest(testKey, "hunter2")
	if !regexp.MustCompile(`^h:[0-9a-f]{24}$`).MatchString(got) {
		t.Fatalf("Digest = %q, want h: followed by 24 hex chars", got)
	}
}

func TestDigestMatchesHMAC(t *testing.T) {
	mac := hmac.New(sha256.New, testKey)
	mac.Write([]byte("hunter2"))
	want := "h:" + hex.EncodeToString(mac.Sum(nil)[:12])
	if got := Digest(testKey, "hunter2"); got != want {
		t.Errorf("Digest = %q, want %q", got, want)
	}
}

func TestRedactEnvironmentLine(t *testing.T) {
	got, n := Line(testKey, "Environment=DB_PASSWORD=hunter2 MODE=prod")
	if strings.Contains(got, "hunter2") || strings.Contains(got, "prod") {
		t.Errorf("secret or value leaked: %q", got)
	}
	if !strings.Contains(got, "DB_PASSWORD=") || !strings.Contains(got, "MODE=") {
		t.Errorf("names were not kept: %q", got)
	}
	if c := len(digestRe.FindAllString(got, -1)); c != 2 {
		t.Errorf("digest count = %d, want 2 in %q", c, got)
	}
	if n != 2 {
		t.Errorf("n = %d, want 2", n)
	}
}

func TestRedactEnvironmentQuoted(t *testing.T) {
	got, n := Line(testKey, `Environment="A=1" B=2`)
	if strings.Contains(got, "=1\"") || strings.Contains(got, " B=2") {
		t.Errorf("value not redacted: %q", got)
	}
	if !strings.HasPrefix(got, `Environment="A=`) || !strings.Contains(got, `" B=`) {
		t.Errorf("names or quotes not kept: %q", got)
	}
	if n != 2 {
		t.Errorf("n = %d, want 2", n)
	}
}

func TestRedactEnvironmentLeadingSpace(t *testing.T) {
	got, n := Line(testKey, "   Environment=MODE=prod")
	if !strings.HasPrefix(got, "   Environment=MODE=<redacted h:") || n != 1 {
		t.Errorf("Line = %q, n = %d", got, n)
	}
}

func TestRedactExport(t *testing.T) {
	got, n := Line(testKey, "export API_TOKEN=abc123")
	if strings.Contains(got, "abc123") {
		t.Errorf("value leaked: %q", got)
	}
	if !strings.HasPrefix(got, "export API_TOKEN=<redacted h:") || n != 1 {
		t.Errorf("Line = %q, n = %d", got, n)
	}
}

func TestRedactExportQuoted(t *testing.T) {
	for _, line := range []string{
		`export DB_PASSWORD="correct horse"`,
		`export DB_PASSWORD='correct horse'`,
	} {
		got, n := Line(testKey, line)
		if strings.Contains(got, "correct") || strings.Contains(got, "horse") {
			t.Errorf("%q: value leaked: %q", line, got)
		}
		if !strings.HasPrefix(got, "export DB_PASSWORD=<redacted h:") || strings.Contains(got, `"`) || strings.Contains(got, "'") {
			t.Errorf("%q: Line = %q, want whole quoted value replaced", line, got)
		}
		if n != 1 {
			t.Errorf("%q: n = %d, want 1", line, n)
		}
	}
}

func TestRedactKeyValueColon(t *testing.T) {
	got, n := Line(testKey, "api_key: s3cr3t")
	if strings.Contains(got, "s3cr3t") || !strings.HasPrefix(got, "api_key: <redacted h:") || n != 1 {
		t.Errorf("Line = %q, n = %d", got, n)
	}
}

func TestRedactKeyValueSpacing(t *testing.T) {
	got, n := Line(testKey, "aws_secret_access_key = wJalr  ")
	if strings.Contains(got, "wJalr") || !strings.HasPrefix(got, "aws_secret_access_key = <redacted h:") || !strings.HasSuffix(got, ">  ") || n != 1 {
		t.Errorf("Line = %q, n = %d", got, n)
	}
}

func TestRedactURLUserinfo(t *testing.T) {
	got, n := Line(testKey, "url = postgres://dbuser:hunter2@db.example.com/app")
	if strings.Contains(got, "dbuser") || strings.Contains(got, "hunter2") {
		t.Errorf("userinfo leaked: %q", got)
	}
	if !strings.Contains(got, "postgres://<redacted h:") || !strings.Contains(got, ">@db.example.com/app") || n != 1 {
		t.Errorf("Line = %q, n = %d", got, n)
	}
}

func TestRedactURLWithoutPasswordUnchanged(t *testing.T) {
	line := "url = https://user@host.example/path"
	got, n := Line(testKey, line)
	if got != line || n != 0 {
		t.Errorf("Line = %q, n = %d; want unchanged", got, n)
	}
}

func TestRedactTwoSecretsOneLine(t *testing.T) {
	got, n := Line(testKey, "fetch https://admin:hunter2@example.com/ token=abc")
	if strings.Contains(got, "hunter2") || strings.Contains(got, "abc") || strings.Contains(got, "admin") {
		t.Errorf("secret leaked: %q", got)
	}
	if n != 2 {
		t.Errorf("n = %d, want 2 (%q)", n, got)
	}
}

func TestRedactSameValueSameDigest(t *testing.T) {
	a, _ := Line(testKey, "DB_PASSWORD=hunter2")
	b, _ := Line(testKey, "DB_PASSWORD=hunter2")
	if a != b {
		t.Errorf("same value gave different output: %q vs %q", a, b)
	}
}

func TestRedactDifferentKeyDifferentDigest(t *testing.T) {
	a, _ := Line([]byte("key-one"), "DB_PASSWORD=hunter2")
	b, _ := Line([]byte("key-two"), "DB_PASSWORD=hunter2")
	if a == b {
		t.Errorf("different keys gave the same digest: %q", a)
	}
}

func TestRedactLeavesOrdinaryLines(t *testing.T) {
	for _, line := range []string{
		"PermitRootLogin no",
		"HostKey /etc/ssh/ssh_host_ed25519_key",
		"PubkeyAuthentication yes",
		"",
		"# just a comment",
	} {
		got, n := Line(testKey, line)
		if got != line || n != 0 {
			t.Errorf("Line(%q) = %q, n = %d; want unchanged", line, got, n)
		}
	}
}

func TestRedactCommentedSecret(t *testing.T) {
	got, n := Line(testKey, "# password = hunter2")
	if strings.Contains(got, "hunter2") || n != 1 {
		t.Errorf("Line = %q, n = %d", got, n)
	}
}
