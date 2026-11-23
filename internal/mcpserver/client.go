package mcpserver

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/donaldsteele/telltale/internal/server"
	"github.com/donaldsteele/telltale/internal/version"
)

const (
	// defaultTimeout bounds every API call, the answer's body included.
	defaultTimeout = 30 * time.Second
	// maxResponse bounds an API answer.
	maxResponse = 64 << 20
	// maxTokenFile bounds the token file; a token is 43 characters.
	maxTokenFile = 4096
	maxToken     = 512
)

// Client talks to a telltale server's API over HTTPS, to exactly one
// certificate: the one whose SHA-256 the owner gave. No certificate
// authority is trusted, the system's included.
type Client struct {
	base  string // https://host:port
	token string
	http  *http.Client
}

// ClientOptions configures a Client.
type ClientOptions struct {
	// Server is the server's address as https://addr:port.
	Server string
	// Token is an API token made in the web UI's settings.
	Token string
	// Fingerprint is the server's certificate SHA-256 as the web UI and
	// the server's console show it, with or without "SHA256:" and colons.
	Fingerprint string
	// Timeout bounds each call; 0 means 30 seconds.
	Timeout time.Duration
}

// FingerprintError means the server's certificate is not the pinned one.
type FingerprintError struct {
	Want, Got string
}

func (e *FingerprintError) Error() string {
	return "the server's HTTPS certificate has the fingerprint " + e.Got + ", not " + e.Want +
		" as given with --fingerprint, so telltale mcp refuses to talk to it. If the server's certificate was replaced on purpose, copy the new fingerprint from its web UI's settings"
}

// ServerError is an error answer from the API: its HTTP status and the
// server's own message.
type ServerError struct {
	Status  int
	Message string
}

func (e *ServerError) Error() string {
	return fmt.Sprintf("the telltale server answered %d %s: %s", e.Status, http.StatusText(e.Status), e.Message)
}

// NewClient checks the options and makes a client. It does not connect.
func NewClient(o ClientOptions) (*Client, error) {
	base, err := serverURL(o.Server)
	if err != nil {
		return nil, err
	}
	pin, err := ParseFingerprint(o.Fingerprint)
	if err != nil {
		return nil, err
	}
	if err := checkToken(o.Token); err != nil {
		return nil, err
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	tr := &http.Transport{
		Proxy:                 nil, // straight to the server, never through a proxy from the environment
		DialContext:           (&net.Dialer{Timeout: min(timeout, 10*time.Second)}).DialContext,
		TLSClientConfig:       pinnedTLS(pin),
		TLSHandshakeTimeout:   min(timeout, 10*time.Second),
		ResponseHeaderTimeout: timeout,
		MaxIdleConns:          2,
		IdleConnTimeout:       time.Minute,
	}
	hc := &http.Client{
		Transport: tr,
		Timeout:   timeout,
		// The API never redirects; a redirect would lead to the web UI.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return &Client{base: base, token: o.Token, http: hc}, nil
}

// serverURL checks the --server address: https, a host, and nothing else.
func serverURL(s string) (string, error) {
	const want = "give the server's address as https://ADDRESS:PORT, as its web UI's settings show it"
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", errors.New(want)
	}
	return "https://" + u.Host, nil
}

// ParseFingerprint reads a certificate's SHA-256 as the web UI shows it
// ("SHA256:AB:CD:..."), in either case, with or without the prefix and the
// colons.
func ParseFingerprint(s string) ([32]byte, error) {
	var pin [32]byte
	s = strings.TrimSpace(s)
	if len(s) >= 7 && strings.EqualFold(s[:7], "SHA256:") {
		s = s[7:]
	}
	b, err := hex.DecodeString(strings.ReplaceAll(s, ":", ""))
	if err != nil || len(b) != len(pin) {
		return pin, errors.New("give the server's certificate fingerprint as SHA256: and 64 hex digits, as its web UI's settings show it")
	}
	copy(pin[:], b)
	return pin, nil
}

// FormatFingerprint writes a SHA-256 the way the web UI shows it, with the
// SHA256: prefix.
func FormatFingerprint(sum [32]byte) string {
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	var b strings.Builder
	b.WriteString("SHA256:")
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(h[i : i+2])
	}
	return b.String()
}

// pinnedTLS trusts exactly the certificate with SHA-256 pin. Certificate
// authorities and names are not checked (the server's certificate is
// self-signed); the pin is checked on every connection, resumed ones too.
func pinnedTLS(pin [32]byte) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    x509.NewCertPool(), // no certificate authority, not even the system's
		// Chain and name checks are replaced by the pin in VerifyConnection.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("the server sent no certificate")
			}
			got := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare(got[:], pin[:]) != 1 {
				return &FingerprintError{Want: FormatFingerprint(pin), Got: FormatFingerprint(got)}
			}
			return nil
		},
	}
}

// checkToken accepts what can be a token: printable ASCII without spaces,
// so it cannot break the Authorization header.
func checkToken(tok string) error {
	if tok == "" {
		return errors.New("no token: make one in the server's web UI, under Settings, MCP access tokens")
	}
	if len(tok) > maxToken {
		return errors.New("that is too long to be a token")
	}
	for i := 0; i < len(tok); i++ {
		if tok[i] <= ' ' || tok[i] > '~' {
			return errors.New("the token holds a space, a line break or another character a token never has")
		}
	}
	return nil
}

// ReadTokenFile reads the API token from a file that only its owner can
// read. A symbolic link (in the last part of the path), anything but a
// regular file, and a file other users can read or change are refused.
func ReadTokenFile(path string) (string, error) {
	// O_NONBLOCK: opening a FIFO must not wait for a writer.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if errors.Is(err, syscall.ELOOP) {
		return "", fmt.Errorf("the token file %s is a symbolic link; give the file itself", path)
	}
	if err != nil {
		return "", fmt.Errorf("the token file: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("the token file: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("the token file %s is not a regular file", path)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return "", fmt.Errorf("the token file %s is open to other users (mode %04o); make it private with: chmod 600 %s", path, perm, path)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxTokenFile+1))
	if err != nil {
		return "", fmt.Errorf("the token file: %w", err)
	}
	if len(b) > maxTokenFile {
		return "", fmt.Errorf("the token file %s is larger than %d bytes; it should hold only the token", path, maxTokenFile)
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return "", fmt.Errorf("the token file %s is empty; paste the token from the server's web UI into it", path)
	}
	if err := checkToken(tok); err != nil {
		return "", fmt.Errorf("the token file %s: %w", path, err)
	}
	return tok, nil
}

// do sends one request and decodes the JSON answer into out.
func (c *Client) do(ctx context.Context, method, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "telltale-mcp/"+version.Version)
	resp, err := c.http.Do(req)
	if err != nil {
		var fe *FingerprintError
		if errors.As(err, &fe) {
			return fe
		}
		return fmt.Errorf("could not reach the telltale server at %s: %w", c.base, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return fmt.Errorf("the telltale server's answer could not be read: %w", err)
	}
	if len(body) > maxResponse {
		return fmt.Errorf("the telltale server's answer is larger than %d MiB", maxResponse>>20)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var e server.APIError
		if json.Unmarshal(body, &e) != nil || e.Error == "" {
			e.Error = "(no message)"
		}
		return &ServerError{Status: resp.StatusCode, Message: e.Error}
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("the telltale server's answer is not what telltale mcp expects (is it the same version?): %w", err)
	}
	return nil
}

func id(n int64) string { return strconv.FormatInt(n, 10) }

// Machines lists the server's machines.
func (c *Client) Machines(ctx context.Context) ([]server.APIMachine, error) {
	var out server.APIMachines
	err := c.do(ctx, http.MethodGet, "/api/v1/machines", &out)
	return out.Machines, err
}

// LatestReport is the machine's latest report.
func (c *Client) LatestReport(ctx context.Context, machineID int64) (*server.APIReport, error) {
	var out server.APIReport
	if err := c.do(ctx, http.MethodGet, "/api/v1/machines/"+id(machineID)+"/report", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Report is one stored report.
func (c *Client) Report(ctx context.Context, reportID int64) (*server.APIReport, error) {
	var out server.APIReport
	if err := c.do(ctx, http.MethodGet, "/api/v1/reports/"+id(reportID), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Compare compares two of the machine's reports; 0 lets the server choose
// (b the latest, a the one before b).
func (c *Client) Compare(ctx context.Context, machineID, a, b int64) (*server.APIComparison, error) {
	q := url.Values{}
	if a > 0 {
		q.Set("a", id(a))
	}
	if b > 0 {
		q.Set("b", id(b))
	}
	p := "/api/v1/machines/" + id(machineID) + "/compare"
	if len(q) > 0 {
		p += "?" + q.Encode()
	}
	var out server.APIComparison
	if err := c.do(ctx, http.MethodGet, p, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Visit asks the server to visit the machine now.
func (c *Client) Visit(ctx context.Context, machineID int64) (*server.APIVisit, error) {
	var out server.APIVisit
	if err := c.do(ctx, http.MethodPost, "/api/v1/machines/"+id(machineID)+"/visit", &out); err != nil {
		return nil, err
	}
	return &out, nil
}
