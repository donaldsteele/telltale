package visit

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// EnrolSnippets returns the two snippets the owner adds to a machine so the
// server can log in as root by key from its own address and nowhere else:
// a line for root's authorized_keys restricted with from=, and a block for
// the end of sshd_config that allows root key login from that address only.
// The machine's global PermitRootLogin stays as it is.
//
// serverAddr is the address the machine sees the server connect from. It
// must pass CheckServerAddr and is written in canonical form. keyLine is
// ServerKey's line, "ssh-ed25519 <base64> <comment>". Anything else is
// refused: a quote would add authorized_keys options, a line break sshd
// directives, and a pattern, range or host name would let in more than the
// server.
func EnrolSnippets(serverAddr, keyLine string) (authorizedKeys, sshdMatch string, err error) {
	a, err := CheckServerAddr(serverAddr)
	if err != nil {
		return "", "", fmt.Errorf("visit: %w", err)
	}
	if err := checkKeyLine(keyLine); err != nil {
		return "", "", fmt.Errorf("visit: %w", err)
	}
	addr := a.String()
	return `from="` + addr + `" ` + keyLine,
		"Match Address " + addr + "\n    PermitRootLogin prohibit-password\n", nil
}

// CheckServerAddr parses the server's address as the machines see it: one
// literal IPv4 or IPv6 address, without a zone. Host names, patterns,
// ranges and the unspecified address are refused. The address is returned
// in canonical form (an IPv4-mapped IPv6 address becomes IPv4, as sshd
// sees it).
func CheckServerAddr(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("the server address %q is not an IP address (host names, patterns and ranges are not allowed)", s)
	}
	if a.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("the server address %q has a zone; give the address without it", s)
	}
	a = a.Unmap()
	if a.IsUnspecified() {
		return netip.Addr{}, fmt.Errorf("the server address %q is the unspecified address, not the server's", s)
	}
	return a, nil
}

// keyCommentRE is what the comment of the server's key line may hold.
var keyCommentRE = regexp.MustCompile(`^[A-Za-z0-9._@+-]+$`)

// checkKeyLine accepts one line "ssh-ed25519 <base64> <comment>" holding an
// ed25519 public key, fields separated by single spaces and the key in
// canonical base64. (Go's decoder skips \r and \n, so a decodable key
// could still span lines.)
func checkKeyLine(line string) error {
	f := strings.Split(line, " ")
	if strings.ContainsAny(line, "\r\n") || len(f) != 3 || f[0] != ssh.KeyAlgoED25519 || !keyCommentRE.MatchString(f[2]) {
		return errors.New(`the server key line is not "ssh-ed25519 <base64> <comment>" on one line`)
	}
	raw, err := base64.StdEncoding.DecodeString(f[1])
	if err == nil && base64.StdEncoding.EncodeToString(raw) != f[1] {
		err = errors.New("the base64 is not in canonical form")
	}
	if err == nil {
		var k ssh.PublicKey
		if k, err = ssh.ParsePublicKey(raw); err == nil && k.Type() != ssh.KeyAlgoED25519 {
			err = errors.New("not an ed25519 key")
		}
	}
	if err != nil {
		return fmt.Errorf("the server key line does not hold an ed25519 key: %w", err)
	}
	return nil
}

// fetchAlgorithms is the host key preference for FetchHostKey: ed25519
// first, then ECDSA, then RSA with SHA-2. Visit puts the pinned key's
// algorithm first and keeps the rest (see algorithmsFor).
var fetchAlgorithms = []string{
	ssh.KeyAlgoED25519,
	ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521,
	ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256,
}

// errGotKey stops FetchHostKey's handshake once the host key is in hand.
var errGotKey = errors.New("host key received")

// FetchHostKey connects to addr (host or host:port; port 22 when none is
// given), takes the host key the machine offers and hangs up before logging
// in. It is the enrolment step: the owner compares the fingerprint with the
// machine's own (ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub) before
// the key is pinned. Visit never trusts a key on first use.
func FetchHostKey(ctx context.Context, addr string) (ssh.PublicKey, string, error) {
	hostport, err := hostPort(addr)
	if err != nil {
		return nil, "", fmt.Errorf("visit: fetch the host key: %w", err)
	}
	var key ssh.PublicKey
	cfg := &ssh.ClientConfig{
		User:              "root",
		HostKeyAlgorithms: fetchAlgorithms,
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
			key = k
			return errGotKey
		},
	}
	conn, err := handshake(ctx, hostport, cfg)
	if conn != nil {
		conn.Close()
	}
	if key != nil {
		return key, ssh.FingerprintSHA256(key), nil
	}
	if err == nil {
		err = errors.New("the machine offered no host key")
	}
	return nil, "", fmt.Errorf("visit: fetch the host key of %s: %w", hostport, err)
}

// withPort adds SSH's port to an address that has none.
func withPort(addr string) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	if len(addr) > 1 && addr[0] == '[' && addr[len(addr)-1] == ']' {
		addr = addr[1 : len(addr)-1] // an IPv6 address in brackets, no port
	}
	return net.JoinHostPort(addr, "22")
}

// hostPort is withPort for an address that names a host. One that does not
// is refused: the dialer would take an empty host for this one.
func hostPort(addr string) (string, error) {
	hp := withPort(addr)
	if host, _, err := net.SplitHostPort(hp); err != nil || strings.TrimSpace(host) == "" {
		return "", fmt.Errorf("the machine has no address (%q)", addr)
	}
	return hp, nil
}

// handshake connects to hostport and runs the SSH handshake (key exchange,
// host key check and, when cfg has auth methods, the login), giving up
// after dialTimeout or when ctx ends.
func handshake(ctx context.Context, hostport string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	var d net.Dialer
	nc, err := d.DialContext(ctx, "tcp", hostport)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		nc.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { nc.Close() })
	conn, chans, reqs, err := ssh.NewClientConn(nc, hostport, cfg)
	if !stop() {
		// ctx ended during the handshake and closed the connection.
		if conn != nil {
			conn.Close()
		}
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, escaped{err}
	}
	nc.SetDeadline(time.Time{})
	return ssh.NewClient(conn, chans, reqs), nil
}
