package visit

import (
	"context"
	"errors"
	"fmt"
	"net"
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
// serverAddr is the address the machine sees the server connect from, and
// keyLine is ServerKey's line. Neither may hold a quote or a line break; the
// caller checks the address it was configured with.
func EnrolSnippets(serverAddr, keyLine string) (authorizedKeys, sshdMatch string) {
	return `from="` + serverAddr + `" ` + keyLine,
		"Match Address " + serverAddr + "\n    PermitRootLogin prohibit-password\n"
}

// fetchAlgorithms is the host key preference for FetchHostKey: ed25519
// first, then ECDSA, then RSA with SHA-2. Visit then asks for the pinned
// key's algorithm only, so a machine with several host keys always shows the
// one that was pinned.
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
