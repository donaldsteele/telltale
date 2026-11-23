package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// The web UI's self-signed certificate and its key, in the data directory.
const (
	certFile = "tls.crt"
	keyFile  = "tls.key"
)

// certValidity is how long a generated certificate is valid. The owner
// trusts it by its fingerprint, not by a CA, so a long life only spares a
// surprise.
const certValidity = 5 * 365 * 24 * time.Hour

// LoadOrCreateCert returns the web UI's certificate from dataDir, making a
// self-signed ECDSA P-256 one on first use for the given IP addresses. The
// key file is written 0600 and never followed through a symbolic link.
// fingerprint is the SHA-256 of the certificate, as browsers show it
// (colon-separated upper-case hex), for the owner to compare.
func LoadOrCreateCert(dataDir string, ips []net.IP) (cert tls.Certificate, fingerprint string, err error) {
	cp, kp := filepath.Join(dataDir, certFile), filepath.Join(dataDir, keyFile)
	certPEM, cerr := readNoFollow(cp)
	keyPEM, kerr := readNoFollow(kp)
	switch {
	case cerr == nil && kerr == nil:
	case errors.Is(cerr, os.ErrNotExist) && errors.Is(kerr, os.ErrNotExist):
		if certPEM, keyPEM, err = newCert(ips); err != nil {
			return tls.Certificate{}, "", err
		}
		// The key first: a certificate without its key is useless, and
		// O_EXCL refuses to replace anything already there.
		if err := writeExcl(kp, keyPEM, 0o600); err != nil {
			return tls.Certificate{}, "", err
		}
		if err := writeExcl(cp, certPEM, 0o644); err != nil {
			return tls.Certificate{}, "", err
		}
	case cerr != nil && !errors.Is(cerr, os.ErrNotExist):
		return tls.Certificate{}, "", cerr
	case kerr != nil && !errors.Is(kerr, os.ErrNotExist):
		return tls.Certificate{}, "", kerr
	default:
		return tls.Certificate{}, "", fmt.Errorf("only one of %s and %s exists; remove the other one and a new certificate is made", cp, kp)
	}
	cert, err = tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("%s and %s: %w", cp, kp, err)
	}
	return cert, Fingerprint(cert.Certificate[0]), nil
}

// Fingerprint is the SHA-256 of a DER certificate as browsers show it.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	parts := make([]string, 0, len(sum))
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

func newCert(ips []net.IP) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "telltale server", Organization: []string{"telltale"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(certValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), nil
}

// readNoFollow reads a small regular file without following a symbolic
// link in its last element; a key file readable by others is made 0600.
func readNoFollow(p string) ([]byte, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, syscall.ELOOP) {
		return nil, fmt.Errorf("%s is a symbolic link; refusing to follow it", p)
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", p)
	}
	if filepath.Base(p) == keyFile && fi.Mode().Perm()&0o077 != 0 {
		if err := f.Chmod(0o600); err != nil {
			return nil, fmt.Errorf("%s is readable by others and could not be made 0600: %w", p, err)
		}
	}
	return io.ReadAll(io.LimitReader(f, 1<<20))
}

func writeExcl(p string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	if err := f.Chmod(mode); err != nil { // the umask may have narrowed it; never widen the key
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(p)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// TLSConfig is the web UI's TLS: version 1.2 or later, and for 1.2 only
// forward-secret AEAD suites for the ECDSA certificate.
func TLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		NextProtos: []string{"h2", "http/1.1"},
	}
}
