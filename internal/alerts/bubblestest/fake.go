// Package bubblestest is a fake bubbles server for tests: the CA on its
// plain-HTTP onboarding port (the HTTPS port + 1, as bubbles' defaults
// are), and over HTTPS, with a certificate from that CA, the endpoints
// telltale uses: status, pairing, channels, alerts and resolve.
package bubblestest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/donaldsteele/bubbles/pkg/protocol"
)

// Token is the app token the fake hands out and accepts.
const Token = "bub_testtoken"

// Code is the pairing code the fake shows.
const Code = "123456"

// Server is a running fake.
type Server struct {
	// CAFingerprint is the CA's "sha256:<hex>"; URL the HTTPS base URL.
	CAFingerprint string
	URL           string

	caDER   []byte
	api     *httptest.Server
	onboard *httptest.Server

	mu           sync.Mutex
	instanceName string
	down         bool
	hang         chan struct{}
	started      int
	posts        []protocol.AlertInput
	resolves     []protocol.ResolveAlertByKeyRequest
	open         map[string]bool
	channels     []protocol.PairingChannel
	request      *protocol.PairingRequest
	approved     bool
	claimed      bool
	cancelled    bool
}

// adjacentListeners are two listeners on 127.0.0.1, the second on the
// port after the first's.
func adjacentListeners(t testing.TB) (net.Listener, net.Listener) {
	t.Helper()
	for range 100 {
		a, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := a.Addr().(*net.TCPAddr).Port
		if port < 65535 {
			if b, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port+1)); err == nil {
				return a, b
			}
		}
		a.Close()
	}
	t.Fatal("no two adjacent free ports")
	return nil, nil
}

// New starts a fake whose bot is in one channel, #telltale-alerts
// (ch-alerts). It stops when the test ends.
func New(t testing.TB) *Server {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "bubbles test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "bubbles"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(caDER)
	s := &Server{CAFingerprint: "sha256:" + hex.EncodeToString(sum[:]), caDER: caDER, open: map[string]bool{}, instanceName: "office chat",
		channels: []protocol.PairingChannel{{ID: "ch-alerts", Name: "telltale-alerts"}}}
	apiLn, onboardLn := adjacentListeners(t)
	s.api = httptest.NewUnstartedServer(http.HandlerFunc(s.serveAPI))
	s.api.Listener.Close()
	s.api.Listener = apiLn
	s.api.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey}}}
	s.api.StartTLS()
	s.URL = s.api.URL
	s.onboard = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ca.crt" {
			http.NotFound(w, r)
			return
		}
		w.Write(s.caDER)
	}))
	s.onboard.Listener.Close()
	s.onboard.Listener = onboardLn
	s.onboard.Start()
	t.Cleanup(func() {
		s.mu.Lock()
		if s.hang != nil {
			close(s.hang)
			s.hang = nil
		}
		s.mu.Unlock()
		s.api.Close()
		s.onboard.Close()
	})
	return s
}

// Address is how the owner would type the server's address: host:port.
func (s *Server) Address() string { return strings.TrimPrefix(s.URL, "https://") }

func apiError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, protocol.ErrorBody{Error: protocol.Error{Code: code, Message: msg}})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func (s *Server) serveAPI(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.started++
	down, hang := s.down, s.hang
	s.mu.Unlock()
	if hang != nil {
		select {
		case <-hang:
		case <-r.Context().Done():
			return
		}
	}
	if down {
		apiError(w, http.StatusServiceUnavailable, protocol.CodeUnavailable, "down for the test")
		return
	}
	authed := r.Header.Get("Authorization") == "Bearer "+Token
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/status":
		writeJSON(w, http.StatusOK, protocol.ServerStatus{InstanceName: s.instanceName})
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/pairing/requests":
		var req protocol.PairingRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			apiError(w, http.StatusBadRequest, protocol.CodeBadRequest, "bad body")
			return
		}
		s.request = &req
		writeJSON(w, http.StatusCreated, protocol.PairingCreated{ID: "pr1", PollSecret: "poll-secret", Code: Code, ExpiresAt: time.Now().Add(10 * time.Minute).Format(time.RFC3339Nano)})
	case r.URL.Path == "/api/v1/pairing/requests/pr1":
		if r.Header.Get(protocol.PairingHeader) != "poll-secret" {
			apiError(w, http.StatusNotFound, protocol.CodeNotFound, "no such request")
			return
		}
		switch {
		case r.Method == http.MethodDelete:
			s.cancelled = true
			w.WriteHeader(http.StatusNoContent)
		case s.cancelled:
			writeJSON(w, http.StatusOK, protocol.PairingStatus{State: protocol.PairingCancelled})
		case s.approved && !s.claimed:
			s.claimed = true
			writeJSON(w, http.StatusOK, protocol.PairingStatus{State: protocol.PairingClaimed, Token: Token, Channels: s.channels})
		case s.claimed:
			writeJSON(w, http.StatusOK, protocol.PairingStatus{State: protocol.PairingClaimed})
		default:
			writeJSON(w, http.StatusOK, protocol.PairingStatus{State: protocol.PairingPending})
		}
	case !authed:
		apiError(w, http.StatusUnauthorized, protocol.CodeUnauthorized, "bad token")
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/channels":
		var items []protocol.Channel
		for _, c := range s.channels {
			name := c.Name
			items = append(items, protocol.Channel{ID: c.ID, Kind: protocol.ChannelPublic, Name: &name})
		}
		writeJSON(w, http.StatusOK, protocol.ChannelList{Items: items})
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/alerts":
		var in protocol.AlertInput
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			apiError(w, http.StatusBadRequest, protocol.CodeBadRequest, "bad body")
			return
		}
		if !slices.ContainsFunc(s.channels, func(c protocol.PairingChannel) bool { return c.ID == in.Channel }) {
			apiError(w, http.StatusNotFound, protocol.CodeNotFound, "no such channel")
			return
		}
		s.posts = append(s.posts, in)
		s.open[in.DedupeKey] = true
		writeJSON(w, http.StatusCreated, protocol.PostedAlert{Transition: "created"})
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/alerts/resolve":
		var in protocol.ResolveAlertByKeyRequest
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			apiError(w, http.StatusBadRequest, protocol.CodeBadRequest, "bad body")
			return
		}
		s.resolves = append(s.resolves, in)
		if !s.open[in.DedupeKey] {
			apiError(w, http.StatusNotFound, protocol.CodeNotFound, "no open alert with that key")
			return
		}
		s.open[in.DedupeKey] = false
		writeJSON(w, http.StatusOK, protocol.Message{})
	default:
		apiError(w, http.StatusNotFound, protocol.CodeNotFound, "no such endpoint")
	}
}

// SetDown makes every API call answer 503, or stops that.
func (s *Server) SetDown(v bool) {
	s.mu.Lock()
	s.down = v
	s.mu.Unlock()
}

// HangAll makes every API call wait until the test ends or the client
// gives up.
func (s *Server) HangAll() {
	s.mu.Lock()
	s.hang = make(chan struct{})
	s.mu.Unlock()
}

// SetInstanceName sets the name GET /status reports.
func (s *Server) SetInstanceName(n string) {
	s.mu.Lock()
	s.instanceName = n
	s.mu.Unlock()
}

// SetChannels sets the channels the bot is in.
func (s *Server) SetChannels(chans ...protocol.PairingChannel) {
	s.mu.Lock()
	s.channels = chans
	s.mu.Unlock()
}

// Approve has the chat admin approve the pairing request.
func (s *Server) Approve() {
	s.mu.Lock()
	s.approved = true
	s.mu.Unlock()
}

// ResetPairing forgets the pairing request, for a second one.
func (s *Server) ResetPairing() {
	s.mu.Lock()
	s.request, s.approved, s.claimed, s.cancelled = nil, false, false, false
	s.mu.Unlock()
}

// Request is the last pairing request, or nil.
func (s *Server) Request() *protocol.PairingRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.request
}

// Cancelled reports whether the pairing request was withdrawn.
func (s *Server) Cancelled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cancelled
}

// Posts are the alerts posted, in order.
func (s *Server) Posts() []protocol.AlertInput {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.posts)
}

// Resolves are the resolves asked for, in order.
func (s *Server) Resolves() []protocol.ResolveAlertByKeyRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.resolves)
}

// Calls is how many API calls began.
func (s *Server) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.started
}
