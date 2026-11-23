package alerts

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/donaldsteele/bubbles/pkg/bubblesclient"
	"github.com/donaldsteele/bubbles/pkg/protocol"

	"github.com/donaldsteele/telltale/internal/escape"
)

// Pairing follows netdiag's wizard: the owner types the bubbles server's
// address (telltale does not browse the network for it); telltale fetches
// the server's CA from its onboarding port and shows the fingerprint, the
// first four groups large, for the owner to compare with the one the chat
// admin reads out; only then does it ask for a token, showing the code the
// admin approves; it waits; and when the bot is in more than one channel
// the owner picks the one for alerts. The token is saved the moment it
// arrives, since bubbles hands it out once.

// The ports a bubbles server listens on unless its admin changed them: the
// HTTPS API and the plain-HTTP onboarding listener that hands out the CA.
const (
	DefaultPort        = 28225
	DefaultOnboardPort = 28226
)

const (
	maxCandidates    = 8
	candidateLife    = 30 * time.Minute
	pairingWaitLimit = 15 * time.Minute
)

// target is a bubbles server address telltale may pair with.
type target struct {
	host          string
	port, onboard int
}

func (t target) hostPort(p int) string { return net.JoinHostPort(t.host, strconv.Itoa(p)) }
func (t target) baseURL() string       { return "https://" + t.hostPort(t.port) }
func (t target) onboardingURL() string { return "http://" + t.hostPort(t.onboard) }
func (t target) address() string       { return t.hostPort(t.port) }

// adminPairingURL is bubbles' Admin > Pairing page.
func (t target) adminPairingURL() string { return t.baseURL() + "/admin/pairing" }

var errTarget = errors.New("Use the address of a bubbles server on the local network, for example 192.168.1.20 or office.local.")

// parseTarget reads an address the owner typed: host, host:port, or
// https://host:port. The port is the HTTPS port (28225 when none is
// given); the onboarding port is 28226, or the HTTPS port + 1 when a port
// is given, as bubbles' own defaults are. Only local addresses are
// accepted, so the token and the alerts never leave the local network:
// private, link-local, shared (100.64.0.0/10) and loopback IPv4
// addresses, unique-local and loopback IPv6 addresses, and names ending
// in .local.
func parseTarget(address string) (target, error) {
	s := strings.TrimSpace(address)
	if i := strings.Index(s, "://"); i >= 0 {
		u, err := url.Parse(s)
		if err != nil || (u.Scheme != "https" && u.Scheme != "bubbles") || u.Host == "" || u.User != nil {
			return target{}, errTarget
		}
		s = u.Host
	}
	s = strings.TrimSuffix(s, "/")
	host, portText := s, ""
	if h, p, err := net.SplitHostPort(s); err == nil {
		host, portText = h, p
	}
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")), ".")
	if !localHost(host) {
		return target{}, errTarget
	}
	if a, err := netip.ParseAddr(host); err == nil {
		host = a.Unmap().String()
	}
	t := target{host: host, port: DefaultPort, onboard: DefaultOnboardPort}
	if portText != "" {
		p, err := strconv.Atoi(portText)
		if err != nil || p < 1 || p > 65535 {
			return target{}, errors.New("The port must be a number from 1 to 65535.")
		}
		t.port, t.onboard = p, p+1
		if p == 65535 {
			t.onboard = DefaultOnboardPort
		}
	}
	return t, nil
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

func localHost(host string) bool {
	if a, err := netip.ParseAddr(host); err == nil {
		if a.Zone() != "" {
			return false
		}
		a = a.Unmap()
		if a.Is4() {
			return a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLoopback() || cgnat.Contains(a)
		}
		return a.IsPrivate() || a.IsLoopback()
	}
	name, ok := strings.CutSuffix(host, ".local")
	if !ok || name == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

// FingerprintGroups splits a CA fingerprint into the 16 groups of four
// that bubbles' admin pages show (Admin > Overview).
func FingerprintGroups(fp string) []string {
	return strings.Fields(bubblesclient.FormatFingerprint(fp))
}

// candidate is a server whose CA was fetched and shown, kept under a
// one-time ID until the owner says the fingerprint matches.
type candidate struct {
	t       target
	fp      string
	name    string
	created time.Time
}

// Inspection is what the owner compares: the fingerprint of the CA the
// server at Address handed out. ID names it when the owner confirms; the
// fingerprint the pairing pins is the one fetched here, never one a form
// sends back. Every string is escaped.
type Inspection struct {
	ID          string
	Address     string
	Fingerprint string
	// Start is the first four groups, shown large; Rest the other twelve.
	Start, Rest string
	ServerName  string
}

func newID() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic("telltale: no randomness: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Inspect fetches the CA of the bubbles server at address from its
// onboarding port and checks that the server's HTTPS certificate chains to
// it. The download proves nothing by itself: the owner compares the
// fingerprint before StartPairing trusts it. The error is in plain words.
func (b *Bubbles) Inspect(ctx context.Context, address string) (Inspection, error) {
	b.init()
	t, err := parseTarget(address)
	if err != nil {
		return Inspection{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	_, fp, err := bubblesclient.FetchCA(ctx, t.onboardingURL())
	if err != nil {
		b.logf("telltale server: bubbles: fetch CA from %s: %s", t.onboardingURL(), escape.Terminal(err.Error()))
		return Inspection{}, errors.New("telltale can't reach a bubbles server at " + t.host + ". Check the address, and that the chat server is running.")
	}
	c, err := bubblesclient.New(bubblesclient.Config{BaseURL: t.baseURL(), CAFingerprint: fp})
	if err != nil {
		return Inspection{}, errors.New(noTalkMsg)
	}
	st, err := c.Status(ctx)
	switch {
	case errors.Is(err, bubblesclient.ErrServerIdentityChanged):
		b.logf("telltale server: bubbles: status of %s: %s", t.baseURL(), escape.Terminal(err.Error()))
		return Inspection{}, errors.New("Something is wrong with the chat server at " + t.host + ": it doesn't prove it is the server it says it is. Stop here and tell your chat admin.")
	case err != nil:
		b.logf("telltale server: bubbles: status of %s: %s", t.baseURL(), escape.Terminal(err.Error()))
		return Inspection{}, errors.New("telltale can't reach the chat server at " + t.address() + ". Check the address, and that the chat server is running.")
	}
	name := strings.TrimSpace(st.InstanceName)
	cand := candidate{t: t, fp: fp, name: name, created: b.now()}
	id := newID()
	b.mu.Lock()
	for k, x := range b.cands {
		if b.now().Sub(x.created) > candidateLife {
			delete(b.cands, k)
		}
	}
	for len(b.cands) >= maxCandidates {
		for k := range b.cands {
			delete(b.cands, k)
			break
		}
	}
	b.cands[id] = cand
	b.mu.Unlock()
	groups := FingerprintGroups(fp)
	return Inspection{ID: id, Address: escape.Terminal(t.address()), Fingerprint: strings.Join(groups, " "),
		Start: strings.Join(groups[:min(4, len(groups))], " "), Rest: strings.Join(groups[min(4, len(groups)):], " "),
		ServerName: escape.Terminal(name)}, nil
}

// PairState is where a pairing request stands.
type PairState string

const (
	PairNone      PairState = ""
	PairPending   PairState = "pending"
	PairApproved  PairState = "approved"
	PairDenied    PairState = "denied"
	PairExpired   PairState = "expired"
	PairClaimed   PairState = "claimed"
	PairCancelled PairState = "cancelled"
	PairFailed    PairState = "failed"
)

// pairSession is the one pairing request telltale has open.
type pairSession struct {
	c       candidate
	p       *bubblesclient.Pairing
	code    string
	expires time.Time
	state   PairState
	msg     string
	cancel  context.CancelFunc
}

// PairStatus is the pairing request as the wizard shows it. Every string
// is escaped.
type PairStatus struct {
	State   PairState
	Code    string // "123 456"
	Expires time.Time
	Address string
	// AdminURL is bubbles' own Admin > Pairing page, for the chat admin.
	AdminURL string
	// Message says why a request ended without a token, in plain words.
	Message string
}

// formatCode shows a six-digit code as two groups: "123 456".
func formatCode(code string) string {
	if len(code) == 6 {
		return code[:3] + " " + code[3:]
	}
	return code
}

// StartPairing asks the server the owner inspected (candidate id) for a
// token, pinning the CA fingerprint the owner compared. It replaces any
// request still waiting. The request then waits for the chat admin in the
// background; PairStatus says how it went. The error is in plain words.
func (b *Bubbles) StartPairing(ctx context.Context, id string) (PairStatus, error) {
	b.init()
	b.mu.Lock()
	c, ok := b.cands[id]
	delete(b.cands, id)
	if !ok || b.now().Sub(c.created) > candidateLife {
		b.mu.Unlock()
		return PairStatus{}, errors.New("Check the chat server's fingerprint again before you connect.")
	}
	b.stopPairLocked()
	b.mu.Unlock()
	desc := "telltale server"
	if h := b.hostname(); h != "" {
		desc = "telltale server on " + escape.Terminal(h)
	}
	rctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	p, err := bubblesclient.RequestPairing(rctx, c.t.baseURL(), c.fp, protocol.PairingRequest{AppName: AppName, Description: desc, RequestedScopes: Scopes})
	if err != nil {
		return PairStatus{}, errors.New(b.explain(err))
	}
	wctx, wcancel := context.WithTimeout(b.baseContext(), pairingWaitLimit)
	s := &pairSession{c: c, p: p, code: p.Code(), expires: p.ExpiresAt(), state: PairPending, cancel: wcancel}
	b.mu.Lock()
	b.stopPairLocked()
	b.pair = s
	b.mu.Unlock()
	go b.wait(wctx, s, p)
	return b.PairStatus(), nil
}

// stopPairLocked cancels the request waiting, if any; b.mu is held.
func (b *Bubbles) stopPairLocked() {
	if b.pair != nil && b.pair.cancel != nil {
		b.pair.cancel()
	}
	b.pair = nil
}

// wait waits for the chat admin, then saves the token at once and picks
// the alert channel: the one used before when the bot is still in it, else
// the only one. With several, the owner chooses.
func (b *Bubbles) wait(ctx context.Context, s *pairSession, p *bubblesclient.Pairing) {
	defer s.cancel()
	cfg, err := p.Wait(ctx)
	if err != nil {
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.pair != s {
			// Cancelled or replaced: bubbles lets the request lapse, or
			// was told to cancel it.
			return
		}
		switch {
		case errors.Is(err, bubblesclient.ErrPairingDenied):
			s.state, s.msg = PairDenied, "Your chat admin said no."
		case errors.Is(err, bubblesclient.ErrPairingExpired), errors.Is(err, context.DeadlineExceeded):
			s.state, s.msg = PairExpired, "The request ran out of time."
		case errors.Is(err, bubblesclient.ErrPairingClaimed):
			s.state, s.msg = PairClaimed, "The chat server says this request was already used. Try again."
		case errors.Is(err, bubblesclient.ErrPairingCancelled):
			s.state, s.msg = PairCancelled, "The request was cancelled."
		default:
			s.state, s.msg = PairFailed, b.explain(err)
		}
		return
	}
	conn, err := cfg.ConnectionString()
	if err == nil {
		err = b.Store.SetSecretSetting(SettingConn, []byte(conn))
	}
	if err != nil {
		b.logf("telltale server: bubbles: the new connection could not be saved: %s", escape.Terminal(err.Error()))
		b.mu.Lock()
		if b.pair == s {
			s.state, s.msg = PairFailed, "telltale couldn't save the connection in its database. Try again; if it keeps happening, check the server's log."
		}
		b.mu.Unlock()
		return
	}
	var prev channelRecord
	_ = b.loadSealed(SettingChannel, &prev)
	var chans []Channel
	for _, ch := range p.Channels() {
		chans = append(chans, Channel{ID: ch.ID, Name: ch.Name})
	}
	rec := channelRecord{Server: s.c.name}
	switch i := slices.IndexFunc(chans, func(c Channel) bool { return c.ID == prev.ID }); {
	case prev.ID != "" && i >= 0:
		rec.Channel = chans[i]
	case len(chans) == 1:
		rec.Channel = chans[0]
	}
	if err := b.saveSealed(SettingChannel, rec); err != nil {
		b.logf("telltale server: bubbles: the alert channel could not be saved: %s", escape.Terminal(err.Error()))
	}
	b.audit("bubbles connected")
	b.mu.Lock()
	// A new connection is trusted afresh: the old one's trouble goes.
	b.trouble, b.since = TroubleNone, time.Time{}
	b.cl, b.clConn = nil, ""
	b.choices, b.choosing = chans, rec.ID == ""
	if b.pair == s {
		s.state = PairApproved
	}
	b.mu.Unlock()
	b.Kick()
}

// PairStatus is the pairing request telltale has open, if any.
func (b *Bubbles) PairStatus() PairStatus {
	b.init()
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.pair
	if s == nil {
		return PairStatus{}
	}
	return PairStatus{State: s.state, Code: escape.Terminal(formatCode(s.code)), Expires: s.expires,
		Address: escape.Terminal(s.c.t.address()), AdminURL: s.c.t.adminPairingURL(), Message: s.msg}
}

// FinishPairing forgets a pairing request that has ended, once the owner
// has seen how it ended. A request still waiting is left alone.
func (b *Bubbles) FinishPairing() {
	b.init()
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pair != nil && b.pair.state != PairPending {
		b.pair = nil
	}
}

// CancelPairing withdraws the request waiting for the chat admin.
func (b *Bubbles) CancelPairing(ctx context.Context) {
	b.init()
	b.mu.Lock()
	s := b.pair
	waiting := s != nil && s.state == PairPending && s.p != nil
	b.stopPairLocked()
	b.mu.Unlock()
	if !waiting {
		return
	}
	// Tell bubbles too, so the admin can no longer approve it. A server
	// too old to know cancelling lets the request lapse.
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	if err := s.p.Cancel(cctx); err != nil {
		b.logf("telltale server: bubbles: cancel the pairing request: %s", escape.Terminal(err.Error()))
	}
}

// Channels lists again the channels telltale's bot can post in (public and
// private ones that are not archived), and has the settings page offer
// them. The error is in plain words.
func (b *Bubbles) Channels(ctx context.Context) ([]Channel, error) {
	b.init()
	cl, _, err := b.client()
	if err != nil {
		return nil, err
	}
	if cl == nil {
		return nil, errors.New("telltale is not connected to bubbles.")
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	list, err := cl.ListChannels(ctx)
	if err != nil {
		b.classify(err, false)
		return nil, errors.New(b.explain(err))
	}
	var out []Channel
	for _, ch := range list {
		if ch.ArchivedAt != nil || ch.Name == nil || (ch.Kind != protocol.ChannelPublic && ch.Kind != protocol.ChannelPrivate) {
			continue
		}
		out = append(out, Channel{ID: ch.ID, Name: *ch.Name})
	}
	slices.SortFunc(out, func(a, c Channel) int { return strings.Compare(a.Name, c.Name) })
	b.mu.Lock()
	b.choices, b.choosing = out, true
	b.mu.Unlock()
	return out, nil
}

// SetChannel sends alerts to the channel with id from now on. It must be
// one of the channels last listed. The error is in plain words.
func (b *Bubbles) SetChannel(id string) (Channel, error) {
	b.init()
	b.mu.Lock()
	i := slices.IndexFunc(b.choices, func(c Channel) bool { return c.ID == id })
	var ch Channel
	if i >= 0 {
		ch = b.choices[i]
	}
	b.mu.Unlock()
	if i < 0 || id == "" {
		return Channel{}, errors.New("telltale isn't in that channel. Choose another one, or ask your chat admin to add telltale to it.")
	}
	var rec channelRecord
	if err := b.loadSealed(SettingChannel, &rec); err != nil {
		return Channel{}, err
	}
	rec.Channel = ch
	if err := b.saveSealed(SettingChannel, rec); err != nil {
		return Channel{}, err
	}
	b.mu.Lock()
	b.choosing = false
	if b.trouble == TroubleNotAllowed || b.trouble == TroubleArchived || b.trouble == TroubleNoChannel {
		b.trouble, b.since = TroubleNone, time.Time{}
	}
	b.mu.Unlock()
	b.Kick()
	return Channel{ID: ch.ID, Name: escape.Terminal(ch.Name)}, nil
}
