package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/donaldsteele/telltale/internal/store"
)

// passwordSetting is the sealed setting that holds the admin password's
// argon2id hash, in the usual $argon2id$v=19$m=...,t=...,p=...$salt$hash form.
const passwordSetting = "admin_password"

const (
	// Passwords shorter than this are refused; longer than the maximum
	// too (hashing is the expensive part of a login).
	minPassword = 12
	maxPassword = 1024

	sessionIdle     = 12 * time.Hour
	sessionLifetime = 7 * 24 * time.Hour
	maxSessions     = 64

	loginWindow   = time.Minute
	loginFailures = 5
	maxLimited    = 4096
)

type argonParams struct {
	time, memoryKiB uint32
	threads         uint8
}

// hashParams is argon2id's cost: 64 MiB, three passes. A variable so tests
// can make it cheap.
var hashParams = argonParams{time: 3, memoryKiB: 64 * 1024, threads: 4}

// hashSlots bounds how many password hashes run at once, so a burst of
// logins cannot take all the memory.
var hashSlots = make(chan struct{}, 2)

func hashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	p := hashParams
	hashSlots <- struct{}{}
	key := argon2.IDKey([]byte(pw), salt, p.time, p.memoryKiB, p.threads, 32)
	<-hashSlots
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.memoryKiB, p.time, p.threads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// checkPassword compares pw with a stored hash in constant time.
func checkPassword(pw, stored string) bool {
	f := strings.Split(stored, "$")
	if len(f) != 6 || f[1] != "argon2id" || f[2] != "v="+strconv.Itoa(argon2.Version) {
		return false
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(f[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil || m == 0 || t == 0 || p == 0 || m > 4<<20 || t > 64 {
		return false
	}
	b64 := base64.RawStdEncoding
	salt, err1 := b64.DecodeString(f[4])
	want, err2 := b64.DecodeString(f[5])
	if err1 != nil || err2 != nil || len(want) == 0 {
		return false
	}
	hashSlots <- struct{}{}
	got := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(len(want)))
	<-hashSlots
	return subtle.ConstantTimeCompare(got, want) == 1
}

// hasPassword reports whether the admin password has been set.
func hasPassword(st *store.Store) (bool, error) {
	b, err := st.SecretSetting(passwordSetting)
	return len(b) > 0, err
}

// NeedsSetup reports whether the first-run setup is still to be done: no
// admin password has been set.
func NeedsSetup(st *store.Store) (bool, error) {
	ok, err := hasPassword(st)
	return !ok, err
}

// checkPasswordRules returns the plain-language reason a new password is
// refused, or "".
func checkPasswordRules(pw, repeat string) string {
	switch {
	case len([]rune(pw)) < minPassword:
		return fmt.Sprintf("Choose a password of at least %d characters.", minPassword)
	case len(pw) > maxPassword:
		return fmt.Sprintf("Choose a password of at most %d bytes.", maxPassword)
	case subtle.ConstantTimeCompare([]byte(pw), []byte(repeat)) != 1:
		return "The two passwords do not match."
	}
	return ""
}

// newToken is 32 random bytes in URL-safe base64.
func newToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("telltale: no randomness: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeToken(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, errors.New("not 32 bytes")
	}
	return b, nil
}

// sameToken compares two tokens in constant time; an empty one never
// matches.
func sameToken(a, b string) bool {
	return a != "" && b != "" && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// session is one logged-in browser. The table holds the SHA-256 of its
// token, never the token itself.
type session struct {
	csrf    string
	created time.Time
	seen    time.Time
	ip      string
	flash   string
	// pending enrolments: host keys fetched and shown, not yet confirmed.
	pending map[string]pendingEnrol
	// pendingKeys: repository keys checked and shown, not yet confirmed.
	pendingKeys map[string]pendingKey
}

// keepPending puts v in m under a new one-time ID and returns the ID. It
// first drops entries older than pendingLifetime, then arbitrary ones
// until fewer than maxPending are left. The session table must be locked.
func keepPending[T any](m map[string]T, created func(T) time.Time, now time.Time, v T) string {
	for k, x := range m {
		if now.Sub(created(x)) > pendingLifetime {
			delete(m, k)
		}
	}
	for len(m) >= maxPending {
		for k := range m {
			delete(m, k)
			break
		}
	}
	id := newToken()
	m[id] = v
	return id
}

// takePending removes and returns the entry under id, when it is there and
// not older than pendingLifetime. The session table must be locked.
func takePending[T any](m map[string]T, created func(T) time.Time, now time.Time, id string) (T, bool) {
	v, ok := m[id]
	delete(m, id)
	if !ok || now.Sub(created(v)) > pendingLifetime {
		var zero T
		return zero, false
	}
	return v, true
}

type sessions struct {
	mu sync.Mutex
	m  map[[32]byte]*session
}

func newSessions() *sessions { return &sessions{m: map[[32]byte]*session{}} }

func tokenHash(token string) ([32]byte, bool) {
	raw, err := decodeToken(token)
	if err != nil {
		return [32]byte{}, false
	}
	return sha256.Sum256(raw), true
}

// create starts a session and returns its token.
func (s *sessions) create(now time.Time, ip string) (string, *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expire(now)
	for len(s.m) >= maxSessions {
		var oldest [32]byte
		var t time.Time
		for h, x := range s.m {
			if t.IsZero() || x.seen.Before(t) {
				oldest, t = h, x.seen
			}
		}
		delete(s.m, oldest)
	}
	tok := newToken()
	h, _ := tokenHash(tok)
	x := &session{csrf: newToken(), created: now, seen: now, ip: ip, pending: map[string]pendingEnrol{}, pendingKeys: map[string]pendingKey{}}
	s.m[h] = x
	return tok, x
}

// get returns the live session for a token and marks it used.
func (s *sessions) get(token string, now time.Time) *session {
	h, ok := tokenHash(token)
	if !ok {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	x := s.m[h]
	if x == nil {
		return nil
	}
	if expired(x, now) {
		delete(s.m, h)
		return nil
	}
	x.seen = now
	return x
}

func expired(x *session, now time.Time) bool {
	return now.Sub(x.seen) > sessionIdle || now.Sub(x.created) > sessionLifetime
}

// expire drops expired sessions; s.mu is held.
func (s *sessions) expire(now time.Time) {
	for h, x := range s.m {
		if expired(x, now) {
			delete(s.m, h)
		}
	}
}

// end ends one session.
func (s *sessions) end(token string) {
	if h, ok := tokenHash(token); ok {
		s.mu.Lock()
		delete(s.m, h)
		s.mu.Unlock()
	}
}

// endAll ends every session (a password change).
func (s *sessions) endAll() {
	s.mu.Lock()
	clear(s.m)
	s.mu.Unlock()
}

// has reports whether the table holds this exact value as a key: a check
// that tokens are stored hashed.
func (s *sessions) has(value string) bool {
	raw, err := decodeToken(value)
	if err != nil {
		return false
	}
	var k [32]byte
	copy(k[:], raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.m[k]
	return ok
}

// with runs f with the session table locked, for changes to a session's
// fields.
func (s *sessions) with(f func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f()
}

// limiter counts failed logins per client address: at most loginFailures
// in loginWindow. The address is the TCP peer's; headers such as
// X-Forwarded-For are never read. IPv6 clients are counted per /64, since
// one host can use any address in its /64.
type limiter struct {
	mu      sync.Mutex
	fails   map[string][]time.Time
	audited map[string]time.Time
}

func newLimiter() *limiter {
	return &limiter{fails: map[string][]time.Time{}, audited: map[string]time.Time{}}
}

func limitKey(ip netip.Addr) string {
	if ip.Is4() || ip.Is4In6() {
		return ip.Unmap().String()
	}
	p, _ := ip.Prefix(64)
	return p.String()
}

func (l *limiter) recent(key string, now time.Time) []time.Time {
	ts := l.fails[key]
	i := 0
	for i < len(ts) && now.Sub(ts[i]) >= loginWindow {
		i++
	}
	ts = ts[i:]
	if len(ts) == 0 {
		delete(l.fails, key)
		return nil
	}
	l.fails[key] = ts
	return ts
}

// attempt asks whether the address may try a password now and, when it
// may, counts the try as a failure until succeed says otherwise: requests
// sent in parallel cannot get more than loginFailures tries a window.
// firstRefusal is set the first time in a window a try is refused, so the
// refusal is audited once, not once per try.
func (l *limiter) attempt(ip netip.Addr, now time.Time) (ok, firstRefusal bool) {
	key := limitKey(ip)
	l.mu.Lock()
	defer l.mu.Unlock()
	ts := l.recent(key, now)
	if len(ts) >= loginFailures {
		if t, seen := l.audited[key]; seen && now.Sub(t) < loginWindow {
			return false, false
		}
		l.audited[key] = now
		return false, true
	}
	if ts == nil && len(l.fails) >= maxLimited {
		l.prune(now)
	}
	l.fails[key] = append(ts, now)
	return true, false
}

// prune drops what has aged out, and an arbitrary address when that is not
// enough, so the table never grows past maxLimited; l.mu is held.
func (l *limiter) prune(now time.Time) {
	for k := range l.fails {
		l.recent(k, now)
	}
	for k, t := range l.audited {
		if now.Sub(t) >= loginWindow {
			delete(l.audited, k)
		}
	}
	for k := range l.fails {
		if len(l.fails) < maxLimited {
			break
		}
		delete(l.fails, k)
	}
}

// over reports whether the address has had loginFailures failures in the
// window, counting nothing. firstRefusal is set the first time in a window,
// so the refusal is audited once. Use it with fail where a try is cheap to
// check and only a real failure may count (API tokens); attempt is for
// passwords.
func (l *limiter) over(ip netip.Addr, now time.Time) (over, firstRefusal bool) {
	key := limitKey(ip)
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.recent(key, now)) < loginFailures {
		return false, false
	}
	if t, seen := l.audited[key]; seen && now.Sub(t) < loginWindow {
		return true, false
	}
	l.audited[key] = now
	return true, true
}

// fail counts one failed try for the address.
func (l *limiter) fail(ip netip.Addr, now time.Time) {
	key := limitKey(ip)
	l.mu.Lock()
	defer l.mu.Unlock()
	ts := l.recent(key, now)
	if ts == nil && len(l.fails) >= maxLimited {
		l.prune(now)
	}
	l.fails[key] = append(ts, now)
}

// succeed forgets an address's tries after a good password.
func (l *limiter) succeed(ip netip.Addr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, limitKey(ip))
}
