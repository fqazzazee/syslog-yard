package auth

import (
	"net/http"
	"sync"
	"time"

	"github.com/syslog-yard/shared/secure"
)

// throttle is a small in-memory failure counter that locks a key for one
// window once max failures accumulate.
//
// In the default (sliding) mode the count survives as long as failures keep
// arriving less than a window apart, so even a slow brute force trips it. In
// fixed mode the count covers one window from the first failure, which bounds
// how much any single source can contribute to a shared key.
type throttle struct {
	max    int           // failures allowed before lockout
	window time.Duration // counting window and lockout duration
	fixed  bool          // count per fixed window instead of sliding idle reset
	limit  int           // most keys tracked at once

	mu      sync.Mutex
	entries map[string]*attempt
}

// maxThrottleEntries caps the keys one throttle tracks, so failures for ever
// new usernames can't grow memory without bound.
const maxThrottleEntries = 10000

// busyRetry is the retry-after for an attempt refused only because others are
// still being checked; they settle within moments.
const busyRetry = time.Second

type attempt struct {
	count int
	start time.Time // first failure of the current window (fixed mode)
	until time.Time // lockout expiry once max is exceeded
	seen  time.Time // last activity, for cleanup

	inflight int // reserved attempts whose outcome isn't known yet
}

func newThrottle(max int, window time.Duration) *throttle {
	return &throttle{max: max, window: window, limit: maxThrottleEntries, entries: map[string]*attempt{}}
}

func newFixedThrottle(max int, window time.Duration) *throttle {
	t := newThrottle(max, window)
	t.fixed = true
	return t
}

// allow reports whether an attempt for key may proceed, and the retry-after
// duration when it may not.
func (t *throttle) allow(key string) (bool, time.Duration) {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.gc(now)
	a := t.entries[key]
	if a == nil {
		return true, 0
	}
	if !a.until.IsZero() && now.Before(a.until) {
		return false, a.until.Sub(now)
	}
	return true, 0
}

// reserve admits an attempt and counts it against max until it is settled
// with release, failReserved or reset, so parallel attempts can't overrun the
// limit while their password checks are still running.
func (t *throttle) reserve(key string) (bool, time.Duration) {
	ok, _, retry := t.reserveTracked(key)
	return ok, retry
}

// reserveTracked is reserve, also reporting whether the attempt holds a
// reservation. When the table is full of entries that can't be evicted, a new
// key is admitted without one: a full table must not lock out unrelated users,
// and the bcrypt concurrency gate still bounds the work. Existing keys keep
// their lockouts and limits.
func (t *throttle) reserveTracked(key string) (ok, tracked bool, retry time.Duration) {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.gc(now)
	a := t.entries[key]
	if a == nil {
		if !t.makeRoom(now) {
			return true, false, 0
		}
		a = &attempt{start: now, seen: now}
		t.entries[key] = a
	}
	if !a.until.IsZero() && now.Before(a.until) {
		return false, false, a.until.Sub(now)
	}
	count := a.count
	if t.expired(a, now) {
		count = 0
	}
	if count+a.inflight >= t.max {
		return false, false, busyRetry
	}
	a.inflight++
	return true, true, 0
}

// release gives back a reservation whose attempt reached no verdict.
func (t *throttle) release(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	a := t.entries[key]
	if a == nil {
		return
	}
	if a.inflight > 0 {
		a.inflight--
	}
	if a.inflight == 0 && a.count == 0 && a.until.IsZero() {
		delete(t.entries, key)
	}
}

// failReserved turns a reservation into a recorded failure in one step.
func (t *throttle) failReserved(key string) {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if a := t.entries[key]; a != nil && a.inflight > 0 {
		a.inflight--
	}
	t.failLocked(key, now)
}

// expired reports whether a's failure count has aged out of the window.
func (t *throttle) expired(a *attempt, now time.Time) bool {
	return now.Sub(a.seen) > t.window || (t.fixed && now.Sub(a.start) > t.window)
}

// makeRoom frees a slot when the table is full by dropping the least recently
// active entry. Live lockouts and in-flight attempts are never dropped; it
// reports false when only those remain. Caller holds the lock.
func (t *throttle) makeRoom(now time.Time) bool {
	if len(t.entries) < t.limit {
		return true
	}
	var victim string
	var oldest time.Time
	found := false
	for k, a := range t.entries {
		if a.inflight > 0 || now.Before(a.until) {
			continue
		}
		if !found || a.seen.Before(oldest) {
			victim, oldest, found = k, a.seen, true
		}
	}
	if found {
		delete(t.entries, victim)
	}
	return found
}

// fail records a failed attempt, arming the lockout once max is reached.
func (t *throttle) fail(key string) {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.failLocked(key, now)
}

func (t *throttle) failLocked(key string, now time.Time) {
	a := t.entries[key]
	if a == nil {
		if !t.makeRoom(now) {
			return
		}
		a = &attempt{start: now}
		t.entries[key] = a
	} else if t.expired(a, now) {
		a = &attempt{start: now, inflight: a.inflight}
		t.entries[key] = a
	}
	a.count++
	a.seen = now
	if a.count >= t.max {
		a.until = now.Add(t.window)
		a.count = 0
		a.start = a.until // a fresh window begins once the lockout ends
	}
}

func (t *throttle) reset(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	a := t.entries[key]
	if a != nil && a.inflight > 0 {
		// Other attempts are still running and keep their reservations.
		a.count, a.until, a.start = 0, time.Time{}, time.Now()
		return
	}
	delete(t.entries, key)
}

// gc drops entries idle for more than one window; caller holds the lock.
func (t *throttle) gc(now time.Time) {
	for k, a := range t.entries {
		if a.inflight == 0 && now.Sub(a.seen) > t.window && now.After(a.until) {
			delete(t.entries, k)
		}
	}
}

// guard combines two throttles for password checks (login and password
// change):
//
//   - per (account, client IP): a handful of failures locks out only that
//     source, so an attacker can't lock a known account — "admin" — out for
//     everyone just by guessing wrong;
//   - per account: a much higher fixed-window ceiling that a single source
//     can't reach on its own, catching a brute force spread over many IPs.
//
// The hose and valve proxy logins through the bucket, so those all arrive
// from the proxying container's address and share one per-source budget.
type guard struct {
	perSource  *throttle
	perAccount *throttle
}

func newGuard() *guard {
	return &guard{
		perSource:  newThrottle(loginMaxFails, loginWindow),
		perAccount: newFixedThrottle(accountMaxFails, accountWindow),
	}
}

func sourceKey(account, ip string) string { return account + "\x00" + ip }

// allow reports whether a password attempt for account from ip may proceed.
func (g *guard) allow(account, ip string) (bool, time.Duration) {
	if ok, retry := g.perAccount.allow(account); !ok {
		return false, retry
	}
	return g.perSource.allow(sourceKey(account, ip))
}

func (g *guard) fail(account, ip string) {
	g.perSource.fail(sourceKey(account, ip))
	g.perAccount.fail(account)
}

// succeed clears both counters: the right password proves the account's
// owner is present, wherever the earlier failures came from.
func (g *guard) succeed(account, ip string) {
	g.perSource.reset(sourceKey(account, ip))
	g.perAccount.reset(account)
}

// slot is one reserved password attempt. Settle it with fail or succeed;
// release (safe to defer) gives it back if neither happened.
type slot struct {
	g               *guard
	account, source string
	settled         bool
	// Whether each throttle holds a reservation; see reserveTracked.
	sourceTracked, accountTracked bool
}

// reserve admits one password attempt for account from ip, counting it
// against both limits until it is settled. A nil slot means refused.
func (g *guard) reserve(account, ip string) (*slot, time.Duration) {
	source := sourceKey(account, ip)
	ok, sourceTracked, retry := g.perSource.reserveTracked(source)
	if !ok {
		return nil, retry
	}
	ok, accountTracked, retry := g.perAccount.reserveTracked(account)
	if !ok {
		if sourceTracked {
			g.perSource.release(source)
		}
		return nil, retry
	}
	return &slot{g: g, account: account, source: source,
		sourceTracked: sourceTracked, accountTracked: accountTracked}, 0
}

func (s *slot) fail() {
	if s.settled {
		return
	}
	s.settled = true
	if s.sourceTracked {
		s.g.perSource.failReserved(s.source)
	} else {
		s.g.perSource.fail(s.source)
	}
	if s.accountTracked {
		s.g.perAccount.failReserved(s.account)
	} else {
		s.g.perAccount.fail(s.account)
	}
}

func (s *slot) succeed() {
	if s.settled {
		return
	}
	s.release()
	s.g.perSource.reset(s.source)
	s.g.perAccount.reset(s.account)
}

func (s *slot) release() {
	if s.settled {
		return
	}
	s.settled = true
	if s.sourceTracked {
		s.g.perSource.release(s.source)
	}
	if s.accountTracked {
		s.g.perAccount.release(s.account)
	}
}

// clientIP returns the address a request came from: the TCP peer, unless the
// peer is a trusted proxy (YARD_TRUSTED_PROXIES), in which case
// X-Forwarded-For is walked from the right, skipping trusted hops, and the
// first untrusted address is used. Taking the right-most untrusted hop (not
// the left-most entry) matters: a proxy that appends to a client-supplied
// header would otherwise let the client choose its own throttle key. The
// hose/valve auth proxy (apps/shared/yardauth) overwrites the header with the
// browser's address, so either rule gives the same answer there. With no
// trusted proxies configured the header is ignored entirely.
func clientIP(r *http.Request, proxies *secure.Policy) string {
	if proxies == nil {
		proxies = &secure.Policy{}
	}
	return proxies.ClientIP(r)
}
