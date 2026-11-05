package auth

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
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

	mu      sync.Mutex
	entries map[string]*attempt
}

type attempt struct {
	count int
	start time.Time // first failure of the current window (fixed mode)
	until time.Time // lockout expiry once max is exceeded
	seen  time.Time // last activity, for cleanup
}

func newThrottle(max int, window time.Duration) *throttle {
	return &throttle{max: max, window: window, entries: map[string]*attempt{}}
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

// fail records a failed attempt, arming the lockout once max is reached.
func (t *throttle) fail(key string) {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	a := t.entries[key]
	expired := a == nil || now.Sub(a.seen) > t.window
	if a != nil && t.fixed && now.Sub(a.start) > t.window {
		expired = true
	}
	if expired {
		a = &attempt{start: now}
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
	delete(t.entries, key)
	t.mu.Unlock()
}

// gc drops entries idle for more than one window; caller holds the lock.
func (t *throttle) gc(now time.Time) {
	for k, a := range t.entries {
		if now.Sub(a.seen) > t.window && now.After(a.until) {
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

// ParseTrustedProxies parses a comma-separated list of IPs and CIDRs
// (BUCKET_TRUSTED_PROXIES) whose X-Forwarded-For header the bucket believes.
func ParseTrustedProxies(v string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.Split(v, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if strings.Contains(f, "/") {
			p, err := netip.ParsePrefix(f)
			if err != nil {
				return nil, fmt.Errorf("trusted proxy %q: %w", f, err)
			}
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(f)
		if err != nil {
			return nil, fmt.Errorf("trusted proxy %q: %w", f, err)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

// clientIP returns the address a request came from: the TCP peer, unless the
// peer is a trusted proxy, in which case X-Forwarded-For is walked from the
// right past further trusted hops. With no trusted proxies configured the
// header is ignored entirely, so clients can't pick their own throttle key.
func clientIP(r *http.Request, trusted []netip.Prefix) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	peer = peer.Unmap()
	if !isTrusted(peer, trusted) {
		return peer.String()
	}
	var hops []string
	for _, h := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(h, ",")...)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break // malformed hop: stop at the last address we could verify
		}
		peer = a.Unmap()
		if !isTrusted(peer, trusted) {
			break
		}
	}
	return peer.String()
}

func isTrusted(a netip.Addr, trusted []netip.Prefix) bool {
	for _, p := range trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
