package auth

import (
	"sync"
	"time"
)

// throttle is a small in-memory failed-login limiter. It is keyed by
// username rather than client IP on purpose: the hose and valve proxy
// their logins through the bucket, so the bucket sees their container IP,
// not the real client — keying by the account being attacked throttles a
// targeted brute-force no matter where the attempts originate. A genuine
// user is unaffected because a correct password resets the counter.
type throttle struct {
	max    int           // failures allowed within the window
	window time.Duration // sliding lockout window

	mu      sync.Mutex
	entries map[string]*attempt
}

type attempt struct {
	count int
	until time.Time // lockout expiry once max is exceeded
	seen  time.Time // last activity, for cleanup
}

func newThrottle(max int, window time.Duration) *throttle {
	return &throttle{max: max, window: window, entries: map[string]*attempt{}}
}

// allow reports whether a login attempt for key may proceed, and the
// retry-after duration when it may not.
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
		return false, time.Until(a.until)
	}
	return true, 0
}

// fail records a failed attempt, arming the lockout once max is reached.
func (t *throttle) fail(key string) {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	a := t.entries[key]
	if a == nil || now.Sub(a.seen) > t.window {
		a = &attempt{}
		t.entries[key] = a
	}
	a.count++
	a.seen = now
	if a.count >= t.max {
		a.until = now.Add(t.window)
		a.count = 0
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
