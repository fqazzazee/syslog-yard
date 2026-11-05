package notify

import (
	"sync"
	"time"
)

// limiter is a per-node sliding-window rate limiter: at most `rate`
// deliveries per trailing minute. The dispatcher always passes a positive
// rate (see EffectiveRate); rate <= 0 here would mean unlimited.
type limiter struct {
	mu    sync.Mutex
	times []time.Time
}

func newLimiter() *limiter { return &limiter{} }

func (l *limiter) allow(rate int) bool {
	if rate <= 0 {
		return true
	}
	now := time.Now()
	cutoff := now.Add(-time.Minute)
	l.mu.Lock()
	defer l.mu.Unlock()
	i := 0
	for i < len(l.times) && l.times[i].Before(cutoff) {
		i++
	}
	l.times = l.times[i:]
	if len(l.times) >= rate {
		return false
	}
	l.times = append(l.times, now)
	return true
}
