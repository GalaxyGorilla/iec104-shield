package proxy

import (
	"math"
	"sync"
	"time"
)

// rateLimiter is a token bucket for master-to-outstation I-frames. The
// capacity is one second's worth of the configured rate (minimum 1), so a
// short burst is absorbed without turning a healthy poll cycle into a denial.
//
// A nil *rateLimiter means unlimited; every method is nil-safe.
type rateLimiter struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
	now    func() time.Time
}

func newRateLimiter(rate int) *rateLimiter {
	if rate <= 0 {
		return nil
	}
	burst := float64(rate)
	if burst < 1 {
		burst = 1
	}
	return &rateLimiter{
		rate:   float64(rate),
		burst:  burst,
		tokens: burst,
		now:    time.Now,
	}
}

// allow consumes one token and reports whether the request may be forwarded.
func (l *rateLimiter) allow() bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if !l.last.IsZero() {
		l.tokens = math.Min(l.burst, l.tokens+now.Sub(l.last).Seconds()*l.rate)
	}
	l.last = now
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}
