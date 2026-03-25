package ratelimit

import (
	"fmt"
	"sync"
	"time"
)

// Limiter implements a token-bucket rate limiter keyed by scope and agent.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens     int
	max        int
	lastRefill time.Time
	window     time.Duration
}

// New creates a new rate limiter.
func New() *Limiter {
	return &Limiter{buckets: make(map[string]*bucket)}
}

// Allow checks whether a request identified by key is within the rate limit.
// maxRequests is the maximum number of requests allowed in the given window.
// Returns nil if allowed, or an error describing the limit.
func (l *Limiter) Allow(key string, maxRequests int, window time.Duration) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{
			tokens:     maxRequests - 1, // consume one token now
			max:        maxRequests,
			lastRefill: time.Now(),
			window:     window,
		}
		l.buckets[key] = b
		return nil
	}

	// Refill tokens if the window has elapsed
	now := time.Now()
	elapsed := now.Sub(b.lastRefill)
	if elapsed >= b.window {
		periods := int(elapsed / b.window)
		b.tokens = b.max
		b.lastRefill = b.lastRefill.Add(time.Duration(periods) * b.window)
	}

	if b.tokens <= 0 {
		return fmt.Errorf("rate limit exceeded: %d requests per %s", b.max, b.window)
	}

	b.tokens--
	return nil
}

// ParseWindow converts a window string like "1m", "30s", "1h" to a Duration.
func ParseWindow(s string) (time.Duration, error) {
	if s == "" {
		return 0, fmt.Errorf("empty window")
	}
	return time.ParseDuration(s)
}
