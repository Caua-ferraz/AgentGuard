package ratelimit

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/metrics"
)

const (
	// MaxBuckets is the maximum number of rate limit buckets kept in memory.
	// When exceeded, stale buckets (fully refilled and older than their window) are evicted.
	MaxBuckets = 10000
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

// BucketCount returns the current number of tracked buckets (for testing).
func (l *Limiter) BucketCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// BucketSnapshot is a point-in-time copy of one bucket's state, used by the
// persistence syncer for write-behind and boot restore. It carries the
// limiter's opaque key ("scope:tenant:agent"); the syncer parses the tenant
// out of it.
type BucketSnapshot struct {
	Key        string
	Tokens     int
	Max        int
	Window     time.Duration
	LastRefill time.Time
}

// Snapshot returns a copy of every live bucket. It holds the limiter lock only
// for the (O(n) struct-copy) duration and is intended for the background
// persistence syncer — it is never called on the request path, so it cannot
// affect the proxy's latency budget.
func (l *Limiter) Snapshot() []BucketSnapshot {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]BucketSnapshot, 0, len(l.buckets))
	for k, b := range l.buckets {
		out = append(out, BucketSnapshot{
			Key: k, Tokens: b.tokens, Max: b.max, Window: b.window, LastRefill: b.lastRefill,
		})
	}
	return out
}

// Restore loads buckets from a prior Snapshot (boot hydration). Entries with a
// matching key are overwritten. Intended to run once, before serving traffic.
func (l *Limiter) Restore(snaps []BucketSnapshot) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, s := range snaps {
		l.buckets[s.Key] = &bucket{tokens: s.Tokens, max: s.Max, window: s.Window, lastRefill: s.LastRefill}
	}
}

// Allow checks whether a request identified by key is within the rate limit.
// maxRequests is the maximum number of requests allowed in the given window.
// Returns nil if allowed, or an error describing the limit.
func (l *Limiter) Allow(key string, maxRequests int, window time.Duration) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Evict stale buckets when at capacity
	if len(l.buckets) >= MaxBuckets {
		l.evictStaleLocked()
	}

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

// evictStaleLocked removes buckets whose window has fully elapsed (they would
// be fully refilled on next access). Must be called with l.mu held.
func (l *Limiter) evictStaleLocked() {
	now := time.Now()
	for key, b := range l.buckets {
		if now.Sub(b.lastRefill) >= b.window {
			delete(l.buckets, key)
			metrics.IncRateLimitBucketEvicted(scopeFromKey(key))
		}
	}
}

// scopeFromKey extracts the scope prefix from a limiter key. The proxy keys
// buckets as "scope:tenant:agent_id" (tenant added in v0.6); scope is kept
// first precisely so this extractor stays a single IndexByte with no parser
// change. Unknown formats return "unknown" so the counter stays well-labeled.
// The scope is the only bounded-cardinality piece of the key, which is why the
// tenant and agent_id fields are discarded (millions of tenant/agent IDs would
// blow up Prometheus series).
func scopeFromKey(key string) string {
	if i := strings.IndexByte(key, ':'); i >= 0 {
		return key[:i]
	}
	return "unknown"
}

// ParseWindow converts a window string like "1m", "30s", "1h" to a Duration.
func ParseWindow(s string) (time.Duration, error) {
	if s == "" {
		return 0, fmt.Errorf("empty window")
	}
	return time.ParseDuration(s)
}
