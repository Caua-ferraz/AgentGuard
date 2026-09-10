package ratelimit

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/metrics"
)

const (
	// MaxBuckets is the maximum number of rate limit buckets kept in memory.
	// When exceeded, stale buckets (fully refilled and older than their window) are evicted.
	MaxBuckets = 10000

	// sweepInterval bounds how often the O(n) stale scan may run. Without it
	// the scan fired on EVERY Allow once the map was full, turning a ~70ns
	// 0-alloc hot path into a ~130us locked scan that serialized every
	// rate-limit check process-wide (audit B3).
	sweepInterval = time.Second

	// sampleSize is how many buckets evictSampledLocked inspects to pick a
	// victim. Go randomizes map iteration, so this is an approximate-LRU
	// sample: O(sampleSize), not O(n), and allocation-free.
	sampleSize = 8

	// maxReclaimPerCall bounds the eviction work a single Allow may do, so no
	// one request pays for an oversized map. Each miss evicts at least one and
	// inserts exactly one, so the map cannot grow once it reaches capacity.
	maxReclaimPerCall = 64
)

// Limiter implements a token-bucket rate limiter keyed by scope and agent.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket

	// lastSweep is when evictStaleLocked last ran. Left at its zero value by
	// New so the first reclamation is never delayed.
	lastSweep time.Time
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

	// Hydration must respect the same bound as the request path. The store
	// query behind these snapshots is unbounded, so a deployment with more
	// live keys than MaxBuckets inside its bucket TTL would otherwise boot
	// straight into the over-capacity state -- no attacker needed, and it
	// would survive every restart (audit B3).
	now := time.Now()
	before := len(l.buckets)
	if before > MaxBuckets {
		l.evictStaleLocked(now)
		l.lastSweep = now
		for len(l.buckets) > MaxBuckets {
			if !l.evictSampledLocked() {
				break
			}
		}
		log.Printf("WARNING: rate-limit hydration restored %d buckets, above the in-memory cap of %d; "+
			"trimmed to %d (least-recently-refilled dropped). Those callers start with a fresh bucket. "+
			"Consider a shorter bucket TTL.", before, MaxBuckets, len(l.buckets))
	}
}

// applyChunk bounds how many BucketDelta entries ApplyDeltas processes under a
// single lock acquisition. The reconcile syncer may hand ApplyDeltas thousands
// of deltas; holding l.mu for the whole O(n) pass would serialize every
// concurrent Allow behind reconcile and blow the hot-path latency budget
// (CLAUDE.md §1). Instead we acquire, apply K, release, and repeat — so a hot
// Allow waits at most K map operations, never the full batch.
const applyChunk = 128

// BucketDelta is a background adjustment to one bucket's remaining tokens.
// TokenAdjust is signed; a NEGATIVE value reduces the remaining tokens (used by
// the multi-node reconcile syncer to subtract other nodes' consumption from
// this node's local view so the cluster-wide limit is respected). It is applied
// by ApplyDeltas, never on the request path.
type BucketDelta struct {
	Key         string
	TokenAdjust int // negative = reduce remaining tokens
}

// ApplyDeltas adjusts the remaining tokens of already-tracked buckets in
// bounded, chunked lock acquisitions. It is the write half of multi-node rate
// reconciliation and is called ONLY from the background syncer goroutine — never
// on the /v1/check hot path, so it cannot itself add hot-path latency.
//
// Semantics (CLAUDE.md §1/§4 safe):
//   - Existing keys only. A delta whose key is not currently tracked is skipped;
//     ApplyDeltas never synthesizes a bucket (it lacks max/window and doing so
//     would let reconcile invent limits).
//   - Chunked locking: at most applyChunk (K≈128) buckets are touched per lock
//     hold, so a concurrent Allow blocks for O(K) map ops, not O(n).
//   - Clamped to [0, max]: a negative adjust never drives remaining below zero;
//     a (spurious) positive adjust never grants MORE than the bucket's capacity.
//     For a firewall, granting above capacity would be a safety regression, so
//     both ends are clamped even though reconcile only ever sends reductions.
//   - It does NOT touch lastRefill/window/max, so the fixed-window rollover math
//     in Allow is unaffected; on the next window reset tokens return to max and
//     the reconcile rebaselines for the new epoch.
func (l *Limiter) ApplyDeltas(deltas []BucketDelta) {
	for i := 0; i < len(deltas); i += applyChunk {
		end := i + applyChunk
		if end > len(deltas) {
			end = len(deltas)
		}
		l.mu.Lock()
		for _, d := range deltas[i:end] {
			if d.TokenAdjust == 0 {
				continue
			}
			b, ok := l.buckets[d.Key]
			if !ok {
				continue // existing keys only — never invent a bucket
			}
			b.tokens += d.TokenAdjust
			if b.tokens < 0 {
				b.tokens = 0
			} else if b.tokens > b.max {
				b.tokens = b.max
			}
		}
		l.mu.Unlock()
	}
}

// Allow checks whether a request identified by key is within the rate limit.
// maxRequests is the maximum number of requests allowed in the given window.
// Returns nil if allowed, or an error describing the limit.
func (l *Limiter) Allow(key string, maxRequests int, window time.Duration) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()

	if b, ok := l.buckets[key]; ok {
		// A hot-reloaded policy must take effect on a LIVE bucket, not only
		// after it goes idle. Preserve what the caller has already consumed
		// and re-baseline against the new cap (audit B23).
		if b.max != maxRequests || b.window != window {
			consumed := b.max - b.tokens
			if consumed < 0 {
				consumed = 0
			}
			b.max = maxRequests
			b.window = window
			b.tokens = maxRequests - consumed
			if b.tokens < 0 {
				b.tokens = 0
			}
			if b.tokens > maxRequests {
				b.tokens = maxRequests
			}
		}

		// Refill tokens if the window has elapsed. The window > 0 guard keeps
		// a corrupt restored row (Window: 0) from panicking on divide-by-zero;
		// such a bucket simply never refills.
		elapsed := now.Sub(b.lastRefill)
		if b.window > 0 && elapsed >= b.window {
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

	// MISS -- the only path that can grow the map, and therefore the only
	// place capacity needs checking. Hits (the overwhelming majority of real
	// traffic) now pay nothing for reclamation; previously every call ran the
	// capacity check and, at capacity, a full O(n) scan (audit B3).
	if len(l.buckets) >= MaxBuckets {
		l.reclaimLocked(now)
	}
	l.buckets[key] = &bucket{
		tokens:     maxRequests - 1, // consume one token now
		max:        maxRequests,
		lastRefill: now,
		window:     window,
	}
	return nil
}

// reclaimLocked frees capacity for one incoming bucket. Must hold l.mu.
//
// Two tiers, deliberately ordered cheapest-effective-first:
//
//  1. The stale scan, rate-limited to once per sweepInterval. It is O(n) but
//     amortized, and it is the only tier that can free many buckets at once.
//  2. Approximate-LRU sampling, which runs when the scan was skipped or freed
//     nothing -- the state a real deployment reaches organically once it has
//     more live keys than MaxBuckets inside one window. This is what actually
//     makes MaxBuckets a bound rather than a suggestion.
func (l *Limiter) reclaimLocked(now time.Time) {
	if now.Sub(l.lastSweep) >= sweepInterval {
		l.lastSweep = now
		l.evictStaleLocked(now)
	}
	for i := 0; i < maxReclaimPerCall && len(l.buckets) >= MaxBuckets; i++ {
		if !l.evictSampledLocked() {
			return
		}
	}
}

// evictSampledLocked deletes the least-recently-refilled bucket among a small
// random sample, reporting whether it evicted anything. Go randomizes map
// iteration order, so ranging and breaking after sampleSize entries IS the
// sample. O(sampleSize) and allocation-free: the victim key is a string header
// copy, and ranging a map does not allocate. Must hold l.mu.
func (l *Limiter) evictSampledLocked() bool {
	var (
		victimKey string
		victimAt  time.Time
		found     bool
		seen      int
	)
	for k, b := range l.buckets {
		if !found || b.lastRefill.Before(victimAt) {
			victimKey, victimAt, found = k, b.lastRefill, true
		}
		if seen++; seen >= sampleSize {
			break
		}
	}
	if !found {
		return false
	}
	delete(l.buckets, victimKey)
	metrics.IncRateLimitBucketEvicted(scopeFromKey(victimKey))
	return true
}

// evictStaleLocked removes buckets whose window has fully elapsed (they would
// be fully refilled on next access). Must be called with l.mu held.
func (l *Limiter) evictStaleLocked(now time.Time) {
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
