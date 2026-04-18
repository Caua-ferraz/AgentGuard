// Package deprecation is the AgentGuard helper for flagging features that are
// scheduled for removal. It does three things:
//
//  1. Logs a single WARN line the first time each deprecated feature is used
//     in a given process (so a long-running server does not spam its log).
//  2. Tracks a per-feature counter that is exported as
//     agentguard_deprecations_used_total{feature="..."} by the metrics package.
//     Scraping the counter before a planned removal release is the way to tell
//     whether anyone is still relying on the feature.
//  3. Keeps the stable feature-key convention in one place. Keys must match the
//     "feature" column in docs/DEPRECATIONS.md — if you add a Warn() call, add
//     the matching row in that table in the same commit.
//
// The helper is deliberately process-local. Cross-restart aggregation happens
// through the scraped Prometheus counter, not through shared state.
package deprecation

import (
	"log"
	"sync"
	"sync/atomic"
)

// state holds the per-feature counter and the once-per-process log guard.
// Using a dedicated struct (rather than two parallel maps) keeps the counter
// pointer stable so callers can atomic.AddUint64 without going through the map
// on every call.
type state struct {
	count  uint64
	logged uint32 // 0 = not yet logged, 1 = logged
}

var (
	mu       sync.RWMutex
	features = map[string]*state{}
)

// Warn records that a deprecated feature was used. The first call per feature
// key emits a WARN log line in the form:
//
//	WARN deprecation feature=<key> msg=<msg>
//
// Subsequent calls with the same key only increment the counter. msg should
// include both the deprecated-in and removal-target releases plus a pointer to
// docs/DEPRECATIONS.md, so operators reading the log can act without digging
// through source.
//
// Callers must use a stable key that matches the "feature" column in
// docs/DEPRECATIONS.md. The metric cardinality is bounded by that table.
func Warn(feature, msg string) {
	s := get(feature)
	atomic.AddUint64(&s.count, 1)
	if atomic.CompareAndSwapUint32(&s.logged, 0, 1) {
		log.Printf("WARN deprecation feature=%s msg=%q", feature, msg)
	}
}

// Count returns the current usage count for the given feature. Primarily used
// by tests; runtime consumers should go through Snapshot().
func Count(feature string) uint64 {
	mu.RLock()
	s, ok := features[feature]
	mu.RUnlock()
	if !ok {
		return 0
	}
	return atomic.LoadUint64(&s.count)
}

// Snapshot returns a copy of all current feature counters. The metrics package
// consumes this to emit agentguard_deprecations_used_total. The returned map
// is owned by the caller.
func Snapshot() map[string]uint64 {
	mu.RLock()
	defer mu.RUnlock()
	out := make(map[string]uint64, len(features))
	for k, s := range features {
		out[k] = atomic.LoadUint64(&s.count)
	}
	return out
}

// Reset clears all feature counters. Test-only helper; not exported for
// production use because deprecation counters must survive the lifetime of the
// server process to be useful for scraping.
func Reset() {
	mu.Lock()
	features = map[string]*state{}
	mu.Unlock()
}

// get returns the state pointer for the given feature, allocating under a
// write lock on first use. The write lock is only taken on the first Warn()
// for each feature; subsequent calls take only the read lock.
func get(feature string) *state {
	mu.RLock()
	s, ok := features[feature]
	mu.RUnlock()
	if ok {
		return s
	}
	mu.Lock()
	// Re-check after acquiring the write lock in case another goroutine won.
	if s, ok = features[feature]; ok {
		mu.Unlock()
		return s
	}
	s = &state{}
	features[feature] = s
	mu.Unlock()
	return s
}
