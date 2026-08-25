package ratelimit

import (
	"fmt"
	"testing"
	"time"
)

// BenchmarkAllowAtCap* guard the audit-B3 regression: before the tiered
// reclamation, Allow at capacity with nothing stale ran a full O(n) scan under
// the limiter lock on EVERY call -- ~133us at 10k buckets and ~603us at 50k,
// versus ~71ns uncontended. The map is now bounded, so both prefills converge
// to MaxBuckets; a return of the O(n) scan shows up here immediately.
func benchAtCap(b *testing.B, prefill int) {
	l := New()
	for i := 0; i < prefill; i++ {
		_ = l.Allow(fmt.Sprintf("shell:local:filler-%d", i), 60, time.Hour)
	}
	const keys = 512
	keyList := make([]string, keys)
	for i := 0; i < keys; i++ {
		keyList[i] = fmt.Sprintf("shell:local:hot-%d", i)
		_ = l.Allow(keyList[i], 1_000_000, time.Hour)
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			_ = l.Allow(keyList[i%keys], 1_000_000, time.Hour)
			i++
		}
	})
}

func BenchmarkAllowAtCap10k(b *testing.B) { benchAtCap(b, 10000) }
func BenchmarkAllowAtCap50k(b *testing.B) { benchAtCap(b, 50000) }
