package ratelimit

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/metrics"
)

func TestLimiter_Allow(t *testing.T) {
	l := New()

	// Should allow up to max requests
	for i := 0; i < 5; i++ {
		if err := l.Allow("test", 5, time.Minute); err != nil {
			t.Errorf("request %d should be allowed: %v", i+1, err)
		}
	}

	// 6th request should be denied
	if err := l.Allow("test", 5, time.Minute); err == nil {
		t.Error("6th request should be denied")
	}
}

func TestLimiter_DifferentKeys(t *testing.T) {
	l := New()

	// Different keys have independent buckets
	if err := l.Allow("a", 1, time.Minute); err != nil {
		t.Errorf("key a should be allowed: %v", err)
	}
	if err := l.Allow("b", 1, time.Minute); err != nil {
		t.Errorf("key b should be allowed: %v", err)
	}

	// Both exhausted
	if err := l.Allow("a", 1, time.Minute); err == nil {
		t.Error("key a should be denied")
	}
	if err := l.Allow("b", 1, time.Minute); err == nil {
		t.Error("key b should be denied")
	}
}

func TestLimiter_WindowRefill(t *testing.T) {
	l := New()

	// Use a very short window
	window := 50 * time.Millisecond

	if err := l.Allow("test", 1, window); err != nil {
		t.Errorf("first request should be allowed: %v", err)
	}
	if err := l.Allow("test", 1, window); err == nil {
		t.Error("second request should be denied")
	}

	// Wait for window to elapse
	time.Sleep(60 * time.Millisecond)

	// Should be allowed again
	if err := l.Allow("test", 1, window); err != nil {
		t.Errorf("request after window should be allowed: %v", err)
	}
}

func TestLimiter_EvictsStale(t *testing.T) {
	l := New()
	window := 50 * time.Millisecond

	// Fill up to MaxBuckets
	for i := 0; i < MaxBuckets; i++ {
		_ = l.Allow(fmt.Sprintf("key-%d", i), 1, window)
	}

	if l.BucketCount() != MaxBuckets {
		t.Fatalf("expected %d buckets, got %d", MaxBuckets, l.BucketCount())
	}

	// Wait for all buckets to become stale
	time.Sleep(60 * time.Millisecond)

	// Next Allow hits the capacity check and triggers eviction
	_ = l.Allow("trigger", 1, window)

	// All stale buckets evicted, only "trigger" remains
	if got := l.BucketCount(); got != 1 {
		t.Errorf("expected 1 bucket after eviction, got %d", got)
	}
}

// TestLimiter_EvictionIncrementsMetricByScope: evictStaleLocked must tag
// each eviction with the scope portion of the bucket key so operators can
// see which scope is churning buckets the fastest.
func TestLimiter_EvictionIncrementsMetricByScope(t *testing.T) {
	l := New()
	window := 50 * time.Millisecond

	// Fill with two scopes so the labeled counter gets exercised.
	for i := 0; i < MaxBuckets/2; i++ {
		_ = l.Allow(fmt.Sprintf("shell:agent-%d", i), 1, window)
	}
	for i := 0; i < MaxBuckets/2; i++ {
		_ = l.Allow(fmt.Sprintf("network:agent-%d", i), 1, window)
	}
	if l.BucketCount() != MaxBuckets {
		t.Fatalf("expected %d buckets, got %d", MaxBuckets, l.BucketCount())
	}

	beforeShell := metrics.RateLimitBucketEvictedFor("shell")
	beforeNet := metrics.RateLimitBucketEvictedFor("network")

	time.Sleep(60 * time.Millisecond)

	// Trigger eviction. Any scope works for the trigger itself.
	_ = l.Allow("shell:trigger", 1, window)

	afterShell := metrics.RateLimitBucketEvictedFor("shell")
	afterNet := metrics.RateLimitBucketEvictedFor("network")

	if got := afterShell - beforeShell; got != uint64(MaxBuckets/2) {
		t.Errorf("shell evictions = %d, want %d", got, MaxBuckets/2)
	}
	if got := afterNet - beforeNet; got != uint64(MaxBuckets/2) {
		t.Errorf("network evictions = %d, want %d", got, MaxBuckets/2)
	}
}

func TestScopeFromKey(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"shell:agent-1", "shell"},
		{"network:", "network"},
		{"filesystem:a:b:c", "filesystem"},
		{"noscope", "unknown"},
		{"", "unknown"},
		{":leading", ""}, // empty prefix is still what the caller sent
	}
	for _, c := range cases {
		if got := scopeFromKey(c.in); got != c.want {
			t.Errorf("scopeFromKey(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestApplyDeltas_ReducesRemainingExistingKeysOnly proves the reconcile
// write-back path: a negative TokenAdjust reduces an existing bucket's remaining
// tokens, a delta for an absent key is a no-op (ApplyDeltas never invents a
// bucket), and the remaining count is clamped at zero.
func TestApplyDeltas_ReducesRemainingExistingKeysOnly(t *testing.T) {
	l := New()
	// Bucket "shell:local:bot" starts with max 5, consume 1 -> 4 remaining.
	if err := l.Allow("shell:local:bot", 5, time.Minute); err != nil {
		t.Fatalf("seed Allow: %v", err)
	}

	// Subtract 3 (other nodes consumed 3) -> 1 remaining. Absent key ignored.
	l.ApplyDeltas([]BucketDelta{
		{Key: "shell:local:bot", TokenAdjust: -3},
		{Key: "does:not:exist", TokenAdjust: -100}, // skipped, no bucket created
	})
	if l.BucketCount() != 1 {
		t.Fatalf("ApplyDeltas created a bucket for an absent key: count=%d", l.BucketCount())
	}
	// 1 remaining: one more Allow ok, the next denied.
	if err := l.Allow("shell:local:bot", 5, time.Minute); err != nil {
		t.Errorf("expected 1 token remaining after -3 adjust, Allow denied: %v", err)
	}
	if err := l.Allow("shell:local:bot", 5, time.Minute); err == nil {
		t.Errorf("expected exhaustion after consuming the last token")
	}

	// Over-subtract clamps at zero (never negative): a big reduction then the
	// next Allow is denied, not "resurrected" by an underflow.
	l.ApplyDeltas([]BucketDelta{{Key: "shell:local:bot", TokenAdjust: -1000}})
	if err := l.Allow("shell:local:bot", 5, time.Minute); err == nil {
		t.Errorf("expected denial after clamped-to-zero remaining")
	}
}

// TestApplyDeltas_ClampsToMax guards the firewall-safety invariant: a positive
// adjust (which reconcile should never emit, but which must not be a footgun)
// can never grant MORE than the bucket's capacity.
func TestApplyDeltas_ClampsToMax(t *testing.T) {
	l := New()
	if err := l.Allow("net:local:bot", 3, time.Minute); err != nil { // 2 remaining
		t.Fatalf("seed: %v", err)
	}
	l.ApplyDeltas([]BucketDelta{{Key: "net:local:bot", TokenAdjust: +999}})
	// Capacity is 3; at most 3 Allows should now succeed, not 1002.
	ok := 0
	for i := 0; i < 10; i++ {
		if l.Allow("net:local:bot", 3, time.Minute) == nil {
			ok++
		}
	}
	if ok > 3 {
		t.Errorf("clamp-to-max violated: %d Allows succeeded, want <= 3", ok)
	}
}

// TestApplyDeltas_EmptyIsNoOp is the single-node contract: an empty delta slice
// mutates nothing.
func TestApplyDeltas_EmptyIsNoOp(t *testing.T) {
	l := New()
	_ = l.Allow("shell:local:bot", 5, time.Minute)
	before := l.Snapshot()
	l.ApplyDeltas(nil)
	l.ApplyDeltas([]BucketDelta{})
	after := l.Snapshot()
	if len(before) != 1 || len(after) != 1 || before[0].Tokens != after[0].Tokens {
		t.Errorf("empty ApplyDeltas changed state: before=%+v after=%+v", before, after)
	}
}

// BenchmarkAllow is the hot-path baseline: parallel Allow with no background
// reconcile. Compare against BenchmarkAllowUnderConcurrentApplyDeltas to see the
// contention cost (if any) of a concurrent chunked-lock ApplyDeltas.
func BenchmarkAllow(b *testing.B) {
	l := New()
	const keys = 512
	keyList := make([]string, keys)
	for i := 0; i < keys; i++ {
		keyList[i] = fmt.Sprintf("shell:local:agent-%d", i)
		_ = l.Allow(keyList[i], 1_000_000, time.Hour)
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			_ = l.Allow(keyList[i%keys], 1_000_000, time.Hour)
			i++
		}
	})
}

// BenchmarkAllowUnderConcurrentApplyDeltas proves the hot-path Allow does not
// regress under a background goroutine hammering ApplyDeltas (the reconcile
// write-back). Chunked locking keeps Allow's critical section short; a single
// O(n) hold would show up here as contention.
func BenchmarkAllowUnderConcurrentApplyDeltas(b *testing.B) {
	l := New()
	// Pre-create a spread of buckets so ApplyDeltas has real work to do.
	const keys = 512
	keyList := make([]string, keys)
	deltas := make([]BucketDelta, keys)
	for i := 0; i < keys; i++ {
		k := fmt.Sprintf("shell:local:agent-%d", i)
		keyList[i] = k
		_ = l.Allow(k, 1_000_000, time.Hour)
		deltas[i] = BucketDelta{Key: k, TokenAdjust: -1}
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				l.ApplyDeltas(deltas)
			}
		}
	}()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			_ = l.Allow(keyList[i%keys], 1_000_000, time.Hour)
			i++
		}
	})
	b.StopTimer()
	close(stop)
	wg.Wait()
}

func TestParseWindow(t *testing.T) {
	tests := []struct {
		input   string
		want    time.Duration
		wantErr bool
	}{
		{"1m", time.Minute, false},
		{"30s", 30 * time.Second, false},
		{"1h", time.Hour, false},
		{"500ms", 500 * time.Millisecond, false},
		{"", 0, true},
		{"invalid", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseWindow(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseWindow(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("ParseWindow(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
