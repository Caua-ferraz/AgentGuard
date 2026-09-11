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

// ---------------------------------------------------------------------------
// Capacity contract.
//
// These tests assert what the limiter is SUPPOSED to guarantee, not what the
// current algorithm happens to do. MaxBuckets is documented as "the maximum
// number of rate limit buckets kept in memory", so the binding contract is:
//
//   C1. BucketCount() never exceeds MaxBuckets, whatever the caller does.
//   C2. A bucket whose window has fully elapsed must not permanently occupy
//       capacity -- it is reclaimable.
//   C3. Reclamation is attributed to the scope that owned the bucket.
//   C4. Allow stays allocation-free at capacity, not merely when the map is
//       small (CLAUDE.md hot-path invariant).
//
// Deliberately NOT asserted: how many buckets a single reclamation frees, when
// reclamation runs, or which victim is chosen. Those are implementation
// choices; pinning them is what let an unbounded map ship green.
// ---------------------------------------------------------------------------

// C2: a fully-elapsed bucket must not permanently occupy capacity.
func TestLimiter_StaleBucketsAreReclaimable(t *testing.T) {
	l := New()
	window := 50 * time.Millisecond

	for i := 0; i < MaxBuckets; i++ {
		_ = l.Allow(fmt.Sprintf("shell:local:key-%d", i), 1, window)
	}
	// Every bucket is now past its window.
	time.Sleep(60 * time.Millisecond)

	// Keep offering NEW keys. If stale buckets were unreclaimable the map
	// would grow without bound; the contract is that it does not.
	for i := 0; i < 100; i++ {
		_ = l.Allow(fmt.Sprintf("shell:local:fresh-%d", i), 1, window)
	}
	if got := l.BucketCount(); got > MaxBuckets {
		t.Errorf("BucketCount = %d, exceeds MaxBuckets = %d: stale buckets were not reclaimed", got, MaxBuckets)
	}
	if got := l.BucketCount(); got == 0 {
		t.Errorf("BucketCount = 0: reclamation dropped the live buckets too")
	}
}

// C2, stated as the guarantee a caller can actually observe: a bucket that is
// fully elapsed must not keep occupying capacity once the limiter is under
// pressure. It matters because the alternative victim is a LIVE bucket, and
// evicting one of those hands a caller who already spent their budget a fresh
// one -- a rate-limit bypass. Asserts the outcome, not which tier delivers it.
func TestLimiter_ElapsedBucketsDoNotHoldCapacity(t *testing.T) {
	l := New()
	short := 50 * time.Millisecond
	long := time.Hour

	// A live caller that has exhausted its budget, created FIRST so it is the
	// least-recently-refilled bucket in the map -- i.e. the most attractive
	// victim to any recency-based reclamation.
	const live = "shell:local:live"
	for i := 0; i < 5; i++ {
		if err := l.Allow(live, 5, long); err != nil {
			t.Fatalf("setup: live request %d should pass: %v", i+1, err)
		}
	}
	if err := l.Allow(live, 5, long); err == nil {
		t.Fatal("setup: live caller should be exhausted after 5 of 5")
	}

	for i := 0; i < MaxBuckets-10; i++ {
		_ = l.Allow(fmt.Sprintf("shell:local:short-%d", i), 1, short)
	}
	time.Sleep(60 * time.Millisecond) // only the short-window buckets elapse

	// Drive past capacity so reclamation has to choose victims.
	for i := 0; i < 200; i++ {
		_ = l.Allow(fmt.Sprintf("shell:local:new-%d", i), 1, long)
	}

	var elapsed int
	for _, snap := range l.Snapshot() {
		if snap.Window > 0 && time.Since(snap.LastRefill) >= snap.Window {
			elapsed++
		}
	}
	if elapsed > 0 {
		t.Errorf("%d fully-elapsed buckets still occupy capacity under pressure; "+
			"they would be refilled to full on next use and are free to reclaim, so holding them "+
			"forces reclamation to evict LIVE buckets instead", elapsed)
	}

	// And the live caller must not have been handed a fresh budget.
	if err := l.Allow(live, 5, long); err == nil {
		t.Error("the exhausted live bucket was reclaimed, resetting that caller's limit -- " +
			"a rate-limit bypass")
	}
}

// C1 -- THE EDGE. Capacity is reached while NOTHING is reclaimable, which is
// the state a real deployment reaches organically (many distinct
// scope:tenant:agent keys inside one window) and the state an attacker reaches
// deliberately by varying agent_id. The map must still not exceed MaxBuckets.
func TestLimiter_BoundedAtCapacityWithNothingStale(t *testing.T) {
	l := New()
	// A window long enough that no bucket can go stale during the test.
	window := time.Hour

	const overshoot = 5000
	for i := 0; i < MaxBuckets+overshoot; i++ {
		_ = l.Allow(fmt.Sprintf("shell:local:agent-%d", i), 60, window)
	}

	if got := l.BucketCount(); got > MaxBuckets {
		t.Errorf("BucketCount = %d, exceeds MaxBuckets = %d by %d "+
			"MaxBuckets does not bound the map when nothing is reclaimable: every distinct "+
			"key an unauthenticated caller supplies adds a bucket permanently, and each "+
			"subsequent Allow pays an O(n) scan under the limiter lock.",
			got, MaxBuckets, got-MaxBuckets)
	}
}

// C1 for the hydration path. Restore replays whatever the store hands back;
// LoadBuckets issues an unbounded SELECT, so a deployment with more live keys
// than MaxBuckets inside BucketTTL hydrates straight past the cap at boot --
// with no attacker involved, and it survives every restart.
func TestLimiter_RestoreRespectsCapacity(t *testing.T) {
	l := New()
	const rows = MaxBuckets * 5
	snaps := make([]BucketSnapshot, 0, rows)
	now := time.Now()
	for i := 0; i < rows; i++ {
		snaps = append(snaps, BucketSnapshot{
			Key:        fmt.Sprintf("shell:local:agent-%d", i),
			Tokens:     60,
			Max:        60,
			Window:     time.Hour,
			LastRefill: now,
		})
	}

	l.Restore(snaps)

	if got := l.BucketCount(); got > MaxBuckets {
		t.Errorf("after Restore of %d rows BucketCount = %d, exceeds MaxBuckets = %d "+
			"boot hydration bypasses the capacity bound entirely.",
			rows, got, MaxBuckets)
	}
}

// C3: reclamation is attributed to the scope that owned the bucket, so an
// operator can see which scope is churning. Asserts ATTRIBUTION, not absolute
// counts -- absolute counts would pin the reclamation strategy.
func TestLimiter_ReclamationIsAttributedByScope(t *testing.T) {
	l := New()
	window := 50 * time.Millisecond

	for i := 0; i < MaxBuckets/2; i++ {
		_ = l.Allow(fmt.Sprintf("shell:agent-%d", i), 1, window)
	}
	for i := 0; i < MaxBuckets/2; i++ {
		_ = l.Allow(fmt.Sprintf("network:agent-%d", i), 1, window)
	}

	beforeShell := metrics.RateLimitBucketEvictedFor("shell")
	beforeNet := metrics.RateLimitBucketEvictedFor("network")
	beforeUnrelated := metrics.RateLimitBucketEvictedFor("browser")

	time.Sleep(60 * time.Millisecond)
	_ = l.Allow("shell:trigger", 1, window)

	gotShell := metrics.RateLimitBucketEvictedFor("shell") - beforeShell
	gotNet := metrics.RateLimitBucketEvictedFor("network") - beforeNet
	gotUnrelated := metrics.RateLimitBucketEvictedFor("browser") - beforeUnrelated

	if gotShell == 0 {
		t.Errorf("no evictions attributed to scope %q despite %d stale buckets in it", "shell", MaxBuckets/2)
	}
	if gotNet == 0 {
		t.Errorf("no evictions attributed to scope %q despite %d stale buckets in it", "network", MaxBuckets/2)
	}
	if gotUnrelated != 0 {
		t.Errorf("%d evictions attributed to scope %q, which owned no buckets", gotUnrelated, "browser")
	}
	// Attribution must not exceed what that scope actually held.
	if gotShell > uint64(MaxBuckets/2)+1 {
		t.Errorf("shell evictions = %d, more than the %d buckets that scope ever held", gotShell, MaxBuckets/2)
	}
	if gotNet > uint64(MaxBuckets/2) {
		t.Errorf("network evictions = %d, more than the %d buckets that scope ever held", gotNet, MaxBuckets/2)
	}
}

// A reloaded policy must actually take effect. Allow receives the CURRENT
// maxRequests/window on every call; a live bucket that keeps enforcing the
// limit it was born with means a tightened policy silently does not apply.
func TestLimiter_LiveBucketAdoptsReloadedLimit(t *testing.T) {
	l := New()
	const key = "shell:local:bot"

	// Born under a limit of 10; consume 2.
	for i := 0; i < 2; i++ {
		if err := l.Allow(key, 10, time.Hour); err != nil {
			t.Fatalf("under the original limit request %d should pass: %v", i+1, err)
		}
	}

	// Operator tightens the policy to 2/hour. The bucket is live and the
	// caller has already spent 2 -- it must now be exhausted.
	if err := l.Allow(key, 2, time.Hour); err == nil {
		t.Error("after tightening the limit to 2/hour with 2 already consumed, " +
			"the next request must be denied; the live bucket is still enforcing " +
			"the limit it was created with")
	}

	// Loosening must apply just as promptly.
	l2 := New()
	if err := l2.Allow(key, 1, time.Hour); err != nil {
		t.Fatalf("first request under limit 1 should pass: %v", err)
	}
	if err := l2.Allow(key, 1, time.Hour); err == nil {
		t.Fatal("second request under limit 1 must be denied")
	}
	if err := l2.Allow(key, 5, time.Hour); err != nil {
		t.Errorf("after loosening the limit to 5/hour the next request should pass, got: %v", err)
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
