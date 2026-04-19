package ratelimit

import (
	"fmt"
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
