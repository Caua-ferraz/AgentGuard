package ratelimit

import (
	"fmt"
	"testing"
	"time"
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
