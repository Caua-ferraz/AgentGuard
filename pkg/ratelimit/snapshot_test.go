package ratelimit

import (
	"testing"
	"time"
)

func TestLimiterSnapshotRestore(t *testing.T) {
	l := New()
	// Consume some tokens across two keys.
	for i := 0; i < 3; i++ {
		_ = l.Allow("shell:local:bot", 5, time.Minute)
	}
	_ = l.Allow("network:acme:bot", 2, time.Minute)

	snaps := l.Snapshot()
	if len(snaps) != 2 {
		t.Fatalf("Snapshot got %d buckets, want 2", len(snaps))
	}

	// Restore into a fresh limiter and confirm the consumed state carried over:
	// "shell" had 5 max, consumed 3 -> 2 left; allowing twice more is fine, the
	// third must be denied.
	l2 := New()
	l2.Restore(snaps)
	if l2.BucketCount() != 2 {
		t.Fatalf("after Restore BucketCount = %d, want 2", l2.BucketCount())
	}
	if err := l2.Allow("shell:local:bot", 5, time.Minute); err != nil {
		t.Errorf("restored bucket should have 2 tokens left, 1st Allow denied: %v", err)
	}
	if err := l2.Allow("shell:local:bot", 5, time.Minute); err != nil {
		t.Errorf("restored bucket should have 2 tokens left, 2nd Allow denied: %v", err)
	}
	if err := l2.Allow("shell:local:bot", 5, time.Minute); err == nil {
		t.Errorf("restored bucket should be exhausted after 2 more Allows, but 3rd was allowed")
	}
}
