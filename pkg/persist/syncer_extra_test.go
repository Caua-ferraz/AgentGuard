package persist

import (
	"context"
	"testing"
	"time"
)

// TestSyncer_NilSourcesAreNoops confirms a syncer with no in-memory sources
// (any subset may be nil in focused deployments/tests) neither panics nor errors.
func TestSyncer_NilSourcesAreNoops(t *testing.T) {
	st := newFileStore(t)
	sy := New(Config{Store: st, CostTTL: time.Hour, ApprovalTTL: time.Hour, BucketTTL: time.Hour})
	ctx := context.Background()
	if err := sy.Hydrate(ctx); err != nil {
		t.Errorf("Hydrate with nil sources: %v", err)
	}
	if err := sy.Flush(ctx); err != nil {
		t.Errorf("Flush with nil sources: %v", err)
	}
	if err := sy.Purge(ctx, time.Now()); err != nil {
		t.Errorf("Purge with empty store: %v", err)
	}
}
