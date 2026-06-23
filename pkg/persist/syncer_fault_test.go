package persist

// Fault-injection tests for the write-behind Syncer (review item C1 + M4).
//
// The dual-tier design (docs/v0.6-ARCHITECTURE-PLAN.md §2.3) promises that
// memory is authoritative and a store outage is survivable: a failed flush must
// surface its error, leave the in-memory accumulators untouched, NOT kill the
// background loop, and retry on the next tick once the store recovers. The
// happy-path tests in syncer_test.go never exercise a failing store, so these
// drive the store into an outage and back.

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
	"github.com/Caua-ferraz/AgentGuard/pkg/store"
)

// errInjectedOutage stands in for any store-side failure (DB locked, disk full,
// connection refused). It is returned synchronously, mirroring how a real
// driver surfaces an unavailable backend to the syncer.
var errInjectedOutage = errors.New("persist test: injected store outage")

// failingStore wraps a real store.Store and, while fail is set, makes every
// mutating (write-behind) method return errInjectedOutage. Reads still delegate
// to the underlying store so a test can observe exactly what was (not)
// persisted. Modeled on the controllable-failure fake pattern used by
// captureLogger in pkg/audit/buffered_test.go.
type failingStore struct {
	store.Store
	fail        atomic.Bool
	upsertCosts atomic.Int64 // total UpsertCosts attempts, for deterministic sync
}

func (f *failingStore) UpsertCosts(ctx context.Context, costs []store.CostState) error {
	f.upsertCosts.Add(1)
	if f.fail.Load() {
		return errInjectedOutage
	}
	return f.Store.UpsertCosts(ctx, costs)
}

func (f *failingStore) UpsertBuckets(ctx context.Context, b []store.BucketState) error {
	if f.fail.Load() {
		return errInjectedOutage
	}
	return f.Store.UpsertBuckets(ctx, b)
}

func (f *failingStore) UpsertApprovals(ctx context.Context, r []store.ApprovalRecord) error {
	if f.fail.Load() {
		return errInjectedOutage
	}
	return f.Store.UpsertApprovals(ctx, r)
}

// waitUntil polls cond until it holds or the timeout elapses, failing the test
// otherwise. Prefer this over a fixed sleep so the tests stay robust under load
// and -race.
func waitUntil(t *testing.T, timeout time.Duration, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

// TestSyncer_FlushErrorRetainsStateAndRecovers: a flush against a down store must
// (1) return the error, (2) leave the authoritative in-memory cost untouched,
// (3) write nothing, and (4) persist the retained state on the next flush once
// the store recovers — i.e. no data is lost across a transient outage.
func TestSyncer_FlushErrorRetainsStateAndRecovers(t *testing.T) {
	ctx := context.Background()
	fs := &failingStore{Store: newFileStore(t)}
	eng := policy.NewEngineFromPolicy(&policy.Policy{Version: "1", Name: "fault"})
	eng.RecordCost("s1", 4.00)

	sy := New(Config{Store: fs, Engine: eng})

	// --- store is down ---
	fs.fail.Store(true)
	if err := sy.Flush(ctx); err == nil {
		t.Fatal("Flush must return the store error during an outage")
	}
	// Memory stays authoritative: the accumulator must be unchanged.
	if got := eng.SessionCost("s1"); got != 4.00 {
		t.Errorf("cost mutated by a failed flush: got %.2f, want 4.00", got)
	}
	if got := eng.SessionCostCount(); got != 1 {
		t.Errorf("cost count changed by a failed flush: got %d, want 1", got)
	}
	// Nothing was written.
	if costs, _ := fs.LoadCosts(ctx); len(costs) != 0 {
		t.Fatalf("a failed flush still wrote %d cost rows", len(costs))
	}

	// --- store recovers ---
	fs.fail.Store(false)
	if err := sy.Flush(ctx); err != nil {
		t.Fatalf("flush after recovery: %v", err)
	}
	costs, _ := fs.LoadCosts(ctx)
	if len(costs) != 1 || costs[0].SessionID != "s1" || costs[0].Cost != 4.00 {
		t.Fatalf("recovered flush did not persist the retained cost: %+v", costs)
	}
}

// TestSyncer_FlushLoopSurvivesStoreOutage: the background flush goroutine must
// not die when a tick's flush errors. It keeps ticking against the down store
// and, once the store recovers, persists the still-in-memory state on a later
// tick.
func TestSyncer_FlushLoopSurvivesStoreOutage(t *testing.T) {
	ctx := context.Background()
	fs := &failingStore{Store: newFileStore(t)}
	fs.fail.Store(true)
	eng := policy.NewEngineFromPolicy(&policy.Policy{Version: "1", Name: "fault"})
	sy := New(Config{Store: fs, Engine: eng, FlushInterval: MinFlushInterval})
	sy.Start()
	defer sy.Close()

	eng.RecordCost("s1", 7.50)

	// The loop must attempt at least one flush against the down store...
	waitUntil(t, 5*time.Second, func() bool { return fs.upsertCosts.Load() >= 1 },
		"the flush loop to attempt a write during the outage")
	// ...all of which fail, so nothing is persisted — proving the loop didn't
	// silently succeed, and (because we get past this point) that it didn't die.
	if costs, _ := fs.LoadCosts(ctx); len(costs) != 0 {
		t.Fatalf("store should be empty during the outage, has %d rows", len(costs))
	}

	// Recover: the still-running loop must persist the retained cost on a later tick.
	fs.fail.Store(false)
	waitUntil(t, 5*time.Second, func() bool {
		costs, _ := fs.LoadCosts(ctx)
		return len(costs) == 1 && costs[0].SessionID == "s1" && costs[0].Cost == 7.50
	}, "the flush loop to recover and persist after the outage clears")
}

// TestSyncer_CloseDuringOutageDoesNotPanicOrHang documents the M4 boundary: when
// the store is down at shutdown, Close's final flush fails but Close must still
// return promptly without panicking. The honest consequence — there is no spool
// for the syncer, so the last interval's state is NOT durable across a
// shutdown-during-total-outage — is asserted, not glossed over.
func TestSyncer_CloseDuringOutageDoesNotPanicOrHang(t *testing.T) {
	ctx := context.Background()
	fs := &failingStore{Store: newFileStore(t)}
	fs.fail.Store(true) // down for the syncer's entire lifetime
	eng := policy.NewEngineFromPolicy(&policy.Policy{Version: "1", Name: "fault"})
	sy := New(Config{Store: fs, Engine: eng, FlushInterval: MinFlushInterval})
	sy.Start()
	eng.RecordCost("late", 2.50)

	done := make(chan struct{})
	go func() { sy.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(15 * time.Second): // > flushTimeout (10s), generous margin
		t.Fatal("Close hung when the store was down at shutdown")
	}

	// Durability boundary: nothing reached the store because it never came back.
	if costs, _ := fs.LoadCosts(ctx); len(costs) != 0 {
		t.Fatalf("expected no persisted costs after a shutdown-during-outage, got %d", len(costs))
	}
}
