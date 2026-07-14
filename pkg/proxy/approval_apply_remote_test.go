package proxy

// Unit + hot-path tests for ApprovalQueue.ApplyRemote — the write half of
// multi-node approval cross-node visibility (v1.0, sub-task 1-A). These prove
// the per-key MERGE rules (the security crux) directly against the queue, plus
// that the hot-path Lookup is unmoved while ApplyRemote hammers concurrently.

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

func apPending(id, tenant string) *PendingAction {
	return &PendingAction{ID: id, TenantID: tenant, CreatedAt: time.Now().UTC()}
}

func apResolved(id, tenant, decision string, at time.Time) *PendingAction {
	return &PendingAction{
		ID: id, TenantID: tenant, CreatedAt: time.Now().UTC(),
		Resolved: true, Decision: decision, ResolvedAt: at,
		Result: policy.CheckResult{Decision: policy.Decision(decision)},
	}
}

// (visibility goal) local pending + remote resolved => adopt remote resolution.
func TestApplyRemote_FlipsLocalPendingToRemoteResolved(t *testing.T) {
	q := newTenantTestQueue()
	q.Restore([]*PendingAction{apPending("ap_x", "")})

	at := time.Now().UTC()
	q.ApplyRemote([]*PendingAction{apResolved("ap_x", "", string(policy.Allow), at)})

	pa, ok := q.Lookup("ap_x", "local")
	if !ok || !pa.Resolved || pa.Decision != string(policy.Allow) {
		t.Fatalf("expected local pending flipped to resolved ALLOW, got ok=%v pa=%+v", ok, pa)
	}
	if !pa.ResolvedAt.Equal(at) {
		t.Errorf("ResolvedAt not copied from remote: got %v want %v", pa.ResolvedAt, at)
	}
	if pa.Result.Decision != policy.Allow {
		t.Errorf("Result not copied from remote: got %v", pa.Result.Decision)
	}
}

// exists remote, not local => INSERT.
func TestApplyRemote_InsertsRemoteOnlyEntry(t *testing.T) {
	q := newTenantTestQueue()
	at := time.Now().UTC()
	q.ApplyRemote([]*PendingAction{apResolved("ap_new", "", string(policy.Deny), at)})

	pa, ok := q.Lookup("ap_new", "local")
	if !ok || !pa.Resolved || pa.Decision != string(policy.Deny) {
		t.Fatalf("expected remote-only entry inserted resolved DENY, got ok=%v pa=%+v", ok, pa)
	}
}

// local resolved + remote pending => KEEP local (never resurrect a resolved action).
func TestApplyRemote_NeverResurrectsResolved(t *testing.T) {
	q := newTenantTestQueue()
	at := time.Now().UTC()
	q.Restore([]*PendingAction{apResolved("ap_x", "", string(policy.Deny), at)})

	q.ApplyRemote([]*PendingAction{apPending("ap_x", "")})

	pa, ok := q.Lookup("ap_x", "local")
	if !ok || !pa.Resolved || pa.Decision != string(policy.Deny) {
		t.Fatalf("resolved entry was resurrected by remote pending: ok=%v pa=%+v", ok, pa)
	}
}

// both resolved, DIFFERING decision => DENY wins, regardless of ResolvedAt.
func TestApplyRemote_DenyWins(t *testing.T) {
	early := time.Now().UTC()
	late := early.Add(time.Hour)

	// (i) local ALLOW resolved LATER, remote DENY resolved EARLIER => DENY wins
	// (a later ALLOW ResolvedAt does NOT beat an earlier DENY).
	q1 := newTenantTestQueue()
	q1.Restore([]*PendingAction{apResolved("ap_x", "", string(policy.Allow), late)})
	q1.ApplyRemote([]*PendingAction{apResolved("ap_x", "", string(policy.Deny), early)})
	if pa, ok := q1.Lookup("ap_x", "local"); !ok || pa.Decision != string(policy.Deny) {
		t.Fatalf("(i) DENY must win over later-resolved local ALLOW: ok=%v pa=%+v", ok, pa)
	}

	// (ii) local DENY resolved EARLIER, remote ALLOW resolved LATER => stays DENY
	// (a later remote ALLOW can NOT overwrite an earlier local DENY).
	q2 := newTenantTestQueue()
	q2.Restore([]*PendingAction{apResolved("ap_x", "", string(policy.Deny), early)})
	q2.ApplyRemote([]*PendingAction{apResolved("ap_x", "", string(policy.Allow), late)})
	if pa, ok := q2.Lookup("ap_x", "local"); !ok || pa.Decision != string(policy.Deny) {
		t.Fatalf("(ii) local DENY must survive a later remote ALLOW: ok=%v pa=%+v", ok, pa)
	}
}

// both resolved, SAME decision => no visible change (ResolvedAt tiebreak no-op).
func TestApplyRemote_SameDecisionKeepsLocal(t *testing.T) {
	q := newTenantTestQueue()
	localAt := time.Now().UTC()
	q.Restore([]*PendingAction{apResolved("ap_x", "", string(policy.Allow), localAt)})
	q.ApplyRemote([]*PendingAction{apResolved("ap_x", "", string(policy.Allow), localAt.Add(time.Hour))})
	pa, ok := q.Lookup("ap_x", "local")
	if !ok || pa.Decision != string(policy.Allow) {
		t.Fatalf("same-decision merge changed the decision: ok=%v pa=%+v", ok, pa)
	}
	if !pa.ResolvedAt.Equal(localAt) {
		t.Errorf("same-decision merge rewrote ResolvedAt (must be a no-op): got %v want %v", pa.ResolvedAt, localAt)
	}
}

// tenant isolation: a remote row for tenant-a must never mutate a tenant-b entry
// that happens to share the same raw ID (CLAUDE.md §3).
func TestApplyRemote_TenantIsolation(t *testing.T) {
	q := newTenantTestQueue()
	q.Restore([]*PendingAction{apPending("ap_shared", "tenant-b")}) // tenant-b pending

	// tenant-a remote row, same raw ID, resolved DENY.
	q.ApplyRemote([]*PendingAction{apResolved("ap_shared", "tenant-a", string(policy.Deny), time.Now().UTC())})

	// tenant-b entry must be untouched (still pending).
	if pa, ok := q.Lookup("ap_shared", "tenant-b"); !ok || pa.Resolved {
		t.Fatalf("tenant-b entry mutated by a tenant-a remote row: ok=%v pa=%+v", ok, pa)
	}
	// tenant-a must NOT have surfaced an entry under the shared ID.
	if _, ok := q.Lookup("ap_shared", "tenant-a"); ok {
		t.Error("tenant-a remote row surfaced cross-tenant (must be dropped, not inserted)")
	}
}

// INSERT honors maxSize exactly as Restore does (drop when full; never evict a
// live entry from ApplyRemote).
func TestApplyRemote_RespectsMaxSizeOnInsert(t *testing.T) {
	q := NewApprovalQueue(2)
	q.ApplyRemote([]*PendingAction{
		apPending("a", ""), apPending("b", ""), apPending("c", ""),
	})
	if got := len(q.Snapshot()); got != 2 {
		t.Errorf("ApplyRemote insert must respect maxSize=2, got %d entries", got)
	}
}

// Chunk boundary: more than remoteApplyChunk records are all applied (mirrors
// policy.TestApplyCostDeltas_Chunked).
func TestApplyRemote_Chunked(t *testing.T) {
	const n = remoteApplyChunk*2 + 7
	q := NewApprovalQueue(n + 10)
	remote := make([]*PendingAction, n)
	for i := 0; i < n; i++ {
		remote[i] = apPending(fmt.Sprintf("ap_%d", i), "")
	}
	q.ApplyRemote(remote)
	if got := len(q.Snapshot()); got != n {
		t.Fatalf("chunked ApplyRemote lost entries across chunk boundaries: got %d want %d", got, n)
	}
}

func TestApplyRemote_NilAndEmptyNoOp(t *testing.T) {
	q := newTenantTestQueue()
	q.Restore([]*PendingAction{apPending("ap_x", "")})
	q.ApplyRemote(nil)
	q.ApplyRemote([]*PendingAction{})
	q.ApplyRemote([]*PendingAction{nil}) // nil element must be skipped, not panic
	if got := len(q.Snapshot()); got != 1 {
		t.Errorf("empty/nil ApplyRemote changed state: got %d entries", got)
	}
}

// Hot-path (test f): Lookup must stay correct and race-free while ApplyRemote
// hammers concurrently. Run under -race for the data-race guarantee.
func TestLookupUnchangedUnderConcurrentApplyRemote(t *testing.T) {
	q := NewApprovalQueue(0)
	const keys = 256
	ids := make([]string, keys)
	remote := make([]*PendingAction, keys)
	for i := 0; i < keys; i++ {
		ids[i] = fmt.Sprintf("ap_%d", i)
		q.Restore([]*PendingAction{apPending(ids[i], "")})
		remote[i] = apResolved(ids[i], "", string(policy.Allow), time.Now().UTC())
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
				q.ApplyRemote(remote)
			}
		}
	}()

	// Concurrent Lookups: every hit must be for the queried id (no torn reads,
	// no cross-id/cross-tenant bleed), whether it observes the pre- or post-merge
	// state.
	for r := 0; r < 5000; r++ {
		id := ids[r%keys]
		if pa, ok := q.Lookup(id, "local"); ok && pa.ID != id {
			t.Fatalf("Lookup(%q) returned a torn entry with ID %q", id, pa.ID)
		}
	}
	close(stop)
	wg.Wait()
}

// BenchmarkLookup is the hot-path baseline: parallel Lookup, no background merge.
// Compare allocs/op + ns/op against BenchmarkLookupUnderConcurrentApplyRemote to
// see the contention/allocation cost (if any) of a concurrent chunked ApplyRemote.
func BenchmarkLookup(b *testing.B) {
	q := NewApprovalQueue(0)
	const keys = 512
	ids := make([]string, keys)
	for i := 0; i < keys; i++ {
		ids[i] = fmt.Sprintf("ap_%d", i)
		q.Restore([]*PendingAction{apPending(ids[i], "")})
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			_, _ = q.Lookup(ids[i%keys], "local")
			i++
		}
	})
}

// BenchmarkLookupUnderConcurrentApplyRemote proves the hot-path Lookup does not
// regress (ns/op or allocs/op) under a background goroutine hammering
// ApplyRemote (the re-hydrate write-back). Chunked locking keeps Lookup's
// RLock critical section short; a single O(n) write hold would show up here as
// contention.
func BenchmarkLookupUnderConcurrentApplyRemote(b *testing.B) {
	q := NewApprovalQueue(0)
	const keys = 512
	ids := make([]string, keys)
	remote := make([]*PendingAction, keys)
	for i := 0; i < keys; i++ {
		ids[i] = fmt.Sprintf("ap_%d", i)
		q.Restore([]*PendingAction{apPending(ids[i], "")})
		remote[i] = apResolved(ids[i], "", string(policy.Allow), time.Now().UTC())
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
				q.ApplyRemote(remote)
			}
		}
	}()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			_, _ = q.Lookup(ids[i%keys], "local")
			i++
		}
	})
	b.StopTimer()
	close(stop)
	wg.Wait()
}
