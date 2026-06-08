package proxy

import (
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// TestApprovalQueueRestoreRespectsMaxSize confirms boot hydration cannot exceed
// the queue's capacity (a persisted backlog larger than maxSize is truncated).
func TestApprovalQueueRestoreRespectsMaxSize(t *testing.T) {
	q := NewApprovalQueue(2)
	now := time.Now()
	q.Restore([]*PendingAction{
		{ID: "a", CreatedAt: now},
		{ID: "b", CreatedAt: now},
		{ID: "c", CreatedAt: now},
	})
	if got := len(q.Snapshot()); got != 2 {
		t.Errorf("Restore must respect maxSize=2, got %d entries", got)
	}
}

func TestApprovalQueueSnapshotRestore(t *testing.T) {
	q := newTenantTestQueue()
	req := policy.ActionRequest{Scope: "shell", Command: "ls"}
	res := policy.CheckResult{Decision: policy.RequireApproval}

	a, _ := q.Add(req, res, "tenant-a")
	b, _ := q.Add(req, res, "tenant-b")
	_ = q.Resolve(b.ID, policy.Allow, "tenant-b") // one resolved

	snap := q.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("Snapshot got %d, want 2 (pending + resolved)", len(snap))
	}

	// Restore into a fresh queue (boot hydration) and confirm tenant ownership
	// + resolution survived.
	q2 := newTenantTestQueue()
	q2.Restore(snap)

	if pa, ok := q2.Lookup(a.ID, "tenant-a"); !ok || pa.Resolved {
		t.Errorf("tenant-a pending approval not restored correctly: ok=%v pa=%+v", ok, pa)
	}
	if _, ok := q2.Lookup(a.ID, "tenant-b"); ok {
		t.Error("restored approval must stay tenant-scoped (tenant-b must not see tenant-a's)")
	}
	if pa, ok := q2.Lookup(b.ID, "tenant-b"); !ok || !pa.Resolved || pa.Decision != string(policy.Allow) {
		t.Errorf("tenant-b resolved approval not restored correctly: ok=%v pa=%+v", ok, pa)
	}

	// Restore is idempotent on ID (no duplicates).
	q2.Restore(snap)
	if got := len(q2.Snapshot()); got != 2 {
		t.Errorf("Restore must skip existing IDs, got %d entries after second restore", got)
	}
}
