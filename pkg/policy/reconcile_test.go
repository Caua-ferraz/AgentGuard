package policy

import (
	"strconv"
	"testing"
)

// costFor returns the accumulated cost for a specific (tenant, session) via the
// tenant-aware snapshot (SessionCost only reads the local tenant).
func costFor(e *Engine, tenant, session string) float64 {
	for _, s := range e.SnapshotCosts() {
		if s.Tenant == tenant && s.Session == session {
			return s.Cost
		}
	}
	return 0
}

func newReconcileEngine(t *testing.T) *Engine {
	t.Helper()
	return NewEngineFromPolicy(&Policy{
		Version: "1",
		Name:    "reconcile-test",
		Rules: []RuleSet{
			{Scope: "cost", Limits: &CostLimits{MaxPerSession: "$100.00"}},
		},
	})
}

// TestApplyCostDeltas_AddsAndClamps proves the reconcile write half: a positive
// adjust folds other-node spend into the local accumulator; a negative adjust
// (refund reconciliation) clamps at zero; a zero adjust is skipped.
func TestApplyCostDeltas_AddsAndClamps(t *testing.T) {
	e := newReconcileEngine(t)

	e.ApplyCostDeltas([]CostDelta{{Tenant: "local", Session: "s1", CostAdjust: 40}})
	if got := costFor(e, "local", "s1"); got != 40 {
		t.Fatalf("after +40, cost = %v, want 40", got)
	}

	// Incremental add.
	e.ApplyCostDeltas([]CostDelta{{Tenant: "local", Session: "s1", CostAdjust: 25}})
	if got := costFor(e, "local", "s1"); got != 65 {
		t.Fatalf("after +25, cost = %v, want 65", got)
	}

	// Over-subtract clamps at zero.
	e.ApplyCostDeltas([]CostDelta{{Tenant: "local", Session: "s1", CostAdjust: -1000}})
	if got := costFor(e, "local", "s1"); got != 0 {
		t.Fatalf("after big refund, cost = %v, want 0 (clamped)", got)
	}
}

// TestApplyCostDeltas_TenantIsolation is the zero-trust core (CLAUDE.md §3):
// two tenants reusing the SAME session id keep independent budgets — a delta for
// tenant A never moves tenant B's accumulator.
func TestApplyCostDeltas_TenantIsolation(t *testing.T) {
	e := newReconcileEngine(t)
	e.ApplyCostDeltas([]CostDelta{
		{Tenant: "acme", Session: "shared", CostAdjust: 30},
		{Tenant: "globex", Session: "shared", CostAdjust: 70},
	})
	if got := costFor(e, "acme", "shared"); got != 30 {
		t.Errorf("acme/shared = %v, want 30", got)
	}
	if got := costFor(e, "globex", "shared"); got != 70 {
		t.Errorf("globex/shared = %v, want 70 (acme must not leak)", got)
	}

	// Moving acme does not move globex.
	e.ApplyCostDeltas([]CostDelta{{Tenant: "acme", Session: "shared", CostAdjust: 5}})
	if got := costFor(e, "globex", "shared"); got != 70 {
		t.Errorf("globex/shared moved to %v after an acme-only delta; want 70", got)
	}
}

// TestApplyCostDeltas_EmptyAndZeroNoOp is the single-node contract: an empty
// slice and zero-adjust deltas leave the accumulator (and its lastUpdated)
// untouched, so reconcile-on and reconcile-off are behavior-identical.
func TestApplyCostDeltas_EmptyAndZeroNoOp(t *testing.T) {
	e := newReconcileEngine(t)
	e.ApplyCostDeltas([]CostDelta{{Tenant: "local", Session: "s1", CostAdjust: 10}})
	before := e.SnapshotCosts()

	e.ApplyCostDeltas(nil)
	e.ApplyCostDeltas([]CostDelta{})
	e.ApplyCostDeltas([]CostDelta{{Tenant: "local", Session: "s1", CostAdjust: 0}})

	after := e.SnapshotCosts()
	if len(before) != 1 || len(after) != 1 {
		t.Fatalf("unexpected entry count: before=%d after=%d", len(before), len(after))
	}
	if before[0] != after[0] {
		t.Errorf("no-op ApplyCostDeltas changed state: before=%+v after=%+v", before[0], after[0])
	}
}

// TestApplyCostDeltas_Chunked exercises the chunked-lock path with more than one
// chunk (K=128) worth of deltas to ensure every entry is applied.
func TestApplyCostDeltas_Chunked(t *testing.T) {
	e := newReconcileEngine(t)
	const n = costApplyChunk*2 + 7
	deltas := make([]CostDelta, n)
	for i := 0; i < n; i++ {
		deltas[i] = CostDelta{Tenant: "local", Session: sessionName(i), CostAdjust: 1}
	}
	e.ApplyCostDeltas(deltas)
	if got := e.SessionCostCount(); got != n {
		t.Fatalf("SessionCostCount = %d, want %d (some chunk was dropped)", got, n)
	}
}

func sessionName(i int) string {
	return "sess-" + strconv.Itoa(i)
}
