package persist

// Multi-node rate-limit + cost reconciliation (v1.0). These tests wire N in-proc
// nodes — each its own Limiter/Engine + Syncer + SQLiteStore handle onto ONE
// shared database file (the multi-node / shared-Postgres analog) — and drive the
// unexported reconcile() pass directly for determinism. They prove:
//   - bounded overshoot on a hammered rate-limit key,
//   - tenant isolation of cost reconciliation,
//   - single-node behavior-identity (reconcile-on == reconcile-off in memory).

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
	"github.com/Caua-ferraz/AgentGuard/pkg/ratelimit"
	"github.com/Caua-ferraz/AgentGuard/pkg/store"
)

type rateNode struct {
	lim *ratelimit.Limiter
	sy  *Syncer
	st  *store.SQLiteStore
}

// newRateNodes builds n nodes sharing one SQLite file, each with a distinct
// node id and reconciliation armed.
func newRateNodes(t *testing.T, n int) []*rateNode {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "shared.db")
	nodes := make([]*rateNode, n)
	for i := 0; i < n; i++ {
		st, err := store.NewSQLiteStore(dbPath)
		if err != nil {
			t.Fatalf("node %d store: %v", i, err)
		}
		t.Cleanup(func() { _ = st.Close() })
		lim := ratelimit.New()
		sy := New(Config{
			Store:             st,
			Limiter:           lim,
			NodeID:            "node-" + string(rune('a'+i)),
			ReconcileInterval: 50 * time.Millisecond, // >0 arms reconcile
		})
		if sy.rc == nil {
			t.Fatalf("node %d: reconcile not armed (rc nil) despite SQLite caps + interval>0", i)
		}
		nodes[i] = &rateNode{lim: lim, sy: sy, st: st}
	}
	return nodes
}

// TestReconcile_RateBoundedOvershoot hammers ONE key across N nodes, reconciling
// after every round, and asserts the cluster admits the global budget but not
// unboundedly more: admitted ∈ [max, max + N*burst].
func TestReconcile_RateBoundedOvershoot(t *testing.T) {
	ctx := context.Background()
	const (
		n     = 4
		max   = 200
		burst = 8
		key   = "shell:local:agent"
	)
	window := time.Hour // no refill during the test => one fixed epoch
	now := time.Now()   // shared, fixed clock => every node derives the same epoch

	nodes := newRateNodes(t, n)

	admitted := 0
	for round := 0; round < 500; round++ {
		roundAdmits := 0
		for _, nd := range nodes {
			for b := 0; b < burst; b++ {
				if nd.lim.Allow(key, max, window) == nil {
					admitted++
					roundAdmits++
				}
			}
		}
		// Reconcile every node (push then pull) so each converges toward global.
		for _, nd := range nodes {
			if err := nd.sy.reconcile(ctx, now); err != nil {
				t.Fatalf("round %d reconcile: %v", round, err)
			}
		}
		if roundAdmits == 0 {
			break // global budget exhausted and reconciled
		}
	}

	if admitted < max {
		t.Errorf("admitted %d < max %d: reconcile starved the budget", admitted, max)
	}
	overshootBound := max + n*burst
	if admitted > overshootBound {
		t.Errorf("admitted %d > bound %d (max=%d + N*burst=%d): overshoot not bounded",
			admitted, overshootBound, max, n*burst)
	}
	t.Logf("admitted=%d (max=%d, bound=%d, N=%d, burst=%d)", admitted, max, overshootBound, n, burst)
}

type costNode struct {
	eng *policy.Engine
	sy  *Syncer
	st  *store.SQLiteStore
}

func costPolicy() *policy.Policy {
	return &policy.Policy{
		Version: "1", Name: "cost-reconcile",
		Rules: []policy.RuleSet{{Scope: "cost", Limits: &policy.CostLimits{MaxPerSession: "$1000.00"}}},
	}
}

func newCostNode(t *testing.T, dbPath, nodeID string) *costNode {
	t.Helper()
	st, err := store.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("cost node store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	eng := policy.NewEngineFromPolicy(costPolicy())
	sy := New(Config{Store: st, Engine: eng, NodeID: nodeID, ReconcileInterval: 50 * time.Millisecond})
	if sy.rc == nil {
		t.Fatalf("cost node %s: reconcile not armed", nodeID)
	}
	return &costNode{eng: eng, sy: sy, st: st}
}

func costOf(e *policy.Engine, tenant, session string) (float64, bool) {
	for _, s := range e.SnapshotCosts() {
		if s.Tenant == tenant && s.Session == session {
			return s.Cost, true
		}
	}
	return 0, false
}

// TestReconcile_CostTenantIsolation: three nodes, all using session id "S".
// node-a and node-c operate under tenant "acme"; node-b under tenant "globex".
// After reconciliation node-a's acme budget must reflect node-c's same-tenant
// spend but NEVER node-b's globex spend — and node-a must hold no globex entry.
func TestReconcile_CostTenantIsolation(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "cost.db")
	na := newCostNode(t, dbPath, "node-a")
	nb := newCostNode(t, dbPath, "node-b")
	nc := newCostNode(t, dbPath, "node-c")

	// Seed each node's local accumulator (tenant-aware) as if the hot path had
	// reserved there.
	na.eng.RestoreCosts([]policy.CostSnapshot{{Tenant: "acme", Session: "S", Cost: 40, LastUpdated: time.Now()}})
	nb.eng.RestoreCosts([]policy.CostSnapshot{{Tenant: "globex", Session: "S", Cost: 40, LastUpdated: time.Now()}})
	nc.eng.RestoreCosts([]policy.CostSnapshot{{Tenant: "acme", Session: "S", Cost: 30, LastUpdated: time.Now()}})

	now := time.Now()
	// Two passes: pass 1 everyone pushes their own cumulative; pass 2 everyone
	// pulls the others.
	for pass := 0; pass < 2; pass++ {
		for _, nd := range []*costNode{na, nb, nc} {
			if err := nd.sy.reconcile(ctx, now); err != nil {
				t.Fatalf("reconcile: %v", err)
			}
		}
	}

	// node-a (acme) sees its own 40 + node-c's same-tenant 30 = 70.
	if got, _ := costOf(na.eng, "acme", "S"); got != 70 {
		t.Errorf("node-a acme/S = %v, want 70 (40 own + 30 node-c)", got)
	}
	// node-a must NOT have picked up globex spend under any tenant.
	if got, ok := costOf(na.eng, "globex", "S"); ok {
		t.Errorf("node-a leaked a globex entry: %v", got)
	}
	// node-b (globex) stays isolated at 40 — no acme leak.
	if got, _ := costOf(nb.eng, "globex", "S"); got != 40 {
		t.Errorf("node-b globex/S = %v, want 40 (isolated)", got)
	}
	if _, ok := costOf(nb.eng, "acme", "S"); ok {
		t.Errorf("node-b leaked an acme entry")
	}
}

// TestReconcile_SingleNodeBehaviorIdentity drives an identical op sequence on a
// reconcile-ARMED single node and a reconcile-DISABLED node and asserts the
// in-memory Snapshot()/SessionCost() sequences are byte-identical — the
// single-node no-op guarantee (others=0 => empty ApplyDeltas/ApplyCostDeltas).
func TestReconcile_SingleNodeBehaviorIdentity(t *testing.T) {
	ctx := context.Background()

	// Armed node.
	stA, err := store.NewSQLiteStore(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stA.Close() })
	limA := ratelimit.New()
	engA := policy.NewEngineFromPolicy(costPolicy())
	syA := New(Config{Store: stA, Limiter: limA, Engine: engA, NodeID: "solo", ReconcileInterval: 10 * time.Millisecond})
	if syA.rc == nil {
		t.Fatal("armed node: reconcile not armed")
	}

	// Disabled node (ReconcileInterval=0 => rc nil).
	stB, err := store.NewSQLiteStore(filepath.Join(t.TempDir(), "b.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stB.Close() })
	limB := ratelimit.New()
	engB := policy.NewEngineFromPolicy(costPolicy())
	syB := New(Config{Store: stB, Limiter: limB, Engine: engB, NodeID: "solo", ReconcileInterval: 0})
	if syB.rc != nil {
		t.Fatal("disabled node: reconcile should NOT be armed with interval=0")
	}

	now := time.Now()
	ops := []struct {
		key     string
		max     int
		session string
		cost    float64
	}{
		{key: "shell:local:bot", max: 5},
		{key: "shell:local:bot", max: 5},
		{session: "s1", cost: 3.5},
		{key: "net:local:bot", max: 2},
		{session: "s1", cost: 1.0},
		{session: "s2", cost: 9.0},
		{key: "shell:local:bot", max: 5},
	}
	for i, op := range ops {
		if op.key != "" {
			_ = limA.Allow(op.key, op.max, time.Hour)
			_ = limB.Allow(op.key, op.max, time.Hour)
		}
		if op.session != "" {
			engA.RecordCost(op.session, op.cost)
			engB.RecordCost(op.session, op.cost)
		}
		// Only the armed node reconciles; it must not diverge from the disabled one.
		if err := syA.reconcile(ctx, now); err != nil {
			t.Fatalf("op %d reconcile: %v", i, err)
		}

		if !sameBuckets(limA.Snapshot(), limB.Snapshot()) {
			t.Fatalf("op %d: limiter snapshots diverged (reconcile mutated single-node state)", i)
		}
		if !sameCosts(engA.SnapshotCosts(), engB.SnapshotCosts()) {
			t.Fatalf("op %d: cost snapshots diverged (reconcile mutated single-node state)", i)
		}
	}
}

func sameBuckets(a, b []ratelimit.BucketSnapshot) bool {
	if len(a) != len(b) {
		return false
	}
	ma := map[string]int{}
	for _, s := range a {
		ma[s.Key] = s.Tokens
	}
	for _, s := range b {
		if tok, ok := ma[s.Key]; !ok || tok != s.Tokens {
			return false
		}
	}
	return true
}

func sameCosts(a, b []policy.CostSnapshot) bool {
	if len(a) != len(b) {
		return false
	}
	ma := map[[2]string]float64{}
	for _, s := range a {
		ma[[2]string{s.Tenant, s.Session}] = s.Cost
	}
	for _, s := range b {
		if c, ok := ma[[2]string{s.Tenant, s.Session}]; !ok || c != s.Cost {
			return false
		}
	}
	return true
}
