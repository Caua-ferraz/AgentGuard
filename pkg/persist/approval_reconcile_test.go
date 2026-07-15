package persist

// Multi-node approval cross-node visibility (v1.0, sub-task 1-A). These tests
// wire N in-proc nodes — each its own ApprovalQueue + Syncer + SQLiteStore handle
// onto ONE shared database file (the multi-node / shared-Postgres analog) — and
// drive the unexported reconcileApprovals() pass directly for determinism. They
// prove: cross-node visibility, no-clobber of unflushed local pendings,
// DENY-wins conflict resolution, tenant isolation, and single-node identity.

import (
	"context"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
	"github.com/Caua-ferraz/AgentGuard/pkg/proxy"
	"github.com/Caua-ferraz/AgentGuard/pkg/store"
)

type apNode struct {
	q  *proxy.ApprovalQueue
	sy *Syncer
	st *store.SQLiteStore
}

// newApNodes builds n nodes sharing one SQLite file, each with a distinct node
// id and approval reconciliation armed.
func newApNodes(t *testing.T, n int) []*apNode {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "approvals.db")
	nodes := make([]*apNode, n)
	for i := 0; i < n; i++ {
		st, err := store.NewSQLiteStore(dbPath)
		if err != nil {
			t.Fatalf("node %d store: %v", i, err)
		}
		t.Cleanup(func() { _ = st.Close() })
		q := proxy.NewApprovalQueue(0)
		sy := New(Config{
			Store:             st,
			Approvals:         q,
			NodeID:            "node-" + string(rune('a'+i)),
			ReconcileInterval: 50 * time.Millisecond, // >0 arms reconcile
		})
		if sy.ra == nil {
			t.Fatalf("node %d: approval reconcile not armed (ra nil) despite SQLite LoadApprovals + interval>0", i)
		}
		nodes[i] = &apNode{q: q, sy: sy, st: st}
	}
	return nodes
}

func lookupOn(t *testing.T, q *proxy.ApprovalQueue, id, tenant string) *proxy.PendingAction {
	t.Helper()
	pa, ok := q.Lookup(id, tenant)
	if !ok {
		return nil
	}
	return pa
}

// (a) cross-node visibility: node A creates a pending, both nodes see it as
// pending after a re-hydrate (INSERT), then A resolves + flushes and node B's
// re-hydrate flips its entry to resolved with A's decision.
func TestReconcileApprovals_CrossNodeVisibility(t *testing.T) {
	ctx := context.Background()
	nodes := newApNodes(t, 2)
	a, b := nodes[0], nodes[1]

	pa, err := a.q.Add(
		policy.ActionRequest{Scope: "shell", Command: "rm -rf /"},
		policy.CheckResult{Decision: policy.RequireApproval},
		"local",
	)
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := a.sy.Flush(ctx); err != nil {
		t.Fatalf("flush A: %v", err)
	}

	// B re-hydrates: inserts A's pending (visibility of the pending queue).
	if err := b.sy.reconcileApprovals(ctx); err != nil {
		t.Fatalf("B reconcile #1: %v", err)
	}
	if got := lookupOn(t, b.q, pa.ID, "local"); got == nil || got.Resolved {
		t.Fatalf("B did not gain visibility of A's pending: %+v", got)
	}

	// A resolves + flushes; B re-hydrates again and flips to resolved ALLOW.
	if err := a.q.Resolve(pa.ID, policy.Allow, "local"); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if err := a.sy.Flush(ctx); err != nil {
		t.Fatalf("flush A #2: %v", err)
	}
	if err := b.sy.reconcileApprovals(ctx); err != nil {
		t.Fatalf("B reconcile #2: %v", err)
	}
	got := lookupOn(t, b.q, pa.ID, "local")
	if got == nil || !got.Resolved || got.Decision != string(policy.Allow) {
		t.Fatalf("B did not see A's resolution: %+v", got)
	}
}

// (b) no-clobber: node B has an unflushed local pending; a re-hydrate whose
// store rows lack that id leaves the local pending intact.
func TestReconcileApprovals_NoClobberUnflushedLocalPending(t *testing.T) {
	ctx := context.Background()
	nodes := newApNodes(t, 2)
	a, b := nodes[0], nodes[1]

	// A writes an unrelated approval into the shared store (so the store is
	// non-empty but does NOT contain B's local pending).
	other, _ := a.q.Add(policy.ActionRequest{Scope: "net"}, policy.CheckResult{Decision: policy.RequireApproval}, "local")
	if err := a.sy.Flush(ctx); err != nil {
		t.Fatalf("flush A: %v", err)
	}

	// B queues a LOCAL pending and never flushes it.
	local, _ := b.q.Add(policy.ActionRequest{Scope: "shell", Command: "ls"}, policy.CheckResult{Decision: policy.RequireApproval}, "local")

	if err := b.sy.reconcileApprovals(ctx); err != nil {
		t.Fatalf("B reconcile: %v", err)
	}

	// B's unflushed local pending survives untouched.
	if got := lookupOn(t, b.q, local.ID, "local"); got == nil || got.Resolved {
		t.Fatalf("re-hydrate clobbered B's unflushed local pending: %+v", got)
	}
	// And B did gain visibility of A's other approval (proves reconcile ran).
	if got := lookupOn(t, b.q, other.ID, "local"); got == nil {
		t.Fatalf("reconcile did not import A's approval %q", other.ID)
	}
}

// (c) deny-wins: node A resolves ALLOW (later ResolvedAt), node B resolves DENY
// (earlier ResolvedAt) for the SAME id; both converge to DENY regardless of
// ResolvedAt. Constructed via Restore so ResolvedAt is controlled exactly.
func TestReconcileApprovals_DenyWins(t *testing.T) {
	ctx := context.Background()
	nodes := newApNodes(t, 2)
	a, b := nodes[0], nodes[1]

	early := time.Now().UTC().Truncate(time.Second)
	late := early.Add(time.Hour)
	req := policy.ActionRequest{Scope: "shell", Command: "curl evil"}

	// Same id resolved differently on the two nodes.
	a.q.Restore([]*proxy.PendingAction{{
		ID: "ap_conflict", Request: req, CreatedAt: early,
		Resolved: true, Decision: string(policy.Allow), ResolvedAt: late, // ALLOW resolved LATER
		Result: policy.CheckResult{Decision: policy.Allow},
	}})
	b.q.Restore([]*proxy.PendingAction{{
		ID: "ap_conflict", Request: req, CreatedAt: early,
		Resolved: true, Decision: string(policy.Deny), ResolvedAt: early, // DENY resolved EARLIER
		Result: policy.CheckResult{Decision: policy.Deny},
	}})

	// Flush A first, then B — the shared store row (last-writer-wins) ends as DENY.
	if err := a.sy.Flush(ctx); err != nil {
		t.Fatalf("flush A: %v", err)
	}
	if err := b.sy.Flush(ctx); err != nil {
		t.Fatalf("flush B: %v", err)
	}

	// A pulls the store's DENY and flips (its later-ResolvedAt ALLOW loses).
	if err := a.sy.reconcileApprovals(ctx); err != nil {
		t.Fatalf("A reconcile: %v", err)
	}
	// B pulls the DENY (== its own) and stays DENY.
	if err := b.sy.reconcileApprovals(ctx); err != nil {
		t.Fatalf("B reconcile: %v", err)
	}

	if got := lookupOn(t, a.q, "ap_conflict", "local"); got == nil || got.Decision != string(policy.Deny) {
		t.Fatalf("node A did not converge to DENY (deny-wins over later ALLOW): %+v", got)
	}
	if got := lookupOn(t, b.q, "ap_conflict", "local"); got == nil || got.Decision != string(policy.Deny) {
		t.Fatalf("node B lost its DENY: %+v", got)
	}
}

// (d) tenant isolation: a tenant-A remote row must never mutate a tenant-B entry
// with the same raw ID.
func TestReconcileApprovals_TenantIsolation(t *testing.T) {
	ctx := context.Background()
	nodes := newApNodes(t, 2)
	a, b := nodes[0], nodes[1]

	now := time.Now().UTC().Truncate(time.Second)
	// Node A owns a RESOLVED DENY under tenant-a, id "ap_shared"; flush to store.
	a.q.Restore([]*proxy.PendingAction{{
		ID: "ap_shared", TenantID: "tenant-a", CreatedAt: now,
		Resolved: true, Decision: string(policy.Deny), ResolvedAt: now,
		Result: policy.CheckResult{Decision: policy.Deny},
	}})
	if err := a.sy.Flush(ctx); err != nil {
		t.Fatalf("flush A: %v", err)
	}

	// Node B owns a PENDING under tenant-b with the SAME raw id.
	b.q.Restore([]*proxy.PendingAction{{
		ID: "ap_shared", TenantID: "tenant-b", CreatedAt: now,
	}})

	if err := b.sy.reconcileApprovals(ctx); err != nil {
		t.Fatalf("B reconcile: %v", err)
	}

	// tenant-b's entry must be untouched (still pending).
	if got := lookupOn(t, b.q, "ap_shared", "tenant-b"); got == nil || got.Resolved {
		t.Fatalf("tenant-a remote row mutated tenant-b's entry: %+v", got)
	}
	// tenant-a must not have surfaced on node B under the shared id.
	if got := lookupOn(t, b.q, "ap_shared", "tenant-a"); got != nil {
		t.Fatalf("tenant-a row surfaced cross-tenant on node B: %+v", got)
	}
}

// (e) single-node identity: a reconcile-ARMED node whose store holds only its
// OWN flushed rows must have a Snapshot() byte-identical to a reconcile-DISABLED
// node fed the same operations — the single-node no-op guarantee.
func TestReconcileApprovals_SingleNodeIdentity(t *testing.T) {
	ctx := context.Background()

	// Armed node.
	stA, err := store.NewSQLiteStore(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stA.Close() })
	qA := proxy.NewApprovalQueue(0)
	syA := New(Config{Store: stA, Approvals: qA, NodeID: "solo", ReconcileInterval: 10 * time.Millisecond})
	if syA.ra == nil {
		t.Fatal("armed node: approval reconcile not armed")
	}

	// Disabled node (ReconcileInterval=0 => ra nil).
	qB := proxy.NewApprovalQueue(0)
	syB := New(Config{Approvals: qB, NodeID: "solo", ReconcileInterval: 0})
	if syB.ra != nil {
		t.Fatal("disabled node: approval reconcile should NOT be armed with interval=0")
	}
	_ = syB // syB only used for the arming assertion; qB is driven directly below.

	now := time.Now().UTC().Truncate(time.Second)
	seed := []*proxy.PendingAction{
		{ID: "ap_1", Request: policy.ActionRequest{Scope: "shell"}, CreatedAt: now},
		{ID: "ap_2", Request: policy.ActionRequest{Scope: "net"}, CreatedAt: now,
			Resolved: true, Decision: string(policy.Allow), ResolvedAt: now, Result: policy.CheckResult{Decision: policy.Allow}},
		{ID: "ap_3", Request: policy.ActionRequest{Scope: "fs"}, TenantID: "acme", CreatedAt: now,
			Resolved: true, Decision: string(policy.Deny), ResolvedAt: now, Result: policy.CheckResult{Decision: policy.Deny}},
	}
	qA.Restore(clonePAs(seed))
	qB.Restore(clonePAs(seed))

	// Armed node flushes its own rows then reconciles — must be a pure no-op.
	if err := syA.Flush(ctx); err != nil {
		t.Fatalf("flush A: %v", err)
	}
	if err := syA.reconcileApprovals(ctx); err != nil {
		t.Fatalf("A reconcile: %v", err)
	}

	if !sameApprovals(qA.Snapshot(), qB.Snapshot()) {
		t.Fatalf("armed single-node reconcile diverged from disabled node:\n armed=%s\n disabled=%s",
			fmtSnap(qA.Snapshot()), fmtSnap(qB.Snapshot()))
	}
}

func clonePAs(in []*proxy.PendingAction) []*proxy.PendingAction {
	out := make([]*proxy.PendingAction, len(in))
	for i, p := range in {
		cp := *p
		out[i] = &cp
	}
	return out
}

func sameApprovals(a, b []*proxy.PendingAction) bool {
	if len(a) != len(b) {
		return false
	}
	type key struct {
		tenant, id, decision string
		resolved             bool
	}
	index := func(s []*proxy.PendingAction) map[string]key {
		m := make(map[string]key, len(s))
		for _, p := range s {
			t := p.TenantID
			if t == "" {
				t = "local"
			}
			m[t+"|"+p.ID] = key{tenant: t, id: p.ID, decision: p.Decision, resolved: p.Resolved}
		}
		return m
	}
	ma, mb := index(a), index(b)
	if len(ma) != len(mb) {
		return false
	}
	for k, va := range ma {
		vb, ok := mb[k]
		if !ok || va != vb {
			return false
		}
	}
	return true
}

func fmtSnap(s []*proxy.PendingAction) string {
	ids := make([]string, 0, len(s))
	for _, p := range s {
		ids = append(ids, p.TenantID+"/"+p.ID+"/"+p.Decision)
	}
	sort.Strings(ids)
	return "[" + join(ids, " ") + "]"
}

func join(xs []string, sep string) string {
	out := ""
	for i, x := range xs {
		if i > 0 {
			out += sep
		}
		out += x
	}
	return out
}

// (f) one-shot consumption propagates cluster-wide: node A resolves an ALLOW
// (with actor stamp) and later consumes it; node B — whose entry already
// carries the SAME decision — must still receive the consumption stamp through
// reconcile (the merge no-op filter must not swallow it) and must refuse to
// honor the replay. A stale flush from B in between must not clear the stamp
// in the store (the UpsertApprovals monotonic-merge guard).
func TestReconcileApprovals_ConsumptionPropagates(t *testing.T) {
	ctx := context.Background()
	nodes := newApNodes(t, 2)
	a, b := nodes[0], nodes[1]

	pa, err := a.q.Add(
		policy.ActionRequest{Scope: "shell", Command: "sudo make install"},
		policy.CheckResult{Decision: policy.RequireApproval},
		"local",
	)
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := a.sy.Flush(ctx); err != nil {
		t.Fatalf("flush A: %v", err)
	}
	if err := b.sy.reconcileApprovals(ctx); err != nil {
		t.Fatalf("B reconcile: %v", err)
	}

	// A resolves ALLOW with an actor stamp; B reconciles the resolution.
	if err := a.q.ResolveWithActor(pa.ID, policy.Allow, "local", "bearer", "192.0.2.9"); err != nil {
		t.Fatalf("resolve on A: %v", err)
	}
	if err := a.sy.Flush(ctx); err != nil {
		t.Fatalf("flush A: %v", err)
	}
	if err := b.sy.reconcileApprovals(ctx); err != nil {
		t.Fatalf("B reconcile: %v", err)
	}
	bpa := lookupOn(t, b.q, pa.ID, "local")
	if bpa == nil || !bpa.Resolved || bpa.Decision != string(policy.Allow) {
		t.Fatalf("B did not adopt A's resolution: %+v", bpa)
	}
	if bpa.ResolvedVia != "bearer" || bpa.ResolvedFrom != "192.0.2.9" {
		t.Errorf("actor stamp lost crossing nodes: via=%q from=%q", bpa.ResolvedVia, bpa.ResolvedFrom)
	}

	// A consumes the one-shot ALLOW and flushes. B then flushes its own STALE
	// (unconsumed) snapshot — the store guard must keep consumed_at — before
	// reconciling the stamp in.
	if cp, _ := a.q.ConsumeResolved(pa.ID, "local", time.Now().UTC(), 0); cp == nil {
		t.Fatal("A failed to consume its own resolved ALLOW")
	}
	if err := a.sy.Flush(ctx); err != nil {
		t.Fatalf("flush A: %v", err)
	}
	if err := b.sy.Flush(ctx); err != nil {
		t.Fatalf("stale flush B: %v", err)
	}
	if err := b.sy.reconcileApprovals(ctx); err != nil {
		t.Fatalf("B reconcile: %v", err)
	}

	bpa = lookupOn(t, b.q, pa.ID, "local")
	if bpa == nil || bpa.ConsumedAt.IsZero() {
		t.Fatalf("consumption stamp did not reach node B (one click would be honorable once per node): %+v", bpa)
	}
	// The replay on B must fall through — nil copy means not honorable
	// (validity 0 disables expiry, and the entry provably exists above).
	if cp, _ := b.q.ConsumeResolved(pa.ID, "local", time.Now().UTC(), 0); cp != nil {
		t.Fatalf("node B honored an ALLOW already spent on node A: %+v", cp)
	}
}

// The merge no-op filter must not classify "same decision, remote consumed,
// local not" as a no-op — that is exactly the update that closes the one-shot
// hole. The genuinely-identical and locally-dominated cases stay filtered.
func TestApprovalMergeNoOp_ConsumptionMustPass(t *testing.T) {
	at := time.Now().UTC()
	mk := func(consumedAt time.Time) *proxy.PendingAction {
		return &proxy.PendingAction{
			ID: "ap_noop", Resolved: true, Decision: string(policy.Allow),
			ResolvedAt: at, ConsumedAt: consumedAt,
		}
	}
	zero := time.Time{}
	cases := []struct {
		name     string
		l, r     *proxy.PendingAction
		wantNoOp bool
	}{
		{"remote consumed, local not => must pass", mk(zero), mk(at.Add(time.Second)), false},
		{"local consumed, remote not => no-op", mk(at.Add(time.Second)), mk(zero), true},
		{"both consumed => no-op", mk(at.Add(time.Second)), mk(at.Add(2 * time.Second)), true},
		{"neither consumed => no-op", mk(zero), mk(zero), true},
	}
	for _, tc := range cases {
		if got := approvalMergeNoOp(tc.l, tc.r); got != tc.wantNoOp {
			t.Errorf("%s: approvalMergeNoOp = %v, want %v", tc.name, got, tc.wantNoOp)
		}
	}
}
