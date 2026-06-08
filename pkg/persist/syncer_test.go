package persist

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
	"github.com/Caua-ferraz/AgentGuard/pkg/proxy"
	"github.com/Caua-ferraz/AgentGuard/pkg/ratelimit"
	"github.com/Caua-ferraz/AgentGuard/pkg/store"
)

func newFileStore(t *testing.T) *store.SQLiteStore {
	t.Helper()
	s, err := store.NewSQLiteStore(filepath.Join(t.TempDir(), "sync.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestSyncer_FlushHydrateRoundTrip is the end-to-end durability test: populate
// the in-memory structures (two tenants), flush to the store, then hydrate a
// SECOND set of fresh structures from the same store and assert the state
// survived with tenant partitioning intact.
func TestSyncer_FlushHydrateRoundTrip(t *testing.T) {
	ctx := context.Background()
	st := newFileStore(t)

	// --- source state (as if a running server) ---
	lim := ratelimit.New()
	eng := policy.NewEngineFromPolicy(&policy.Policy{Version: "1", Name: "sync"})
	q := proxy.NewApprovalQueue(0)

	// rate-limit buckets for two tenants (consume tokens)
	_ = lim.Allow("shell:local:bot", 5, time.Minute)
	_ = lim.Allow("shell:local:bot", 5, time.Minute)
	_ = lim.Allow("network:acme:bot", 3, time.Minute)

	// session costs: same session id, two tenants — must not collide
	eng.RecordCost("s1", 4.00) // local
	// non-local cost via the internal helper is not exported; drive it through
	// the snapshot path instead by recording another local + verifying counts.
	eng.RecordCost("s2", 1.25)

	// approvals: one pending (local), one resolved (acme)
	pa, _ := q.Add(policy.ActionRequest{Scope: "shell", Command: "ls"}, policy.CheckResult{Decision: policy.RequireApproval}, "local")
	pb, _ := q.Add(policy.ActionRequest{Scope: "network", Domain: "x"}, policy.CheckResult{Decision: policy.RequireApproval}, "acme")
	_ = q.Resolve(pb.ID, policy.Allow, "acme")

	sy := New(Config{Store: st, Limiter: lim, Engine: eng, Approvals: q})
	if err := sy.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	// --- fresh structures, hydrate from the store ---
	lim2 := ratelimit.New()
	eng2 := policy.NewEngineFromPolicy(&policy.Policy{Version: "1", Name: "sync2"})
	q2 := proxy.NewApprovalQueue(0)
	sy2 := New(Config{Store: st, Limiter: lim2, Engine: eng2, Approvals: q2})
	if err := sy2.Hydrate(ctx); err != nil {
		t.Fatalf("Hydrate: %v", err)
	}

	// buckets survived: shell:local:bot had 5 max, consumed 2 -> 3 left.
	if got := lim2.BucketCount(); got != 2 {
		t.Errorf("hydrated bucket count = %d, want 2", got)
	}
	for i := 0; i < 3; i++ {
		if err := lim2.Allow("shell:local:bot", 5, time.Minute); err != nil {
			t.Errorf("hydrated bucket should have 3 tokens, Allow #%d denied: %v", i+1, err)
		}
	}
	if err := lim2.Allow("shell:local:bot", 5, time.Minute); err == nil {
		t.Errorf("hydrated bucket should be exhausted after 3 Allows")
	}

	// costs survived.
	if got := eng2.SessionCostCount(); got != 2 {
		t.Errorf("hydrated cost count = %d, want 2", got)
	}
	if got := eng2.SessionCost("s1"); got != 4.00 {
		t.Errorf("hydrated local s1 cost = %.2f, want 4.00", got)
	}

	// approvals survived with tenant scoping + resolution.
	if a, ok := q2.Lookup(pa.ID, "local"); !ok || a.Resolved {
		t.Errorf("hydrated local pending approval wrong: ok=%v a=%+v", ok, a)
	}
	if b, ok := q2.Lookup(pb.ID, "acme"); !ok || !b.Resolved || b.Decision != string(policy.Allow) {
		t.Errorf("hydrated acme resolved approval wrong: ok=%v b=%+v", ok, b)
	}
	if _, ok := q2.Lookup(pb.ID, "local"); ok {
		t.Error("hydrated approval leaked across tenants (local saw acme's id)")
	}
}

// TestSyncer_FlushIntervalFloor confirms the 1s floor is enforced.
func TestSyncer_FlushIntervalFloor(t *testing.T) {
	sy := New(Config{Store: newFileStore(t), FlushInterval: 10 * time.Millisecond})
	if sy.cfg.FlushInterval != MinFlushInterval {
		t.Errorf("flush interval = %v, want clamped to %v", sy.cfg.FlushInterval, MinFlushInterval)
	}
}

// TestSyncer_StartCloseFinalFlush verifies the background loop runs and Close
// performs a final flush (no data lost on shutdown).
func TestSyncer_StartCloseFinalFlush(t *testing.T) {
	ctx := context.Background()
	st := newFileStore(t)
	eng := policy.NewEngineFromPolicy(&policy.Policy{Version: "1", Name: "x"})
	sy := New(Config{Store: st, Engine: eng, FlushInterval: MinFlushInterval})
	sy.Start()

	// Record a cost AFTER Start; Close's final flush must persist it even if no
	// ticker fired in between.
	eng.RecordCost("late", 2.50)
	sy.Close()

	costs, err := st.LoadCosts(ctx)
	if err != nil {
		t.Fatalf("LoadCosts: %v", err)
	}
	if len(costs) != 1 || costs[0].SessionID != "late" || costs[0].Cost != 2.50 {
		t.Fatalf("final flush did not persist late cost: %+v", costs)
	}
}

// TestSyncer_Purge confirms TTL-based GC removes stale costs and keeps fresh.
func TestSyncer_Purge(t *testing.T) {
	ctx := context.Background()
	st := newFileStore(t)
	now := time.Now()
	_ = st.UpsertCosts(ctx, []store.CostState{
		{TenantID: "t", SessionID: "stale", Cost: 1, LastUpdated: now.Add(-2 * time.Hour)},
		{TenantID: "t", SessionID: "fresh", Cost: 1, LastUpdated: now},
	})
	sy := New(Config{Store: st, CostTTL: time.Hour})
	if err := sy.Purge(ctx, now); err != nil {
		t.Fatalf("Purge: %v", err)
	}
	got, _ := st.LoadCosts(ctx)
	if len(got) != 1 || got[0].SessionID != "fresh" {
		t.Errorf("purge kept wrong rows: %+v", got)
	}
}

// TestTenantFromBucketKey covers the key-parse helper.
func TestTenantFromBucketKey(t *testing.T) {
	cases := map[string]string{
		"shell:local:bot":  "local",
		"network:acme:bot": "acme",
		"shell:t:a:b":      "t", // extra colons go to the agent field
		"malformed":        "local",
		"scope::agent":     "local", // empty tenant field -> local
	}
	for in, want := range cases {
		if got := tenantFromBucketKey(in); got != want {
			t.Errorf("tenantFromBucketKey(%q) = %q, want %q", in, got, want)
		}
	}
}
