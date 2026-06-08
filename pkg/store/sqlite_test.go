package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

func newTestStore(t *testing.T) *SQLiteStore {
	t.Helper()
	s, err := NewSQLiteStore(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// --- functionality: round-trip per entity type ---

func TestSQLiteStore_ApprovalsRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)

	recs := []ApprovalRecord{
		{
			TenantID:  "local",
			ID:        "ap_pending",
			Request:   policy.ActionRequest{Scope: "shell", Command: "ls -la", AgentID: "bot"},
			Result:    policy.CheckResult{Decision: policy.RequireApproval, Reason: "needs review"},
			CreatedAt: now,
		},
		{
			TenantID:   "acme",
			ID:         "ap_resolved",
			Request:    policy.ActionRequest{Scope: "network", Domain: "evil.example", AgentID: "bot2"},
			Result:     policy.CheckResult{Decision: policy.RequireApproval},
			CreatedAt:  now,
			Resolved:   true,
			Decision:   "ALLOW",
			ResolvedAt: now.Add(time.Minute),
		},
	}
	if err := s.UpsertApprovals(ctx, recs); err != nil {
		t.Fatalf("UpsertApprovals: %v", err)
	}

	got, err := s.LoadApprovals(ctx)
	if err != nil {
		t.Fatalf("LoadApprovals: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("LoadApprovals returned %d, want 2", len(got))
	}
	byID := map[string]ApprovalRecord{}
	for _, r := range got {
		byID[r.ID] = r
	}
	p := byID["ap_pending"]
	if p.TenantID != "local" || p.Request.Command != "ls -la" || p.Resolved {
		t.Errorf("pending round-trip wrong: %+v", p)
	}
	r := byID["ap_resolved"]
	if r.TenantID != "acme" || !r.Resolved || r.Decision != "ALLOW" || r.Request.Domain != "evil.example" {
		t.Errorf("resolved round-trip wrong: %+v", r)
	}
	if !r.ResolvedAt.Equal(now.Add(time.Minute)) {
		t.Errorf("resolved_at round-trip: got %v want %v", r.ResolvedAt, now.Add(time.Minute))
	}

	// Idempotent upsert: re-upsert resolved with a new decision updates in place.
	recs[1].Decision = "DENY"
	if err := s.UpsertApprovals(ctx, recs[1:]); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	got, _ = s.LoadApprovals(ctx)
	if len(got) != 2 {
		t.Errorf("upsert must update in place, got %d rows", len(got))
	}
}

func TestSQLiteStore_BucketsRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)

	in := []BucketState{
		{TenantID: "local", Key: "shell:local:bot", Tokens: 3, Max: 5, Window: time.Minute, LastRefill: now},
		{TenantID: "acme", Key: "network:acme:bot", Tokens: 0, Max: 10, Window: 30 * time.Second, LastRefill: now},
	}
	if err := s.UpsertBuckets(ctx, in); err != nil {
		t.Fatalf("UpsertBuckets: %v", err)
	}
	got, err := s.LoadBuckets(ctx)
	if err != nil {
		t.Fatalf("LoadBuckets: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("LoadBuckets got %d want 2", len(got))
	}
	for _, b := range got {
		switch b.Key {
		case "shell:local:bot":
			if b.Tokens != 3 || b.Max != 5 || b.Window != time.Minute || b.TenantID != "local" {
				t.Errorf("bucket local wrong: %+v", b)
			}
		case "network:acme:bot":
			if b.Tokens != 0 || b.Max != 10 || b.Window != 30*time.Second {
				t.Errorf("bucket acme wrong: %+v", b)
			}
		default:
			t.Errorf("unexpected bucket key %q", b.Key)
		}
	}
}

func TestSQLiteStore_CostsRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)

	in := []CostState{
		{TenantID: "local", SessionID: "s1", Cost: 12.50, LastUpdated: now},
		{TenantID: "acme", SessionID: "s1", Cost: 3.25, LastUpdated: now},
	}
	if err := s.UpsertCosts(ctx, in); err != nil {
		t.Fatalf("UpsertCosts: %v", err)
	}
	got, err := s.LoadCosts(ctx)
	if err != nil {
		t.Fatalf("LoadCosts: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("LoadCosts got %d want 2 (same session_id under two tenants must not collide)", len(got))
	}
}

func TestSQLiteStore_AuditRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	entries := []audit.Entry{
		{Timestamp: time.Now().UTC(), AgentID: "bot", SessionID: "s1",
			Request: policy.ActionRequest{Scope: "shell", Command: "ls"},
			Result:  policy.CheckResult{Decision: policy.Allow, Reason: "ok"}, DurationMs: 2},
		{Timestamp: time.Now().UTC(), AgentID: "bot", TenantID: "acme",
			Request: policy.ActionRequest{Scope: "network", Domain: "x"},
			Result:  policy.CheckResult{Decision: policy.Deny}, Transport: audit.TransportMCPGateway},
	}
	if err := s.AppendAudit(ctx, entries); err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}

	all, err := s.QueryAudit(ctx, "", audit.QueryFilter{})
	if err != nil {
		t.Fatalf("QueryAudit all: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("QueryAudit all got %d want 2", len(all))
	}
	// Local entry was stored with EffectiveTenant -> "local"; query it back.
	loc, _ := s.QueryAudit(ctx, "local", audit.QueryFilter{})
	if len(loc) != 1 || loc[0].AgentID != "bot" || loc[0].Result.Decision != policy.Allow {
		t.Errorf("QueryAudit(local) wrong: %+v", loc)
	}
	if loc[0].EffectiveTransport() != audit.TransportSDK {
		t.Errorf("local entry transport: want sdk default, got %q", loc[0].EffectiveTransport())
	}
}

// --- multi-tenant isolation ---

func TestSQLiteStore_MultiTenantIsolation(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	ts := time.Now().UTC()

	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		if err := s.AppendAudit(ctx, []audit.Entry{{
			Timestamp: ts, TenantID: tenant, AgentID: "bot",
			Request: policy.ActionRequest{Scope: "shell", Command: "cmd-" + tenant},
			Result:  policy.CheckResult{Decision: policy.Allow},
		}}); err != nil {
			t.Fatalf("AppendAudit %s: %v", tenant, err)
		}
	}

	a, _ := s.QueryAudit(ctx, "tenant-a", audit.QueryFilter{})
	if len(a) != 1 || a[0].Request.Command != "cmd-tenant-a" {
		t.Errorf("tenant-a query leaked or missed: %+v", a)
	}
	b, _ := s.QueryAudit(ctx, "tenant-b", audit.QueryFilter{})
	if len(b) != 1 || b[0].Request.Command != "cmd-tenant-b" {
		t.Errorf("tenant-b query leaked or missed: %+v", b)
	}
	ghost, _ := s.QueryAudit(ctx, "tenant-c", audit.QueryFilter{})
	if len(ghost) != 0 {
		t.Errorf("unknown tenant must see nothing, got %d", len(ghost))
	}
}

// --- zero-trust: empty tenant rejected ---

func TestSQLiteStore_ZeroTrust(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if err := s.UpsertApprovals(ctx, []ApprovalRecord{{ID: "x"}}); !errors.Is(err, ErrTenantRequired) {
		t.Errorf("UpsertApprovals empty tenant: want ErrTenantRequired, got %v", err)
	}
	if err := s.UpsertBuckets(ctx, []BucketState{{Key: "k"}}); !errors.Is(err, ErrTenantRequired) {
		t.Errorf("UpsertBuckets empty tenant: want ErrTenantRequired, got %v", err)
	}
	if err := s.UpsertCosts(ctx, []CostState{{SessionID: "s"}}); !errors.Is(err, ErrTenantRequired) {
		t.Errorf("UpsertCosts empty tenant: want ErrTenantRequired, got %v", err)
	}
	// A rejected batch must not have written its first valid rows either.
	if got, _ := s.LoadCosts(ctx); len(got) != 0 {
		t.Errorf("rejected upsert must be atomic, found %d rows", len(got))
	}
}

// --- persistence: survives close + reopen ---

func TestSQLiteStore_PersistenceAcrossReopen(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "persist.db")

	s1, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("open #1: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	if err := s1.UpsertCosts(ctx, []CostState{{TenantID: "acme", SessionID: "s1", Cost: 7.5, LastUpdated: now}}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := s1.UpsertApprovals(ctx, []ApprovalRecord{{TenantID: "acme", ID: "ap1", CreatedAt: now}}); err != nil {
		t.Fatalf("upsert approval: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("close #1: %v", err)
	}

	// Reopen the same file: data must still be there.
	s2, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("open #2: %v", err)
	}
	defer s2.Close()
	costs, err := s2.LoadCosts(ctx)
	if err != nil {
		t.Fatalf("load after reopen: %v", err)
	}
	if len(costs) != 1 || costs[0].Cost != 7.5 || costs[0].TenantID != "acme" {
		t.Fatalf("cost did not survive reopen: %+v", costs)
	}
	aps, _ := s2.LoadApprovals(ctx)
	if len(aps) != 1 || aps[0].ID != "ap1" {
		t.Fatalf("approval did not survive reopen: %+v", aps)
	}
}

// --- capacity: bulk insert + load ---

func TestSQLiteStore_Capacity(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	const n = 5000
	now := time.Now().UTC()

	costs := make([]CostState, n)
	for i := 0; i < n; i++ {
		tenant := "t" + fmt.Sprint(i%4) // 4 tenants
		costs[i] = CostState{TenantID: tenant, SessionID: fmt.Sprintf("sess-%d", i), Cost: float64(i), LastUpdated: now}
	}
	start := time.Now()
	if err := s.UpsertCosts(ctx, costs); err != nil {
		t.Fatalf("bulk UpsertCosts: %v", err)
	}
	writeMs := float64(time.Since(start).Microseconds()) / 1000.0

	start = time.Now()
	got, err := s.LoadCosts(ctx)
	if err != nil {
		t.Fatalf("LoadCosts: %v", err)
	}
	readMs := float64(time.Since(start).Microseconds()) / 1000.0
	if len(got) != n {
		t.Fatalf("capacity load got %d want %d", len(got), n)
	}
	t.Logf("capacity: wrote %d cost rows in %.1f ms, loaded all in %.1f ms", n, writeMs, readMs)
}

// --- GC / purge ---

func TestSQLiteStore_Purge(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	old := time.Now().Add(-2 * time.Hour).UTC()
	fresh := time.Now().UTC()
	cutoff := time.Now().Add(-time.Hour)

	// Costs: one stale, one fresh.
	_ = s.UpsertCosts(ctx, []CostState{
		{TenantID: "t", SessionID: "stale", Cost: 1, LastUpdated: old},
		{TenantID: "t", SessionID: "fresh", Cost: 1, LastUpdated: fresh},
	})
	n, err := s.PurgeCosts(ctx, cutoff)
	if err != nil || n != 1 {
		t.Fatalf("PurgeCosts: n=%d err=%v want n=1", n, err)
	}
	if got, _ := s.LoadCosts(ctx); len(got) != 1 || got[0].SessionID != "fresh" {
		t.Errorf("PurgeCosts kept wrong rows: %+v", got)
	}

	// Resolved approvals: stale resolved purged, pending kept.
	_ = s.UpsertApprovals(ctx, []ApprovalRecord{
		{TenantID: "t", ID: "old-resolved", CreatedAt: old, Resolved: true, Decision: "ALLOW", ResolvedAt: old},
		{TenantID: "t", ID: "pending", CreatedAt: old},
	})
	n, err = s.PurgeResolvedApprovals(ctx, cutoff)
	if err != nil || n != 1 {
		t.Fatalf("PurgeResolvedApprovals: n=%d err=%v want n=1", n, err)
	}
	if got, _ := s.LoadApprovals(ctx); len(got) != 1 || got[0].ID != "pending" {
		t.Errorf("PurgeResolvedApprovals kept wrong rows: %+v", got)
	}

	// Buckets: stale refilled bucket purged.
	_ = s.UpsertBuckets(ctx, []BucketState{
		{TenantID: "t", Key: "stale", Tokens: 5, Max: 5, Window: time.Minute, LastRefill: old},
		{TenantID: "t", Key: "fresh", Tokens: 1, Max: 5, Window: time.Minute, LastRefill: fresh},
	})
	n, err = s.PurgeBuckets(ctx, cutoff)
	if err != nil || n != 1 {
		t.Fatalf("PurgeBuckets: n=%d err=%v want n=1", n, err)
	}
}

// --- audit query filters ---

func TestSQLiteStore_AuditQueryFilters(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	base := time.Now().UTC()
	for i := 0; i < 5; i++ {
		dec := policy.Allow
		if i%2 == 0 {
			dec = policy.Deny
		}
		_ = s.AppendAudit(ctx, []audit.Entry{{
			Timestamp: base.Add(time.Duration(i) * time.Second), TenantID: "t", AgentID: "bot",
			Request: policy.ActionRequest{Scope: "shell"}, Result: policy.CheckResult{Decision: dec},
		}})
	}
	denied, _ := s.QueryAudit(ctx, "t", audit.QueryFilter{Decision: "DENY"})
	if len(denied) != 3 {
		t.Errorf("decision filter: got %d want 3", len(denied))
	}
	limited, _ := s.QueryAudit(ctx, "t", audit.QueryFilter{Limit: 2})
	if len(limited) != 2 {
		t.Errorf("limit: got %d want 2", len(limited))
	}
	offset, _ := s.QueryAudit(ctx, "t", audit.QueryFilter{Limit: 2, Offset: 4})
	if len(offset) != 1 {
		t.Errorf("limit+offset: got %d want 1", len(offset))
	}
}

// --- latency: total ms per Store method (off-hot-path, but measured) ---

func TestSQLiteStore_Latency(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	type op struct {
		name string
		fn   func() error
	}
	ops := []op{
		{"UpsertApprovals(1)", func() error {
			return s.UpsertApprovals(ctx, []ApprovalRecord{{TenantID: "t", ID: "ap", CreatedAt: now}})
		}},
		{"UpsertBuckets(1)", func() error {
			return s.UpsertBuckets(ctx, []BucketState{{TenantID: "t", Key: "k", Tokens: 1, Max: 5, Window: time.Minute, LastRefill: now}})
		}},
		{"UpsertCosts(1)", func() error {
			return s.UpsertCosts(ctx, []CostState{{TenantID: "t", SessionID: "s", Cost: 1, LastUpdated: now}})
		}},
		{"AppendAudit(1)", func() error {
			return s.AppendAudit(ctx, []audit.Entry{{Timestamp: now, TenantID: "t", Request: policy.ActionRequest{Scope: "shell"}, Result: policy.CheckResult{Decision: policy.Allow}}})
		}},
		{"QueryAudit", func() error { _, err := s.QueryAudit(ctx, "t", audit.QueryFilter{Limit: 100}); return err }},
		{"LoadCosts", func() error { _, err := s.LoadCosts(ctx); return err }},
		{"LoadBuckets", func() error { _, err := s.LoadBuckets(ctx); return err }},
		{"LoadApprovals", func() error { _, err := s.LoadApprovals(ctx); return err }},
		{"Ping", func() error { return s.Ping(ctx) }},
	}

	const maxMs = 100.0 // generous ceiling for a single cold-path op on a temp-file DB
	for _, o := range ops {
		// Warm once (first call pays statement-prepare / page-cache cost).
		if err := o.fn(); err != nil {
			t.Fatalf("%s: %v", o.name, err)
		}
		start := time.Now()
		if err := o.fn(); err != nil {
			t.Fatalf("%s: %v", o.name, err)
		}
		ms := float64(time.Since(start).Microseconds()) / 1000.0
		t.Logf("store latency: %-20s %7.3f ms", o.name, ms)
		if ms > maxMs {
			t.Errorf("%s took %.3f ms (> %.0f ms ceiling) — investigate", o.name, ms, maxMs)
		}
	}
}

// --- benchmarks: `go test -bench .` reports ns/op per method ---

func BenchmarkUpsertCosts1(b *testing.B) {
	s, _ := NewSQLiteStore(filepath.Join(b.TempDir(), "b.db"))
	defer s.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.UpsertCosts(ctx, []CostState{{TenantID: "t", SessionID: "s", Cost: float64(i), LastUpdated: now}})
	}
}

func BenchmarkAppendAudit1(b *testing.B) {
	s, _ := NewSQLiteStore(filepath.Join(b.TempDir(), "b.db"))
	defer s.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	e := audit.Entry{Timestamp: now, TenantID: "t", Request: policy.ActionRequest{Scope: "shell", Command: "ls"}, Result: policy.CheckResult{Decision: policy.Allow}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.AppendAudit(ctx, []audit.Entry{e})
	}
}

func BenchmarkQueryAudit(b *testing.B) {
	s, _ := NewSQLiteStore(filepath.Join(b.TempDir(), "b.db"))
	defer s.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	for i := 0; i < 1000; i++ {
		_ = s.AppendAudit(ctx, []audit.Entry{{Timestamp: now, TenantID: "t", Request: policy.ActionRequest{Scope: "shell"}, Result: policy.CheckResult{Decision: policy.Allow}}})
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = s.QueryAudit(ctx, "t", audit.QueryFilter{Limit: 100})
	}
}
