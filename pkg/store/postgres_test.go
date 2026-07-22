package store

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// newTestPGStore opens a PostgresStore against AGENTGUARD_PG_DSN, skipping the
// test when the env var is unset so `go test ./...` stays deterministic and
// green with no Postgres available. The four Store-managed tables are truncated
// (RESTART IDENTITY, so the BIGSERIAL audit id ordering is fresh) before each
// test, giving every test a clean, isolated starting state — the DSN must point
// at a throwaway test database.
func newTestPGStore(t *testing.T) *PostgresStore {
	t.Helper()
	dsn := os.Getenv("AGENTGUARD_PG_DSN")
	if dsn == "" {
		t.Skip("set AGENTGUARD_PG_DSN to run Postgres store tests")
	}
	s, err := NewPostgresStore(dsn)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if _, err := s.db.ExecContext(context.Background(),
		`TRUNCATE approvals, rate_buckets, session_costs, audit_entries RESTART IDENTITY`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	return s
}

// --- migration idempotency ---

func TestPostgresStore_MigrateIdempotent(t *testing.T) {
	s := newTestPGStore(t)
	ctx := context.Background()
	// The constructor already migrated once; a second and third call must be
	// no-ops (every statement is IF NOT EXISTS).
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate #2: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate #3: %v", err)
	}
	if err := s.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

// --- functionality: round-trip per entity type ---

func TestPostgresStore_ApprovalsRoundTrip(t *testing.T) {
	s := newTestPGStore(t)
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

func TestPostgresStore_BucketsRoundTrip(t *testing.T) {
	s := newTestPGStore(t)
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

func TestPostgresStore_CostsRoundTrip(t *testing.T) {
	s := newTestPGStore(t)
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

func TestPostgresStore_AuditRoundTrip(t *testing.T) {
	s := newTestPGStore(t)
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

	// Filters: decision, limit, offset (mirrors the SQLite filter test intent).
	denied, _ := s.QueryAudit(ctx, "acme", audit.QueryFilter{Decision: "DENY"})
	if len(denied) != 1 || denied[0].Request.Domain != "x" {
		t.Errorf("decision filter wrong: %+v", denied)
	}
	limited, _ := s.QueryAudit(ctx, "", audit.QueryFilter{Limit: 1})
	if len(limited) != 1 {
		t.Errorf("limit: got %d want 1", len(limited))
	}
	offset, _ := s.QueryAudit(ctx, "", audit.QueryFilter{Offset: 1})
	if len(offset) != 1 {
		t.Errorf("offset (no limit): got %d want 1", len(offset))
	}
}

// --- multi-tenant isolation ---

func TestPostgresStore_MultiTenantIsolation(t *testing.T) {
	s := newTestPGStore(t)
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

func TestPostgresStore_ZeroTrust(t *testing.T) {
	s := newTestPGStore(t)
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

// --- GC / purge ---

func TestPostgresStore_Purge(t *testing.T) {
	s := newTestPGStore(t)
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

// --- persistence: survives close + reopen (shared server, no truncate on #2) ---

func TestPostgresStore_PersistenceAcrossReopen(t *testing.T) {
	s := newTestPGStore(t) // truncates, then closes at cleanup
	ctx := context.Background()
	dsn := os.Getenv("AGENTGUARD_PG_DSN")
	now := time.Now().UTC().Truncate(time.Millisecond)

	if err := s.UpsertCosts(ctx, []CostState{{TenantID: "acme", SessionID: "s1", Cost: 7.5, LastUpdated: now}}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close #1: %v", err)
	}

	// Reopen with a fresh handle (does NOT truncate): the row must still be there.
	s2, err := NewPostgresStore(dsn)
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
}
