package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

// --- SQLite: multi-node consumption tables (v1.0 reconciliation) ---

func TestSQLiteStore_RateConsumptionRoundTrip(t *testing.T) {
	s := newTestStore(t)
	runRateConsumptionRoundTrip(t, s)
}

func TestSQLiteStore_CostConsumptionRoundTrip(t *testing.T) {
	s := newTestStore(t)
	runCostConsumptionRoundTrip(t, s)
}

// consumptionStore is the concrete surface exercised by the shared round-trip
// helpers, so the same assertions run against SQLite and Postgres.
type consumptionStore interface {
	UpsertRateConsumption(ctx context.Context, rows []RateConsumption) error
	LoadRateConsumption(ctx context.Context) ([]RateConsumption, error)
	PurgeRateConsumption(ctx context.Context, cutoff time.Time) (int, error)
	UpsertCostConsumption(ctx context.Context, rows []CostConsumption) error
	LoadCostConsumption(ctx context.Context) ([]CostConsumption, error)
	PurgeCostConsumption(ctx context.Context, cutoff time.Time) (int, error)
}

func runRateConsumptionRoundTrip(t *testing.T, s consumptionStore) {
	t.Helper()
	ctx := context.Background()
	epoch := time.Now().UTC().Truncate(time.Minute)
	now := time.Now().UTC().Truncate(time.Millisecond)

	// Two nodes, same (tenant, key, epoch): distinct node_id rows co-exist.
	rows := []RateConsumption{
		{TenantID: "local", Key: "shell:local:bot", WindowEpoch: epoch, NodeID: "node-a", Consumed: 5, UpdatedAt: now},
		{TenantID: "local", Key: "shell:local:bot", WindowEpoch: epoch, NodeID: "node-b", Consumed: 3, UpdatedAt: now},
		{TenantID: "acme", Key: "net:acme:bot", WindowEpoch: epoch, NodeID: "node-a", Consumed: 9, UpdatedAt: now},
	}
	if err := s.UpsertRateConsumption(ctx, rows); err != nil {
		t.Fatalf("UpsertRateConsumption: %v", err)
	}
	got, err := s.LoadRateConsumption(ctx)
	if err != nil {
		t.Fatalf("LoadRateConsumption: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("loaded %d rows, want 3", len(got))
	}

	// Idempotent last-writer-wins on a node's OWN row (absolute cumulative).
	if err := s.UpsertRateConsumption(ctx, []RateConsumption{
		{TenantID: "local", Key: "shell:local:bot", WindowEpoch: epoch, NodeID: "node-a", Consumed: 8, UpdatedAt: now.Add(time.Second)},
	}); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	got, _ = s.LoadRateConsumption(ctx)
	if len(got) != 3 {
		t.Fatalf("re-upsert changed row count to %d, want 3 (must update in place)", len(got))
	}
	// Verify the epoch round-trips and node-a now reads 8.
	var nodeA *RateConsumption
	for i := range got {
		if got[i].Key == "shell:local:bot" && got[i].NodeID == "node-a" {
			nodeA = &got[i]
		}
	}
	if nodeA == nil {
		t.Fatal("node-a row missing after re-upsert")
	}
	if nodeA.Consumed != 8 {
		t.Errorf("node-a consumed = %d, want 8", nodeA.Consumed)
	}
	if !nodeA.WindowEpoch.Equal(epoch) {
		t.Errorf("epoch round-trip: got %v want %v", nodeA.WindowEpoch, epoch)
	}

	// Zero-trust: empty tenant rejected.
	if err := s.UpsertRateConsumption(ctx, []RateConsumption{
		{TenantID: "", Key: "k", WindowEpoch: epoch, NodeID: "n", Consumed: 1, UpdatedAt: now},
	}); !errors.Is(err, ErrTenantRequired) {
		t.Errorf("empty tenant: got %v, want ErrTenantRequired", err)
	}

	// Purge by updated_at cutoff: everything older than "tomorrow" goes.
	deleted, err := s.PurgeRateConsumption(ctx, now.Add(24*time.Hour))
	if err != nil {
		t.Fatalf("PurgeRateConsumption: %v", err)
	}
	if deleted != 3 {
		t.Errorf("purged %d rows, want 3", deleted)
	}
	if got, _ = s.LoadRateConsumption(ctx); len(got) != 0 {
		t.Errorf("after purge %d rows remain, want 0", len(got))
	}
}

func runCostConsumptionRoundTrip(t *testing.T, s consumptionStore) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)

	rows := []CostConsumption{
		{TenantID: "local", SessionID: "sess", NodeID: "node-a", Consumed: 12.5, UpdatedAt: now},
		{TenantID: "local", SessionID: "sess", NodeID: "node-b", Consumed: 7.25, UpdatedAt: now},
		// Same session id under a DIFFERENT tenant is a distinct row (zero-trust).
		{TenantID: "acme", SessionID: "sess", NodeID: "node-a", Consumed: 99.0, UpdatedAt: now},
	}
	if err := s.UpsertCostConsumption(ctx, rows); err != nil {
		t.Fatalf("UpsertCostConsumption: %v", err)
	}
	got, err := s.LoadCostConsumption(ctx)
	if err != nil {
		t.Fatalf("LoadCostConsumption: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("loaded %d rows, want 3", len(got))
	}

	// Sum within (tenant, session) excludes the other tenant.
	var localSum float64
	for _, r := range got {
		if r.TenantID == "local" && r.SessionID == "sess" {
			localSum += r.Consumed
		}
	}
	if localSum != 19.75 {
		t.Errorf("local/sess sum = %v, want 19.75 (acme must not leak)", localSum)
	}

	// Idempotent absolute-cumulative update.
	if err := s.UpsertCostConsumption(ctx, []CostConsumption{
		{TenantID: "local", SessionID: "sess", NodeID: "node-a", Consumed: 20.0, UpdatedAt: now.Add(time.Second)},
	}); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	if got, _ = s.LoadCostConsumption(ctx); len(got) != 3 {
		t.Fatalf("re-upsert changed count to %d, want 3", len(got))
	}

	if err := s.UpsertCostConsumption(ctx, []CostConsumption{
		{TenantID: "", SessionID: "s", NodeID: "n", Consumed: 1, UpdatedAt: now},
	}); !errors.Is(err, ErrTenantRequired) {
		t.Errorf("empty tenant: got %v, want ErrTenantRequired", err)
	}

	deleted, err := s.PurgeCostConsumption(ctx, now.Add(24*time.Hour))
	if err != nil {
		t.Fatalf("PurgeCostConsumption: %v", err)
	}
	if deleted != 3 {
		t.Errorf("purged %d rows, want 3", deleted)
	}
}

// --- Postgres: same tables, env-gated (skips without AGENTGUARD_PG_DSN) ---

func TestPostgresStore_RateConsumptionRoundTrip(t *testing.T) {
	s := newTestPGStore(t)
	truncateConsumption(t, s)
	runRateConsumptionRoundTrip(t, s)
}

func TestPostgresStore_CostConsumptionRoundTrip(t *testing.T) {
	s := newTestPGStore(t)
	truncateConsumption(t, s)
	runCostConsumptionRoundTrip(t, s)
}

// truncateConsumption clears the two v1.0 consumption tables (not covered by
// newTestPGStore's TRUNCATE) so each Postgres consumption test starts clean.
func truncateConsumption(t *testing.T, s *PostgresStore) {
	t.Helper()
	if _, err := s.db.ExecContext(context.Background(),
		`TRUNCATE rate_consumption, cost_consumption`); err != nil {
		t.Fatalf("truncate consumption: %v", err)
	}
}
