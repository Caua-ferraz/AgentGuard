package store

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

func benchStore(b *testing.B) *SQLiteStore {
	b.Helper()
	s, err := NewSQLiteStore(filepath.Join(b.TempDir(), "b.db"))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = s.Close() })
	return s
}

// --- coverage for the small new functions ---

func TestStore_EffectiveTenant(t *testing.T) {
	if got := EffectiveTenant(""); got != TenantLocal {
		t.Errorf(`EffectiveTenant("") = %q, want %q`, got, TenantLocal)
	}
	if got := EffectiveTenant("acme"); got != "acme" {
		t.Errorf("EffectiveTenant(acme) = %q, want acme", got)
	}
}

func TestSQLiteStore_Path(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.db")
	s, err := NewSQLiteStore(p)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.Path() != p {
		t.Errorf("Path() = %q, want %q", s.Path(), p)
	}
}

// TestNewAuditLogger_Adapter covers the store→audit.Logger adapter (Log/Query/
// Close) directly — the glue the buffered logger and proxy /v1/audit ride on.
func TestNewAuditLogger_Adapter(t *testing.T) {
	s := newTestStore(t)
	lg := NewAuditLogger(s)
	e := audit.Entry{
		Timestamp: time.Now().UTC(), TenantID: "t", AgentID: "bot",
		Request: policy.ActionRequest{Scope: "shell", Command: "ls"},
		Result:  policy.CheckResult{Decision: policy.Allow},
	}
	if err := lg.Log(e); err != nil {
		t.Fatalf("Log: %v", err)
	}
	got, err := lg.Query(audit.QueryFilter{TenantID: "t"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 1 || got[0].AgentID != "bot" {
		t.Errorf("adapter round-trip wrong: %+v", got)
	}
	if err := lg.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// --- delay-check benchmarks for every store method (run: go test -bench . -benchmem) ---

func BenchmarkStore_UpsertApprovals1(b *testing.B) {
	s := benchStore(b)
	ctx := context.Background()
	now := time.Now().UTC()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.UpsertApprovals(ctx, []ApprovalRecord{{TenantID: "t", ID: "ap", CreatedAt: now}})
	}
}

func BenchmarkStore_UpsertBuckets1(b *testing.B) {
	s := benchStore(b)
	ctx := context.Background()
	now := time.Now().UTC()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.UpsertBuckets(ctx, []BucketState{{TenantID: "t", Key: "shell:t:bot", Tokens: 1, Max: 5, Window: time.Minute, LastRefill: now}})
	}
}

func BenchmarkStore_LoadCosts1000(b *testing.B) {
	s := benchStore(b)
	ctx := context.Background()
	now := time.Now().UTC()
	costs := make([]CostState, 1000)
	for i := range costs {
		costs[i] = CostState{TenantID: "t", SessionID: fmt.Sprintf("s%d", i), Cost: float64(i), LastUpdated: now}
	}
	_ = s.UpsertCosts(ctx, costs)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = s.LoadCosts(ctx)
	}
}

func BenchmarkStore_LoadApprovals1000(b *testing.B) {
	s := benchStore(b)
	ctx := context.Background()
	now := time.Now().UTC()
	recs := make([]ApprovalRecord, 1000)
	for i := range recs {
		recs[i] = ApprovalRecord{TenantID: "t", ID: fmt.Sprintf("ap%d", i), CreatedAt: now}
	}
	_ = s.UpsertApprovals(ctx, recs)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = s.LoadApprovals(ctx)
	}
}

func BenchmarkStore_PutPolicy(b *testing.B) {
	s := benchStore(b)
	ctx := context.Background()
	doc := []byte("version: \"1\"\nname: bench\nrules:\n  - scope: shell\n    allow:\n      - pattern: \"ls *\"\n")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.PutPolicy(ctx, "acme", doc)
	}
}

func BenchmarkStore_GetPolicyYAML(b *testing.B) {
	s := benchStore(b)
	ctx := context.Background()
	_ = s.PutPolicy(ctx, "acme", []byte("version: \"1\"\nname: bench\n"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = s.GetPolicyYAML(ctx, "acme")
	}
}

func BenchmarkStore_Ping(b *testing.B) {
	s := benchStore(b)
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.Ping(ctx)
	}
}
