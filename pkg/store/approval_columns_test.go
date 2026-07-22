package store

// Tests for the post-v0.9.0 approval-hardening columns (consumed_at,
// resolved_via, resolved_from). Two properties are pinned:
//
//  1. Round-trip fidelity — a consumed/stamped approval that goes through
//     Upsert + Load keeps its state, because losing ConsumedAt across a
//     restart would resurrect a spent one-shot ALLOW as replayable.
//  2. Old-database upgrade — a DB created by a pre-hardening build (whose
//     approvals table lacks the columns) must gain them transparently on
//     open via Migrate's guarded ALTERs, and must round-trip the new
//     fields afterwards. CREATE TABLE IF NOT EXISTS alone would silently
//     skip existing tables and every Upsert would fail.

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

func TestApprovals_ConsumedAndActorRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	resolved := time.Now().UTC().Truncate(time.Millisecond)
	consumed := resolved.Add(3 * time.Second)
	in := ApprovalRecord{
		TenantID:  "local",
		ID:        "ap_roundtrip1",
		Request:   policy.ActionRequest{Scope: "shell", Command: "sudo x", AgentID: "a"},
		Result:    policy.CheckResult{Decision: policy.RequireApproval},
		CreatedAt: resolved.Add(-time.Minute),
		Resolved:  true, Decision: string(policy.Allow), ResolvedAt: resolved,
		ConsumedAt: consumed, ResolvedVia: "bearer", ResolvedFrom: "192.0.2.1",
	}
	if err := s.UpsertApprovals(ctx, []ApprovalRecord{in}); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	recs, err := s.LoadApprovals(ctx)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	got := recs[0]
	if !got.ConsumedAt.Equal(consumed) {
		t.Errorf("ConsumedAt = %v, want %v (a lost consumption stamp reopens the one-shot hole across restarts)", got.ConsumedAt, consumed)
	}
	if got.ResolvedVia != "bearer" || got.ResolvedFrom != "192.0.2.1" {
		t.Errorf("actor stamp = via=%q from=%q, want bearer/192.0.2.1", got.ResolvedVia, got.ResolvedFrom)
	}

	// An unconsumed row must load with a zero ConsumedAt (not some parse
	// artifact) so the queue treats it as still-spendable exactly once.
	in2 := in
	in2.ID = "ap_roundtrip2"
	in2.ConsumedAt = time.Time{}
	in2.ResolvedVia, in2.ResolvedFrom = "", ""
	if err := s.UpsertApprovals(ctx, []ApprovalRecord{in2}); err != nil {
		t.Fatalf("upsert unconsumed: %v", err)
	}
	recs, _ = s.LoadApprovals(ctx)
	for _, r := range recs {
		if r.ID == "ap_roundtrip2" && !r.ConsumedAt.IsZero() {
			t.Errorf("unconsumed row loaded with non-zero ConsumedAt: %v", r.ConsumedAt)
		}
	}
}

// oldApprovalsSchema is the approvals DDL exactly as it shipped before the
// hardening columns. Kept verbatim so this test fails loudly if someone
// "cleans up" Migrate's guarded ALTERs assuming CREATE TABLE covers it.
const oldApprovalsSchema = `
CREATE TABLE approvals (
    tenant_id   TEXT    NOT NULL,
    id          TEXT    NOT NULL,
    request     TEXT    NOT NULL,
    result      TEXT    NOT NULL,
    created_at  TEXT    NOT NULL,
    resolved    INTEGER NOT NULL DEFAULT 0,
    decision    TEXT    NOT NULL DEFAULT '',
    resolved_at TEXT    NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, id)
);`

func TestMigrate_UpgradesPreHardeningApprovalsTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")

	// Simulate a database created by an older build: approvals exists
	// WITHOUT the new columns, and already holds a row.
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	if _, err := raw.Exec(oldApprovalsSchema); err != nil {
		t.Fatalf("create old schema: %v", err)
	}
	if _, err := raw.Exec(
		`INSERT INTO approvals (tenant_id, id, request, result, created_at, resolved, decision, resolved_at)
		 VALUES ('local', 'ap_old1', '{"scope":"shell"}', '{"decision":"REQUIRE_APPROVAL"}', ?, 1, 'ALLOW', ?)`,
		time.Now().UTC().Format(time.RFC3339Nano), time.Now().UTC().Format(time.RFC3339Nano),
	); err != nil {
		t.Fatalf("seed old row: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close raw: %v", err)
	}

	// Opening through the store must upgrade the table in place…
	s, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("NewSQLiteStore over old DB: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()

	// …the legacy row loads with zero-value hardening fields…
	recs, err := s.LoadApprovals(ctx)
	if err != nil {
		t.Fatalf("load after upgrade: %v", err)
	}
	if len(recs) != 1 || recs[0].ID != "ap_old1" {
		t.Fatalf("legacy row lost in upgrade: %+v", recs)
	}
	if !recs[0].ConsumedAt.IsZero() || recs[0].ResolvedVia != "" {
		t.Errorf("legacy row must upgrade with zero hardening fields, got %+v", recs[0])
	}

	// …and new-field writes round-trip on the upgraded table.
	up := recs[0]
	up.ConsumedAt = time.Now().UTC().Truncate(time.Millisecond)
	up.ResolvedVia, up.ResolvedFrom = "session", "203.0.113.9"
	if err := s.UpsertApprovals(ctx, []ApprovalRecord{up}); err != nil {
		t.Fatalf("upsert on upgraded table: %v", err)
	}
	recs, _ = s.LoadApprovals(ctx)
	if len(recs) != 1 || recs[0].ResolvedVia != "session" || recs[0].ConsumedAt.IsZero() {
		t.Errorf("upgraded table did not round-trip hardening fields: %+v", recs)
	}

	// Migrate must stay idempotent on the upgraded DB (second boot).
	if err := s.Migrate(ctx); err != nil {
		t.Errorf("second Migrate on upgraded DB: %v", err)
	}
}
