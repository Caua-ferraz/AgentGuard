package store

// Store-level MONOTONIC merge guards on UpsertApprovals (see the interface
// contract in store.go). With multiple nodes flushing independent snapshots of
// the same (tenant_id, id), plain last-write-wins would let a lagging node's
// stale view regress state another node advanced: un-resolve a terminal row,
// flip a DENY back to ALLOW, or clear a one-shot consumption stamp (making a
// spent ALLOW replayable for whoever hydrates next). One helper drives a
// single approval through the full lifecycle against both backends.

import (
	"context"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

func runUpsertApprovalsMonotonicMerge(t *testing.T, s Store) {
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Millisecond)
	base := ApprovalRecord{
		TenantID:  "local",
		ID:        "ap_guard",
		Request:   policy.ActionRequest{Scope: "shell", Command: "sudo x", AgentID: "a"},
		Result:    policy.CheckResult{Decision: policy.RequireApproval},
		CreatedAt: at.Add(-time.Minute),
	}
	upsert := func(mut func(*ApprovalRecord)) {
		t.Helper()
		rec := base
		if mut != nil {
			mut(&rec)
		}
		if err := s.UpsertApprovals(ctx, []ApprovalRecord{rec}); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	load := func() ApprovalRecord {
		t.Helper()
		recs, err := s.LoadApprovals(ctx)
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		for _, r := range recs {
			if r.ID == base.ID {
				return r
			}
		}
		t.Fatalf("approval %q not found after upsert", base.ID)
		return ApprovalRecord{}
	}

	// Pending insert, then normal advancement pending -> resolved ALLOW (the
	// guard must only block regressions, never forward progress).
	upsert(nil)
	upsert(func(r *ApprovalRecord) {
		r.Resolved, r.Decision, r.ResolvedAt = true, string(policy.Allow), at
		r.ResolvedVia, r.ResolvedFrom = "bearer", "192.0.2.1"
	})
	if got := load(); !got.Resolved || got.Decision != string(policy.Allow) || got.ResolvedVia != "bearer" {
		t.Fatalf("pending->resolved advancement blocked: %+v", got)
	}

	// Never-unresolve: a stale node's pending snapshot must not regress the
	// terminal resolution.
	upsert(nil)
	if got := load(); !got.Resolved || got.Decision != string(policy.Allow) {
		t.Fatalf("unresolved upsert regressed a resolved row: %+v", got)
	}

	// Consumed-wins: once any node stamps consumed_at, an unconsumed snapshot
	// of the same resolution must not clear it.
	consumed := at.Add(2 * time.Second)
	upsert(func(r *ApprovalRecord) {
		r.Resolved, r.Decision, r.ResolvedAt = true, string(policy.Allow), at
		r.ConsumedAt = consumed
	})
	upsert(func(r *ApprovalRecord) {
		r.Resolved, r.Decision, r.ResolvedAt = true, string(policy.Allow), at
	})
	if got := load(); !got.ConsumedAt.Equal(consumed) {
		t.Fatalf("unconsumed snapshot cleared consumed_at (spent ALLOW became replayable): got %v want %v", got.ConsumedAt, consumed)
	}

	// DENY-wins forward: a conflicting DENY resolution may overwrite the ALLOW.
	upsert(func(r *ApprovalRecord) {
		r.Resolved, r.Decision, r.ResolvedAt = true, string(policy.Deny), at.Add(3*time.Second)
	})
	if got := load(); got.Decision != string(policy.Deny) {
		t.Fatalf("DENY failed to overwrite ALLOW (cluster must converge to DENY): %+v", got)
	}

	// Sticky-DENY: a resolved DENY is terminal for the whole cluster — a
	// non-DENY snapshot (ALLOW here) must bounce off.
	upsert(func(r *ApprovalRecord) {
		r.Resolved, r.Decision, r.ResolvedAt = true, string(policy.Allow), at.Add(4*time.Second)
	})
	if got := load(); got.Decision != string(policy.Deny) {
		t.Fatalf("ALLOW overwrote a resolved DENY (sticky-DENY violated): %+v", got)
	}
}

func TestSQLiteStore_UpsertApprovalsMonotonicMerge(t *testing.T) {
	runUpsertApprovalsMonotonicMerge(t, newTestStore(t))
}

func TestPostgresStore_UpsertApprovalsMonotonicMerge(t *testing.T) {
	runUpsertApprovalsMonotonicMerge(t, newTestPGStore(t))
}

// The consumed/actor columns must round-trip through Postgres exactly as they
// do through SQLite (approval_columns_test.go) — Postgres is the multi-node
// backend, so losing ConsumedAt there resurrects spent ALLOWs on every other
// node, not just across a restart.
func TestPostgresStore_ConsumedAndActorRoundTrip(t *testing.T) {
	s := newTestPGStore(t)
	ctx := context.Background()

	resolved := time.Now().UTC().Truncate(time.Millisecond)
	consumed := resolved.Add(3 * time.Second)
	in := ApprovalRecord{
		TenantID:  "local",
		ID:        "ap_pg_roundtrip",
		Request:   policy.ActionRequest{Scope: "shell", Command: "sudo x", AgentID: "a"},
		Result:    policy.CheckResult{Decision: policy.RequireApproval},
		CreatedAt: resolved.Add(-time.Minute),
		Resolved:  true, Decision: string(policy.Allow), ResolvedAt: resolved,
		ConsumedAt: consumed, ResolvedVia: "session", ResolvedFrom: "192.0.2.7",
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
		t.Errorf("ConsumedAt = %v, want %v", got.ConsumedAt, consumed)
	}
	if got.ResolvedVia != "session" || got.ResolvedFrom != "192.0.2.7" {
		t.Errorf("actor stamp = via=%q from=%q, want session/192.0.2.7", got.ResolvedVia, got.ResolvedFrom)
	}
}
