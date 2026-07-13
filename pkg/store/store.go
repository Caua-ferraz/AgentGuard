// Package store is AgentGuard's durable, multi-tenant persistence tier — the
// "cold path" behind the in-memory fast path described in
// docs/v0.6-ARCHITECTURE-PLAN.md (§2.3 write-behind dual-tier).
//
// CONTRACT (see CLAUDE.md):
//   - Implementations MUST NOT be called on the streaming proxy hot path. The
//     in-memory maps in pkg/ratelimit, pkg/policy (Engine.sessionCosts) and
//     pkg/proxy (ApprovalQueue) stay authoritative for /v1/check; a Store is
//     reconciled asynchronously (write-behind by the syncer) and read only at
//     boot (hydration) or from operator/query paths.
//   - Zero-trust: every persisted row carries a non-empty tenant_id. The
//     mutating batch methods reject any record whose TenantID is empty with
//     ErrTenantRequired; the request-driven read (QueryAudit) takes an explicit
//     tenantID. The all-tenant Load*/Purge* methods are SYSTEM operations
//     (boot hydration / GC), never reached from a per-request handler.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// ErrTenantRequired is returned by a mutating Store method when a record's
// TenantID is empty. Enforces the zero-trust rule at the lowest layer so a
// caller that forgets to stamp the tenant fails loudly rather than silently
// writing an unattributed row. The default tenant is the literal "local"
// (TenantLocal) — never the empty string at the persistence layer.
var ErrTenantRequired = errors.New("store: tenant_id is required")

// TenantLocal is the canonical id of the default single-tenant deployment.
// The proxy stores the local tenant as "" on the wire for byte-identity; the
// syncer normalizes that to TenantLocal before it reaches a Store so every
// persisted row is attributed.
const TenantLocal = "local"

// EffectiveTenant coerces an empty tenant id to TenantLocal. Callers building
// Store records from in-memory state (where local may be "") route through
// this so persisted rows are never unattributed.
func EffectiveTenant(t string) string {
	if t == "" {
		return TenantLocal
	}
	return t
}

// ApprovalRecord is the persisted form of pkg/proxy.PendingAction plus its
// owning tenant. Kept here (rather than importing the proxy type) to avoid a
// pkg/store → pkg/proxy import cycle; the syncer maps between the two.
type ApprovalRecord struct {
	TenantID   string
	ID         string
	Request    policy.ActionRequest
	Result     policy.CheckResult
	CreatedAt  time.Time
	Resolved   bool
	Decision   string
	ResolvedAt time.Time
	// ConsumedAt persists the one-shot consumption stamp so a restart can
	// never resurrect an already-spent ALLOW as replayable. Zero while
	// unconsumed.
	ConsumedAt time.Time
	// ResolvedVia / ResolvedFrom persist the resolution actor stamp
	// ("bearer" / "session" / "open" + peer host) for incident
	// reconstruction. Empty while pending.
	ResolvedVia  string
	ResolvedFrom string
}

// BucketState is one token-bucket's persisted state. Key is the limiter's
// opaque "scope:tenant:agent" key; TenantID is the parsed-out tenant so the row
// is attributable and queryable without re-parsing the key.
type BucketState struct {
	TenantID   string
	Key        string
	Tokens     int
	Max        int
	Window     time.Duration
	LastRefill time.Time
}

// CostState is one session's persisted cost accumulator.
type CostState struct {
	TenantID    string
	SessionID   string
	Cost        float64
	LastUpdated time.Time
}

// ApprovalStore persists the approval queue (restart-survival + per-tenant
// pending lists).
type ApprovalStore interface {
	// UpsertApprovals writes new/updated approvals (write-behind from
	// ApprovalQueue snapshots). Idempotent on (tenant_id, id). Rejects any
	// record with an empty TenantID.
	UpsertApprovals(ctx context.Context, recs []ApprovalRecord) error
	// LoadApprovals returns every approval (pending and still-retained
	// resolved) across all tenants — boot hydration only.
	LoadApprovals(ctx context.Context) ([]ApprovalRecord, error)
	// PurgeResolvedApprovals deletes resolved approvals resolved before cutoff
	// (durable analogue of the in-memory LRU eviction). Returns rows deleted.
	PurgeResolvedApprovals(ctx context.Context, cutoff time.Time) (int, error)
}

// RateLimitStore persists token buckets so a restart does not reset every
// limiter to full. Snapshot/restore only — the authoritative check stays in
// pkg/ratelimit (CLAUDE.md rule #2: async syncs only for rate limits/costs).
type RateLimitStore interface {
	UpsertBuckets(ctx context.Context, buckets []BucketState) error
	LoadBuckets(ctx context.Context) ([]BucketState, error)
	// PurgeBuckets deletes buckets whose last refill predates cutoff (fully
	// refilled, equivalent to evicted). Returns rows deleted.
	PurgeBuckets(ctx context.Context, cutoff time.Time) (int, error)
}

// CostStore persists session-cost accumulators.
type CostStore interface {
	UpsertCosts(ctx context.Context, costs []CostState) error
	LoadCosts(ctx context.Context) ([]CostState, error)
	// PurgeCosts deletes cost rows last updated before cutoff (durable analogue
	// of Engine.SweepSessionCosts). Returns rows deleted.
	PurgeCosts(ctx context.Context, cutoff time.Time) (int, error)
}

// AuditSink persists the audit trail. AppendAudit is batched write-behind fed
// by the existing BufferedAsyncLogger workers; QueryAudit backs the
// tenant-scoped /v1/audit read.
type AuditSink interface {
	AppendAudit(ctx context.Context, entries []audit.Entry) error
	QueryAudit(ctx context.Context, tenantID string, filter audit.QueryFilter) ([]audit.Entry, error)
}

// Store is the composed, durable persistence abstraction. SQLiteStore (and a
// future PostgresStore) satisfy it.
type Store interface {
	ApprovalStore
	RateLimitStore
	CostStore
	AuditSink

	// Migrate creates/updates the schema. Idempotent; safe on every boot.
	Migrate(ctx context.Context) error
	// Ping verifies connectivity for health checks without touching data.
	Ping(ctx context.Context) error
	// Close releases the underlying handle(s). Idempotent.
	Close() error
}
