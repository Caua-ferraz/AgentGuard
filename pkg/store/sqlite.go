package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, registered under the name "sqlite"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// SQLiteStore is the single-node, zero-config Store backend (docs/v0.6-
// ARCHITECTURE-PLAN.md §2.4). It owns one database file holding every
// persistence table, opened in WAL mode so the eventual direct-reading
// dashboard can read concurrently with the write-behind syncer.
//
// Concurrency: MaxOpenConns is pinned to 1. The Store is a cold-path component
// (write-behind flushes + boot hydration + occasional audit queries), so
// serializing its handle is the simplest correct guard against SQLITE_BUSY and
// costs nothing on the proxy's request path, which never touches it.
type SQLiteStore struct {
	db   *sql.DB
	path string
}

// NewSQLiteStore opens (creating if absent) the SQLite database at path, sets
// WAL + a busy timeout, and runs the schema migration. A ":memory:" path (or
// any modernc in-memory DSN) yields an ephemeral store, used by tests.
//
// The database file and its -wal/-shm sidecars are held at mode 0600: they
// carry the full audit trail plus approval/cost/bucket state, and the security
// brief requires owner-only access (audit 2026-06, M2). The file is pre-created
// 0600 so SQLite inherits that mode for the sidecars it creates, and existing
// files from pre-fix versions are tightened on every open.
func NewSQLiteStore(path string) (*SQLiteStore, error) {
	if !isMemoryDSN(path) {
		f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
		if err != nil {
			return nil, fmt.Errorf("store: create %q: %w", path, err)
		}
		_ = f.Close()
		// Tighten files created by older versions under the process umask,
		// including sidecars left over from a previous run. Chmod failures are
		// non-fatal (e.g. filesystems without POSIX modes): the pre-create
		// above already guarantees new deployments are 0600.
		_ = os.Chmod(path, 0o600)
		for _, sidecar := range []string{path + "-wal", path + "-shm"} {
			if _, err := os.Stat(sidecar); err == nil {
				_ = os.Chmod(sidecar, 0o600)
			}
		}
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("store: open %q: %w", path, err)
	}
	// One connection: a cold-path single-file writer. See type doc.
	db.SetMaxOpenConns(1)

	// WAL for concurrent external readers; NORMAL sync is the standard
	// durability/throughput balance under WAL; busy_timeout makes the rare
	// lock contention wait rather than erroring.
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA foreign_keys=ON",
	} {
		if _, err := db.Exec(pragma); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("store: %q: %w", pragma, err)
		}
	}

	s := &SQLiteStore{db: db, path: path}
	if err := s.Migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// isMemoryDSN reports whether path selects an ephemeral in-memory database
// (":memory:" or any modernc DSN carrying mode=memory), which has no on-disk
// file to permission.
func isMemoryDSN(path string) bool {
	return strings.Contains(path, ":memory:") || strings.Contains(path, "mode=memory")
}

// Path returns the database path (for logging / health).
func (s *SQLiteStore) Path() string { return s.path }

const schemaSQL = `
CREATE TABLE IF NOT EXISTS approvals (
    tenant_id     TEXT    NOT NULL,
    id            TEXT    NOT NULL,
    request       TEXT    NOT NULL,
    result        TEXT    NOT NULL,
    created_at    TEXT    NOT NULL,
    resolved      INTEGER NOT NULL DEFAULT 0,
    decision      TEXT    NOT NULL DEFAULT '',
    resolved_at   TEXT    NOT NULL DEFAULT '',
    consumed_at   TEXT    NOT NULL DEFAULT '',
    resolved_via  TEXT    NOT NULL DEFAULT '',
    resolved_from TEXT    NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS idx_approvals_resolved ON approvals(resolved, resolved_at);

CREATE TABLE IF NOT EXISTS rate_buckets (
    tenant_id   TEXT    NOT NULL,
    key         TEXT    NOT NULL,
    tokens      INTEGER NOT NULL,
    max_tokens  INTEGER NOT NULL,
    window_ns   INTEGER NOT NULL,
    last_refill TEXT    NOT NULL,
    PRIMARY KEY (tenant_id, key)
);
CREATE INDEX IF NOT EXISTS idx_buckets_refill ON rate_buckets(last_refill);

CREATE TABLE IF NOT EXISTS session_costs (
    tenant_id    TEXT NOT NULL,
    session_id   TEXT NOT NULL,
    cost         REAL NOT NULL,
    last_updated TEXT NOT NULL,
    PRIMARY KEY (tenant_id, session_id)
);
CREATE INDEX IF NOT EXISTS idx_costs_updated ON session_costs(last_updated);

CREATE TABLE IF NOT EXISTS audit_entries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id   TEXT    NOT NULL DEFAULT 'local',
    timestamp   TEXT    NOT NULL,
    session_id  TEXT    NOT NULL DEFAULT '',
    agent_id    TEXT    NOT NULL DEFAULT '',
    scope       TEXT    NOT NULL DEFAULT '',
    action      TEXT    NOT NULL DEFAULT '',
    command     TEXT    NOT NULL DEFAULT '',
    path        TEXT    NOT NULL DEFAULT '',
    domain      TEXT    NOT NULL DEFAULT '',
    url         TEXT    NOT NULL DEFAULT '',
    decision    TEXT    NOT NULL DEFAULT '',
    reason      TEXT    NOT NULL DEFAULT '',
    rule        TEXT    NOT NULL DEFAULT '',
    duration_ms INTEGER NOT NULL DEFAULT 0,
    transport   TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_tenant_ts ON audit_entries(tenant_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_agent     ON audit_entries(agent_id);
CREATE INDEX IF NOT EXISTS idx_audit_decision  ON audit_entries(decision);
CREATE INDEX IF NOT EXISTS idx_audit_scope     ON audit_entries(scope);

CREATE TABLE IF NOT EXISTS policies (
    tenant_id   TEXT NOT NULL PRIMARY KEY,
    policy_yaml TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rate_consumption (
    tenant_id    TEXT    NOT NULL,
    key          TEXT    NOT NULL,
    window_epoch TEXT    NOT NULL,
    node_id      TEXT    NOT NULL,
    consumed     INTEGER NOT NULL,
    updated_at   TEXT    NOT NULL,
    PRIMARY KEY (tenant_id, key, window_epoch, node_id)
);
CREATE INDEX IF NOT EXISTS idx_rate_consumption_updated ON rate_consumption(updated_at);

CREATE TABLE IF NOT EXISTS cost_consumption (
    tenant_id  TEXT NOT NULL,
    session_id TEXT NOT NULL,
    node_id    TEXT NOT NULL,
    consumed   REAL NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, session_id, node_id)
);
CREATE INDEX IF NOT EXISTS idx_cost_consumption_updated ON cost_consumption(updated_at);
`

// Migrate creates the schema. Idempotent (CREATE ... IF NOT EXISTS), so it is
// safe to run on every boot. Additive columns introduced after a table first
// shipped are applied with guarded ALTERs — CREATE IF NOT EXISTS skips
// existing tables, so a DB created by an older build would otherwise never
// gain them.
func (s *SQLiteStore) Migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, schemaSQL); err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}
	// approvals one-shot/actor columns (post-v0.9.0 approval hardening).
	additive := []string{
		`ALTER TABLE approvals ADD COLUMN consumed_at   TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE approvals ADD COLUMN resolved_via  TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE approvals ADD COLUMN resolved_from TEXT NOT NULL DEFAULT ''`,
	}
	for _, stmt := range additive {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			// SQLite has no ADD COLUMN IF NOT EXISTS; a duplicate column
			// error just means this DB already has it.
			if strings.Contains(err.Error(), "duplicate column name") {
				continue
			}
			return fmt.Errorf("store: migrate (additive column): %w", err)
		}
	}
	return nil
}

// Ping verifies connectivity.
func (s *SQLiteStore) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

// Close closes the database. Idempotent at the sql.DB layer.
func (s *SQLiteStore) Close() error { return s.db.Close() }

// --- time helpers ---

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}

// --- approvals ---

func (s *SQLiteStore) UpsertApprovals(ctx context.Context, recs []ApprovalRecord) error {
	if len(recs) == 0 {
		return nil
	}
	for i := range recs {
		if recs[i].TenantID == "" {
			return ErrTenantRequired
		}
	}
	return s.inTx(ctx, func(tx *sql.Tx) error {
		stmt, err := tx.PrepareContext(ctx, `
			INSERT INTO approvals (tenant_id, id, request, result, created_at, resolved, decision, resolved_at, consumed_at, resolved_via, resolved_from)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(tenant_id, id) DO UPDATE SET
				request=excluded.request, result=excluded.result,
				resolved=excluded.resolved, decision=excluded.decision,
				resolved_at=excluded.resolved_at, consumed_at=excluded.consumed_at,
				resolved_via=excluded.resolved_via, resolved_from=excluded.resolved_from`)
		if err != nil {
			return err
		}
		defer func() { _ = stmt.Close() }()
		for _, r := range recs {
			reqJSON, err := json.Marshal(r.Request)
			if err != nil {
				return fmt.Errorf("store: marshal approval request: %w", err)
			}
			resJSON, err := json.Marshal(r.Result)
			if err != nil {
				return fmt.Errorf("store: marshal approval result: %w", err)
			}
			if _, err := stmt.ExecContext(ctx,
				r.TenantID, r.ID, string(reqJSON), string(resJSON),
				fmtTime(r.CreatedAt), boolToInt(r.Resolved), r.Decision, fmtTime(r.ResolvedAt),
				fmtTime(r.ConsumedAt), r.ResolvedVia, r.ResolvedFrom,
			); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *SQLiteStore) LoadApprovals(ctx context.Context) ([]ApprovalRecord, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT tenant_id, id, request, result, created_at, resolved, decision, resolved_at, consumed_at, resolved_via, resolved_from FROM approvals`)
	if err != nil {
		return nil, fmt.Errorf("store: load approvals: %w", err)
	}
	defer rows.Close()

	var out []ApprovalRecord
	for rows.Next() {
		var (
			r                                 ApprovalRecord
			reqJSON, resJSON                  string
			createdAt, resolvedAt, consumedAt string
			resolvedInt                       int
		)
		if err := rows.Scan(&r.TenantID, &r.ID, &reqJSON, &resJSON, &createdAt, &resolvedInt, &r.Decision, &resolvedAt, &consumedAt, &r.ResolvedVia, &r.ResolvedFrom); err != nil {
			return out, fmt.Errorf("store: scan approval: %w", err)
		}
		if err := json.Unmarshal([]byte(reqJSON), &r.Request); err != nil {
			return out, fmt.Errorf("store: unmarshal approval request %q: %w", r.ID, err)
		}
		if err := json.Unmarshal([]byte(resJSON), &r.Result); err != nil {
			return out, fmt.Errorf("store: unmarshal approval result %q: %w", r.ID, err)
		}
		r.CreatedAt = parseTime(createdAt)
		r.ResolvedAt = parseTime(resolvedAt)
		r.ConsumedAt = parseTime(consumedAt)
		r.Resolved = resolvedInt != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) PurgeResolvedApprovals(ctx context.Context, cutoff time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM approvals WHERE resolved = 1 AND resolved_at != '' AND resolved_at < ?`,
		fmtTime(cutoff))
	if err != nil {
		return 0, fmt.Errorf("store: purge approvals: %w", err)
	}
	return rowsAffected(res), nil
}

// --- rate buckets ---

func (s *SQLiteStore) UpsertBuckets(ctx context.Context, buckets []BucketState) error {
	if len(buckets) == 0 {
		return nil
	}
	for i := range buckets {
		if buckets[i].TenantID == "" {
			return ErrTenantRequired
		}
	}
	return s.inTx(ctx, func(tx *sql.Tx) error {
		stmt, err := tx.PrepareContext(ctx, `
			INSERT INTO rate_buckets (tenant_id, key, tokens, max_tokens, window_ns, last_refill)
			VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT(tenant_id, key) DO UPDATE SET
				tokens=excluded.tokens, max_tokens=excluded.max_tokens,
				window_ns=excluded.window_ns, last_refill=excluded.last_refill`)
		if err != nil {
			return err
		}
		defer func() { _ = stmt.Close() }()
		for _, b := range buckets {
			if _, err := stmt.ExecContext(ctx,
				b.TenantID, b.Key, b.Tokens, b.Max, int64(b.Window), fmtTime(b.LastRefill),
			); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *SQLiteStore) LoadBuckets(ctx context.Context) ([]BucketState, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT tenant_id, key, tokens, max_tokens, window_ns, last_refill FROM rate_buckets`)
	if err != nil {
		return nil, fmt.Errorf("store: load buckets: %w", err)
	}
	defer rows.Close()

	var out []BucketState
	for rows.Next() {
		var (
			b        BucketState
			windowNs int64
			refill   string
		)
		if err := rows.Scan(&b.TenantID, &b.Key, &b.Tokens, &b.Max, &windowNs, &refill); err != nil {
			return out, fmt.Errorf("store: scan bucket: %w", err)
		}
		b.Window = time.Duration(windowNs)
		b.LastRefill = parseTime(refill)
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) PurgeBuckets(ctx context.Context, cutoff time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM rate_buckets WHERE last_refill != '' AND last_refill < ?`, fmtTime(cutoff))
	if err != nil {
		return 0, fmt.Errorf("store: purge buckets: %w", err)
	}
	return rowsAffected(res), nil
}

// --- session costs ---

func (s *SQLiteStore) UpsertCosts(ctx context.Context, costs []CostState) error {
	if len(costs) == 0 {
		return nil
	}
	for i := range costs {
		if costs[i].TenantID == "" {
			return ErrTenantRequired
		}
	}
	return s.inTx(ctx, func(tx *sql.Tx) error {
		stmt, err := tx.PrepareContext(ctx, `
			INSERT INTO session_costs (tenant_id, session_id, cost, last_updated)
			VALUES (?, ?, ?, ?)
			ON CONFLICT(tenant_id, session_id) DO UPDATE SET
				cost=excluded.cost, last_updated=excluded.last_updated`)
		if err != nil {
			return err
		}
		defer func() { _ = stmt.Close() }()
		for _, c := range costs {
			if _, err := stmt.ExecContext(ctx,
				c.TenantID, c.SessionID, c.Cost, fmtTime(c.LastUpdated),
			); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *SQLiteStore) LoadCosts(ctx context.Context) ([]CostState, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT tenant_id, session_id, cost, last_updated FROM session_costs`)
	if err != nil {
		return nil, fmt.Errorf("store: load costs: %w", err)
	}
	defer rows.Close()

	var out []CostState
	for rows.Next() {
		var (
			c       CostState
			updated string
		)
		if err := rows.Scan(&c.TenantID, &c.SessionID, &c.Cost, &updated); err != nil {
			return out, fmt.Errorf("store: scan cost: %w", err)
		}
		c.LastUpdated = parseTime(updated)
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) PurgeCosts(ctx context.Context, cutoff time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM session_costs WHERE last_updated != '' AND last_updated < ?`, fmtTime(cutoff))
	if err != nil {
		return 0, fmt.Errorf("store: purge costs: %w", err)
	}
	return rowsAffected(res), nil
}

// --- audit ---

func (s *SQLiteStore) AppendAudit(ctx context.Context, entries []audit.Entry) error {
	if len(entries) == 0 {
		return nil
	}
	return s.inTx(ctx, func(tx *sql.Tx) error {
		stmt, err := tx.PrepareContext(ctx, `
			INSERT INTO audit_entries
			    (tenant_id, timestamp, session_id, agent_id, scope, action, command, path, domain, url, decision, reason, rule, duration_ms, transport)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		defer func() { _ = stmt.Close() }()
		for _, e := range entries {
			ts := e.Timestamp
			if ts.IsZero() {
				ts = time.Now().UTC()
			}
			if _, err := stmt.ExecContext(ctx,
				e.EffectiveTenant(), ts.UTC().Format(time.RFC3339Nano),
				e.SessionID, e.AgentID, e.Request.Scope, e.Request.Action, e.Request.Command,
				e.Request.Path, e.Request.Domain, e.Request.URL,
				string(e.Result.Decision), e.Result.Reason, e.Result.Rule, e.DurationMs, e.EffectiveTransport(),
			); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *SQLiteStore) QueryAudit(ctx context.Context, tenantID string, filter audit.QueryFilter) ([]audit.Entry, error) {
	var conds []string
	var args []any

	// tenantID param wins; fall back to the filter's own TenantID. Empty means
	// "all tenants" (operator/global path) — the proxy always passes a concrete
	// tenant, so a request-driven query is never unscoped.
	t := tenantID
	if t == "" {
		t = filter.TenantID
	}
	if t != "" {
		conds = append(conds, "tenant_id = ?")
		args = append(args, EffectiveTenant(t))
	}
	if filter.AgentID != "" {
		conds = append(conds, "agent_id = ?")
		args = append(args, filter.AgentID)
	}
	if filter.SessionID != "" {
		conds = append(conds, "session_id = ?")
		args = append(args, filter.SessionID)
	}
	if filter.Decision != "" {
		conds = append(conds, "decision = ?")
		args = append(args, filter.Decision)
	}
	if filter.Scope != "" {
		conds = append(conds, "scope = ?")
		args = append(args, filter.Scope)
	}
	if filter.Transport != "" {
		conds = append(conds, "transport = ?")
		args = append(args, filter.Transport)
	}
	if filter.Since != nil {
		conds = append(conds, "timestamp >= ?")
		args = append(args, filter.Since.UTC().Format(time.RFC3339Nano))
	}

	q := `SELECT tenant_id, timestamp, session_id, agent_id, scope, action, command, path, domain, url, decision, reason, rule, duration_ms, transport FROM audit_entries`
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	q += " ORDER BY id ASC"
	if filter.Limit > 0 {
		q += " LIMIT ?"
		args = append(args, filter.Limit)
		if filter.Offset > 0 {
			q += " OFFSET ?"
			args = append(args, filter.Offset)
		}
	} else if filter.Offset > 0 {
		q += " LIMIT -1 OFFSET ?"
		args = append(args, filter.Offset)
	}

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: query audit: %w", err)
	}
	defer rows.Close()

	var out []audit.Entry
	for rows.Next() {
		var (
			e        audit.Entry
			tsStr    string
			decision string
		)
		if err := rows.Scan(
			&e.TenantID, &tsStr, &e.SessionID, &e.AgentID, &e.Request.Scope, &e.Request.Action,
			&e.Request.Command, &e.Request.Path, &e.Request.Domain, &e.Request.URL,
			&decision, &e.Result.Reason, &e.Result.Rule, &e.DurationMs, &e.Transport,
		); err != nil {
			return out, fmt.Errorf("store: scan audit: %w", err)
		}
		e.Timestamp = parseTime(tsStr)
		e.Result.Decision = policy.Decision(decision)
		out = append(out, e)
	}
	return out, rows.Err()
}

// --- helpers ---

// inTx runs fn inside a transaction, committing on success and rolling back on
// error. Batching the write-behind upserts in one transaction keeps the flush
// to a single fsync under WAL.
func (s *SQLiteStore) inTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin tx: %w", err)
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func rowsAffected(res sql.Result) int {
	n, err := res.RowsAffected()
	if err != nil {
		return 0
	}
	return int(n)
}

// --- multi-node reconciliation (v1.0) ---
//
// RateConsumption and CostConsumption back multi-node rate-limit / session-cost
// reconciliation. They are DELIBERATELY NOT part of the exported store.Store
// interface (CLAUDE.md §4 v1.0 lock: store.Store gains no methods). The concrete
// *SQLiteStore and *PostgresStore carry the six Upsert/Load/Purge methods, and
// pkg/persist reaches them through an unexported capability interface (mirroring
// cmd/agentguard's persistentStore pattern). Everything here is cold-path,
// written and read only by the background reconcile syncer.

// RateConsumption is one node's ABSOLUTE cumulative consumption of a rate-limit
// bucket within a fixed window (epoch). Rows are summed per (tenant, key, epoch)
// across nodes to derive cluster-wide consumption; each node upserts only its own
// (…, node_id) row, so writes are idempotent last-writer-wins with no
// read-modify-write race. The tenant_id is part of the PK (zero-trust §3).
type RateConsumption struct {
	TenantID    string
	Key         string
	WindowEpoch time.Time
	NodeID      string
	Consumed    int
	UpdatedAt   time.Time
}

// CostConsumption is one node's ABSOLUTE cumulative cost reservation for a
// (tenant, session). Session cost is monotonic within a session, so no window is
// needed. tenant_id is part of the PK (zero-trust §3).
type CostConsumption struct {
	TenantID  string
	SessionID string
	NodeID    string
	Consumed  float64
	UpdatedAt time.Time
}

func (s *SQLiteStore) UpsertRateConsumption(ctx context.Context, rows []RateConsumption) error {
	if len(rows) == 0 {
		return nil
	}
	for i := range rows {
		if rows[i].TenantID == "" {
			return ErrTenantRequired
		}
	}
	return s.inTx(ctx, func(tx *sql.Tx) error {
		stmt, err := tx.PrepareContext(ctx, `
			INSERT INTO rate_consumption (tenant_id, key, window_epoch, node_id, consumed, updated_at)
			VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT(tenant_id, key, window_epoch, node_id) DO UPDATE SET
				consumed=excluded.consumed, updated_at=excluded.updated_at`)
		if err != nil {
			return err
		}
		defer func() { _ = stmt.Close() }()
		for _, r := range rows {
			if _, err := stmt.ExecContext(ctx,
				r.TenantID, r.Key, fmtTime(r.WindowEpoch), r.NodeID, r.Consumed, fmtTime(r.UpdatedAt),
			); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *SQLiteStore) LoadRateConsumption(ctx context.Context) ([]RateConsumption, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT tenant_id, key, window_epoch, node_id, consumed, updated_at FROM rate_consumption`)
	if err != nil {
		return nil, fmt.Errorf("store: load rate_consumption: %w", err)
	}
	defer rows.Close()

	var out []RateConsumption
	for rows.Next() {
		var (
			r              RateConsumption
			epoch, updated string
		)
		if err := rows.Scan(&r.TenantID, &r.Key, &epoch, &r.NodeID, &r.Consumed, &updated); err != nil {
			return out, fmt.Errorf("store: scan rate_consumption: %w", err)
		}
		r.WindowEpoch = parseTime(epoch)
		r.UpdatedAt = parseTime(updated)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) PurgeRateConsumption(ctx context.Context, cutoff time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM rate_consumption WHERE updated_at != '' AND updated_at < ?`, fmtTime(cutoff))
	if err != nil {
		return 0, fmt.Errorf("store: purge rate_consumption: %w", err)
	}
	return rowsAffected(res), nil
}

func (s *SQLiteStore) UpsertCostConsumption(ctx context.Context, rows []CostConsumption) error {
	if len(rows) == 0 {
		return nil
	}
	for i := range rows {
		if rows[i].TenantID == "" {
			return ErrTenantRequired
		}
	}
	return s.inTx(ctx, func(tx *sql.Tx) error {
		stmt, err := tx.PrepareContext(ctx, `
			INSERT INTO cost_consumption (tenant_id, session_id, node_id, consumed, updated_at)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(tenant_id, session_id, node_id) DO UPDATE SET
				consumed=excluded.consumed, updated_at=excluded.updated_at`)
		if err != nil {
			return err
		}
		defer func() { _ = stmt.Close() }()
		for _, r := range rows {
			if _, err := stmt.ExecContext(ctx,
				r.TenantID, r.SessionID, r.NodeID, r.Consumed, fmtTime(r.UpdatedAt),
			); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *SQLiteStore) LoadCostConsumption(ctx context.Context) ([]CostConsumption, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT tenant_id, session_id, node_id, consumed, updated_at FROM cost_consumption`)
	if err != nil {
		return nil, fmt.Errorf("store: load cost_consumption: %w", err)
	}
	defer rows.Close()

	var out []CostConsumption
	for rows.Next() {
		var (
			r       CostConsumption
			updated string
		)
		if err := rows.Scan(&r.TenantID, &r.SessionID, &r.NodeID, &r.Consumed, &updated); err != nil {
			return out, fmt.Errorf("store: scan cost_consumption: %w", err)
		}
		r.UpdatedAt = parseTime(updated)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) PurgeCostConsumption(ctx context.Context, cutoff time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM cost_consumption WHERE updated_at != '' AND updated_at < ?`, fmtTime(cutoff))
	if err != nil {
		return 0, fmt.Errorf("store: purge cost_consumption: %w", err)
	}
	return rowsAffected(res), nil
}

// Verify SQLiteStore satisfies the full Store interface at compile time.
var _ Store = (*SQLiteStore)(nil)
