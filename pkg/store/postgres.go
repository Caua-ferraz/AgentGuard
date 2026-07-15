package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // pure-Go Postgres driver, registered under the name "pgx"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// PostgresStore is the multi-node Store backend (docs/v0.6-ARCHITECTURE-PLAN.md
// §2.4 forward-looks to this for the "validated v1.0" Postgres/multi-node
// target). It mirrors SQLiteStore column-for-column and semantics-for-semantics,
// adapting only the SQL dialect (positional $N placeholders, native types,
// BIGSERIAL audit id). Times are stored as RFC3339Nano TEXT and integers/bools
// via the same helpers SQLiteStore uses, so a row round-trips identically across
// the two backends and the Purge* string comparisons behave the same.
//
// Concurrency: unlike SQLiteStore (single-file writer pinned to one conn),
// Postgres handles concurrent sessions, so a small pool is used. This is still
// a COLD-PATH component — the streaming proxy /v1/check path NEVER touches a
// Store (CLAUDE.md §1/§2); PostgresStore is reached only by the write-behind
// syncer, boot hydration, GC, and operator audit queries.
type PostgresStore struct {
	db  *sql.DB
	dsn string
}

// Cold-path pool sizing. Small, bounded, and recycled — the syncer batches its
// flushes and audit queries are infrequent, so a large pool would be wasted
// connections against the Postgres server. None of this is on the hot path.
const (
	pgMaxOpenConns    = 8
	pgMaxIdleConns    = 4
	pgConnMaxIdleTime = 5 * time.Minute
	pgConnMaxLifetime = time.Hour
)

// NewPostgresStore opens the Postgres database identified by dsn (a
// "postgres://" / "postgresql://" URL or a libpq keyword/value string), sets a
// modest cold-path connection pool, and runs the schema migration. Connectivity
// is verified lazily by Migrate's first round-trip, mirroring how
// NewSQLiteStore surfaces open errors through Migrate.
func NewPostgresStore(dsn string) (*PostgresStore, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open postgres: %w", err)
	}
	db.SetMaxOpenConns(pgMaxOpenConns)
	db.SetMaxIdleConns(pgMaxIdleConns)
	db.SetConnMaxIdleTime(pgConnMaxIdleTime)
	db.SetConnMaxLifetime(pgConnMaxLifetime)

	s := &PostgresStore{db: db, dsn: dsn}
	if err := s.Migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// DSN returns the connection string (for logging / health). Mirrors
// SQLiteStore.Path().
func (s *PostgresStore) DSN() string { return s.dsn }

// pgSchemaStmts is the Postgres schema, mirroring SQLiteStore's schemaSQL table
// by table. Kept as individual statements (rather than one multi-statement
// string) because the pgx stdlib driver runs queries through the extended
// protocol, which permits only one statement per Exec. Every statement is
// IF NOT EXISTS, so Migrate stays idempotent and safe on every boot.
//
// Dialect deltas vs. SQLite: window_ns / duration_ms are BIGINT (they hold
// int64 nanoseconds / millis that overflow a 32-bit INTEGER); cost is DOUBLE
// PRECISION (SQLite REAL is 8-byte float); the audit surrogate key is BIGSERIAL
// (SQLite INTEGER PRIMARY KEY AUTOINCREMENT), which is likewise monotonic so
// the "ORDER BY id ASC" insertion order in QueryAudit is preserved.
var pgSchemaStmts = []string{
	`CREATE TABLE IF NOT EXISTS approvals (
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
	)`,
	`CREATE INDEX IF NOT EXISTS idx_approvals_resolved ON approvals(resolved, resolved_at)`,
	// approvals one-shot/actor columns (post-v0.9.0 approval hardening) for
	// DBs whose approvals table predates them; Postgres has native
	// IF NOT EXISTS so no duplicate-column dance is needed (mirror of
	// SQLiteStore.Migrate's guarded ALTERs).
	`ALTER TABLE approvals ADD COLUMN IF NOT EXISTS consumed_at   TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE approvals ADD COLUMN IF NOT EXISTS resolved_via  TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE approvals ADD COLUMN IF NOT EXISTS resolved_from TEXT NOT NULL DEFAULT ''`,

	`CREATE TABLE IF NOT EXISTS rate_buckets (
	    tenant_id   TEXT    NOT NULL,
	    key         TEXT    NOT NULL,
	    tokens      INTEGER NOT NULL,
	    max_tokens  INTEGER NOT NULL,
	    window_ns   BIGINT  NOT NULL,
	    last_refill TEXT    NOT NULL,
	    PRIMARY KEY (tenant_id, key)
	)`,
	`CREATE INDEX IF NOT EXISTS idx_buckets_refill ON rate_buckets(last_refill)`,

	`CREATE TABLE IF NOT EXISTS session_costs (
	    tenant_id    TEXT             NOT NULL,
	    session_id   TEXT             NOT NULL,
	    cost         DOUBLE PRECISION NOT NULL,
	    last_updated TEXT             NOT NULL,
	    PRIMARY KEY (tenant_id, session_id)
	)`,
	`CREATE INDEX IF NOT EXISTS idx_costs_updated ON session_costs(last_updated)`,

	`CREATE TABLE IF NOT EXISTS audit_entries (
	    id          BIGSERIAL PRIMARY KEY,
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
	    duration_ms BIGINT  NOT NULL DEFAULT 0,
	    transport   TEXT    NOT NULL DEFAULT ''
	)`,
	`CREATE INDEX IF NOT EXISTS idx_audit_tenant_ts ON audit_entries(tenant_id, timestamp)`,
	`CREATE INDEX IF NOT EXISTS idx_audit_agent     ON audit_entries(agent_id)`,
	`CREATE INDEX IF NOT EXISTS idx_audit_decision  ON audit_entries(decision)`,
	`CREATE INDEX IF NOT EXISTS idx_audit_scope     ON audit_entries(scope)`,

	`CREATE TABLE IF NOT EXISTS policies (
	    tenant_id   TEXT NOT NULL PRIMARY KEY,
	    policy_yaml TEXT NOT NULL,
	    updated_at  TEXT NOT NULL
	)`,

	`CREATE TABLE IF NOT EXISTS rate_consumption (
	    tenant_id    TEXT    NOT NULL,
	    key          TEXT    NOT NULL,
	    window_epoch TEXT    NOT NULL,
	    node_id      TEXT    NOT NULL,
	    consumed     BIGINT  NOT NULL,
	    updated_at   TEXT    NOT NULL,
	    PRIMARY KEY (tenant_id, key, window_epoch, node_id)
	)`,
	`CREATE INDEX IF NOT EXISTS idx_rate_consumption_updated ON rate_consumption(updated_at)`,

	`CREATE TABLE IF NOT EXISTS cost_consumption (
	    tenant_id  TEXT             NOT NULL,
	    session_id TEXT             NOT NULL,
	    node_id    TEXT             NOT NULL,
	    consumed   DOUBLE PRECISION NOT NULL,
	    updated_at TEXT             NOT NULL,
	    PRIMARY KEY (tenant_id, session_id, node_id)
	)`,
	`CREATE INDEX IF NOT EXISTS idx_cost_consumption_updated ON cost_consumption(updated_at)`,
}

// Migrate creates the schema. Idempotent (every statement is IF NOT EXISTS), so
// it is safe to run on every boot. Runs inside one transaction so a partial
// failure leaves the schema untouched.
func (s *PostgresStore) Migrate(ctx context.Context) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		for _, stmt := range pgSchemaStmts {
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("store: migrate: %w", err)
			}
		}
		return nil
	})
}

// Ping verifies connectivity.
func (s *PostgresStore) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

// Close closes the database. Idempotent at the sql.DB layer.
func (s *PostgresStore) Close() error { return s.db.Close() }

// --- approvals ---

func (s *PostgresStore) UpsertApprovals(ctx context.Context, recs []ApprovalRecord) error {
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
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
			ON CONFLICT (tenant_id, id) DO UPDATE SET
				request=excluded.request, result=excluded.result,
				resolved=excluded.resolved, decision=excluded.decision,
				resolved_at=excluded.resolved_at,
				consumed_at=CASE WHEN approvals.consumed_at <> '' THEN approvals.consumed_at ELSE excluded.consumed_at END,
				resolved_via=excluded.resolved_via, resolved_from=excluded.resolved_from
			WHERE NOT (approvals.resolved <> 0 AND excluded.resolved = 0)
			  AND NOT (approvals.resolved <> 0 AND approvals.decision = 'DENY' AND excluded.decision <> 'DENY')`)
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

func (s *PostgresStore) LoadApprovals(ctx context.Context) ([]ApprovalRecord, error) {
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

func (s *PostgresStore) PurgeResolvedApprovals(ctx context.Context, cutoff time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM approvals WHERE resolved = 1 AND resolved_at <> '' AND resolved_at < $1`,
		fmtTime(cutoff))
	if err != nil {
		return 0, fmt.Errorf("store: purge approvals: %w", err)
	}
	return rowsAffected(res), nil
}

// --- rate buckets ---

func (s *PostgresStore) UpsertBuckets(ctx context.Context, buckets []BucketState) error {
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
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (tenant_id, key) DO UPDATE SET
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

func (s *PostgresStore) LoadBuckets(ctx context.Context) ([]BucketState, error) {
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

func (s *PostgresStore) PurgeBuckets(ctx context.Context, cutoff time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM rate_buckets WHERE last_refill <> '' AND last_refill < $1`, fmtTime(cutoff))
	if err != nil {
		return 0, fmt.Errorf("store: purge buckets: %w", err)
	}
	return rowsAffected(res), nil
}

// --- session costs ---

func (s *PostgresStore) UpsertCosts(ctx context.Context, costs []CostState) error {
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
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (tenant_id, session_id) DO UPDATE SET
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

func (s *PostgresStore) LoadCosts(ctx context.Context) ([]CostState, error) {
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

func (s *PostgresStore) PurgeCosts(ctx context.Context, cutoff time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM session_costs WHERE last_updated <> '' AND last_updated < $1`, fmtTime(cutoff))
	if err != nil {
		return 0, fmt.Errorf("store: purge costs: %w", err)
	}
	return rowsAffected(res), nil
}

// --- audit ---

func (s *PostgresStore) AppendAudit(ctx context.Context, entries []audit.Entry) error {
	if len(entries) == 0 {
		return nil
	}
	return s.inTx(ctx, func(tx *sql.Tx) error {
		stmt, err := tx.PrepareContext(ctx, `
			INSERT INTO audit_entries
			    (tenant_id, timestamp, session_id, agent_id, scope, action, command, path, domain, url, decision, reason, rule, duration_ms, transport)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`)
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

func (s *PostgresStore) QueryAudit(ctx context.Context, tenantID string, filter audit.QueryFilter) ([]audit.Entry, error) {
	var conds []string
	var args []any
	// nextPlaceholder returns the positional placeholder for the arg that is
	// about to be appended (Postgres uses $1, $2, … rather than SQLite's ?).
	nextPlaceholder := func() string { return "$" + strconv.Itoa(len(args)+1) }

	// tenantID param wins; fall back to the filter's own TenantID. Empty means
	// "all tenants" (operator/global path) — the proxy always passes a concrete
	// tenant, so a request-driven query is never unscoped.
	t := tenantID
	if t == "" {
		t = filter.TenantID
	}
	if t != "" {
		conds = append(conds, "tenant_id = "+nextPlaceholder())
		args = append(args, EffectiveTenant(t))
	}
	if filter.AgentID != "" {
		conds = append(conds, "agent_id = "+nextPlaceholder())
		args = append(args, filter.AgentID)
	}
	if filter.SessionID != "" {
		conds = append(conds, "session_id = "+nextPlaceholder())
		args = append(args, filter.SessionID)
	}
	if filter.Decision != "" {
		conds = append(conds, "decision = "+nextPlaceholder())
		args = append(args, filter.Decision)
	}
	if filter.Scope != "" {
		conds = append(conds, "scope = "+nextPlaceholder())
		args = append(args, filter.Scope)
	}
	if filter.Transport != "" {
		conds = append(conds, "transport = "+nextPlaceholder())
		args = append(args, filter.Transport)
	}
	if filter.Since != nil {
		conds = append(conds, "timestamp >= "+nextPlaceholder())
		args = append(args, filter.Since.UTC().Format(time.RFC3339Nano))
	}

	q := `SELECT tenant_id, timestamp, session_id, agent_id, scope, action, command, path, domain, url, decision, reason, rule, duration_ms, transport FROM audit_entries`
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	q += " ORDER BY id ASC"
	// LIMIT/OFFSET: mirror SQLiteStore's semantics. SQLite spells "offset with no
	// limit" as "LIMIT -1 OFFSET n"; Postgres expresses the same as a bare
	// "OFFSET n".
	if filter.Limit > 0 {
		q += " LIMIT " + nextPlaceholder()
		args = append(args, filter.Limit)
		if filter.Offset > 0 {
			q += " OFFSET " + nextPlaceholder()
			args = append(args, filter.Offset)
		}
	} else if filter.Offset > 0 {
		q += " OFFSET " + nextPlaceholder()
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

// --- tenant policies (mirrors pkg/store/policy.go for SQLiteStore) ---

// PutPolicy stores (or replaces) the policy document for a tenant. The bytes
// are stored verbatim; validation is the caller's responsibility (the CLI and
// MultiTenantProvider validate before/after). Rejects an empty tenant.
func (s *PostgresStore) PutPolicy(ctx context.Context, tenantID string, policyYAML []byte) error {
	if tenantID == "" {
		return ErrTenantRequired
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO policies (tenant_id, policy_yaml, updated_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (tenant_id) DO UPDATE SET
			policy_yaml=excluded.policy_yaml, updated_at=excluded.updated_at`,
		tenantID, string(policyYAML), fmtTime(time.Now().UTC()))
	if err != nil {
		return fmt.Errorf("store: put policy %q: %w", tenantID, err)
	}
	return nil
}

// GetPolicyYAML returns the stored policy document for a tenant. ok=false when
// the tenant has no policy row (distinct from an error).
func (s *PostgresStore) GetPolicyYAML(ctx context.Context, tenantID string) ([]byte, bool, error) {
	if tenantID == "" {
		return nil, false, ErrTenantRequired
	}
	var y string
	err := s.db.QueryRowContext(ctx, `SELECT policy_yaml FROM policies WHERE tenant_id = $1`, tenantID).Scan(&y)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("store: get policy %q: %w", tenantID, err)
	}
	return []byte(y), true, nil
}

// ListPolicyTenants returns every tenant id that has a stored policy, sorted.
// Used by MultiTenantProvider to eager-load all tenants on boot.
func (s *PostgresStore) ListPolicyTenants(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT tenant_id FROM policies ORDER BY tenant_id`)
	if err != nil {
		return nil, fmt.Errorf("store: list policy tenants: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return out, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeletePolicy removes a tenant's policy. ok reports whether a row existed.
func (s *PostgresStore) DeletePolicy(ctx context.Context, tenantID string) (bool, error) {
	if tenantID == "" {
		return false, ErrTenantRequired
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM policies WHERE tenant_id = $1`, tenantID)
	if err != nil {
		return false, fmt.Errorf("store: delete policy %q: %w", tenantID, err)
	}
	return rowsAffected(res) > 0, nil
}

// --- helpers ---

// inTx runs fn inside a transaction, committing on success and rolling back on
// error. Mirrors SQLiteStore.inTx: batching the write-behind upserts in one
// transaction keeps each flush to a single commit.
func (s *PostgresStore) inTx(ctx context.Context, fn func(*sql.Tx) error) error {
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

// --- multi-node reconciliation (v1.0) ---
//
// Mirrors the *SQLiteStore consumption methods column-for-column and
// semantics-for-semantics (see the RateConsumption/CostConsumption doc in
// sqlite.go). Dialect deltas: positional $N placeholders; rate consumed is
// BIGINT (scanned through an int64 intermediate). NOT part of store.Store — the
// reconcile syncer reaches these via pkg/persist's capability interface.

func (s *PostgresStore) UpsertRateConsumption(ctx context.Context, rows []RateConsumption) error {
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
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (tenant_id, key, window_epoch, node_id) DO UPDATE SET
				consumed=excluded.consumed, updated_at=excluded.updated_at`)
		if err != nil {
			return err
		}
		defer func() { _ = stmt.Close() }()
		for _, r := range rows {
			if _, err := stmt.ExecContext(ctx,
				r.TenantID, r.Key, fmtTime(r.WindowEpoch), r.NodeID, int64(r.Consumed), fmtTime(r.UpdatedAt),
			); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *PostgresStore) LoadRateConsumption(ctx context.Context) ([]RateConsumption, error) {
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
			consumed       int64
		)
		if err := rows.Scan(&r.TenantID, &r.Key, &epoch, &r.NodeID, &consumed, &updated); err != nil {
			return out, fmt.Errorf("store: scan rate_consumption: %w", err)
		}
		r.Consumed = int(consumed)
		r.WindowEpoch = parseTime(epoch)
		r.UpdatedAt = parseTime(updated)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *PostgresStore) PurgeRateConsumption(ctx context.Context, cutoff time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM rate_consumption WHERE updated_at <> '' AND updated_at < $1`, fmtTime(cutoff))
	if err != nil {
		return 0, fmt.Errorf("store: purge rate_consumption: %w", err)
	}
	return rowsAffected(res), nil
}

func (s *PostgresStore) UpsertCostConsumption(ctx context.Context, rows []CostConsumption) error {
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
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (tenant_id, session_id, node_id) DO UPDATE SET
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

func (s *PostgresStore) LoadCostConsumption(ctx context.Context) ([]CostConsumption, error) {
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

func (s *PostgresStore) PurgeCostConsumption(ctx context.Context, cutoff time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM cost_consumption WHERE updated_at <> '' AND updated_at < $1`, fmtTime(cutoff))
	if err != nil {
		return 0, fmt.Errorf("store: purge cost_consumption: %w", err)
	}
	return rowsAffected(res), nil
}

// Verify PostgresStore satisfies the full Store interface at compile time.
var _ Store = (*PostgresStore)(nil)
