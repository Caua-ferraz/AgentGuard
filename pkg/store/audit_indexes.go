package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"
)

// auditIndex is an index on audit_entries added after the table first
// shipped. On an existing database it is built over every row already
// there, and audit_entries has no retention, so the build can take a
// while; it therefore runs outside the bounded boot migration (see
// SQLiteStore.buildAuditIndexes and PostgresStore.buildAuditIndexes).
type auditIndex struct {
	name    string
	columns string
}

// auditSessionIndexes serve the session queries (v1.4): one session's
// entries, and the sessions started by a parent. Every query works without
// them, only slower.
var auditSessionIndexes = []auditIndex{
	{name: "idx_audit_tenant_session", columns: "tenant_id, session_id"},
	{name: "idx_audit_tenant_parent", columns: "tenant_id, parent_session_id"},
}

// pgIndexLockKey namespaces the session-level advisory lock one replica
// holds while it builds the audit indexes, so replicas starting together
// don't build the same index twice. Must stay stable, like
// pgMigrateLockKey. "AG_IDX" in ASCII.
const pgIndexLockKey int64 = 0x41475F494458

// buildAuditIndexes creates the missing audit indexes. It runs at the end
// of Migrate with no deadline: the database has answered by then, so a
// large audit table makes the first start of a new version slow, which is
// logged, rather than failing it on the 30 s reachability timeout.
func (s *SQLiteStore) buildAuditIndexes(ctx context.Context) error {
	for _, ix := range auditSessionIndexes {
		var n int
		if err := s.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?`, ix.name).Scan(&n); err != nil {
			return fmt.Errorf("store: migrate (index %s): %w", ix.name, err)
		}
		if n > 0 {
			continue
		}
		// MAX(id) is instant and close enough to a row count for a log line.
		var rows int64
		_ = s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(id), 0) FROM audit_entries`).Scan(&rows)
		if rows > 0 {
			log.Printf("store: building index %s on audit_entries (about %d rows); this runs once and can take a while on a large audit table", ix.name, rows)
		}
		start := time.Now()
		if _, err := s.db.ExecContext(ctx,
			"CREATE INDEX IF NOT EXISTS "+ix.name+" ON audit_entries("+ix.columns+")"); err != nil {
			return fmt.Errorf("store: migrate (index %s): %w", ix.name, err)
		}
		if rows > 0 {
			log.Printf("store: built index %s in %s", ix.name, time.Since(start).Round(time.Millisecond))
		}
	}
	return nil
}

// startAuditIndexBuild builds the missing audit indexes in the background,
// after the boot migration has committed. Inside the migration transaction
// the build held ACCESS EXCLUSIVE on audit_entries for its whole length and
// could run past the boot timeout, which rolled the migration back and
// crash-looped the node. Close stops it.
func (s *PostgresStore) startAuditIndexBuild() {
	ctx, cancel := context.WithCancel(context.Background())
	s.stopIndexes = cancel
	s.indexesDone = make(chan struct{})
	go func() {
		defer close(s.indexesDone)
		if err := s.buildAuditIndexes(ctx); err != nil && ctx.Err() == nil {
			log.Printf("WARN store: audit index build failed; session and audit queries still work, slower, and the build is retried on the next start: %v", err)
		}
	}()
}

// buildAuditIndexes creates the missing audit indexes with CREATE INDEX
// CONCURRENTLY, which doesn't block writes. It needs a connection outside
// any transaction.
//
// One replica builds at a time: the first to take pgIndexLockKey builds,
// the others skip (the indexes are checked again on their next start).
// They don't wait for the lock, because a concurrent build waits for every
// transaction with an older snapshot, and a statement blocked on the lock
// would be one of them.
//
// An interrupted concurrent build leaves an INVALID index behind, which IF
// NOT EXISTS would keep forever; one is dropped and built again.
func (s *PostgresStore) buildAuditIndexes(ctx context.Context) error {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	var locked bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, pgIndexLockKey).Scan(&locked); err != nil {
		return fmt.Errorf("take the index-build lock: %w", err)
	}
	if !locked {
		log.Printf("store: another replica is building the audit indexes; skipping")
		return nil
	}
	defer func() {
		_, _ = conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, pgIndexLockKey)
	}()

	for _, ix := range auditSessionIndexes {
		var valid bool
		err := conn.QueryRowContext(ctx,
			`SELECT indisvalid FROM pg_index WHERE indexrelid = to_regclass($1::text)`, ix.name).Scan(&valid)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			// Not there yet.
		case err != nil:
			return fmt.Errorf("check index %s: %w", ix.name, err)
		case valid:
			continue
		default:
			log.Printf("store: index %s was left invalid by an interrupted build; dropping it to build it again", ix.name)
			if _, err := conn.ExecContext(ctx, "DROP INDEX CONCURRENTLY IF EXISTS "+ix.name); err != nil {
				return fmt.Errorf("drop invalid index %s: %w", ix.name, err)
			}
		}
		var rows float64
		_ = conn.QueryRowContext(ctx,
			`SELECT GREATEST(reltuples, 0) FROM pg_class WHERE oid = to_regclass('audit_entries')`).Scan(&rows)
		log.Printf("store: building index %s on audit_entries (about %.0f rows) in the background; audit queries work meanwhile, slower", ix.name, rows)
		start := time.Now()
		if _, err := conn.ExecContext(ctx,
			"CREATE INDEX CONCURRENTLY IF NOT EXISTS "+ix.name+" ON audit_entries ("+ix.columns+")"); err != nil {
			return fmt.Errorf("build index %s: %w", ix.name, err)
		}
		log.Printf("store: built index %s in %s", ix.name, time.Since(start).Round(time.Millisecond))
	}
	return nil
}
