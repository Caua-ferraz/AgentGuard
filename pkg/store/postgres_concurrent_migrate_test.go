package store

// Cold-start migration contract for the multi-node backend.
//
// The defect these tests pin: replicas that boot together each ran the schema
// DDL in their own transaction with no mutual exclusion, so a losing node
// failed its constructor and exited at boot.
//
// Two distinct failures, both reproduced here:
//
//   - Empty database: `CREATE TABLE IF NOT EXISTS` is not atomic against a
//     concurrent creator, so nodes collide on the pg_type unique index
//     (SQLSTATE 23505). Measured on 5 of 6 three-replica cold starts.
//   - Existing schema: the `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`
//     statements still take ACCESS EXCLUSIVE locks even when the columns are
//     already there, so concurrent migrations deadlock (SQLSTATE 40P01) —
//     6 of 8 replicas in the test below. This makes it a rolling-restart
//     defect too, not only a first-deploy one.
//
// A single node was never affected either way, which is what identifies this
// as a race rather than a schema fault.
//
// The pre-existing TestPostgresStore_MigrateIdempotent could not catch this:
// it re-migrates SEQUENTIALLY on an already-created schema, so no two
// statements ever contend. These tests boot N stores simultaneously from a
// dropped schema, which is the state a fresh deployment is actually in.

import (
	"context"
	"database/sql"
	"os"
	"sync"
	"testing"
	"time"
)

// pgDSNOrSkip returns AGENTGUARD_PG_DSN, skipping when unset so
// `go test ./...` stays deterministic without a Postgres available. CI's
// postgres-integration job sets it.
func pgDSNOrSkip(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("AGENTGUARD_PG_DSN")
	if dsn == "" {
		t.Skip("set AGENTGUARD_PG_DSN to run Postgres store tests")
	}
	return dsn
}

// agentGuardTables is every table pgSchemaStmts creates. Dropping them puts the
// database back into the fresh-deployment state the race needs.
var agentGuardTables = []string{
	"approvals", "rate_buckets", "session_costs", "policies",
	"audit_entries", "rate_consumption", "cost_consumption",
}

// dropSchema removes every AgentGuard table so the next Migrate really creates
// them.
//
// This is more destructive than newTestPGStore's TRUNCATE and carries the same
// contract more sharply: AGENTGUARD_PG_DSN must name a throwaway database with
// no live AgentGuard nodes attached. CI's postgres-integration job gives the
// suite a dedicated service container. Pointing it at a database a running
// cluster is using will not corrupt the cluster (it re-creates what it needs on
// the next migration) but the two will contend badly — measured here at 4.7s
// for the suite alone versus 99s alongside a three-node cluster.
func dropSchema(t *testing.T, dsn string) {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open for drop: %v", err)
	}
	defer func() { _ = db.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	stmt := "DROP TABLE IF EXISTS "
	for i, tbl := range agentGuardTables {
		if i > 0 {
			stmt += ", "
		}
		stmt += tbl
	}
	if _, err := db.ExecContext(ctx, stmt+" CASCADE"); err != nil {
		t.Fatalf("drop schema: %v", err)
	}
}

// tablesPresent reports which AgentGuard tables currently exist.
func tablesPresent(t *testing.T, dsn string) map[string]bool {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open for inspect: %v", err)
	}
	defer func() { _ = db.Close() }()
	present := map[string]bool{}
	for _, tbl := range agentGuardTables {
		var ok bool
		if err := db.QueryRow(
			`SELECT EXISTS (SELECT 1 FROM information_schema.tables
			                WHERE table_schema = current_schema() AND table_name = $1)`,
			tbl).Scan(&ok); err != nil {
			t.Fatalf("inspect %s: %v", tbl, err)
		}
		present[tbl] = ok
	}
	return present
}

// bootConcurrently starts n PostgresStore constructors simultaneously (released
// by a barrier so they genuinely contend) and returns each one's error.
func bootConcurrently(dsn string, n int) []error {
	errs := make([]error, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			s, err := NewPostgresStore(dsn)
			if err != nil {
				errs[i] = err
				return
			}
			_ = s.Close()
		}(i)
	}
	close(start)
	wg.Wait()
	return errs
}

// TestPostgresStore_ConcurrentColdStart is the regression test for the cold-
// start race: every replica booting at once against an empty database must
// come up. Repeated rounds because a single round can get lucky — the observed
// pre-fix failure rate was ~83% per round, so three rounds detect it with
// better than 99% probability.
func TestPostgresStore_ConcurrentColdStart(t *testing.T) {
	dsn := pgDSNOrSkip(t)
	const (
		replicas = 5
		rounds   = 3
	)
	for round := 1; round <= rounds; round++ {
		dropSchema(t, dsn)
		errs := bootConcurrently(dsn, replicas)
		for i, err := range errs {
			if err != nil {
				t.Fatalf("round %d: replica %d failed to boot against an empty database: %v\n"+
					"(a fresh multi-node deployment must not lose a node to a migration race)",
					round, i, err)
			}
		}
		for tbl, ok := range tablesPresent(t, dsn) {
			if !ok {
				t.Fatalf("round %d: table %q missing after %d concurrent migrations", round, tbl, replicas)
			}
		}
	}
}

// TestPostgresStore_ConcurrentMigrateOnExistingSchema covers the steady-state
// case: replicas restarting together against a schema that already exists —
// i.e. every rolling restart, not just the first deploy.
//
// This was expected to be the harmless counterweight, on the reasoning that
// every statement is IF NOT EXISTS and so has nothing to do. It is not:
// without the advisory lock 6 of 8 replicas here fail with SQLSTATE 40P01.
// The `ALTER TABLE approvals ADD COLUMN IF NOT EXISTS` statements still take
// an ACCESS EXCLUSIVE lock on the table even when the column is already
// present, so concurrent migration transactions deadlock against each other
// on an untouched schema. That makes the defect a restart problem, not only a
// cold-start one. It also pins that the fix serialises rather than stalls: the
// whole batch must finish inside migrateTimeout.
func TestPostgresStore_ConcurrentMigrateOnExistingSchema(t *testing.T) {
	dsn := pgDSNOrSkip(t)
	seed, err := NewPostgresStore(dsn) // ensure the schema exists
	if err != nil {
		t.Fatalf("seed migrate: %v", err)
	}
	_ = seed.Close()

	deadline := time.Now().Add(migrateTimeout)
	errs := bootConcurrently(dsn, 8)
	for i, err := range errs {
		if err != nil {
			t.Errorf("replica %d failed on an already-migrated schema: %v", i, err)
		}
	}
	if time.Now().After(deadline) {
		t.Errorf("8 concurrent migrations took longer than migrateTimeout (%s); the advisory lock should serialise, not stall", migrateTimeout)
	}
}

// TestPostgresStore_MigrateIsSerialisedByAdvisoryLock proves the mechanism
// rather than only the outcome: while one transaction holds the migration
// lock, a Migrate on another connection must wait, and must proceed once the
// holder commits. Without the lock in Migrate this returns immediately and the
// test fails.
func TestPostgresStore_MigrateIsSerialisedByAdvisoryLock(t *testing.T) {
	dsn := pgDSNOrSkip(t)
	store, err := NewPostgresStore(dsn)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	// Hold the migration lock on a separate connection, outside the store.
	holder, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open holder: %v", err)
	}
	defer func() { _ = holder.Close() }()
	ctx := context.Background()
	tx, err := holder.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin holder tx: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, pgMigrateLockKey); err != nil {
		_ = tx.Rollback()
		t.Fatalf("acquire holder lock: %v", err)
	}

	// A migration must now block. Give it a short deadline: timing out is the
	// expected outcome while the lock is held.
	blocked := make(chan error, 1)
	go func() {
		bctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		blocked <- store.Migrate(bctx)
	}()

	select {
	case err := <-blocked:
		if err == nil {
			_ = tx.Rollback()
			t.Fatal("Migrate completed while another session held the migration lock — the DDL is not serialised")
		}
		// Timed out waiting for the lock: exactly what should happen.
	case <-time.After(5 * time.Second):
		_ = tx.Rollback()
		t.Fatal("Migrate neither completed nor returned within 5s")
	}

	// Release the lock; a fresh migration must now succeed promptly.
	if err := tx.Rollback(); err != nil {
		t.Fatalf("release holder lock: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		mctx, cancel := context.WithTimeout(context.Background(), migrateTimeout)
		defer cancel()
		done <- store.Migrate(mctx)
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Migrate after the lock was released: %v", err)
		}
	case <-time.After(migrateTimeout + 5*time.Second):
		t.Fatal("Migrate did not complete after the lock was released")
	}
}

// TestPostgresStore_MigrateLockKeyIsStable pins the advisory-lock key. Changing
// it would silently stop new binaries from excluding old ones during a rolling
// upgrade — reintroducing the exact race, at the worst possible moment.
func TestPostgresStore_MigrateLockKeyIsStable(t *testing.T) {
	const want int64 = 0x41475F4D4947
	if pgMigrateLockKey != want {
		t.Errorf("pgMigrateLockKey = %#x, want %#x — the key is a cross-version contract and must never change",
			pgMigrateLockKey, want)
	}
	if got := decodeASCII(pgMigrateLockKey); got != "AG_MIG" {
		t.Errorf("lock key no longer spells AG_MIG, got %q", got)
	}
}

// decodeASCII renders the low bytes of the key as text, documenting where the
// constant came from.
func decodeASCII(v int64) string {
	var b []byte
	for shift := 40; shift >= 0; shift -= 8 {
		if c := byte(v >> uint(shift)); c != 0 {
			b = append(b, c)
		}
	}
	return string(b)
}
