package store

import (
	"bytes"
	"context"
	"database/sql"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

func indexEntry(i int, session, parent string) audit.Entry {
	return audit.Entry{
		Timestamp: time.Date(2026, 10, 1, 0, 0, i, 0, time.UTC), SessionID: session, AgentID: "bot",
		Request: policy.ActionRequest{Scope: "shell", Command: "ls", ParentSessionID: parent},
		Result:  policy.CheckResult{Decision: policy.Allow},
	}
}

// Every audit and session query works before the v1.4 indexes exist, and
// Migrate builds them on a table that already holds rows, saying so.
func TestSQLiteStore_AuditIndexesBuiltAfterRowsExist(t *testing.T) {
	s, err := NewSQLiteStore(filepath.Join(t.TempDir(), "agentguard.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()
	for _, ix := range auditSessionIndexes {
		if _, err := s.db.ExecContext(ctx, "DROP INDEX "+ix.name); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.AppendAudit(ctx, []audit.Entry{indexEntry(1, "orch", ""), indexEntry(2, "child", "orch")}); err != nil {
		t.Fatal(err)
	}

	kids, err := s.QuerySessions(ctx, "local", audit.SessionFilter{ParentSessionID: "orch"})
	if err != nil || len(kids) != 1 || kids[0].SessionID != "child" {
		t.Fatalf("sessions without the indexes = %+v, %v", kids, err)
	}
	if got, err := s.QueryAudit(ctx, "local", audit.QueryFilter{SessionID: "orch"}); err != nil || len(got) != 1 {
		t.Fatalf("audit query without the indexes = %+v, %v", got, err)
	}

	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	for _, ix := range auditSessionIndexes {
		var n int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?`, ix.name).Scan(&n); err != nil || n != 1 {
			t.Errorf("index %s not built (count %d, err %v)", ix.name, n, err)
		}
		if !strings.Contains(logs.String(), "building index "+ix.name+" on audit_entries (about 2 rows)") {
			t.Errorf("no progress line for %s in %q", ix.name, logs.String())
		}
	}

	// Nothing to do the second time, and nothing logged.
	logs.Reset()
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if logs.Len() != 0 {
		t.Errorf("second Migrate logged %q", logs.String())
	}
}

func TestPostgresStore_AuditIndexesBuildInTheBackground(t *testing.T) {
	s := newTestPGStore(t)
	ctx := context.Background()
	<-s.indexesDone // the build the constructor started

	for _, ix := range auditSessionIndexes {
		if _, err := s.db.ExecContext(ctx, "DROP INDEX IF EXISTS "+ix.name); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.AppendAudit(ctx, []audit.Entry{indexEntry(1, "orch", ""), indexEntry(2, "child", "orch")}); err != nil {
		t.Fatal(err)
	}
	// Queries work before the indexes exist.
	kids, err := s.QuerySessions(ctx, "local", audit.SessionFilter{ParentSessionID: "orch"})
	if err != nil || len(kids) != 1 {
		t.Fatalf("sessions without the indexes = %+v, %v", kids, err)
	}

	// Leave one index INVALID, as an interrupted concurrent build does.
	if _, err := s.db.ExecContext(ctx, "CREATE INDEX "+auditSessionIndexes[0].name+" ON audit_entries ("+auditSessionIndexes[0].columns+")"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE pg_index SET indisvalid = false WHERE indexrelid = to_regclass($1::text)`, auditSessionIndexes[0].name); err != nil {
		t.Skipf("can't mark an index invalid here (needs superuser): %v", err)
	}

	if err := s.buildAuditIndexes(ctx); err != nil {
		t.Fatalf("buildAuditIndexes: %v", err)
	}
	for _, ix := range auditSessionIndexes {
		var valid bool
		if err := s.db.QueryRowContext(ctx, `SELECT indisvalid FROM pg_index WHERE indexrelid = to_regclass($1::text)`, ix.name).Scan(&valid); err != nil || !valid {
			t.Errorf("index %s: valid %v, err %v", ix.name, valid, err)
		}
	}
	// Idempotent: a second build finds both valid.
	if err := s.buildAuditIndexes(ctx); err != nil {
		t.Fatal(err)
	}
}

// Migrate skips the CREATE INDEX statements whose index already exists, so
// every one of them must yield its index name.
func TestPgIndexName_CoversEverySchemaIndex(t *testing.T) {
	n := 0
	for _, stmt := range pgSchemaStmts {
		if !strings.HasPrefix(stmt, "CREATE INDEX") {
			if pgIndexName(stmt) != "" {
				t.Errorf("pgIndexName(%q) = %q, want none", stmt, pgIndexName(stmt))
			}
			continue
		}
		n++
		if pgIndexName(stmt) == "" {
			t.Errorf("no index name parsed from %q", stmt)
		}
	}
	if n == 0 {
		t.Fatal("pgSchemaStmts has no CREATE INDEX statements")
	}
}

// Migrate on an existing schema must not wait behind another replica's
// background CREATE INDEX CONCURRENTLY, which itself waits for every older
// transaction. Before, Migrate's CREATE INDEX IF NOT EXISTS statements
// locked audit_entries before finding the index there, so a boot could time
// out behind any long reader.
func TestPostgresStore_MigrateDoesNotWaitBehindIndexBuild(t *testing.T) {
	s := newTestPGStore(t)
	ctx := context.Background()
	reader, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Rollback() }()
	var n int
	if err := reader.QueryRowContext(ctx, `SELECT count(*) FROM audit_entries`).Scan(&n); err != nil {
		t.Fatal(err)
	}

	conn, err := s.db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	built := make(chan error, 1)
	go func() {
		_, err := conn.ExecContext(ctx, `CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_test_build_probe ON audit_entries (agent_id, scope)`)
		built <- err
	}()
	t.Cleanup(func() {
		_, _ = s.db.ExecContext(context.Background(), `DROP INDEX IF EXISTS idx_test_build_probe`)
	})
	deadline := time.Now().Add(10 * time.Second)
	for {
		var waiting bool
		if err := s.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity
			WHERE query LIKE 'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_test_build_probe%'
			AND wait_event_type = 'Lock')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the concurrent index build never started waiting on the open reader")
		}
		time.Sleep(20 * time.Millisecond)
	}

	tctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := s.Migrate(tctx); err != nil {
		t.Fatalf("Migrate waited behind a concurrent index build: %v", err)
	}
	_ = reader.Rollback()
	if err := <-built; err != nil {
		t.Fatalf("concurrent index build: %v", err)
	}
}
