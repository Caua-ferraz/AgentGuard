package store

import (
	"bytes"
	"context"
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
