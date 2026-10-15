package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// oldAuditSchema is audit_entries exactly as it shipped before the v1.4
// session columns. Kept verbatim so this test fails loudly if Migrate's
// guarded ALTERs are dropped on the assumption CREATE TABLE covers them.
const oldAuditSchema = `
CREATE TABLE audit_entries (
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
CREATE INDEX idx_audit_tenant_ts ON audit_entries(tenant_id, timestamp);`

func TestMigrate_AddsSessionColumnsToAnOldAuditTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	old := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

	// A database written by an older build, already holding an entry.
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	if _, err := raw.Exec(oldAuditSchema); err != nil {
		t.Fatalf("create old schema: %v", err)
	}
	if _, err := raw.Exec(
		`INSERT INTO audit_entries (tenant_id, timestamp, session_id, agent_id, scope, command, decision, transport)
		 VALUES ('local', ?, 'old-session', 'bot', 'shell', 'ls', 'ALLOW', 'sdk')`,
		old.Format(time.RFC3339Nano),
	); err != nil {
		t.Fatalf("seed old row: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close raw: %v", err)
	}

	s, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("NewSQLiteStore over old DB: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()

	// The old row reads back with empty session fields…
	got, err := s.QueryAudit(ctx, "local", audit.QueryFilter{})
	if err != nil {
		t.Fatalf("query after upgrade: %v", err)
	}
	if len(got) != 1 || got[0].SessionID != "old-session" || got[0].Request.ParentSessionID != "" || got[0].Request.Meta != nil {
		t.Fatalf("old row after upgrade = %+v", got)
	}

	// …new rows carry them, and the session queries work on the table.
	child := audit.Entry{
		Timestamp: old.Add(time.Minute), SessionID: "child", AgentID: "bot",
		Request: policy.ActionRequest{Scope: "shell", Command: "pwd", ParentSessionID: "old-session",
			Meta: map[string]string{audit.SubagentMetaKey: "Explore", "other": "not stored"}},
		Result: policy.CheckResult{Decision: policy.Deny},
	}
	if err := s.AppendAudit(ctx, []audit.Entry{child}); err != nil {
		t.Fatalf("append on upgraded table: %v", err)
	}
	got, err = s.QueryAudit(ctx, "local", audit.QueryFilter{ParentSessionID: "old-session"})
	if err != nil || len(got) != 1 || got[0].Request.Meta[audit.SubagentMetaKey] != "Explore" {
		t.Fatalf("child entry = %+v, %v", got, err)
	}
	sessions, err := s.QuerySessions(ctx, "local", audit.SessionFilter{ParentSessionID: "old-session"})
	if err != nil || len(sessions) != 1 || sessions[0].SessionID != "child" || sessions[0].ParentSessionID != "old-session" {
		t.Fatalf("children of old-session = %+v, %v", sessions, err)
	}

	// The indexes exist, and a second boot changes nothing.
	for _, name := range []string{"idx_audit_tenant_session", "idx_audit_tenant_parent"} {
		var n int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?`, name).Scan(&n); err != nil || n != 1 {
			t.Errorf("index %s: count %d, err %v", name, n, err)
		}
	}
	if err := s.Migrate(ctx); err != nil {
		t.Errorf("second Migrate on upgraded DB: %v", err)
	}
}

// Sessions are per tenant at the SQL layer too: a tenant never sees
// another's sessions, even when the session ids are the same.
func TestSQLiteStore_SessionsStayInTheirTenant(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	if err := s.AppendAudit(ctx, []audit.Entry{
		{Timestamp: now, TenantID: "acme", SessionID: "shared", AgentID: "acme-bot",
			Request: policy.ActionRequest{Scope: "shell"}, Result: policy.CheckResult{Decision: policy.Allow}},
		{Timestamp: now, TenantID: "globex", SessionID: "shared", AgentID: "globex-bot",
			Request: policy.ActionRequest{Scope: "shell", ParentSessionID: "p"}, Result: policy.CheckResult{Decision: policy.Deny}},
	}); err != nil {
		t.Fatal(err)
	}
	got, err := s.QuerySessions(ctx, "acme", audit.SessionFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Counts.Total != 1 || got[0].Agents[0].AgentID != "acme-bot" || got[0].ParentSessionID != "" {
		t.Errorf("acme sessions = %+v", got)
	}
	if got, _ := s.QuerySessions(ctx, "acme", audit.SessionFilter{ParentSessionID: "p"}); len(got) != 0 {
		t.Errorf("acme sees globex's child session: %+v", got)
	}
}

func TestPostgresStore_AuditBackendsAgree(t *testing.T) {
	pg := newTestPGStore(t)
	fileLogger, err := audit.NewFileLogger(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fileLogger.Close() })
	pgLogger := NewAuditLogger(pg)
	for _, l := range []audit.Logger{fileLogger, pgLogger} {
		for _, e := range parityEntries() {
			if err := l.Log(e); err != nil {
				t.Fatalf("log: %v", err)
			}
		}
	}
	t.Run("query", func(t *testing.T) { checkQueryParity(t, fileLogger, pgLogger) })
	t.Run("sessions", func(t *testing.T) { checkSessionParity(t, fileLogger, pgLogger) })
	t.Run("detail", func(t *testing.T) { checkDetailParity(t, fileLogger, pgLogger) })
}

func TestPostgresStore_MigrateAddsSessionColumns(t *testing.T) {
	s := newTestPGStore(t)
	ctx := context.Background()
	// Put the table back in its pre-v1.4 shape, as an old build left it.
	if _, err := s.db.ExecContext(ctx, `ALTER TABLE audit_entries DROP COLUMN parent_session_id, DROP COLUMN subagent`); err != nil {
		t.Fatalf("drop columns: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate over old table: %v", err)
	}
	e := audit.Entry{Timestamp: time.Now().UTC(), SessionID: "c", AgentID: "bot",
		Request: policy.ActionRequest{Scope: "shell", ParentSessionID: "p"}, Result: policy.CheckResult{Decision: policy.Allow}}
	if err := s.AppendAudit(ctx, []audit.Entry{e}); err != nil {
		t.Fatalf("append: %v", err)
	}
	got, err := s.QuerySessions(ctx, "local", audit.SessionFilter{ParentSessionID: "p"})
	if err != nil || len(got) != 1 || got[0].ParentSessionID != "p" {
		t.Fatalf("sessions after migrate = %+v, %v", got, err)
	}
}

// On a schema that has every column, Migrate runs no ALTER, so an open
// reader of approvals or audit_entries (ACCESS SHARE) doesn't block it.
// Before, ADD COLUMN IF NOT EXISTS took ACCESS EXCLUSIVE on every boot.
func TestPostgresStore_MigrateSkipsPresentColumns(t *testing.T) {
	s := newTestPGStore(t)
	ctx := context.Background()
	reader, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Rollback() }()
	for _, q := range []string{`SELECT count(*) FROM approvals`, `SELECT count(*) FROM audit_entries`} {
		var n int
		if err := reader.QueryRowContext(ctx, q).Scan(&n); err != nil {
			t.Fatal(err)
		}
	}
	tctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := s.Migrate(tctx); err != nil {
		t.Fatalf("Migrate blocked behind an open reader: %v", err)
	}
}
