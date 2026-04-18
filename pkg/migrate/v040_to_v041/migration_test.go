package v040_to_v041

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/migrate"
)

// legacyContent is a minimal pair of v0.4.0-style audit records — headerless
// JSONL, matches what `FileLogger` produced in v0.4.0.
const legacyContent = `{"timestamp":"2025-01-01T00:00:00Z","agent_id":"legacy-a","request":{"scope":"shell","command":"ls"},"result":{"decision":"ALLOW","reason":"ok"},"duration_ms":1}
{"timestamp":"2025-01-01T00:00:01Z","agent_id":"legacy-b","request":{"scope":"shell","command":"cat"},"result":{"decision":"DENY","reason":"blocked"},"duration_ms":0}
`

func envFor(t *testing.T, body string) migrate.Env {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	if body != "" {
		if err := os.WriteFile(p, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return migrate.Env{AuditLogPath: p}
}

// TestDetect_LegacyHeaderlessFile: a v0.4.0 file with content but no _meta
// line must be detected as needing migration.
func TestDetect_LegacyHeaderlessFile(t *testing.T) {
	m := &Migration{}
	env := envFor(t, legacyContent)

	need, err := m.Detect(context.Background(), env)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !need {
		t.Error("Detect must return true for a headerless legacy file")
	}
}

// TestDetect_AlreadyV2: a file that already has a _meta header must be
// skipped.
func TestDetect_AlreadyV2(t *testing.T) {
	m := &Migration{}
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")

	// Create a v2 file via NewFileLogger (writes the header).
	l, err := audit.NewFileLogger(p)
	if err != nil {
		t.Fatal(err)
	}
	l.Close()

	need, err := m.Detect(context.Background(), migrate.Env{AuditLogPath: p})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if need {
		t.Error("Detect must return false for an already-v2 file")
	}
}

// TestDetect_MissingFile: a fresh install (no audit file yet) is not an
// error and must not return true.
func TestDetect_MissingFile(t *testing.T) {
	m := &Migration{}
	dir := t.TempDir()
	need, err := m.Detect(context.Background(), migrate.Env{
		AuditLogPath: filepath.Join(dir, "never.jsonl"),
	})
	if err != nil {
		t.Errorf("missing audit must not error: %v", err)
	}
	if need {
		t.Error("missing audit must not trigger migration")
	}
}

// TestDetect_EmptyFile: a zero-byte audit file is also skipped — the
// schema header will be written the first time an entry lands.
func TestDetect_EmptyFile(t *testing.T) {
	m := &Migration{}
	env := envFor(t, "")
	// Create an empty file.
	if err := os.WriteFile(env.AuditLogPath, []byte{}, 0600); err != nil {
		t.Fatal(err)
	}
	need, err := m.Detect(context.Background(), env)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if need {
		t.Error("empty audit file must not trigger migration")
	}
}

// TestMigrate_WritesHeaderAndBackup: after Migrate(dryRun=false) the live
// file carries a v2 meta line, the original bytes survive at .v040-backup,
// and the data lines round-trip via Query.
func TestMigrate_WritesHeaderAndBackup(t *testing.T) {
	m := &Migration{}
	env := envFor(t, legacyContent)

	res, err := m.Migrate(context.Background(), env, false)
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if res.DryRun {
		t.Error("DryRun flag must be false for a real migration")
	}

	// 1. Live file now has a meta header.
	meta, err := audit.ReadMeta(env.AuditLogPath)
	if err != nil {
		t.Fatalf("ReadMeta: %v", err)
	}
	if meta == nil {
		t.Fatal("post-migration file must have a meta header")
	}
	if meta.SchemaVersion != audit.CurrentSchemaVersion {
		t.Errorf("schema_version=%d, want %d", meta.SchemaVersion, audit.CurrentSchemaVersion)
	}

	// 2. Backup holds the original bytes verbatim.
	backup := env.AuditLogPath + BackupSuffix
	bData, err := os.ReadFile(backup)
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if string(bData) != legacyContent {
		t.Errorf("backup contents do not match original; got:\n%s", bData)
	}

	// 3. Query returns the two legacy entries through the new logger.
	l, err := audit.NewFileLogger(env.AuditLogPath)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	entries, err := l.Query(audit.QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 entries post-migration, got %d", len(entries))
	}
}

// TestMigrate_DryRunWritesNothing: --dry-run must not create any files.
func TestMigrate_DryRunWritesNothing(t *testing.T) {
	m := &Migration{}
	env := envFor(t, legacyContent)

	before, err := os.ReadFile(env.AuditLogPath)
	if err != nil {
		t.Fatal(err)
	}

	res, err := m.Migrate(context.Background(), env, true)
	if err != nil {
		t.Fatalf("Migrate dry-run: %v", err)
	}
	if !res.DryRun {
		t.Error("DryRun flag must be true on dry-run result")
	}

	after, err := os.ReadFile(env.AuditLogPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("dry-run must not modify the live audit file")
	}

	// Backup file must not exist after dry-run.
	if _, err := os.Stat(env.AuditLogPath + BackupSuffix); !os.IsNotExist(err) {
		t.Errorf("dry-run must not create a backup; stat: %v", err)
	}
}

// TestMigrate_PreservesExistingBackup: a previous partial run may have
// written a backup already; a later retry must not overwrite it because
// the earliest pre-migration state is the safest to roll back to.
func TestMigrate_PreservesExistingBackup(t *testing.T) {
	m := &Migration{}
	env := envFor(t, legacyContent)

	// Pretend a previous run left a backup of a different content.
	prior := "old backup content\n"
	if err := os.WriteFile(env.AuditLogPath+BackupSuffix, []byte(prior), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := m.Migrate(context.Background(), env, false); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	data, err := os.ReadFile(env.AuditLogPath + BackupSuffix)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != prior {
		t.Errorf("pre-existing backup was overwritten; got %q", data)
	}
}

// TestMigrate_RemovesStaleCheckpoint: a replay checkpoint keyed off byte
// offsets in the pre-migration file becomes meaningless once the file is
// rewritten; Migrate must delete it.
func TestMigrate_RemovesStaleCheckpoint(t *testing.T) {
	m := &Migration{}
	env := envFor(t, legacyContent)
	env.CheckpointPath = env.AuditLogPath + ".replay-checkpoint"

	if err := os.WriteFile(env.CheckpointPath, []byte(`{"offset":100,"audit_size":100}`), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := m.Migrate(context.Background(), env, false); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if _, err := os.Stat(env.CheckpointPath); !os.IsNotExist(err) {
		t.Errorf("stale checkpoint must be removed after rewrite; stat: %v", err)
	}
}

// TestVerify_PostMigrate: Verify must succeed on a freshly-migrated file
// and fail on a file that is still headerless.
func TestVerify_PostMigrate(t *testing.T) {
	m := &Migration{}
	env := envFor(t, legacyContent)

	// Before migration: Verify fails.
	if err := m.Verify(context.Background(), env); err == nil {
		t.Error("Verify must fail on an un-migrated file")
	}

	if _, err := m.Migrate(context.Background(), env, false); err != nil {
		t.Fatal(err)
	}

	// After migration: Verify succeeds.
	if err := m.Verify(context.Background(), env); err != nil {
		t.Errorf("Verify must succeed post-migration, got: %v", err)
	}
}

// TestMigrate_IdempotentAfterFirstRun: running a successful migration and
// then Detecting again must return false (nothing left to do).
func TestMigrate_IdempotentAfterFirstRun(t *testing.T) {
	m := &Migration{}
	env := envFor(t, legacyContent)

	if _, err := m.Migrate(context.Background(), env, false); err != nil {
		t.Fatal(err)
	}
	need, err := m.Detect(context.Background(), env)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if need {
		t.Error("Detect must return false after a successful run")
	}
}

// TestRegistration: importing the package must have registered the
// migration with the framework so RunStartup / RunCLI can find it.
func TestRegistration(t *testing.T) {
	found := false
	for _, m := range migrate.Registered() {
		if m.ID() == MigrationID {
			found = true
			if m.FromVersion() != "1" {
				t.Errorf("FromVersion = %q, want \"1\"", m.FromVersion())
			}
			if !strings.Contains(m.Description(), "schema-v2") {
				t.Errorf("Description should mention schema-v2: %q", m.Description())
			}
			break
		}
	}
	if !found {
		t.Errorf("migration %q not registered", MigrationID)
	}
}

// TestBackupDirOverride: when env.BackupDir is set, the backup lands there
// rather than alongside the live audit file.
func TestBackupDirOverride(t *testing.T) {
	m := &Migration{}
	env := envFor(t, legacyContent)
	env.BackupDir = t.TempDir()

	if _, err := m.Migrate(context.Background(), env, false); err != nil {
		t.Fatal(err)
	}

	expected := filepath.Join(env.BackupDir, filepath.Base(env.AuditLogPath)+BackupSuffix)
	if _, err := os.Stat(expected); err != nil {
		t.Errorf("backup not found at override path %s: %v", expected, err)
	}

	// Default backup path must not exist when an override is specified.
	if _, err := os.Stat(env.AuditLogPath + BackupSuffix); !os.IsNotExist(err) {
		t.Errorf("backup must not be placed next to audit log when BackupDir is set; stat: %v", err)
	}
}
