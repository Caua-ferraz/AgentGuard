package main

// Tests for `agentguard migrate` (review finding R2).
//
// The defect: the CLI computed the replay checkpoint as
// `<audit-dir>/.replay-checkpoint` while `agentguard serve` reads and writes
// `<audit-log>.replay-checkpoint`, so `--reset-checkpoint` deleted a file
// that never existed and reported success, and a CLI-run migration left the
// live checkpoint pointing at byte offsets of the old file. No test drove
// runMigrate, which is how it shipped. These tests pin the cross-component
// contract by booting the real server to write the checkpoint and then
// driving the real CLI code path against it.

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/metrics"
	"github.com/Caua-ferraz/AgentGuard/pkg/migrate"
	"github.com/Caua-ferraz/AgentGuard/pkg/notify"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
	"github.com/Caua-ferraz/AgentGuard/pkg/proxy"
)

const legacyAuditLines = `{"timestamp":"2025-01-01T00:00:00Z","agent_id":"legacy-a","request":{"scope":"shell","command":"ls"},"result":{"decision":"ALLOW","reason":"ok"},"duration_ms":1}
{"timestamp":"2025-01-01T00:00:01Z","agent_id":"legacy-b","request":{"scope":"shell","command":"cat"},"result":{"decision":"DENY","reason":"blocked"},"duration_ms":0}
`

// bootRealServer runs the real startup seeder over logPath (which writes the
// checkpoint exactly as production does) and returns the counters it seeded.
func bootRealServer(t *testing.T, logPath string) uint64 {
	t.Helper()
	l, err := audit.NewFileLogger(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	metrics.Reset()
	srv := proxy.NewServer(proxy.Config{
		Engine:   policy.NewEngineFromPolicy(&policy.Policy{Version: "1", Name: "x"}),
		Logger:   l,
		Notifier: notify.NewDispatcher(policy.NotificationCfg{}),
		Version:  "test",
	})
	srv.Shutdown()
	return metrics.ChecksTotal()
}

func seedV2Audit(t *testing.T, logPath string, n int) {
	t.Helper()
	l, err := audit.NewFileLogger(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if err := l.Log(audit.Entry{
			Timestamp: time.Now().UTC(),
			AgentID:   "seed",
			Request:   policy.ActionRequest{Scope: "shell", Command: "echo"},
			Result:    policy.CheckResult{Decision: policy.Allow},
		}); err != nil {
			t.Fatal(err)
		}
	}
	l.Close()
}

func runMigrateCLI(t *testing.T, o migrateCmdOpts) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = executeMigrate(o, &out, &errb)
	return code, out.String(), errb.String()
}

func staleCLIPath(logPath string) string {
	return filepath.Join(filepath.Dir(logPath), ".replay-checkpoint")
}

func TestDefaultCheckpointPath_IsTheServersCheckpoint(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	if got, want := defaultCheckpointPath(logPath), audit.CheckpointPath(logPath); got != want {
		t.Fatalf("defaultCheckpointPath = %q, want the server's %q", got, want)
	}
	if got := defaultCheckpointPath(logPath); got == staleCLIPath(logPath) {
		t.Fatalf("defaultCheckpointPath must not be the <audit-dir>/.replay-checkpoint form: %q", got)
	}
}

func TestMigrate_ResetCheckpointDeletesTheFileTheServerWrote(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	seedV2Audit(t, logPath, 3)
	if got := bootRealServer(t, logPath); got != 3 {
		t.Fatalf("test setup: server seeded %d, want 3", got)
	}
	if cp, err := audit.ReadCheckpoint(logPath); err != nil || cp == nil {
		t.Fatalf("test setup: server must have written a checkpoint, got %v err=%v", cp, err)
	}
	before, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}

	code, out, errb := runMigrateCLI(t, migrateCmdOpts{AuditPath: logPath, ResetCheckpoint: true})
	if code != 0 {
		t.Fatalf("exit %d, stderr:\n%s", code, errb)
	}
	if !strings.Contains(out, "checkpoint removed") {
		t.Errorf("stdout must confirm the removal, got:\n%s", out)
	}
	if cp, err := audit.ReadCheckpoint(logPath); err != nil || cp != nil {
		t.Errorf("the server's checkpoint must be gone after --reset-checkpoint, got %+v err=%v", cp, err)
	}
	if _, err := os.Stat(staleCLIPath(logPath)); !os.IsNotExist(err) {
		t.Errorf("CLI must not create or touch %s; stat: %v", staleCLIPath(logPath), err)
	}
	after, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("an already-migrated audit file must not be rewritten by `migrate`")
	}

	// The next boot really does a full replay and lands on the same totals.
	if got := bootRealServer(t, logPath); got != 3 {
		t.Errorf("boot after reset: ChecksTotal = %d, want 3", got)
	}
}

func TestMigrate_ResetCheckpointReportsWhenNothingToReset(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	seedV2Audit(t, logPath, 1)

	code, out, errb := runMigrateCLI(t, migrateCmdOpts{AuditPath: logPath, ResetCheckpoint: true})
	if code != 0 {
		t.Fatalf("exit %d, stderr:\n%s", code, errb)
	}
	if strings.Contains(out, "checkpoint removed") {
		t.Errorf("must not claim a removal when no checkpoint existed:\n%s", out)
	}
	if !strings.Contains(out, "no checkpoint found") {
		t.Errorf("must say that nothing was there to reset:\n%s", out)
	}
}

func TestMigrate_LegacyFileMigrationInvalidatesTheServersCheckpoint(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(logPath, []byte(legacyAuditLines), 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	// A checkpoint the server wrote against the PRE-migration byte layout.
	if err := audit.WriteCheckpoint(logPath, audit.Checkpoint{Offset: info.Size(), AuditSize: info.Size()}); err != nil {
		t.Fatal(err)
	}

	code, _, errb := runMigrateCLI(t, migrateCmdOpts{AuditPath: logPath})
	if code != 0 {
		t.Fatalf("exit %d, stderr:\n%s", code, errb)
	}
	meta, err := audit.ReadMeta(logPath)
	if err != nil || meta == nil {
		t.Fatalf("migration must have added a header, got meta=%v err=%v", meta, err)
	}
	if cp, err := audit.ReadCheckpoint(logPath); err != nil || cp != nil {
		t.Fatalf("migration rewrote the file, so the server's checkpoint must be invalidated; got %+v err=%v", cp, err)
	}
	if _, err := os.Stat(staleCLIPath(logPath)); !os.IsNotExist(err) {
		t.Errorf("CLI must not create %s; stat: %v", staleCLIPath(logPath), err)
	}
	if got := bootRealServer(t, logPath); got != 2 {
		t.Errorf("boot after migration: ChecksTotal = %d, want 2 (full replay of the migrated file)", got)
	}
}

func TestMigrate_ExplicitCheckpointFlagIsHonored(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	seedV2Audit(t, logPath, 1)
	custom := filepath.Join(dir, "elsewhere.cp")
	if err := os.WriteFile(custom, []byte(`{"offset":1,"audit_size":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := audit.WriteCheckpoint(logPath, audit.Checkpoint{Offset: 1, AuditSize: 1}); err != nil {
		t.Fatal(err)
	}

	code, out, errb := runMigrateCLI(t, migrateCmdOpts{AuditPath: logPath, CheckpointPath: custom, ResetCheckpoint: true})
	if code != 0 {
		t.Fatalf("exit %d, stderr:\n%s", code, errb)
	}
	if !strings.Contains(out, custom) {
		t.Errorf("stdout must name the explicit path, got:\n%s", out)
	}
	if _, err := os.Stat(custom); !os.IsNotExist(err) {
		t.Errorf("explicit checkpoint must be removed; stat: %v", err)
	}
	if cp, err := audit.ReadCheckpoint(logPath); err != nil || cp == nil {
		t.Errorf("the default-path checkpoint must be untouched when --checkpoint is explicit; got %+v err=%v", cp, err)
	}
}

func TestMigrate_ListAndDryRunLeaveDiskAlone(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(logPath, []byte(legacyAuditLines), 0600); err != nil {
		t.Fatal(err)
	}
	if err := audit.WriteCheckpoint(logPath, audit.Checkpoint{Offset: 7, AuditSize: 7}); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(logPath)

	code, out, errb := runMigrateCLI(t, migrateCmdOpts{AuditPath: logPath, List: true})
	if code != 0 || !strings.Contains(out, "v040_to_v041") {
		t.Fatalf("--list: exit %d, out:\n%s\nstderr:\n%s", code, out, errb)
	}
	code, _, errb = runMigrateCLI(t, migrateCmdOpts{AuditPath: logPath, DryRun: true})
	if code != 0 {
		t.Fatalf("--dry-run: exit %d, stderr:\n%s", code, errb)
	}
	after, _ := os.ReadFile(logPath)
	if !bytes.Equal(before, after) {
		t.Error("--dry-run must not rewrite the audit file")
	}
	if cp, err := audit.ReadCheckpoint(logPath); err != nil || cp == nil || cp.Offset != 7 {
		t.Errorf("--list/--dry-run must not touch the checkpoint; got %+v err=%v", cp, err)
	}
}

func TestMigrate_IDOverrideOnMigratedFileIsSafe(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	seedV2Audit(t, logPath, 2)
	bootRealServer(t, logPath)
	before, _ := os.ReadFile(logPath)

	code, _, errb := runMigrateCLI(t, migrateCmdOpts{AuditPath: logPath, ID: "v040_to_v041"})
	if code != 0 {
		t.Fatalf("exit %d, stderr:\n%s", code, errb)
	}
	after, _ := os.ReadFile(logPath)
	if !bytes.Equal(before, after) {
		t.Error("--id override on an already-migrated file must not rewrite it (a second header shifts every replay offset)")
	}
	if !strings.Contains(errb, "already carries") {
		t.Errorf("operator must be told nothing was migrated; log:\n%s", errb)
	}
	if cp, err := audit.ReadCheckpoint(logPath); err != nil || cp == nil {
		t.Errorf("a no-op migration must leave the server's checkpoint in place; got %+v err=%v", cp, err)
	}
	if got := bootRealServer(t, logPath); got != 2 {
		t.Errorf("boot after no-op override: ChecksTotal = %d, want 2", got)
	}
}

func TestMigrate_UsageErrors(t *testing.T) {
	if code, _, errb := runMigrateCLI(t, migrateCmdOpts{}); code != 1 || !strings.Contains(errb, "--audit-log") {
		t.Errorf("empty audit path: exit %d, stderr:\n%s", code, errb)
	}
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	seedV2Audit(t, logPath, 1)
	if code, _, errb := runMigrateCLI(t, migrateCmdOpts{AuditPath: logPath, ID: "no_such_migration"}); code != 1 || !strings.Contains(errb, "not found") {
		t.Errorf("unknown --id: exit %d, stderr:\n%s", code, errb)
	}
}

// The startup path (buildAuditPipeline) must hand the migration framework
// the same checkpoint path the seeder reads, so a boot-time migration can
// never leave a stale checkpoint behind either.
func TestBuildAuditPipeline_MigratesLegacyFileAndInvalidatesCheckpoint(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(logPath, []byte(legacyAuditLines), 0600); err != nil {
		t.Fatal(err)
	}
	if err := audit.WriteCheckpoint(logPath, audit.Checkpoint{Offset: 5, AuditSize: 5}); err != nil {
		t.Fatal(err)
	}

	p, err := buildAuditPipeline(logPath, false, nil, auditRotationOpts{}, auditBufferedOpts{Enabled: false})
	if err != nil {
		t.Fatalf("buildAuditPipeline: %v", err)
	}
	p.Close()

	if meta, err := audit.ReadMeta(logPath); err != nil || meta == nil {
		t.Fatalf("startup must migrate a legacy file before opening it, got meta=%v err=%v", meta, err)
	}
	if cp, err := audit.ReadCheckpoint(logPath); err != nil || cp != nil {
		t.Errorf("startup migration must invalidate the seeder's checkpoint; got %+v err=%v", cp, err)
	}
	if _, err := os.Stat(staleCLIPath(logPath)); !os.IsNotExist(err) {
		t.Errorf("startup must not create %s; stat: %v", staleCLIPath(logPath), err)
	}

	// And the framework path the CLI uses is the same one (no second registry).
	need, err := detectV040(t, logPath)
	if err != nil || need {
		t.Errorf("after startup migration Detect must be false, got need=%v err=%v", need, err)
	}
}

func detectV040(t *testing.T, logPath string) (bool, error) {
	t.Helper()
	for _, m := range migrate.Registered() {
		if m.ID() == "v040_to_v041" {
			return m.Detect(context.Background(), migrate.Env{AuditLogPath: logPath})
		}
	}
	t.Fatal("v040_to_v041 is not registered in this binary")
	return false, nil
}
