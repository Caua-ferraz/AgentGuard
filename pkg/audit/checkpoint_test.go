package audit

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// TestCheckpoint_RoundTrip verifies WriteCheckpoint / ReadCheckpoint produce
// matching Checkpoint structs.
func TestCheckpoint_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	audit := filepath.Join(dir, "audit.jsonl")

	want := Checkpoint{Offset: 1234, AuditSize: 1234}
	if err := WriteCheckpoint(audit, want); err != nil {
		t.Fatalf("WriteCheckpoint: %v", err)
	}
	got, err := ReadCheckpoint(audit)
	if err != nil {
		t.Fatalf("ReadCheckpoint: %v", err)
	}
	if got == nil || *got != want {
		t.Errorf("round-trip mismatch: got %+v, want %+v", got, want)
	}
}

// TestReadCheckpoint_MissingIsNotAnError: no checkpoint file is the expected
// first-boot state — must not surface as an error.
func TestReadCheckpoint_MissingIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	got, err := ReadCheckpoint(filepath.Join(dir, "no-such.jsonl"))
	if err != nil {
		t.Errorf("missing checkpoint must not error: %v", err)
	}
	if got != nil {
		t.Errorf("missing checkpoint must return nil, got %+v", got)
	}
}

// TestReadCheckpoint_CorruptIsNotAnError: a garbled file must downgrade
// cleanly to "no checkpoint" so one corrupted marker doesn't break startup.
func TestReadCheckpoint_CorruptIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	audit := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(checkpointPath(audit), []byte("not json at all"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadCheckpoint(audit)
	if err != nil {
		t.Errorf("corrupt checkpoint must not error: %v", err)
	}
	if got != nil {
		t.Errorf("corrupt checkpoint must return nil, got %+v", got)
	}
}

// TestReplayFrom_FullScanWhenNoCheckpoint: first boot has no checkpoint;
// every entry (skipping meta) must be replayed.
func TestReplayFrom_FullScanWhenNoCheckpoint(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	logger, err := NewFileLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		_ = logger.Log(Entry{
			Timestamp: time.Now().UTC(),
			AgentID:   "bot",
			Result:    policy.CheckResult{Decision: policy.Allow},
		})
	}
	logger.Close()

	var count int
	offset, err := ReplayFrom(path, nil, func(Entry) { count++ })
	if err != nil {
		t.Fatalf("ReplayFrom: %v", err)
	}
	if count != 3 {
		t.Errorf("expected 3 entries, got %d", count)
	}
	info, _ := os.Stat(path)
	if offset != info.Size() {
		t.Errorf("returned offset %d, want file size %d", offset, info.Size())
	}
}

// TestReplayFrom_ResumesFromCheckpoint: after a checkpoint, only newly
// appended entries are replayed.
func TestReplayFrom_ResumesFromCheckpoint(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	logger, err := NewFileLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		_ = logger.Log(Entry{
			Timestamp: time.Now().UTC(),
			AgentID:   "old",
			Result:    policy.CheckResult{Decision: policy.Allow},
		})
	}
	logger.Close()

	// First replay: checkpoints the current EOF.
	var first int
	offset, err := ReplayFrom(path, nil, func(Entry) { first++ })
	if err != nil {
		t.Fatalf("first ReplayFrom: %v", err)
	}
	if first != 2 {
		t.Errorf("first replay: expected 2 entries, got %d", first)
	}
	if err := WriteCheckpoint(path, Checkpoint{Offset: offset, AuditSize: offset}); err != nil {
		t.Fatalf("WriteCheckpoint: %v", err)
	}

	// Append more entries.
	logger2, err := NewFileLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		_ = logger2.Log(Entry{
			Timestamp: time.Now().UTC(),
			AgentID:   "new",
			Result:    policy.CheckResult{Decision: policy.Deny},
		})
	}
	logger2.Close()

	// Second replay: must see only the 3 new entries.
	cp, err := ReadCheckpoint(path)
	if err != nil {
		t.Fatalf("ReadCheckpoint: %v", err)
	}
	var second int
	var seenAgents []string
	_, err = ReplayFrom(path, cp, func(e Entry) {
		second++
		seenAgents = append(seenAgents, e.AgentID)
	})
	if err != nil {
		t.Fatalf("second ReplayFrom: %v", err)
	}
	if second != 3 {
		t.Errorf("resumed replay: expected 3 entries, got %d", second)
	}
	for _, a := range seenAgents {
		if a != "new" {
			t.Errorf("resumed replay saw stale entry (agent=%q) — offset not applied", a)
		}
	}
}

// TestReplayFrom_DiscardsCheckpointOnTruncation: if the file is smaller than
// AuditSize recorded in the checkpoint, we must rescan from the start rather
// than seeking past EOF.
func TestReplayFrom_DiscardsCheckpointOnTruncation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	// Make a file with some content.
	logger, err := NewFileLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = logger.Log(Entry{
		Timestamp: time.Now().UTC(),
		AgentID:   "after-truncate",
		Result:    policy.CheckResult{Decision: policy.Allow},
	})
	logger.Close()

	info, _ := os.Stat(path)

	// Pretend the previous boot saved a checkpoint from a much larger file.
	stale := &Checkpoint{Offset: info.Size() + 10_000, AuditSize: info.Size() + 10_000}

	var count int
	_, err = ReplayFrom(path, stale, func(Entry) { count++ })
	if err != nil {
		t.Fatalf("ReplayFrom: %v", err)
	}
	// Meta line + 1 entry → count should be 1 (meta is skipped).
	if count != 1 {
		t.Errorf("stale checkpoint must trigger a full rescan; expected 1 entry, got %d", count)
	}
}

// TestReplayFrom_MissingAuditFile: a brand new deployment (no audit file
// yet) must return (0, nil) rather than erroring.
func TestReplayFrom_MissingAuditFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "never-created.jsonl")
	offset, err := ReplayFrom(path, nil, func(Entry) {
		t.Error("fn must not be invoked for missing file")
	})
	if err != nil {
		t.Errorf("missing file must not error, got: %v", err)
	}
	if offset != 0 {
		t.Errorf("missing file must return offset 0, got %d", offset)
	}
}

// TestFileLogger_Path returns the file path we opened.
func TestFileLogger_Path(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	logger, err := NewFileLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()
	if got := logger.Path(); got != path {
		t.Errorf("Path() = %q, want %q", got, path)
	}
}
