package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// TestFileLogger_Permissions verifies the audit log is created with owner-only permissions.
func TestFileLogger_Permissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permission checks are not reliable on Windows")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "perm_audit.jsonl")

	logger, err := NewFileLogger(path)
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	defer logger.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}

	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("expected file permissions 0600, got %04o", perm)
	}
}

// TestFileLogger_CorruptEntry verifies that corrupt JSON entries are skipped
// during Query without breaking subsequent valid entries.
func TestFileLogger_CorruptEntry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "corrupt_audit.jsonl")

	// Write a valid entry, then corrupt data, then another valid entry
	logger, err := NewFileLogger(path)
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	if err := logger.Log(Entry{
		AgentID: "bot-1",
		Request: policy.ActionRequest{Scope: "shell", Command: "echo first"},
		Result:  policy.CheckResult{Decision: policy.Allow, Reason: "ok"},
	}); err != nil {
		t.Fatalf("Log: %v", err)
	}
	logger.Close()

	// Manually inject corrupt data
	f, _ := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
	_, _ = f.WriteString("{corrupt json\n")
	f.Close()

	// Write another valid entry
	logger2, err := NewFileLogger(path)
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	if err := logger2.Log(Entry{
		AgentID: "bot-2",
		Request: policy.ActionRequest{Scope: "shell", Command: "echo second"},
		Result:  policy.CheckResult{Decision: policy.Allow, Reason: "ok"},
	}); err != nil {
		t.Fatalf("Log: %v", err)
	}

	// Query should return both valid entries (skipping corrupt one)
	results, err := logger2.Query(QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	logger2.Close()

	if len(results) != 2 {
		t.Errorf("expected 2 valid entries (corrupt skipped), got %d", len(results))
	}
	if len(results) > 0 && results[0].AgentID != "bot-1" {
		t.Errorf("first entry agent should be bot-1, got %s", results[0].AgentID)
	}
	if len(results) > 1 && results[1].AgentID != "bot-2" {
		t.Errorf("second entry agent should be bot-2, got %s", results[1].AgentID)
	}
}

// TestFileLogger_QueryCombinedFilters verifies that multiple filters work together.
func TestFileLogger_QueryCombinedFilters(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "combined_audit.jsonl")

	logger, err := NewFileLogger(path)
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	defer logger.Close()

	entries := []Entry{
		{AgentID: "bot-a", Request: policy.ActionRequest{Scope: "shell"}, Result: policy.CheckResult{Decision: policy.Allow}},
		{AgentID: "bot-a", Request: policy.ActionRequest{Scope: "network"}, Result: policy.CheckResult{Decision: policy.Deny}},
		{AgentID: "bot-b", Request: policy.ActionRequest{Scope: "shell"}, Result: policy.CheckResult{Decision: policy.Deny}},
		{AgentID: "bot-a", Request: policy.ActionRequest{Scope: "shell"}, Result: policy.CheckResult{Decision: policy.Deny}},
	}
	for _, e := range entries {
		if err := logger.Log(e); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}

	// Agent=bot-a AND Decision=DENY
	results, err := logger.Query(QueryFilter{AgentID: "bot-a", Decision: "DENY"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("expected 2 entries (bot-a + DENY), got %d", len(results))
	}

	// Agent=bot-a AND Scope=shell
	results, err = logger.Query(QueryFilter{AgentID: "bot-a", Scope: "shell"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("expected 2 entries (bot-a + shell), got %d", len(results))
	}

	// Agent=bot-a AND Scope=shell AND Decision=DENY
	results, err = logger.Query(QueryFilter{AgentID: "bot-a", Scope: "shell", Decision: "DENY"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("expected 1 entry (bot-a + shell + DENY), got %d", len(results))
	}
}

// TestFileLogger_EmptyLog verifies querying an empty log returns empty slice.
func TestFileLogger_EmptyLog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty_audit.jsonl")

	logger, err := NewFileLogger(path)
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	defer logger.Close()

	results, err := logger.Query(QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 entries from empty log, got %d", len(results))
	}
}

// TestFileLogger_LargeVolume verifies logging and querying many entries.
func TestFileLogger_LargeVolume(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "volume_audit.jsonl")

	logger, err := NewFileLogger(path)
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	defer logger.Close()

	n := 500
	for i := 0; i < n; i++ {
		if err := logger.Log(Entry{
			AgentID: "bot",
			Request: policy.ActionRequest{Scope: "shell", Command: "echo test"},
			Result:  policy.CheckResult{Decision: policy.Allow, Reason: "ok"},
		}); err != nil {
			t.Fatalf("Log %d: %v", i, err)
		}
	}

	results, err := logger.Query(QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(results) != n {
		t.Errorf("expected %d entries, got %d", n, len(results))
	}

	// Query with limit
	results, err = logger.Query(QueryFilter{Limit: 10})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(results) != 10 {
		t.Errorf("expected 10 entries with limit, got %d", len(results))
	}
}

// TestScannerErrChecked verifies that Query surfaces an error when the
// audit log contains a single line that exceeds the scanner's max buffer
// (bufio.ErrTooLong). The contract: return both the successfully decoded
// prefix AND a non-nil error so callers know the result set is incomplete.
func TestScannerErrChecked(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	// Step 1: write a valid entry through NewFileLogger (so the meta
	// header is in place and a real Entry follows it).
	logger, err := NewFileLogger(path)
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	good := Entry{
		AgentID: "bot-a",
		Request: policy.ActionRequest{Scope: "shell", Command: "ls"},
		Result:  policy.CheckResult{Decision: policy.Allow, Reason: "ok"},
	}
	if err := logger.Log(good); err != nil {
		t.Fatalf("Log good: %v", err)
	}
	logger.Close()

	// Step 2: append a 5 MiB line directly to the file. We construct a
	// JSON object whose `request.command` field is one giant string. This
	// line is well past the 4 MiB scanner buffer so Scan() halts with
	// bufio.ErrTooLong before consuming the trailing newline.
	huge := strings.Repeat("A", 5*1024*1024)
	bad := Entry{
		AgentID: "bot-bad",
		Request: policy.ActionRequest{Scope: "shell", Command: huge},
		Result:  policy.CheckResult{Decision: policy.Allow, Reason: "huge"},
	}
	encoded, err := json.Marshal(bad)
	if err != nil {
		t.Fatalf("marshal bad: %v", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("open for append: %v", err)
	}
	if _, err := f.Write(append(encoded, '\n')); err != nil {
		t.Fatalf("write huge: %v", err)
	}
	f.Close()

	// Step 3: Query — must return an error AND the valid entry collected
	// before the scanner halted.
	logger2, err := NewFileLogger(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer logger2.Close()

	results, err := logger2.Query(QueryFilter{})
	if err == nil {
		t.Fatal("Query: expected scanner error for oversize line, got nil")
	}
	if len(results) != 1 {
		t.Fatalf("Query: expected 1 valid entry returned alongside error, got %d", len(results))
	}
	if results[0].AgentID != "bot-a" {
		t.Errorf("Query: expected the small entry to come back, got AgentID=%q", results[0].AgentID)
	}
}
