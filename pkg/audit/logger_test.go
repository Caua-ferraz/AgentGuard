package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

func TestFileLogger_LogAndQuery(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test_audit.jsonl")

	logger, err := NewFileLogger(path)
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	defer logger.Close()

	// Log some entries
	entries := []Entry{
		{
			Timestamp: time.Now().UTC(),
			SessionID: "sess-1",
			AgentID:   "bot-a",
			Request: policy.ActionRequest{
				Scope:   "shell",
				Command: "ls -la",
				AgentID: "bot-a",
			},
			Result: policy.CheckResult{
				Decision: policy.Allow,
				Reason:   "Allowed by shell rule",
			},
			DurationMs: 1,
		},
		{
			Timestamp: time.Now().UTC(),
			SessionID: "sess-1",
			AgentID:   "bot-a",
			Request: policy.ActionRequest{
				Scope:   "shell",
				Command: "rm -rf /",
				AgentID: "bot-a",
			},
			Result: policy.CheckResult{
				Decision: policy.Deny,
				Reason:   "Destructive command blocked",
			},
			DurationMs: 0,
		},
		{
			Timestamp: time.Now().UTC(),
			SessionID: "sess-2",
			AgentID:   "bot-b",
			Request: policy.ActionRequest{
				Scope:  "network",
				Domain: "api.openai.com",
			},
			Result: policy.CheckResult{
				Decision: policy.Allow,
				Reason:   "Allowed by network rule",
			},
			DurationMs: 2,
		},
	}

	for _, e := range entries {
		if err := logger.Log(e); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}

	// Query all
	results, err := logger.Query(QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(results) != 3 {
		t.Errorf("expected 3 entries, got %d", len(results))
	}

	// Query by agent
	results, err = logger.Query(QueryFilter{AgentID: "bot-a"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("expected 2 entries for bot-a, got %d", len(results))
	}

	// Query by decision
	results, err = logger.Query(QueryFilter{Decision: "DENY"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("expected 1 DENY entry, got %d", len(results))
	}

	// Query by session
	results, err = logger.Query(QueryFilter{SessionID: "sess-2"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("expected 1 entry for sess-2, got %d", len(results))
	}

	// Query by scope
	results, err = logger.Query(QueryFilter{Scope: "network"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("expected 1 network entry, got %d", len(results))
	}

	// Query with limit
	results, err = logger.Query(QueryFilter{Limit: 1})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("expected 1 entry with limit, got %d", len(results))
	}
}

// TestFileLogger_Offset covers the Phase 1.1 Offset field on QueryFilter.
// Offset discards the first N matching records before Limit is applied, so
// that a UI paginating the audit log can page forward without re-scanning
// from scratch.
func TestFileLogger_Offset(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "offset.jsonl")
	logger, err := NewFileLogger(path)
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	defer logger.Close()

	// Five entries, all for bot-o, with distinct commands so we can assert
	// which slice came back.
	for i := 0; i < 5; i++ {
		if err := logger.Log(Entry{
			Timestamp: time.Now().UTC(),
			AgentID:   "bot-o",
			Request:   policy.ActionRequest{Scope: "shell", Command: fmt.Sprintf("cmd-%d", i)},
			Result:    policy.CheckResult{Decision: policy.Allow, Reason: "ok"},
		}); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}

	cases := []struct {
		name     string
		filter   QueryFilter
		wantCmds []string
	}{
		{"no offset", QueryFilter{}, []string{"cmd-0", "cmd-1", "cmd-2", "cmd-3", "cmd-4"}},
		{"offset skips first two", QueryFilter{Offset: 2}, []string{"cmd-2", "cmd-3", "cmd-4"}},
		{"offset + limit paginates", QueryFilter{Offset: 2, Limit: 2}, []string{"cmd-2", "cmd-3"}},
		{"offset past end is empty", QueryFilter{Offset: 100}, nil},
		{"negative offset treated as zero", QueryFilter{Offset: -3, Limit: 1}, []string{"cmd-0"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := logger.Query(tc.filter)
			if err != nil {
				t.Fatalf("Query: %v", err)
			}
			if len(got) != len(tc.wantCmds) {
				t.Fatalf("got %d entries, want %d", len(got), len(tc.wantCmds))
			}
			for i, want := range tc.wantCmds {
				if got[i].Request.Command != want {
					t.Errorf("entry %d: got %q, want %q", i, got[i].Request.Command, want)
				}
			}
		})
	}
}

func TestFileLogger_Persistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "persist_audit.jsonl")

	// Write with first logger
	logger1, err := NewFileLogger(path)
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	if err := logger1.Log(Entry{
		Timestamp: time.Now().UTC(),
		AgentID:   "bot-1",
		Request:   policy.ActionRequest{Scope: "shell", Command: "echo hello"},
		Result:    policy.CheckResult{Decision: policy.Allow, Reason: "ok"},
	}); err != nil {
		t.Fatalf("Log: %v", err)
	}
	logger1.Close()

	// Read with second logger (append mode)
	logger2, err := NewFileLogger(path)
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	if err := logger2.Log(Entry{
		Timestamp: time.Now().UTC(),
		AgentID:   "bot-2",
		Request:   policy.ActionRequest{Scope: "shell", Command: "echo world"},
		Result:    policy.CheckResult{Decision: policy.Allow, Reason: "ok"},
	}); err != nil {
		t.Fatalf("Log: %v", err)
	}

	results, err := logger2.Query(QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("expected 2 persisted entries, got %d", len(results))
	}
	logger2.Close()
}

func TestFileLogger_AutoTimestamp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ts_audit.jsonl")

	logger, err := NewFileLogger(path)
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	defer logger.Close()

	// Log with zero timestamp — should be auto-filled
	if err := logger.Log(Entry{
		AgentID: "bot",
		Request: policy.ActionRequest{Scope: "shell", Command: "ls"},
		Result:  policy.CheckResult{Decision: policy.Allow, Reason: "ok"},
	}); err != nil {
		t.Fatalf("Log: %v", err)
	}

	results, err := logger.Query(QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(results))
	}
	if results[0].Timestamp.IsZero() {
		t.Error("expected auto-filled timestamp, got zero")
	}
}

func TestMatchesFilter(t *testing.T) {
	entry := Entry{
		Timestamp: time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC),
		SessionID: "sess-1",
		AgentID:   "bot-a",
		Request:   policy.ActionRequest{Scope: "shell"},
		Result:    policy.CheckResult{Decision: policy.Allow},
	}

	tests := []struct {
		name   string
		filter QueryFilter
		want   bool
	}{
		{"empty filter matches all", QueryFilter{}, true},
		{"matching agent", QueryFilter{AgentID: "bot-a"}, true},
		{"non-matching agent", QueryFilter{AgentID: "bot-b"}, false},
		{"matching session", QueryFilter{SessionID: "sess-1"}, true},
		{"non-matching session", QueryFilter{SessionID: "sess-2"}, false},
		{"matching decision", QueryFilter{Decision: "ALLOW"}, true},
		{"non-matching decision", QueryFilter{Decision: "DENY"}, false},
		{"matching scope", QueryFilter{Scope: "shell"}, true},
		{"non-matching scope", QueryFilter{Scope: "network"}, false},
		{
			"since before entry",
			QueryFilter{Since: timePtr(time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC))},
			true,
		},
		{
			"since after entry",
			QueryFilter{Since: timePtr(time.Date(2025, 7, 1, 0, 0, 0, 0, time.UTC))},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchesFilter(entry, tt.filter)
			if got != tt.want {
				t.Errorf("matchesFilter() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewFileLogger_InvalidPath(t *testing.T) {
	_, err := NewFileLogger("/nonexistent/dir/audit.jsonl")
	if err == nil {
		t.Error("expected error for invalid path")
	}
}

func timePtr(t time.Time) *time.Time {
	return &t
}

// Verify the log file actually has content
func TestFileLogger_FileContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "content_audit.jsonl")

	logger, err := NewFileLogger(path)
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	if err := logger.Log(Entry{
		AgentID: "bot",
		Request: policy.ActionRequest{Scope: "shell", Command: "echo test"},
		Result:  policy.CheckResult{Decision: policy.Allow, Reason: "ok"},
	}); err != nil {
		t.Fatalf("Log: %v", err)
	}
	logger.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty log file")
	}
}

// --- Schema v2 header ---

func TestFileLogger_NewFileWritesSchemaHeader(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	logger, err := NewFileLogger(path)
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	logger.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	firstLine := strings.SplitN(string(data), "\n", 2)[0]
	if !strings.HasPrefix(firstLine, `{"_meta"`) {
		t.Errorf("first line of a new audit file must be the _meta header, got %q", firstLine)
	}

	// Unmarshal and verify schema version.
	var env struct {
		Meta struct {
			SchemaVersion int       `json:"schema_version"`
			CreatedAt     time.Time `json:"created_at"`
		} `json:"_meta"`
	}
	if err := json.Unmarshal([]byte(firstLine), &env); err != nil {
		t.Fatalf("parse meta: %v", err)
	}
	if env.Meta.SchemaVersion != CurrentSchemaVersion {
		t.Errorf("expected schema_version=%d, got %d", CurrentSchemaVersion, env.Meta.SchemaVersion)
	}
	if env.Meta.CreatedAt.IsZero() {
		t.Error("created_at must be set in meta record")
	}
}

func TestFileLogger_DoesNotDuplicateHeaderOnReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	// First open: header should be written.
	l1, err := NewFileLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = l1.Log(Entry{Timestamp: time.Now().UTC(), AgentID: "a"})
	l1.Close()

	// Second open: file already has content, no new header.
	l2, err := NewFileLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = l2.Log(Entry{Timestamp: time.Now().UTC(), AgentID: "b"})
	l2.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	count := strings.Count(string(data), `{"_meta"`)
	if count != 1 {
		t.Errorf("expected exactly 1 _meta line across reopens, got %d; contents:\n%s", count, data)
	}
}

func TestFileLogger_Query_SkipsMetaLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	logger, err := NewFileLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = logger.Log(Entry{Timestamp: time.Now().UTC(), AgentID: "a"})
	_ = logger.Log(Entry{Timestamp: time.Now().UTC(), AgentID: "b"})
	logger.Close()

	entries, err := logger.Query(QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("expected exactly 2 entries (meta skipped), got %d: %+v", len(entries), entries)
	}
	for _, e := range entries {
		if e.AgentID == "" {
			t.Errorf("Query returned a record with empty AgentID — looks like the _meta line leaked through: %+v", e)
		}
	}
}

func TestFileLogger_Query_ToleratesLegacyHeaderlessFile(t *testing.T) {
	// Simulate a v0.4.0 audit file that has no _meta header.
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy.jsonl")

	legacy := `{"timestamp":"2025-01-01T00:00:00Z","agent_id":"legacy-a","request":{},"result":{"decision":"ALLOW"}}
{"timestamp":"2025-01-01T00:00:01Z","agent_id":"legacy-b","request":{},"result":{"decision":"DENY"}}
`
	if err := os.WriteFile(path, []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}

	// Opening against a non-empty, headerless file must NOT inject a header.
	logger, err := NewFileLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	logger.Close()

	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), `{"_meta"`) {
		t.Errorf("NewFileLogger must not add a header to a non-empty legacy file; got:\n%s", data)
	}

	// Query still returns both legacy entries.
	l2, err := NewFileLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	entries, err := l2.Query(QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 legacy entries readable, got %d", len(entries))
	}
}

// --- ReadMeta ---

func TestReadMeta_SchemaV2File(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	l, err := NewFileLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	l.Close()

	m, err := ReadMeta(path)
	if err != nil {
		t.Fatalf("ReadMeta: %v", err)
	}
	if m == nil {
		t.Fatal("expected non-nil meta for v2 file")
	}
	if m.SchemaVersion != CurrentSchemaVersion {
		t.Errorf("expected v%d, got v%d", CurrentSchemaVersion, m.SchemaVersion)
	}
}

func TestReadMeta_LegacyFileReturnsNil(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy.jsonl")
	if err := os.WriteFile(path, []byte(`{"timestamp":"2025-01-01T00:00:00Z","agent_id":"x","request":{},"result":{"decision":"ALLOW"}}`+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	m, err := ReadMeta(path)
	if err != nil {
		t.Fatalf("ReadMeta: %v", err)
	}
	if m != nil {
		t.Errorf("expected nil meta for headerless file, got %+v", m)
	}
}

func TestReadMeta_RefusesNewerSchema(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "future.jsonl")
	future := fmt.Sprintf(`{"_meta":{"schema_version":%d,"created_at":"2030-01-01T00:00:00Z"}}`+"\n", CurrentSchemaVersion+5)
	if err := os.WriteFile(path, []byte(future), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := ReadMeta(path)
	if err == nil {
		t.Fatal("ReadMeta must refuse schema_version > CurrentSchemaVersion")
	}
	if !strings.Contains(err.Error(), "schema_version") {
		t.Errorf("error should mention schema_version, got: %v", err)
	}
}
