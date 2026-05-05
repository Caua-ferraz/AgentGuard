package audit

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// BenchmarkFileLogger_Log measures single-threaded encode + append cost of
// FileLogger.Log against a fresh temp file. This is the per-request audit
// write that hangs off every /v1/check, so its allocation profile feeds
// directly into the SLO.
//
// Rotation is intentionally disabled here (NewFileLogger, not
// NewFileLoggerWithRotation) so we measure the steady-state path. Closes
// R4 S1 (audit ns/op + B/op baseline).
func BenchmarkFileLogger_Log(b *testing.B) {
	dir := b.TempDir()
	path := filepath.Join(dir, "bench.jsonl")

	logger, err := NewFileLogger(path)
	if err != nil {
		b.Fatalf("NewFileLogger: %v", err)
	}
	b.Cleanup(func() { _ = logger.Close() })

	entry := Entry{
		Timestamp: time.Now().UTC(),
		SessionID: "sess-bench",
		AgentID:   "agent-bench",
		Request: policy.ActionRequest{
			Scope:   "shell",
			Command: "ls -la /tmp",
			AgentID: "agent-bench",
		},
		Result: policy.CheckResult{
			Decision: policy.Allow,
			Reason:   "Allowed by shell rule",
			Rule:     "allow:shell:ls *",
		},
		DurationMs: 1,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := logger.Log(entry); err != nil {
			b.Fatalf("Log: %v", err)
		}
	}
}
