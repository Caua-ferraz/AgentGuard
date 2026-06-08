package proxy

import (
	"path/filepath"
	"testing"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// TestServerAccessors covers the v0.6 Server.Limiter() / Server.ApprovalQueue()
// accessors used by the persistence syncer — they must return the server's LIVE
// in-memory structures, not copies.
func TestServerAccessors(t *testing.T) {
	lg, err := audit.NewFileLogger(filepath.Join(t.TempDir(), "a.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lg.Close() })

	srv := NewServer(Config{
		Engine: policy.NewEngineFromPolicy(&policy.Policy{Version: "1", Name: "x"}),
		Logger: lg,
	})
	if srv.Limiter() == nil {
		t.Fatal("Limiter() returned nil")
	}
	q := srv.ApprovalQueue()
	if q == nil {
		t.Fatal("ApprovalQueue() returned nil")
	}
	// Adding through the accessor must be visible through the accessor again —
	// i.e. it is the server's live queue, what the syncer snapshots.
	pa, err := q.Add(policy.ActionRequest{Scope: "shell", Command: "ls"}, policy.CheckResult{Decision: policy.RequireApproval}, "local")
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, ok := srv.ApprovalQueue().Lookup(pa.ID, "local"); !ok {
		t.Error("ApprovalQueue() did not expose the server's live queue")
	}
}
