package gateclient

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

func TestNewFallbackAuditWriter_EmptyPathDisables(t *testing.T) {
	if w := NewFallbackAuditWriter(""); w != nil {
		t.Fatalf("empty path must return nil writer, got %v", w)
	}
	// nil receiver is a no-op, never a panic.
	var w *FallbackAuditWriter
	w.Record(policy.ActionRequest{Scope: "shell"}, Decision{}, "llm_api_proxy", "local")
}

func TestFallbackAuditWriter_RecordsCanonicalEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fail-audit.jsonl")
	w := NewFallbackAuditWriter(path)

	ar := policy.ActionRequest{
		Scope:     "shell",
		AgentID:   "agent-x",
		SessionID: "sess-9",
		Command:   "rm -rf /",
	}
	d := Decision{
		Allow:  false,
		Reason: "central server unreachable: connection refused",
		Rule:   "deny:gateway:fail_closed_audit",
	}
	w.Record(ar, d, "mcp_gateway", "acme")
	w.Record(ar, Decision{Allow: true, Rule: "allow:gateway:fail_open"}, "mcp_gateway", "acme")

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open fallback file: %v", err)
	}
	defer f.Close()

	var entries []audit.Entry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e audit.Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("fallback line is not a canonical audit.Entry: %v\nline: %s", err, sc.Text())
		}
		entries = append(entries, e)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(entries))
	}

	e := entries[0]
	if e.AgentID != "agent-x" || e.SessionID != "sess-9" || e.TenantID != "acme" ||
		e.Transport != "mcp_gateway" || e.Request.Command != "rm -rf /" {
		t.Errorf("entry fields wrong: %+v", e)
	}
	if e.Result.Decision != policy.Deny || e.Result.Rule != "deny:gateway:fail_closed_audit" {
		t.Errorf("entry result wrong: %+v", e.Result)
	}
	if e.Timestamp.IsZero() {
		t.Error("timestamp must be stamped")
	}
	if entries[1].Result.Decision != policy.Allow {
		t.Errorf("fail-open record should carry ALLOW, got %v", entries[1].Result.Decision)
	}
}
