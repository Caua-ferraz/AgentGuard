package proxy

// Verifies that requests routed through the legacy /v1/check URL and
// requests routed through the tenant-aware /v1/t/local/check URL produce
// equivalent audit-trail entries (modulo per-request fields like
// timestamp / duration_ms / approval_id).
//
// Failure mode this catches: a silent dropped field, a different rule
// string, or one URL family routing through a stale Engine pointer —
// the audit log would diverge between families and downstream consumers
// (SIEM, dashboards) would see inconsistent event streams.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/notify"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// TestATIntegration_TenantAuditParity sends one request via /v1/check
// and an identical request via /v1/t/local/check, queries /v1/audit, and
// asserts every operationally-meaningful field matches across the two
// audit entries.
func TestATIntegration_TenantAuditParity(t *testing.T) {
	const apiKey = "at-tenant-audit-key"

	dir := t.TempDir()
	logger, err := audit.NewFileLogger(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })

	pol := &policy.Policy{
		Version: "1",
		Name:    "at-tenant-audit",
		Rules: []policy.RuleSet{{
			Scope: "shell",
			Allow: []policy.Rule{{Pattern: "ls *"}, {Pattern: "echo *"}},
		}},
	}

	disp := notify.NewDispatcher(policy.NotificationCfg{})
	t.Cleanup(func() { disp.Close() })

	srv := NewServer(Config{
		Port:     0,
		Engine:   policy.NewEngineFromPolicy(pol),
		Logger:   logger,
		Notifier: disp,
		APIKey:   apiKey,
		BaseURL:  "http://127.0.0.1:0",
		Version:  "at-tenant-audit",
	})
	ts := httptest.NewServer(srv.http.Handler)
	t.Cleanup(ts.Close)

	body := `{"scope":"shell","command":"ls -la","agent_id":"at-bot","session_id":"sess-1"}`
	post := func(path string) {
		t.Helper()
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
			ts.URL+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("POST %s status=%d body=%s", path, resp.StatusCode, raw)
		}
	}

	post("/v1/check")
	post("/v1/t/local/check")

	// Give the audit logger a brief moment to flush — FileLogger writes
	// synchronously, but the test must tolerate buffered loggers a future
	// worker may add.
	time.Sleep(50 * time.Millisecond)

	// Query the audit endpoint with the bearer.
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet,
		ts.URL+"/v1/audit?limit=10", nil)
	req.Header.Set("Authorization", "Bearer "+apiKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /v1/audit: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/v1/audit status=%d body=%s", resp.StatusCode, raw)
	}

	// /v1/audit returns a JSON array of Entry directly.
	var entries []audit.Entry
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&entries); err != nil {
		t.Fatalf("decode /v1/audit: %v body=%s", err, raw)
	}

	// Filter to the entries our two POSTs produced.
	var ours []audit.Entry
	for _, e := range entries {
		if e.AgentID == "at-bot" && e.SessionID == "sess-1" {
			ours = append(ours, e)
		}
	}
	if len(ours) < 2 {
		t.Fatalf("expected at least 2 audit entries for at-bot/sess-1, got %d (raw=%s)", len(ours), raw)
	}

	// Compare the two most-recent entries (sorted DESC by timestamp by
	// /v1/audit). Operationally meaningful fields must match.
	a, b := ours[0], ours[1]

	if a.AgentID != b.AgentID {
		t.Errorf("agent_id differs: %q vs %q", a.AgentID, b.AgentID)
	}
	if a.SessionID != b.SessionID {
		t.Errorf("session_id differs: %q vs %q", a.SessionID, b.SessionID)
	}
	if a.Result.Decision != b.Result.Decision {
		t.Errorf("decision differs: %q vs %q", a.Result.Decision, b.Result.Decision)
	}
	if a.Result.Decision != policy.Allow {
		t.Errorf("expected ALLOW, got %s", a.Result.Decision)
	}
	if a.Result.Rule != b.Result.Rule {
		t.Errorf("rule differs: %q vs %q", a.Result.Rule, b.Result.Rule)
	}
	if a.Request.Scope != b.Request.Scope {
		t.Errorf("scope differs: %q vs %q", a.Request.Scope, b.Request.Scope)
	}
	if a.Request.Command != b.Request.Command {
		t.Errorf("command differs: %q vs %q", a.Request.Command, b.Request.Command)
	}
	if a.Request.Action != b.Request.Action {
		t.Errorf("action differs: %q vs %q", a.Request.Action, b.Request.Action)
	}
	if a.Request.Path != b.Request.Path {
		t.Errorf("path differs: %q vs %q", a.Request.Path, b.Request.Path)
	}
	if a.Request.Domain != b.Request.Domain {
		t.Errorf("domain differs: %q vs %q", a.Request.Domain, b.Request.Domain)
	}
}
