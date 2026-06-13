package mcpgw_test

// AT (Test Wrangler) — approval flow E2E.
//
// Validates docs/MCP_GATEWAY.md § 6.1 + § 6.2 (the `_meta` round-trip):
//
//   1. Tool call against a require_approval rule returns isError=true
//      with the approval_id + approval_url surfaced in `_meta`.
//   2. The dashboard approves the action via /v1/t/local/approve/{id}
//      with the API key.
//   3. /v1/status/{id} reports the approval as resolved=true,
//      decision="ALLOW".
//   4. The model retries the same tools/call with
//      `_meta.dev.agentguard/approval_id` set; the bridge stamps it on
//      the /v1/check body's top-level ApprovalID field; the central
//      server's handleCheck consults the approval queue, sees the
//      resolved ALLOW, and short-circuits. The retry succeeds with a
//      non-error result. The audit log gains a SECOND mcp_gateway
//      entry tagged rule="allow:approved" — investigators can
//      distinguish policy-allowed from human-approved decisions in the
//      audit log.
//
// Important caveat: this test verifies `_meta` round-tripping inside
// the gateway's own retry path. It does NOT verify that real Claude
// Desktop preserves `_meta` across the retry — that's a manual-test
// concern.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/mcpgw"
	"github.com/Caua-ferraz/AgentGuard/pkg/notify"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
	"github.com/Caua-ferraz/AgentGuard/pkg/proxy"
)

// startCentralServerForApproval is a customised version of
// startCentralServer that exposes the audit logger so we can re-query
// after the approval round-trip.
func startCentralServerForApproval(t *testing.T, pol *policy.Policy) (string, audit.Logger) {
	t.Helper()
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	fl, err := audit.NewFileLogger(auditPath)
	if err != nil {
		t.Fatalf("audit logger: %v", err)
	}
	t.Cleanup(func() { _ = fl.Close() })

	cfg := proxy.Config{
		Engine:           policy.NewEngineFromPolicy(pol),
		Logger:           fl,
		DashboardEnabled: false,
		Notifier:         notify.NewDispatcher(policy.NotificationCfg{}),
		APIKey:           "AT-approval-key",
		BaseURL:          "http://127.0.0.1:0",
		Version:          "test",
	}
	srv := proxy.NewServer(cfg)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts.URL, fl
}

// TestAT_ApprovalE2E_RequireApproveRetry drives the full approval
// round-trip.
func TestAT_ApprovalE2E_RequireApproveRetry(t *testing.T) {
	if testing.Short() {
		t.Skip("skip in short mode (boots central server + spawns subprocess)")
	}

	// Policy: mcp_tool requires approval for fs:dangerous_tool.
	pol := &policy.Policy{
		Version: "1",
		Name:    "AT-approval-e2e",
		Rules: []policy.RuleSet{
			{
				Scope: "mcp_tool",
				RequireApproval: []policy.Rule{
					{Pattern: "fs:dangerous_tool"},
				},
				Allow: []policy.Rule{
					{Pattern: "fs:*"}, // safety net
				},
			},
		},
	}

	centralURL, fl := startCentralServerForApproval(t, pol)

	cfg := &mcpgw.Config{
		GuardURL:                  centralURL,
		APIKey:                    "AT-approval-key",
		TenantID:                  "local",
		FailMode:                  "deny",
		PolicyMode:                "fast", // single-check; mapped scope not needed
		LogLevel:                  "info",
		UpstreamTimeout:           5 * time.Second,
		ReconnectCap:              60 * time.Second,
		SupportedProtocolVersions: append([]string{}, mcpgw.DefaultSupportedProtocolVersions...),
		Upstreams: []mcpgw.UpstreamSpec{
			{Namespace: "fs", Command: "stub-server", Transport: "stdio"},
		},
	}
	bridge := mcpgw.NewBridge(cfg, io.Discard, "0.5.0-AT-approval-e2e")
	gate := mcpgw.NewHTTPPolicyClient(cfg, pol)
	bridge.PolicyCheck = gate.Check

	factory := stubFactoryForE2E(t,
		"--name", "stub-fs",
		"--tool", "dangerous_tool",
		"--proto-version", "2025-11-25",
	)
	up := mcpgw.NewStdioUpstreamWithOptions(mcpgw.UpstreamSpec{
		Namespace: "fs",
		Command:   "stub-server",
	}, mcpgw.StdioUpstreamOptions{
		CommandFactory: factory,
		Backoff:        []time.Duration{100 * time.Millisecond},
	})
	startCtx, startCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer startCancel()
	if err := up.Start(startCtx); err != nil {
		t.Fatalf("up.Start: %v", err)
	}
	if _, err := up.Initialize(startCtx, "2025-11-25", map[string]interface{}{}, mcpgw.ClientInfo{Name: "AT-approval"}); err != nil {
		t.Fatalf("up.Initialize: %v", err)
	}
	bridge.SetUpstream(up)
	t.Cleanup(func() { _ = up.Close() })

	h := newE2EHarness(t, bridge)

	// Initialize through bridge.
	h.send(map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2025-11-25",
			"capabilities":    map[string]interface{}{},
			"clientInfo":      map[string]interface{}{"name": "AT-approval"},
		},
	})
	_ = h.readResponse()

	// 1. Call without approval id → REQUIRE_APPROVAL → isError=true,
	//    approval_id in `_meta`.
	h.send(map[string]interface{}{
		"jsonrpc": "2.0", "id": 2, "method": "tools/call",
		"params": map[string]interface{}{
			"name":      "fs:dangerous_tool",
			"arguments": map[string]interface{}{"target": "x"},
		},
	})
	r1 := h.readResponse()
	if r1.Error != nil {
		t.Fatalf("first call returned JSON-RPC error: %+v", r1.Error)
	}
	approvalID, approvalURL := extractApprovalMeta(t, r1.Result)
	if approvalID == "" {
		t.Fatalf("approval response missing approval_id in _meta: %s", string(r1.Result))
	}
	if approvalURL == "" {
		t.Errorf("approval response missing approval_url in _meta: %s", string(r1.Result))
	}

	// 2. Approve via the central server (simulates the dashboard's
	//    POST to /v1/t/local/approve/{id}).
	approveReq, _ := http.NewRequest(http.MethodPost,
		centralURL+"/v1/t/local/approve/"+approvalID,
		bytes.NewReader([]byte(`{}`)))
	approveReq.Header.Set("Authorization", "Bearer AT-approval-key")
	approveReq.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(approveReq)
	if err != nil {
		t.Fatalf("approve POST: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("approve POST status = %d; want 200", resp.StatusCode)
	}

	// 3. Verify /v1/status/{id} reports the approval as resolved
	//    decision=ALLOW. This is the path the SDK polls.
	statusReq, _ := http.NewRequest(http.MethodGet,
		centralURL+"/v1/t/local/status/"+approvalID, nil)
	statusReq.Header.Set("Authorization", "Bearer AT-approval-key")
	statusResp, err := http.DefaultClient.Do(statusReq)
	if err != nil {
		t.Fatalf("status GET: %v", err)
	}
	defer statusResp.Body.Close()
	if statusResp.StatusCode != http.StatusOK {
		t.Fatalf("status GET returned %d", statusResp.StatusCode)
	}
	// Wire shape: {"id": "...", "status": "resolved", "decision": "ALLOW"}
	// or {"id": "...", "status": "pending"}
	var status struct {
		Status   string `json:"status"`
		Decision string `json:"decision"`
	}
	if err := json.NewDecoder(statusResp.Body).Decode(&status); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if status.Status != "resolved" {
		t.Errorf("status.Status = %q; want \"resolved\" after operator approval", status.Status)
	}
	if status.Decision != "ALLOW" {
		t.Errorf("status.Decision = %q; want ALLOW", status.Decision)
	}

	// 4. Retry the tools/call with `_meta.dev.agentguard/approval_id`
	//    set. The bridge stamps it onto ToolsCallRequest.ApprovalID;
	//    HTTPPolicyClient.Check propagates that to the /v1/check body's
	//    top-level ApprovalID field; the central server's handleCheck
	//    consults the approval queue, sees the resolved ALLOW, and
	//    short-circuits without creating a fresh approval entry.
	//    The retry MUST succeed with a non-error result.
	h.send(map[string]interface{}{
		"jsonrpc": "2.0", "id": 3, "method": "tools/call",
		"params": map[string]interface{}{
			"name":      "fs:dangerous_tool",
			"arguments": map[string]interface{}{"target": "x"},
			"_meta": map[string]interface{}{
				mcpgw.MetaApprovalIDKey: approvalID,
			},
		},
	})
	r2 := h.readResponse()
	if r2.Error != nil {
		t.Fatalf("retry returned JSON-RPC error: %+v", r2.Error)
	}
	var retryResult mcpgw.ToolsCallResult
	if err := json.Unmarshal(r2.Result, &retryResult); err != nil {
		t.Fatalf("decode retry: %v", err)
	}
	if retryResult.IsError {
		// Surface the body so a regression here is debuggable from CI logs.
		var bodyText string
		if len(retryResult.Content) > 0 {
			bodyText = retryResult.Content[0].Text
		}
		t.Fatalf("retry returned isError=true; expected ALLOW short-circuit. body: %q", bodyText)
	}
	// The retry must NOT contain a new approval_id in _meta — the
	// short-circuit path returns ALLOW directly.
	if retryID, _ := extractApprovalMeta(t, r2.Result); retryID != "" {
		t.Errorf("retry surfaced approval_id %q in _meta; short-circuit ALLOW should not advertise an approval", retryID)
	}

	// 5. Audit log invariants:
	//    - Two mcp_gateway entries: REQUIRE_APPROVAL on the first call,
	//      ALLOW on the retry.
	//    - The retry's ALLOW carries rule="allow:approved" so audit
	//      investigators can distinguish human-approved from
	//      policy-allowed decisions (T1 reinforcement).
	//    - No fresh approval entry was created on the retry — the
	//      original entry is reused.
	entries, err := fl.Query(audit.QueryFilter{
		Transport: audit.TransportMCPGateway,
	})
	if err != nil {
		t.Fatalf("audit query: %v", err)
	}
	if len(entries) < 2 {
		t.Fatalf("expected ≥2 mcp_gateway audit entries (REQUIRE_APPROVAL + ALLOW), got %d", len(entries))
	}
	var sawRequireApproval, sawAllowApproved bool
	for _, e := range entries {
		if e.EffectiveTransport() != audit.TransportMCPGateway {
			t.Errorf("entry has transport=%q; want mcp_gateway", e.EffectiveTransport())
		}
		switch string(e.Result.Decision) {
		case "REQUIRE_APPROVAL":
			sawRequireApproval = true
		case "ALLOW":
			if e.Result.Rule == "allow:approved" {
				sawAllowApproved = true
			}
		}
	}
	if !sawRequireApproval {
		t.Errorf("audit log missing REQUIRE_APPROVAL entry from the first call")
	}
	if !sawAllowApproved {
		t.Errorf("audit log missing ALLOW entry with rule=allow:approved from the retry; the short-circuit may not have fired")
	}
}

// extractApprovalMeta parses the `_meta` block from a tools/call result
// raw JSON and returns the approval_id + approval_url.
func extractApprovalMeta(t *testing.T, raw json.RawMessage) (id, url string) {
	t.Helper()
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		t.Fatalf("probe result: %v", err)
	}
	metaRaw, ok := probe["_meta"]
	if !ok {
		return "", ""
	}
	var meta map[string]string
	if err := json.Unmarshal(metaRaw, &meta); err != nil {
		t.Fatalf("decode _meta: %v", err)
	}
	return meta[mcpgw.MetaApprovalIDKey], meta["dev.agentguard/approval_url"]
}
