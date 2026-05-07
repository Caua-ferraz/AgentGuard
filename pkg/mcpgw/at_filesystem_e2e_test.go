package mcpgw_test

// AT (Test Wrangler) — filesystem allow/deny E2E.
//
// The plan called for this scenario against
// `npx @modelcontextprotocol/server-filesystem`. We substitute the
// Phase 4B Go stub (testdata/stub_server) and hand-code read_file
// semantics, because:
//   - Node/npx is not guaranteed in CI runners.
//   - The substitution exercises the SAME bridge code path; the
//     filesystem-server-specific behaviour (real read of /etc/passwd)
//     is irrelevant for verifying the AgentGuard DENY before the call.
//
// What this test exercises end-to-end:
//
//   1. A real central AgentGuard server (pkg/proxy.NewServer) backed
//      by an on-disk audit log and a real Engine.
//   2. A real MCP gateway (pkg/mcpgw.Bridge) wired against the central
//      server via mcpgw.HTTPPolicyClient (A18's gate).
//   3. A stub upstream pretending to be a filesystem MCP server.
//
// The policy denies reads under /etc/** and allows reads under /tmp/**.
// We drive two tools/call requests through the bridge and assert:
//   - /etc/passwd → JSON-RPC error or isError=true content block
//     (per docs/MCP_GATEWAY.md § 6.1)
//   - /tmp/hello.txt → success
//   - The audit log on the central server has TWO entries with
//     transport: "mcp_gateway", one ALLOW one DENY.

import (
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/mcpgw"
	"github.com/Caua-ferraz/AgentGuard/pkg/notify"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
	"github.com/Caua-ferraz/AgentGuard/pkg/proxy"
)

// startCentralServer boots a real pkg/proxy.Server with the supplied
// policy + a fresh on-disk audit log under tempDir. Returns the
// server's base URL, a handle to the audit logger (for end-of-test
// inspection), and an HTTP-test server bound to it.
func startCentralServer(t *testing.T, pol *policy.Policy) (baseURL string, logger audit.Logger, ts *httptest.Server) {
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
		APIKey:           "AT-e2e-secret",
		BaseURL:          "http://127.0.0.1:0",
		Version:          "test",
	}
	srv := proxy.NewServer(cfg)
	ts = httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts.URL, fl, ts
}

// TestAT_FilesystemE2E_AllowAndDeny is the headline v0.5 E2E.
func TestAT_FilesystemE2E_AllowAndDeny(t *testing.T) {
	if testing.Short() {
		t.Skip("skip in short mode (boots central server + spawns subprocess)")
	}

	// Policy: mcp_tool allows fs:read_file (so the dual-check flows
	// to the mapped scope); filesystem allows /tmp/** and denies /etc/**.
	pol := &policy.Policy{
		Version: "1",
		Name:    "AT-fs-e2e",
		Rules: []policy.RuleSet{
			{
				Scope: "mcp_tool",
				Allow: []policy.Rule{
					{Pattern: "fs:*"},
				},
			},
			{
				Scope: "filesystem",
				Deny: []policy.Rule{
					{
						Action:  "read",
						Paths:   []string{"/etc/**"},
						Message: "system files are off-limits",
					},
				},
				Allow: []policy.Rule{
					{
						Action: "read",
						Paths:  []string{"/tmp/**"},
					},
				},
			},
		},
		ToolScopeMap: []policy.ToolScopeMapping{
			{Pattern: "fs:*", Scope: "filesystem"},
		},
	}

	centralURL, fl, _ := startCentralServer(t, pol)

	// Build the gateway with a real stub upstream + the gate pointed at
	// the central server.
	cfg := &mcpgw.Config{
		GuardURL:                  centralURL,
		APIKey:                    "AT-e2e-secret",
		TenantID:                  "local",
		FailMode:                  "deny",
		PolicyMode:                "strict",
		LogLevel:                  "info",
		UpstreamTimeout:           5 * time.Second,
		ReconnectCap:              60 * time.Second,
		SupportedProtocolVersions: append([]string{}, mcpgw.DefaultSupportedProtocolVersions...),
		Upstreams: []mcpgw.UpstreamSpec{
			{Namespace: "fs", Command: "stub-server", Transport: "stdio"},
		},
	}
	bridge := mcpgw.NewBridge(cfg, io.Discard, "0.5.0-AT-fs-e2e")

	// Wire A18's gate against the central server.
	gate := mcpgw.NewHTTPPolicyClient(cfg, pol)
	bridge.PolicyCheck = gate.Check

	// Spawn a real stub_server to play the upstream filesystem server.
	factory := stubFactoryForE2E(t,
		"--name", "stub-fs",
		"--tool", "read_file",
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
		t.Fatalf("stub up.Start: %v", err)
	}
	if _, err := up.Initialize(startCtx, "2025-11-25", map[string]interface{}{}, mcpgw.ClientInfo{Name: "AT"}); err != nil {
		t.Fatalf("stub up.Initialize: %v", err)
	}
	bridge.SetUpstream(up)
	t.Cleanup(func() { _ = up.Close() })

	// Drive the bridge through stdin/stdout pipes.
	h := newE2EHarness(t, bridge)

	// Initialize handshake (host → gateway).
	h.send(map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2025-11-25",
			"capabilities":    map[string]interface{}{},
			"clientInfo":      map[string]interface{}{"name": "AT-e2e"},
		},
	})
	if r := h.readResponse(); r.Error != nil {
		t.Fatalf("initialize: %+v", r.Error)
	}

	// Call 1: /tmp/hello.txt → ALLOW.
	h.send(map[string]interface{}{
		"jsonrpc": "2.0", "id": 2, "method": "tools/call",
		"params": map[string]interface{}{
			"name":      "fs:read_file",
			"arguments": map[string]interface{}{"path": "/tmp/hello.txt"},
		},
	})
	r1 := h.readResponse()
	if r1.Error != nil {
		t.Fatalf("/tmp call returned JSON-RPC error: %+v", r1.Error)
	}
	var allowResult mcpgw.ToolsCallResult
	if err := json.Unmarshal(r1.Result, &allowResult); err != nil {
		t.Fatalf("decode allow: %v", err)
	}
	if allowResult.IsError {
		t.Errorf("/tmp/hello.txt should have been ALLOWed, but got isError=true: %+v", allowResult)
	}

	// Call 2: /etc/passwd → DENY (filesystem scope deny via dual-check).
	h.send(map[string]interface{}{
		"jsonrpc": "2.0", "id": 3, "method": "tools/call",
		"params": map[string]interface{}{
			"name":      "fs:read_file",
			"arguments": map[string]interface{}{"path": "/etc/passwd"},
		},
	})
	r2 := h.readResponse()
	if r2.Error != nil {
		// JSON-RPC error path is also acceptable per the design (some
		// future build may surface deny as -32000); v0.5 prefers the
		// isError tool result.
		t.Logf("got JSON-RPC error path on deny: %+v", r2.Error)
	} else {
		var denyResult mcpgw.ToolsCallResult
		if err := json.Unmarshal(r2.Result, &denyResult); err != nil {
			t.Fatalf("decode deny: %v", err)
		}
		if !denyResult.IsError {
			t.Fatalf("/etc/passwd should have been DENIED (isError=true), got %+v", denyResult)
		}
		if !strings.Contains(denyResult.Content[0].Text, "denied") &&
			!strings.Contains(denyResult.Content[0].Text, "DENY") {
			t.Errorf("deny content text doesn't mention denial: %q", denyResult.Content[0].Text)
		}
	}

	// Verify the audit log on the central server has two entries with
	// transport=mcp_gateway. The gate fires TWO checks per tools/call
	// in strict mode (mcp_tool + filesystem); we expect 4 audit entries
	// for the ALLOW path (2 ALLOW) + at least 2 for the DENY path (1
	// mcp_tool ALLOW + 1 filesystem DENY).
	entries, err := fl.Query(audit.QueryFilter{
		Transport: audit.TransportMCPGateway,
	})
	if err != nil {
		t.Fatalf("audit query: %v", err)
	}
	if len(entries) < 3 {
		t.Fatalf("expected at least 3 mcp_gateway audit entries, got %d", len(entries))
	}
	var sawAllow, sawDeny bool
	for _, e := range entries {
		if e.Transport != audit.TransportMCPGateway {
			t.Errorf("entry transport = %q; want mcp_gateway", e.Transport)
		}
		if string(e.Result.Decision) == "ALLOW" {
			sawAllow = true
		}
		if string(e.Result.Decision) == "DENY" {
			sawDeny = true
		}
	}
	if !sawAllow {
		t.Errorf("audit log missing any ALLOW mcp_gateway entry")
	}
	if !sawDeny {
		t.Errorf("audit log missing any DENY mcp_gateway entry (the dual-check filesystem deny)")
	}
}
