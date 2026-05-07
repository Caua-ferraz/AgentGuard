package mcpgw

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// mockGuardServer stands in for the central AgentGuard /v1/check
// endpoint. Each test wires a handler that returns the policy
// decision it wants to assert on, and the server records every
// received ActionRequest for cross-call assertions (e.g.,
// dual-check fired exactly N times against scope X).
type mockGuardServer struct {
	srv      *httptest.Server
	calls    atomic.Int64
	scopeMu  sync.Mutex
	receivedScopes []string
	receivedReqs   []policy.ActionRequest
	handlerMu sync.Mutex
	handler   func(ar policy.ActionRequest) (status int, result policy.CheckResult, raw string)
}

func newMockGuardServer(t *testing.T) *mockGuardServer {
	t.Helper()
	m := &mockGuardServer{}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.calls.Add(1)
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		// Path must be /v1/t/{tenant}/check.
		if !strings.HasPrefix(r.URL.Path, "/v1/t/") || !strings.HasSuffix(r.URL.Path, "/check") {
			http.Error(w, "path", http.StatusNotFound)
			return
		}
		var ar policy.ActionRequest
		dec := json.NewDecoder(r.Body)
		if err := dec.Decode(&ar); err != nil {
			http.Error(w, "decode: "+err.Error(), http.StatusBadRequest)
			return
		}
		m.scopeMu.Lock()
		m.receivedScopes = append(m.receivedScopes, ar.Scope)
		m.receivedReqs = append(m.receivedReqs, ar)
		m.scopeMu.Unlock()

		m.handlerMu.Lock()
		h := m.handler
		m.handlerMu.Unlock()

		if h == nil {
			// Default: ALLOW.
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(policy.CheckResult{
				SchemaVersion: "v1",
				Decision:      policy.Allow,
				Reason:        "default mock allow",
				Rule:          "allow:mock:default",
			})
			return
		}
		status, result, raw := h(ar)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if raw != "" {
			_, _ = w.Write([]byte(raw))
			return
		}
		_ = json.NewEncoder(w).Encode(result)
	}))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockGuardServer) URL() string { return m.srv.URL }
func (m *mockGuardServer) Calls() int  { return int(m.calls.Load()) }
func (m *mockGuardServer) Scopes() []string {
	m.scopeMu.Lock()
	defer m.scopeMu.Unlock()
	return append([]string{}, m.receivedScopes...)
}
func (m *mockGuardServer) SetHandler(h func(ar policy.ActionRequest) (status int, result policy.CheckResult, raw string)) {
	m.handlerMu.Lock()
	m.handler = h
	m.handlerMu.Unlock()
}

func newGateForTest(t *testing.T, m *mockGuardServer, mode string, pol *policy.Policy) *HTTPPolicyClient {
	t.Helper()
	cfg := &Config{
		GuardURL:   m.URL(),
		APIKey:     "test-key",
		TenantID:   "local",
		PolicyMode: mode,
		FailMode:   "deny",
	}
	return NewHTTPPolicyClient(cfg, pol)
}

func toolsCallReq(fullName string, args map[string]interface{}) *ToolsCallRequest {
	ns, tool, _ := splitNamespacedName(fullName)
	return &ToolsCallRequest{
		Namespace: ns,
		ToolName:  tool,
		FullName:  fullName,
		Arguments: args,
		TenantID:  "local",
		AgentID:   "mcp-gateway:test",
		SessionID: "mcp-gateway:test",
	}
}

// --- Tests ---

func TestHTTPPolicyClient_AllowPath(t *testing.T) {
	m := newMockGuardServer(t)
	gate := newGateForTest(t, m, "fast", nil)

	dec, err := gate.Check(context.Background(), toolsCallReq("fs:read_file", map[string]interface{}{"path": "/tmp/x"}))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !dec.Allow {
		t.Fatalf("expected ALLOW, got %+v", dec)
	}
	if m.Calls() != 1 {
		t.Errorf("expected 1 mock call (fast mode), got %d", m.Calls())
	}
}

func TestHTTPPolicyClient_DenyPath(t *testing.T) {
	m := newMockGuardServer(t)
	m.SetHandler(func(ar policy.ActionRequest) (int, policy.CheckResult, string) {
		return 200, policy.CheckResult{
			SchemaVersion: "v1",
			Decision:      policy.Deny,
			Reason:        "blocked by test",
			Rule:          "deny:mcp_tool:fs:read_file",
		}, ""
	})
	gate := newGateForTest(t, m, "fast", nil)

	dec, err := gate.Check(context.Background(), toolsCallReq("fs:read_file", nil))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if dec.Allow {
		t.Fatalf("expected DENY, got %+v", dec)
	}
	if dec.Rule == "" {
		t.Errorf("expected Rule populated, got empty")
	}
	if dec.RequiresApproval {
		t.Errorf("DENY should not be RequiresApproval")
	}
}

func TestHTTPPolicyClient_ApprovalPath(t *testing.T) {
	m := newMockGuardServer(t)
	m.SetHandler(func(ar policy.ActionRequest) (int, policy.CheckResult, string) {
		return 200, policy.CheckResult{
			SchemaVersion: "v1",
			Decision:      policy.RequireApproval,
			Reason:        "needs approval",
			Rule:          "require_approval:mcp_tool:*",
			ApprovalID:    "ap_deadbeef",
			ApprovalURL:   "http://127.0.0.1:8080/dashboard?approval=ap_deadbeef",
		}, ""
	})
	gate := newGateForTest(t, m, "fast", nil)

	dec, err := gate.Check(context.Background(), toolsCallReq("github:create_issue", nil))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if dec.Allow || !dec.RequiresApproval {
		t.Fatalf("expected RequiresApproval, got %+v", dec)
	}
	if dec.ApprovalID != "ap_deadbeef" || dec.ApprovalURL == "" {
		t.Fatalf("approval id/url not propagated: %+v", dec)
	}
}

func TestHTTPPolicyClient_DualCheckMcpToolDeny(t *testing.T) {
	m := newMockGuardServer(t)
	m.SetHandler(func(ar policy.ActionRequest) (int, policy.CheckResult, string) {
		// mcp_tool denies on first call. Mapped scope must NOT be hit.
		return 200, policy.CheckResult{
			SchemaVersion: "v1",
			Decision:      policy.Deny,
			Reason:        "denied at mcp_tool layer",
			Rule:          "deny:mcp_tool:fs:write_file",
		}, ""
	})

	pol := &policy.Policy{
		Version: "1",
		Name:    "x",
		ToolScopeMap: []policy.ToolScopeMapping{
			{Pattern: "fs:*", Scope: "filesystem"},
		},
	}
	gate := newGateForTest(t, m, "strict", pol)

	dec, err := gate.Check(context.Background(), toolsCallReq("fs:write_file", map[string]interface{}{"path": "/etc/shadow"}))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if dec.Allow {
		t.Fatalf("expected DENY, got %+v", dec)
	}
	if m.Calls() != 1 {
		t.Errorf("strict-mode mcp_tool DENY should short-circuit; expected 1 call, got %d", m.Calls())
	}
	if got := m.Scopes(); len(got) != 1 || got[0] != "mcp_tool" {
		t.Errorf("expected only mcp_tool scope hit, got %v", got)
	}
}

func TestHTTPPolicyClient_DualCheckMappedDeny(t *testing.T) {
	m := newMockGuardServer(t)
	m.SetHandler(func(ar policy.ActionRequest) (int, policy.CheckResult, string) {
		switch ar.Scope {
		case "mcp_tool":
			return 200, policy.CheckResult{
				SchemaVersion: "v1",
				Decision:      policy.Allow,
				Reason:        "ok at mcp layer",
				Rule:          "allow:mcp_tool:fs:read_file",
			}, ""
		case "filesystem":
			return 200, policy.CheckResult{
				SchemaVersion: "v1",
				Decision:      policy.Deny,
				Reason:        "system path blocked",
				Rule:          "deny:filesystem:/etc/**",
			}, ""
		}
		return 200, policy.CheckResult{Decision: policy.Allow, Reason: "fallthrough"}, ""
	})

	pol := &policy.Policy{
		Version: "1", Name: "x",
		ToolScopeMap: []policy.ToolScopeMapping{
			{Pattern: "fs:*", Scope: "filesystem"},
		},
	}
	gate := newGateForTest(t, m, "strict", pol)

	dec, err := gate.Check(context.Background(), toolsCallReq("fs:read_file", map[string]interface{}{"path": "/etc/shadow"}))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if dec.Allow {
		t.Fatalf("expected DENY (filesystem layer), got %+v", dec)
	}
	if !strings.Contains(dec.Reason, "mapped scope=filesystem") {
		t.Errorf("expected reason to note the mapped scope, got %q", dec.Reason)
	}
	if m.Calls() != 2 {
		t.Errorf("expected 2 calls (mcp_tool + filesystem), got %d", m.Calls())
	}
	got := m.Scopes()
	if len(got) != 2 || got[0] != "mcp_tool" || got[1] != "filesystem" {
		t.Errorf("expected scope order [mcp_tool, filesystem], got %v", got)
	}
}

func TestHTTPPolicyClient_FastModeSkipsMappedCheck(t *testing.T) {
	m := newMockGuardServer(t)
	m.SetHandler(func(ar policy.ActionRequest) (int, policy.CheckResult, string) {
		return 200, policy.CheckResult{Decision: policy.Allow, Reason: "ok"}, ""
	})

	pol := &policy.Policy{
		Version: "1", Name: "x",
		ToolScopeMap: []policy.ToolScopeMapping{
			{Pattern: "fs:*", Scope: "filesystem"},
		},
	}
	gate := newGateForTest(t, m, "fast", pol)

	dec, err := gate.Check(context.Background(), toolsCallReq("fs:read_file", map[string]interface{}{"path": "/tmp/x"}))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !dec.Allow {
		t.Fatalf("expected ALLOW, got %+v", dec)
	}
	if m.Calls() != 1 {
		t.Errorf("fast mode should skip mapped check; expected 1 call, got %d", m.Calls())
	}
}

func TestHTTPPolicyClient_StrictModeNoMapping(t *testing.T) {
	m := newMockGuardServer(t)
	pol := &policy.Policy{
		Version: "1", Name: "x",
		// No tool_scope_map entry covers this tool.
		ToolScopeMap: []policy.ToolScopeMapping{
			{Pattern: "github:*", Scope: "network"},
		},
	}
	gate := newGateForTest(t, m, "strict", pol)

	dec, err := gate.Check(context.Background(), toolsCallReq("everything:noop", nil))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !dec.Allow {
		t.Fatalf("expected ALLOW, got %+v", dec)
	}
	if m.Calls() != 1 {
		t.Errorf("no mapping should result in single mcp_tool call; got %d", m.Calls())
	}
}

func TestHTTPPolicyClient_FailModeDeny(t *testing.T) {
	// Server that immediately closes the connection on every request.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", 500)
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			return
		}
		_ = conn.Close()
	}))
	defer srv.Close()

	cfg := &Config{
		GuardURL:   srv.URL,
		TenantID:   "local",
		PolicyMode: "fast",
		FailMode:   "deny",
	}
	gate := NewHTTPPolicyClient(cfg, nil)
	gate.HTTPClient = &http.Client{Timeout: 500 * time.Millisecond}

	dec, err := gate.Check(context.Background(), toolsCallReq("fs:read_file", nil))
	if err != nil {
		t.Fatalf("Check should not bubble err in fail-mode deny, got %v", err)
	}
	if dec.Allow {
		t.Fatalf("fail-mode deny should DENY when guard unreachable, got %+v", dec)
	}
	if dec.Rule != FailModeRuleClosed {
		t.Errorf("expected Rule=%s, got %q", FailModeRuleClosed, dec.Rule)
	}
	if !strings.Contains(dec.Reason, "central server unreachable") {
		t.Errorf("expected fail-closed reason, got %q", dec.Reason)
	}
}

func TestHTTPPolicyClient_FailModeAllow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, _ := w.(http.Hijacker)
		conn, _, _ := hj.Hijack()
		_ = conn.Close()
	}))
	defer srv.Close()

	cfg := &Config{
		GuardURL:   srv.URL,
		TenantID:   "local",
		PolicyMode: "fast",
		FailMode:   "allow",
	}
	gate := NewHTTPPolicyClient(cfg, nil)
	gate.HTTPClient = &http.Client{Timeout: 500 * time.Millisecond}

	dec, err := gate.Check(context.Background(), toolsCallReq("fs:read_file", nil))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !dec.Allow {
		t.Fatalf("fail-mode allow should ALLOW when guard unreachable, got %+v", dec)
	}
	if dec.Rule != "allow:gateway:fail_open" {
		t.Errorf("expected fail-open rule, got %q", dec.Rule)
	}
}

func TestHTTPPolicyClient_PolicyWatchUpdatesCache(t *testing.T) {
	m := newMockGuardServer(t)
	m.SetHandler(func(ar policy.ActionRequest) (int, policy.CheckResult, string) {
		return 200, policy.CheckResult{Decision: policy.Allow, Reason: "ok"}, ""
	})

	// Initial: no map entry covers "fs:read_file".
	pol1 := &policy.Policy{Version: "1", Name: "v1"}
	gate := newGateForTest(t, m, "strict", pol1)

	dec, err := gate.Check(context.Background(), toolsCallReq("fs:read_file", map[string]interface{}{"path": "/tmp/x"}))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !dec.Allow {
		t.Fatalf("expected ALLOW, got %+v", dec)
	}
	if m.Calls() != 1 {
		t.Fatalf("expected 1 call before SetPolicy, got %d", m.Calls())
	}

	// After update: tool now maps to filesystem → expect dual-check.
	pol2 := &policy.Policy{
		Version: "1", Name: "v2",
		ToolScopeMap: []policy.ToolScopeMapping{
			{Pattern: "fs:*", Scope: "filesystem"},
		},
	}
	gate.SetPolicy(pol2)

	dec, err = gate.Check(context.Background(), toolsCallReq("fs:read_file", map[string]interface{}{"path": "/tmp/x"}))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !dec.Allow {
		t.Fatalf("expected ALLOW, got %+v", dec)
	}
	if m.Calls() != 3 {
		t.Errorf("expected 3 total calls (1 + 2 dual-check), got %d", m.Calls())
	}
}

func TestHTTPPolicyClient_BuildsTenantURL(t *testing.T) {
	var capturedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(policy.CheckResult{
			SchemaVersion: "v1",
			Decision:      policy.Allow,
		})
	}))
	defer srv.Close()

	cfg := &Config{
		GuardURL:   srv.URL,
		TenantID:   "local",
		PolicyMode: "fast",
		FailMode:   "deny",
	}
	gate := NewHTTPPolicyClient(cfg, nil)

	if _, err := gate.Check(context.Background(), toolsCallReq("fs:read_file", nil)); err != nil {
		t.Fatalf("Check err: %v", err)
	}
	if capturedPath != "/v1/t/local/check" {
		t.Errorf("expected tenant URL /v1/t/local/check, got %q", capturedPath)
	}
}

func TestHTTPPolicyClient_SendsBearerHeader(t *testing.T) {
	var capturedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(policy.CheckResult{
			SchemaVersion: "v1",
			Decision:      policy.Allow,
		})
	}))
	defer srv.Close()

	cfg := &Config{
		GuardURL:   srv.URL,
		APIKey:     "supersecret",
		TenantID:   "local",
		PolicyMode: "fast",
		FailMode:   "deny",
	}
	gate := NewHTTPPolicyClient(cfg, nil)
	if _, err := gate.Check(context.Background(), toolsCallReq("fs:read_file", nil)); err != nil {
		t.Fatalf("Check err: %v", err)
	}
	if capturedAuth != "Bearer supersecret" {
		t.Errorf("expected Bearer header, got %q", capturedAuth)
	}
}

func TestBuildMappedActionRequest_FilesystemArgs(t *testing.T) {
	ar := buildMappedActionRequest(toolsCallReq("fs:read_file", map[string]interface{}{
		"path": "/etc/shadow",
	}), "filesystem")
	if ar.Path != "/etc/shadow" {
		t.Errorf("expected Path=/etc/shadow, got %q", ar.Path)
	}
	if ar.Action != "read" {
		t.Errorf("expected Action=read, got %q", ar.Action)
	}
}

func TestBuildMappedActionRequest_NetworkArgs(t *testing.T) {
	ar := buildMappedActionRequest(toolsCallReq("github:fetch_issue", map[string]interface{}{
		"url": "https://api.github.com/repos/x/y/issues/1",
	}), "network")
	if ar.URL == "" {
		t.Fatalf("URL should be populated")
	}
	if ar.Domain != "api.github.com" {
		t.Errorf("expected Domain=api.github.com, got %q", ar.Domain)
	}
}

func TestBuildMappedActionRequest_ShellArgs(t *testing.T) {
	ar := buildMappedActionRequest(toolsCallReq("runner:execute", map[string]interface{}{
		"command": "rm -rf /",
	}), "shell")
	if ar.Command != "rm -rf /" {
		t.Errorf("expected Command='rm -rf /', got %q", ar.Command)
	}
}

// TestHTTPPolicyClient_PropagatesApprovalID — A19b. The bridge stamps
// ToolsCallRequest.ApprovalID from `_meta.dev.agentguard/approval_id`;
// the gateway's HTTPPolicyClient must forward this as a top-level
// ApprovalID field on the /v1/check body so the central server can
// look up the approval queue and short-circuit. This pins the wire
// shape — without it, the "approve once, model proceeds" UX would
// silently degrade to "every retry creates a fresh approval".
func TestHTTPPolicyClient_PropagatesApprovalID(t *testing.T) {
	m := newMockGuardServer(t)
	gate := newGateForTest(t, m, "fast", nil)

	req := toolsCallReq("fs:dangerous_tool", map[string]interface{}{"target": "x"})
	req.ApprovalID = "ap_12345_test_round_trip"

	if _, err := gate.Check(context.Background(), req); err != nil {
		t.Fatalf("Check: %v", err)
	}

	m.scopeMu.Lock()
	defer m.scopeMu.Unlock()
	if len(m.receivedReqs) == 0 {
		t.Fatal("mock server received zero requests")
	}
	for _, ar := range m.receivedReqs {
		if ar.ApprovalID != req.ApprovalID {
			t.Errorf("ActionRequest.ApprovalID = %q; want %q (scope=%s)", ar.ApprovalID, req.ApprovalID, ar.Scope)
		}
	}
}

// TestHTTPPolicyClient_PropagatesApprovalID_DualCheck — same
// guarantee for the strict-mode dual-check path: the approval id
// must appear on BOTH the mcp_tool and the mapped-scope /v1/check
// calls so the server can short-circuit either layer's decision.
func TestHTTPPolicyClient_PropagatesApprovalID_DualCheck(t *testing.T) {
	m := newMockGuardServer(t)
	pol := &policy.Policy{
		Version: "1",
		Name:    "x",
		ToolScopeMap: []policy.ToolScopeMapping{
			{Pattern: "fs:*", Scope: "filesystem"},
		},
	}
	gate := newGateForTest(t, m, "strict", pol)

	req := toolsCallReq("fs:write_file", map[string]interface{}{"path": "/tmp/x"})
	req.ApprovalID = "ap_dualcheck_test"

	if _, err := gate.Check(context.Background(), req); err != nil {
		t.Fatalf("Check: %v", err)
	}

	m.scopeMu.Lock()
	defer m.scopeMu.Unlock()
	if len(m.receivedReqs) != 2 {
		t.Fatalf("expected 2 mock calls (mcp_tool + filesystem), got %d", len(m.receivedReqs))
	}
	for _, ar := range m.receivedReqs {
		if ar.ApprovalID != req.ApprovalID {
			t.Errorf("ActionRequest.ApprovalID on scope=%s = %q; want %q", ar.Scope, ar.ApprovalID, req.ApprovalID)
		}
	}
}

func TestInferFilesystemAction(t *testing.T) {
	cases := map[string]string{
		"read_file":   "read",
		"list_dir":    "read",
		"get_file":    "read",
		"write_file":  "write",
		"edit_file":   "write",
		"delete_file": "delete",
		"remove_dir":  "delete",
		"unknown":     "",
	}
	for in, want := range cases {
		if got := inferFilesystemAction(in); got != want {
			t.Errorf("inferFilesystemAction(%q) = %q, want %q", in, got, want)
		}
	}
}
