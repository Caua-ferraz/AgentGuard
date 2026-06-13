package llmproxy

// gate_test.go covers the HTTPPolicyClient: /v1/check wire shape, mapped
// scope projection, fail-mode branches, hot-reload, and argument
// projection helpers. Mirrors pkg/mcpgw/gate_test.go's mock-server
// pattern so reviewing across the two proxies stays mechanical.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// mockGuardServer stands in for the central AgentGuard /v1/check
// endpoint. Tests register a handler that returns the desired
// CheckResult; the server records every received ActionRequest for
// cross-call assertions.
type mockGuardServer struct {
	srv            *httptest.Server
	calls          atomic.Int64
	mu             sync.Mutex
	receivedReqs   []policy.ActionRequest
	receivedScopes []string
	handlerMu      sync.Mutex
	handler        func(ar policy.ActionRequest) (status int, result policy.CheckResult, raw string)
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
		if !strings.HasPrefix(r.URL.Path, "/v1/t/") || !strings.HasSuffix(r.URL.Path, "/check") {
			http.Error(w, "path", http.StatusNotFound)
			return
		}
		var ar policy.ActionRequest
		if err := json.NewDecoder(r.Body).Decode(&ar); err != nil {
			http.Error(w, "decode: "+err.Error(), http.StatusBadRequest)
			return
		}
		m.mu.Lock()
		m.receivedReqs = append(m.receivedReqs, ar)
		m.receivedScopes = append(m.receivedScopes, ar.Scope)
		m.mu.Unlock()

		m.handlerMu.Lock()
		h := m.handler
		m.handlerMu.Unlock()

		if h == nil {
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
func (m *mockGuardServer) Received() []policy.ActionRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]policy.ActionRequest, len(m.receivedReqs))
	copy(out, m.receivedReqs)
	return out
}
func (m *mockGuardServer) SetHandler(h func(ar policy.ActionRequest) (int, policy.CheckResult, string)) {
	m.handlerMu.Lock()
	m.handler = h
	m.handlerMu.Unlock()
}

func newGateForTest(t *testing.T, m *mockGuardServer, failMode string, pol *policy.Policy) *HTTPPolicyClient {
	t.Helper()
	cfg := &Config{
		GuardURL: m.URL(),
		APIKey:   "test-key",
		TenantID: "local",
		FailMode: failMode,
	}
	return NewHTTPPolicyClient(cfg, pol)
}

// toolCall builds a ToolCallCheck shaped like A22 would emit.
func toolCall(provider, toolName string, args map[string]interface{}) *ToolCallCheck {
	return &ToolCallCheck{
		Provider:   provider,
		ToolName:   toolName,
		ToolCallID: "call_" + toolName,
		Arguments:  args,
		AgentID:    "llm-proxy",
		SessionID:  "sess_test",
		TenantID:   "local",
		Stream:     true,
	}
}

// --- Decision-path tests ---

func TestLLMHTTPPolicyClient_AllowPath(t *testing.T) {
	m := newMockGuardServer(t)
	gate := newGateForTest(t, m, "deny", nil)

	dec, err := gate.Check(context.Background(), toolCall("openai", "read_file", map[string]interface{}{"path": "/tmp/x"}))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !dec.Allow {
		t.Fatalf("expected ALLOW, got %+v", dec)
	}
	if dec.Rule == "" {
		t.Errorf("expected Rule populated on ALLOW, got empty")
	}
	if m.Calls() != 1 {
		t.Errorf("expected 1 mock call, got %d", m.Calls())
	}
}

func TestLLMHTTPPolicyClient_DenyPath(t *testing.T) {
	m := newMockGuardServer(t)
	m.SetHandler(func(ar policy.ActionRequest) (int, policy.CheckResult, string) {
		return 200, policy.CheckResult{
			SchemaVersion: "v1",
			Decision:      policy.Deny,
			Reason:        "blocked by test",
			Rule:          "deny:filesystem:/etc/**",
		}, ""
	})
	gate := newGateForTest(t, m, "deny", nil)

	dec, err := gate.Check(context.Background(), toolCall("openai", "read_file", map[string]interface{}{"path": "/etc/shadow"}))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if dec.Allow {
		t.Fatalf("expected DENY, got %+v", dec)
	}
	if dec.RequiresApproval {
		t.Errorf("DENY should not be RequiresApproval")
	}
	if dec.Rule == "" {
		t.Errorf("expected Rule populated, got empty")
	}
}

func TestLLMHTTPPolicyClient_ApprovalPath(t *testing.T) {
	m := newMockGuardServer(t)
	m.SetHandler(func(ar policy.ActionRequest) (int, policy.CheckResult, string) {
		return 200, policy.CheckResult{
			SchemaVersion: "v1",
			Decision:      policy.RequireApproval,
			Reason:        "needs human approval",
			Rule:          "require_approval:network:*",
			ApprovalID:    "ap_deadbeef",
			ApprovalURL:   "http://127.0.0.1:8080/dashboard?approval=ap_deadbeef",
		}, ""
	})
	gate := newGateForTest(t, m, "deny", nil)

	dec, err := gate.Check(context.Background(), toolCall("openai", "fetch_url", map[string]interface{}{"url": "https://example.com/p"}))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if dec.Allow || !dec.RequiresApproval {
		t.Fatalf("expected RequiresApproval, got %+v", dec)
	}
	if dec.ApprovalID != "ap_deadbeef" {
		t.Errorf("ApprovalID not propagated: %q", dec.ApprovalID)
	}
	if dec.ApprovalURL == "" {
		t.Errorf("ApprovalURL not propagated: %q", dec.ApprovalURL)
	}
}

// --- Fail-mode tests ---

func unreachableServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hijack and close — guarantees a transport-level error in
		// the gate without depending on httptest.Server.Close ordering.
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
	t.Cleanup(srv.Close)
	return srv
}

func TestLLMHTTPPolicyClient_FailModeDeny(t *testing.T) {
	srv := unreachableServer(t)
	cfg := &Config{
		GuardURL: srv.URL,
		TenantID: "local",
		FailMode: "deny",
	}
	gate := NewHTTPPolicyClient(cfg, nil)
	gate.HTTPClient = &http.Client{Timeout: 500 * time.Millisecond}

	dec, err := gate.Check(context.Background(), toolCall("openai", "bash", map[string]interface{}{"command": "ls"}))
	if err == nil {
		t.Errorf("expected underlying err to surface, got nil")
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

func TestLLMHTTPPolicyClient_FailModeAllow(t *testing.T) {
	srv := unreachableServer(t)
	cfg := &Config{
		GuardURL: srv.URL,
		TenantID: "local",
		FailMode: "allow",
	}
	gate := NewHTTPPolicyClient(cfg, nil)
	gate.HTTPClient = &http.Client{Timeout: 500 * time.Millisecond}

	dec, err := gate.Check(context.Background(), toolCall("openai", "bash", map[string]interface{}{"command": "ls"}))
	if err == nil {
		t.Errorf("expected underlying err to surface even in fail-mode allow")
	}
	if !dec.Allow {
		t.Fatalf("fail-mode allow should ALLOW when guard unreachable, got %+v", dec)
	}
	if dec.Rule != FailModeRuleOpen {
		t.Errorf("expected fail-open rule %q, got %q", FailModeRuleOpen, dec.Rule)
	}
}

func TestLLMHTTPPolicyClient_FailModeClosedAudit(t *testing.T) {
	srv := unreachableServer(t)
	cfg := &Config{
		GuardURL: srv.URL,
		TenantID: "local",
		FailMode: "fail-closed-with-audit",
	}
	gate := NewHTTPPolicyClient(cfg, nil)
	gate.HTTPClient = &http.Client{Timeout: 500 * time.Millisecond}

	dec, _ := gate.Check(context.Background(), toolCall("openai", "bash", map[string]interface{}{"command": "ls"}))
	if dec.Allow {
		t.Fatalf("fail-closed-with-audit should DENY, got %+v", dec)
	}
	if dec.Rule != FailModeRuleClosedAudit {
		t.Errorf("expected fail-closed-audit rule %q, got %q", FailModeRuleClosedAudit, dec.Rule)
	}
}

// --- Wire-shape tests ---

func TestLLMHTTPPolicyClient_StampsTransportMeta(t *testing.T) {
	m := newMockGuardServer(t)
	gate := newGateForTest(t, m, "deny", nil)

	if _, err := gate.Check(context.Background(), toolCall("openai", "read_file", map[string]interface{}{"path": "/tmp/x"})); err != nil {
		t.Fatalf("Check: %v", err)
	}
	got := m.Received()
	if len(got) != 1 {
		t.Fatalf("expected 1 received request, got %d", len(got))
	}
	ar := got[0]
	if ar.Meta["transport"] != "llm_api_proxy" {
		t.Errorf("meta.transport = %q, want llm_api_proxy", ar.Meta["transport"])
	}
	if ar.Meta["provider"] != "openai" {
		t.Errorf("meta.provider = %q, want openai", ar.Meta["provider"])
	}
	if ar.Meta["tool_name"] != "read_file" {
		t.Errorf("meta.tool_name = %q, want read_file", ar.Meta["tool_name"])
	}
	if ar.Meta["tool_call_id"] != "call_read_file" {
		t.Errorf("meta.tool_call_id = %q, want call_read_file", ar.Meta["tool_call_id"])
	}
}

func TestLLMHTTPPolicyClient_StampsMappedScope(t *testing.T) {
	m := newMockGuardServer(t)
	gate := newGateForTest(t, m, "deny", nil)

	cases := []struct {
		toolName  string
		args      map[string]interface{}
		wantScope string
	}{
		{"read_file", map[string]interface{}{"path": "/tmp/x"}, "filesystem"},
		{"bash", map[string]interface{}{"command": "ls"}, "shell"},
		{"web_search", map[string]interface{}{"query": "agentguard"}, "network"},
		{"fetch_url", map[string]interface{}{"url": "https://example.com"}, "network"},
		{"playwright_click", map[string]interface{}{"selector": "#submit"}, "browser"},
	}
	for _, c := range cases {
		if _, err := gate.Check(context.Background(), toolCall("openai", c.toolName, c.args)); err != nil {
			t.Fatalf("Check %s: %v", c.toolName, err)
		}
	}
	got := m.Received()
	if len(got) != len(cases) {
		t.Fatalf("expected %d calls, got %d", len(cases), len(got))
	}
	for i, c := range cases {
		if got[i].Scope != c.wantScope {
			t.Errorf("call %d (%s): scope = %q, want %q", i, c.toolName, got[i].Scope, c.wantScope)
		}
		if got[i].Meta["mapped_scope"] != c.wantScope {
			t.Errorf("call %d (%s): meta.mapped_scope = %q, want %q", i, c.toolName, got[i].Meta["mapped_scope"], c.wantScope)
		}
	}
}

func TestLLMHTTPPolicyClient_StampsUnmappedScopeForUnknownTools(t *testing.T) {
	m := newMockGuardServer(t)
	gate := newGateForTest(t, m, "deny", nil)

	if _, err := gate.Check(context.Background(), toolCall("openai", "totally_unknown_xyz", map[string]interface{}{"foo": "bar"})); err != nil {
		t.Fatalf("Check: %v", err)
	}
	got := m.Received()
	if len(got) != 1 {
		t.Fatalf("expected 1 call, got %d", len(got))
	}
	if got[0].Scope != UnmappedScope {
		t.Errorf("expected scope %q for unmapped tool, got %q", UnmappedScope, got[0].Scope)
	}
}

func TestLLMHTTPPolicyClient_PropagatesApprovalID(t *testing.T) {
	m := newMockGuardServer(t)
	gate := newGateForTest(t, m, "deny", nil)

	tc := toolCall("anthropic", "delete_file", map[string]interface{}{"path": "/etc/shadow"})
	tc.ApprovalID = "ap_round_trip_test"

	if _, err := gate.Check(context.Background(), tc); err != nil {
		t.Fatalf("Check: %v", err)
	}
	got := m.Received()
	if len(got) != 1 {
		t.Fatalf("expected 1 call, got %d", len(got))
	}
	if got[0].ApprovalID != "ap_round_trip_test" {
		t.Errorf("top-level ApprovalID not propagated: got %q", got[0].ApprovalID)
	}
	if got[0].Meta["approval_id"] != "ap_round_trip_test" {
		t.Errorf("meta.approval_id not propagated: got %q", got[0].Meta["approval_id"])
	}
}

func TestLLMHTTPPolicyClient_RedactsSecretArgs(t *testing.T) {
	m := newMockGuardServer(t)
	gate := newGateForTest(t, m, "deny", nil)

	args := map[string]interface{}{
		"command":  "curl -H 'Authorization: Bearer sk-secret-token-12345abcdef' https://api.example.com",
		"password": "hunter2",
	}
	if _, err := gate.Check(context.Background(), toolCall("openai", "bash", args)); err != nil {
		t.Fatalf("Check: %v", err)
	}
	got := m.Received()
	if len(got) != 1 {
		t.Fatalf("expected 1 call, got %d", len(got))
	}
	ar := got[0]
	// Bearer token in command should be scrubbed.
	if strings.Contains(ar.Command, "sk-secret-token-12345abcdef") {
		t.Errorf("command leaked bearer token: %q", ar.Command)
	}
	// Password key in meta should be wholesale redacted by name.
	if ar.Meta["arg_password"] != "[REDACTED]" {
		t.Errorf("expected arg_password redacted by name, got %q", ar.Meta["arg_password"])
	}
}

func TestLLMHTTPPolicyClient_PolicyHotReloadUpdatesMappings(t *testing.T) {
	gate := NewHTTPPolicyClient(&Config{
		GuardURL: "http://example.invalid",
		TenantID: "local",
		FailMode: "deny",
	}, nil)

	// Without operator policy: unknown tool maps to unmapped sentinel.
	if got := gate.MapScope("custom_db_query"); got != UnmappedScope {
		t.Errorf("baseline: MapScope(custom_db_query) = %q, want %q", got, UnmappedScope)
	}

	// With operator policy: tool maps to data scope.
	pol := &policy.Policy{
		Version: "1", Name: "ops",
		ToolScopeMap: []policy.ToolScopeMapping{
			{Pattern: "custom_db_query", Scope: "data"},
		},
	}
	gate.SetPolicy(pol)
	if got := gate.MapScope("custom_db_query"); got != "data" {
		t.Errorf("after SetPolicy: MapScope(custom_db_query) = %q, want data", got)
	}

	// Operator overrides default: read_file → audit instead of filesystem.
	pol2 := &policy.Policy{
		Version: "1", Name: "ops2",
		ToolScopeMap: []policy.ToolScopeMapping{
			{Pattern: "read_file", Scope: "data"},
		},
	}
	gate.SetPolicy(pol2)
	if got := gate.MapScope("read_file"); got != "data" {
		t.Errorf("operator override: MapScope(read_file) = %q, want data", got)
	}
	// And the previously-set custom_db_query is gone (new snapshot replaced).
	if got := gate.MapScope("custom_db_query"); got != UnmappedScope {
		t.Errorf("after second SetPolicy: MapScope(custom_db_query) = %q, want %q (no longer in policy)", got, UnmappedScope)
	}
}

func TestLLMHTTPPolicyClient_BuildsTenantURL(t *testing.T) {
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

	gate := NewHTTPPolicyClient(&Config{
		GuardURL: srv.URL,
		TenantID: "tenant-7",
		FailMode: "deny",
	}, nil)
	if _, err := gate.Check(context.Background(), toolCall("openai", "read_file", nil)); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if capturedPath != "/v1/t/tenant-7/check" {
		t.Errorf("expected tenant URL /v1/t/tenant-7/check, got %q", capturedPath)
	}
}

func TestLLMHTTPPolicyClient_SendsBearerHeader(t *testing.T) {
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

	gate := NewHTTPPolicyClient(&Config{
		GuardURL: srv.URL,
		APIKey:   "supersecret-llm",
		TenantID: "local",
		FailMode: "deny",
	}, nil)
	if _, err := gate.Check(context.Background(), toolCall("openai", "read_file", nil)); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if capturedAuth != "Bearer supersecret-llm" {
		t.Errorf("expected Bearer header, got %q", capturedAuth)
	}
}

func TestLLMHTTPPolicyClient_NilRequestIsRejected(t *testing.T) {
	m := newMockGuardServer(t)
	gate := newGateForTest(t, m, "deny", nil)
	dec, err := gate.Check(context.Background(), nil)
	if err != nil {
		t.Fatalf("nil req should not surface err, got %v", err)
	}
	if dec.Allow {
		t.Errorf("nil req should DENY, got %+v", dec)
	}
	if m.Calls() != 0 {
		t.Errorf("nil req should NOT hit /v1/check, got %d calls", m.Calls())
	}
}

func TestLLMHTTPPolicyClient_Non2xxSurfacesAsFailMode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"server boom"}`))
	}))
	defer srv.Close()

	gate := NewHTTPPolicyClient(&Config{
		GuardURL: srv.URL,
		TenantID: "local",
		FailMode: "deny",
	}, nil)
	dec, err := gate.Check(context.Background(), toolCall("openai", "bash", map[string]interface{}{"command": "ls"}))
	if err == nil {
		t.Errorf("expected non-2xx to surface as err")
	}
	if dec.Allow {
		t.Errorf("non-2xx with fail-mode deny should DENY, got %+v", dec)
	}
	if dec.Rule != FailModeRuleClosed {
		t.Errorf("expected Rule=%s, got %q", FailModeRuleClosed, dec.Rule)
	}
}

// --- Argument projection helpers ---

func TestProjectPath_Filesystem(t *testing.T) {
	cases := []struct {
		name string
		args map[string]interface{}
		want string
	}{
		{"path", map[string]interface{}{"path": "/tmp/a"}, "/tmp/a"},
		{"file_path", map[string]interface{}{"file_path": "/tmp/b"}, "/tmp/b"},
		{"target", map[string]interface{}{"target": "/tmp/c"}, "/tmp/c"},
		{"target_path", map[string]interface{}{"target_path": "/tmp/d"}, "/tmp/d"},
		{"filename", map[string]interface{}{"filename": "/tmp/e"}, "/tmp/e"},
		{"file", map[string]interface{}{"file": "/tmp/f"}, "/tmp/f"},
		{"empty", map[string]interface{}{}, ""},
		{"non-string-skipped", map[string]interface{}{"path": 42}, ""},
		{"empty-string-skipped-then-fallback", map[string]interface{}{"path": "", "file_path": "/tmp/g"}, "/tmp/g"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := projectPath("filesystem", c.args); got != c.want {
				t.Errorf("projectPath = %q, want %q", got, c.want)
			}
		})
	}
}

func TestProjectPath_NonFilesystemReturnsEmpty(t *testing.T) {
	if got := projectPath("network", map[string]interface{}{"path": "/tmp/x"}); got != "" {
		t.Errorf("projectPath should be empty for non-filesystem scope, got %q", got)
	}
}

func TestProjectURL_Network(t *testing.T) {
	cases := []struct {
		name string
		args map[string]interface{}
		want string
	}{
		{"url", map[string]interface{}{"url": "https://a.example/p"}, "https://a.example/p"},
		{"uri", map[string]interface{}{"uri": "https://b.example/p"}, "https://b.example/p"},
		{"endpoint", map[string]interface{}{"endpoint": "https://c.example/p"}, "https://c.example/p"},
		{"target_url", map[string]interface{}{"target_url": "https://d.example/p"}, "https://d.example/p"},
		{"empty", map[string]interface{}{}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := projectURL("network", c.args); got != c.want {
				t.Errorf("projectURL = %q, want %q", got, c.want)
			}
		})
	}
}

func TestProjectURL_BrowserAlsoRecognised(t *testing.T) {
	if got := projectURL("browser", map[string]interface{}{"url": "https://b.example"}); got != "https://b.example" {
		t.Errorf("browser URL should be projected, got %q", got)
	}
}

func TestProjectDomain_Network(t *testing.T) {
	cases := []struct {
		name string
		args map[string]interface{}
		want string
	}{
		{"derived from url", map[string]interface{}{"url": "https://api.example.com/v1/x"}, "api.example.com"},
		{"bare domain arg", map[string]interface{}{"domain": "api.example.com"}, "api.example.com"},
		{"bare host arg", map[string]interface{}{"host": "host.example.com"}, "host.example.com"},
		{"hostname arg", map[string]interface{}{"hostname": "h.example.com"}, "h.example.com"},
		{"url wins over domain", map[string]interface{}{"url": "https://from-url.example", "domain": "from-domain.example"}, "from-url.example"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := projectDomain("network", c.args); got != c.want {
				t.Errorf("projectDomain = %q, want %q", got, c.want)
			}
		})
	}
}

func TestFormatLLMCommand_Shell(t *testing.T) {
	tc := &ToolCallCheck{ToolName: "bash", Arguments: map[string]interface{}{"command": "rm -rf /tmp/x"}}
	if got := formatLLMCommand(tc, "shell", nil); got != "rm -rf /tmp/x" {
		t.Errorf("shell command projection: got %q", got)
	}
}

func TestFormatLLMCommand_Filesystem(t *testing.T) {
	tc := &ToolCallCheck{ToolName: "read_file", Arguments: map[string]interface{}{"path": "/tmp/x"}}
	if got := formatLLMCommand(tc, "filesystem", nil); got != "read_file /tmp/x" {
		t.Errorf("filesystem command projection: got %q", got)
	}
}

func TestFormatLLMCommand_Network(t *testing.T) {
	tc := &ToolCallCheck{ToolName: "fetch_url", Arguments: map[string]interface{}{"url": "https://example.com"}}
	if got := formatLLMCommand(tc, "network", nil); got != "fetch_url https://example.com" {
		t.Errorf("network command projection: got %q", got)
	}
}

func TestFormatLLMCommand_UnmappedFallsBackToToolName(t *testing.T) {
	tc := &ToolCallCheck{ToolName: "weird_tool", Arguments: map[string]interface{}{"x": 1}}
	if got := formatLLMCommand(tc, UnmappedScope, nil); got != "weird_tool" {
		t.Errorf("unmapped projection: got %q", got)
	}
}

func TestIsSecretKeyName(t *testing.T) {
	hits := []string{"password", "Password", "api_token", "AUTH_TOKEN", "GITHUB_TOKEN", "secret", "ApiKey", "apikey", "MY_AUTH"}
	misses := []string{"path", "command", "url", "name", "x"}
	for _, k := range hits {
		if !isSecretKeyName(k) {
			t.Errorf("isSecretKeyName(%q) = false, want true", k)
		}
	}
	for _, k := range misses {
		if isSecretKeyName(k) {
			t.Errorf("isSecretKeyName(%q) = true, want false", k)
		}
	}
}

// TestHTTPPolicyClient_FailClosedWithAudit_WritesLocalFallback: in
// fail-closed-with-audit mode, a /v1/check failure must leave a local
// audit record (--fail-audit-log) so the outage window stays
// reconstructable without the central server.
func TestHTTPPolicyClient_FailClosedWithAudit_WritesLocalFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, _ := w.(http.Hijacker)
		conn, _, _ := hj.Hijack()
		_ = conn.Close()
	}))
	defer srv.Close()

	fallbackPath := filepath.Join(t.TempDir(), "fail-audit.jsonl")
	cfg := &Config{
		GuardURL:     srv.URL,
		TenantID:     "acme",
		FailMode:     "fail-closed-with-audit",
		FailAuditLog: fallbackPath,
	}
	gate := NewHTTPPolicyClient(cfg, nil)
	gate.HTTPClient = &http.Client{Timeout: 250 * time.Millisecond}

	dec, err := gate.Check(context.Background(), &ToolCallCheck{
		ToolName:  "run_command",
		AgentID:   "agent-x",
		Arguments: map[string]interface{}{"command": "rm -rf /"},
	})
	if err == nil {
		t.Fatal("expected transport error alongside the fail-mode decision")
	}
	if dec.Allow || dec.Rule != FailModeRuleClosedAudit {
		t.Fatalf("expected audit-variant deny, got %+v", dec)
	}

	data, rerr := os.ReadFile(fallbackPath)
	if rerr != nil {
		t.Fatalf("fallback file not written: %v", rerr)
	}
	var entry audit.Entry
	if jerr := json.Unmarshal([]byte(strings.TrimSpace(string(data))), &entry); jerr != nil {
		t.Fatalf("fallback line is not a canonical audit.Entry: %v\n%s", jerr, data)
	}
	if entry.Transport != "llm_api_proxy" || entry.TenantID != "acme" ||
		entry.Result.Rule != FailModeRuleClosedAudit || entry.AgentID != "agent-x" {
		t.Errorf("fallback entry fields wrong: %+v", entry)
	}
}
