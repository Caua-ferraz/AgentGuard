package mcpgw

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeUpstream is an in-process Upstream implementation used by the
// bridge tests. It records every request it receives and responds
// from a programmable handler so tests can assert routing behaviour
// without spawning subprocesses.
type fakeUpstream struct {
	ns       string
	status   atomic.Value // string
	mu       sync.Mutex
	received []recordedReq

	// initResult is returned from Initialize.
	initResult *InitializeResult

	// handleSend dispatches non-initialize requests. If nil, the
	// upstream returns a synthetic ALLOW response.
	handleSend func(req *Request) *Response
}

type recordedReq struct {
	Method string
	Params json.RawMessage
}

func newFakeUpstream(ns string) *fakeUpstream {
	u := &fakeUpstream{ns: ns}
	u.status.Store(StatusOK)
	u.initResult = &InitializeResult{
		ProtocolVersion: "2025-11-25",
		Capabilities: map[string]interface{}{
			"tools": map[string]interface{}{"listChanged": false},
		},
		ServerInfo: ServerInfo{Name: "fake-" + ns, Version: "0.0.0"},
	}
	return u
}

func (u *fakeUpstream) Namespace() string { return u.ns }
func (u *fakeUpstream) Status() string    { return u.status.Load().(string) }

func (u *fakeUpstream) Initialize(ctx context.Context, _ string, _ map[string]interface{}, _ ClientInfo) (*InitializeResult, error) {
	return u.initResult, nil
}

func (u *fakeUpstream) Send(ctx context.Context, req *Request) (*Response, error) {
	u.mu.Lock()
	u.received = append(u.received, recordedReq{Method: req.Method, Params: req.Params})
	u.mu.Unlock()

	if u.handleSend != nil {
		resp := u.handleSend(req)
		resp.ID = req.ID
		return resp, nil
	}
	// Default: empty result.
	return &Response{
		JSONRPC: JSONRPCVersion,
		ID:      req.ID,
		Result:  json.RawMessage(`{}`),
	}, nil
}

func (u *fakeUpstream) Notify(ctx context.Context, n *Notification) error { return nil }
func (u *fakeUpstream) Close() error {
	u.status.Store(StatusStopped)
	return nil
}

// driveBridge runs the bridge against in-memory pipes and returns a
// helper that lets the test send frames + read responses.
type bridgeHarness struct {
	t       *testing.T
	bridge  *Bridge
	stdinW  *io.PipeWriter
	stdoutR *io.PipeReader
	cancel  context.CancelFunc
	done    chan error
}

func newBridgeHarness(t *testing.T, b *Bridge) *bridgeHarness {
	t.Helper()
	stdinR, stdinW := io.Pipe()
	stdoutR, stdoutW := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- b.Run(ctx, stdinR, stdoutW, io.Discard)
		_ = stdoutW.Close()
	}()

	t.Cleanup(func() {
		cancel()
		_ = stdinW.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Logf("bridge.Run did not exit cleanly")
		}
	})

	return &bridgeHarness{
		t:       t,
		bridge:  b,
		stdinW:  stdinW,
		stdoutR: stdoutR,
		cancel:  cancel,
		done:    done,
	}
}

// send writes one frame to the bridge's stdin.
func (h *bridgeHarness) send(v interface{}) {
	h.t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		h.t.Fatalf("marshal frame: %v", err)
	}
	data = append(data, '\n')
	if _, err := h.stdinW.Write(data); err != nil {
		h.t.Fatalf("write stdin: %v", err)
	}
}

// readResponse reads one newline-terminated frame from the bridge's
// stdout. Times out at 5 seconds.
func (h *bridgeHarness) readResponse() *Response {
	h.t.Helper()
	type result struct {
		resp *Response
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		var buf bytes.Buffer
		one := make([]byte, 1)
		for {
			n, err := h.stdoutR.Read(one)
			if n > 0 {
				if one[0] == '\n' {
					var resp Response
					if uerr := json.Unmarshal(buf.Bytes(), &resp); uerr != nil {
						ch <- result{nil, fmt.Errorf("decode response %q: %w", buf.String(), uerr)}
						return
					}
					ch <- result{&resp, nil}
					return
				}
				buf.Write(one[:n])
				continue
			}
			if err != nil {
				ch <- result{nil, err}
				return
			}
		}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			h.t.Fatalf("read response: %v", r.err)
		}
		return r.resp
	case <-time.After(5 * time.Second):
		h.t.Fatalf("timed out waiting for response")
		return nil
	}
}

func newTestBridge(t *testing.T, upstreams ...*fakeUpstream) *Bridge {
	t.Helper()
	cfg := &Config{
		GuardURL:                  "http://127.0.0.1:8080",
		TenantID:                  "local",
		FailMode:                  "deny",
		PolicyMode:                "strict",
		LogLevel:                  "info",
		UpstreamTimeout:           2 * time.Second,
		ReconnectCap:              60 * time.Second,
		SupportedProtocolVersions: append([]string{}, DefaultSupportedProtocolVersions...),
	}
	for _, up := range upstreams {
		cfg.Upstreams = append(cfg.Upstreams, UpstreamSpec{
			Namespace: up.Namespace(),
			Command:   "fake",
			Transport: "stdio",
		})
	}
	b := NewBridge(cfg, io.Discard, "0.5.0-test")
	for _, up := range upstreams {
		b.SetUpstream(up)
	}
	return b
}

func TestBridge_InitializeReturnsCapabilities(t *testing.T) {
	up := newFakeUpstream("fs")
	b := newTestBridge(t, up)
	h := newBridgeHarness(t, b)

	h.send(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2025-11-25",
			"capabilities":    map[string]interface{}{},
			"clientInfo":      map[string]interface{}{"name": "test-host"},
		},
	})
	resp := h.readResponse()
	if resp.Error != nil {
		t.Fatalf("error: %+v", resp.Error)
	}
	var ir InitializeResult
	if err := json.Unmarshal(resp.Result, &ir); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if ir.ServerInfo.Name != GatewayServerName {
		t.Errorf("ServerInfo.Name: got %q, want %q", ir.ServerInfo.Name, GatewayServerName)
	}
	if _, ok := ir.Capabilities["tools"]; !ok {
		t.Errorf("capabilities missing tools: %+v", ir.Capabilities)
	}
}

func TestBridge_InitializeUnsupportedVersion(t *testing.T) {
	up := newFakeUpstream("fs")
	b := newTestBridge(t, up)
	h := newBridgeHarness(t, b)

	h.send(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "1999-01-01",
			"clientInfo":      map[string]interface{}{"name": "old-host"},
		},
	})
	resp := h.readResponse()
	if resp.Error == nil {
		t.Fatalf("expected error response, got result")
	}
	if resp.Error.Code != ErrCodeInvalidParams {
		t.Errorf("error code: got %d, want %d", resp.Error.Code, ErrCodeInvalidParams)
	}
	if !strings.Contains(resp.Error.Message, "Unsupported protocol version") {
		t.Errorf("error message: got %q", resp.Error.Message)
	}
}

func TestBridge_ToolsListNamespacePrefixed(t *testing.T) {
	upFS := newFakeUpstream("fs")
	upFS.handleSend = func(req *Request) *Response {
		return &Response{
			JSONRPC: JSONRPCVersion,
			Result: mustMarshal(t, ToolsListResult{
				Tools: []ToolDescriptor{
					{Name: "read_file", Description: "fs read"},
					{Name: "write_file"},
				},
			}),
		}
	}
	upGH := newFakeUpstream("github")
	upGH.handleSend = func(req *Request) *Response {
		return &Response{
			JSONRPC: JSONRPCVersion,
			Result: mustMarshal(t, ToolsListResult{
				Tools: []ToolDescriptor{
					{Name: "create_issue"},
				},
			}),
		}
	}
	b := newTestBridge(t, upFS, upGH)
	h := newBridgeHarness(t, b)

	h.send(map[string]interface{}{
		"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": map[string]interface{}{},
	})
	resp := h.readResponse()
	if resp.Error != nil {
		t.Fatalf("error: %+v", resp.Error)
	}
	var list ToolsListResult
	if err := json.Unmarshal(resp.Result, &list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	got := map[string]bool{}
	for _, tool := range list.Tools {
		got[tool.Name] = true
	}
	wantNames := []string{"fs:read_file", "fs:write_file", "github:create_issue"}
	for _, name := range wantNames {
		if !got[name] {
			t.Errorf("missing tool %q in %+v", name, list.Tools)
		}
	}
}

func TestBridge_ToolsCallRoutesByNamespace(t *testing.T) {
	upFS := newFakeUpstream("fs")
	var fsCalled atomic.Int32
	upFS.handleSend = func(req *Request) *Response {
		if req.Method == MethodToolsCall {
			fsCalled.Add(1)
			// Verify the namespace prefix was stripped.
			var p ToolsCallParams
			_ = json.Unmarshal(req.Params, &p)
			if p.Name != "read_file" {
				t.Errorf("upstream got unprefixed name %q, want %q", p.Name, "read_file")
			}
		}
		return &Response{Result: mustMarshal(t, ToolsCallResult{
			Content: []ContentBlock{{Type: "text", Text: "ok"}},
		})}
	}
	upGH := newFakeUpstream("github")
	var ghCalled atomic.Int32
	upGH.handleSend = func(req *Request) *Response {
		if req.Method == MethodToolsCall {
			ghCalled.Add(1)
		}
		return &Response{Result: mustMarshal(t, ToolsCallResult{
			Content: []ContentBlock{{Type: "text", Text: "ok"}},
		})}
	}
	b := newTestBridge(t, upFS, upGH)
	h := newBridgeHarness(t, b)

	// Call fs:read_file
	h.send(map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]interface{}{
			"name":      "fs:read_file",
			"arguments": map[string]interface{}{"path": "/tmp/x"},
		},
	})
	_ = h.readResponse()

	// Call github:create_issue
	h.send(map[string]interface{}{
		"jsonrpc": "2.0", "id": 2, "method": "tools/call",
		"params": map[string]interface{}{
			"name":      "github:create_issue",
			"arguments": map[string]interface{}{"title": "x"},
		},
	})
	_ = h.readResponse()

	if fsCalled.Load() != 1 {
		t.Errorf("fs upstream called %d times, want 1", fsCalled.Load())
	}
	if ghCalled.Load() != 1 {
		t.Errorf("github upstream called %d times, want 1", ghCalled.Load())
	}
}

func TestBridge_ToolsCallUnknownNamespace(t *testing.T) {
	up := newFakeUpstream("fs")
	b := newTestBridge(t, up)
	h := newBridgeHarness(t, b)

	h.send(map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]interface{}{
			"name":      "unknown:tool",
			"arguments": map[string]interface{}{},
		},
	})
	resp := h.readResponse()
	if resp.Error == nil {
		t.Fatalf("expected error, got result %s", string(resp.Result))
	}
	if resp.Error.Code != ErrCodeInvalidParams {
		t.Errorf("error code: got %d", resp.Error.Code)
	}
}

func TestBridge_ToolsCallNoColonName(t *testing.T) {
	up := newFakeUpstream("fs")
	b := newTestBridge(t, up)
	h := newBridgeHarness(t, b)

	h.send(map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]interface{}{
			"name":      "no_namespace_here",
			"arguments": map[string]interface{}{},
		},
	})
	resp := h.readResponse()
	if resp.Error == nil {
		t.Fatalf("expected error")
	}
	if resp.Error.Code != ErrCodeInvalidParams {
		t.Errorf("error code: got %d", resp.Error.Code)
	}
}

func TestBridge_PolicyHookCanDeny(t *testing.T) {
	up := newFakeUpstream("fs")
	upCalled := atomic.Int32{}
	up.handleSend = func(req *Request) *Response {
		if req.Method == MethodToolsCall {
			upCalled.Add(1)
		}
		return &Response{Result: mustMarshal(t, ToolsCallResult{})}
	}
	b := newTestBridge(t, up)
	b.PolicyCheck = func(ctx context.Context, req *ToolsCallRequest) (Decision, error) {
		return Decision{
			Allow:  false,
			Reason: "test deny",
			Rule:   "deny:test",
		}, nil
	}
	h := newBridgeHarness(t, b)

	h.send(map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]interface{}{
			"name":      "fs:read_file",
			"arguments": map[string]interface{}{},
		},
	})
	resp := h.readResponse()
	// Per docs/MCP_GATEWAY.md § 6.1, deny is surfaced as
	// isError=true, NOT a JSON-RPC error.
	if resp.Error != nil {
		t.Fatalf("got JSON-RPC error, expected isError result: %+v", resp.Error)
	}
	var tcr ToolsCallResult
	if err := json.Unmarshal(resp.Result, &tcr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !tcr.IsError {
		t.Errorf("expected isError=true, got %+v", tcr)
	}
	if upCalled.Load() != 0 {
		t.Errorf("upstream was called despite DENY (count=%d)", upCalled.Load())
	}
	if !strings.Contains(tcr.Content[0].Text, "denied") {
		t.Errorf("text: %q", tcr.Content[0].Text)
	}
}

func TestBridge_PolicyHookApproval(t *testing.T) {
	up := newFakeUpstream("fs")
	b := newTestBridge(t, up)
	b.PolicyCheck = func(ctx context.Context, req *ToolsCallRequest) (Decision, error) {
		return Decision{
			RequiresApproval: true,
			Allow:            false,
			Reason:           "needs operator approval",
			Rule:             "require_approval:fs:write",
			ApprovalID:       "ap_abc123",
			ApprovalURL:      "http://127.0.0.1:8080/dashboard?approval=ap_abc123",
		}, nil
	}
	h := newBridgeHarness(t, b)

	h.send(map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]interface{}{
			"name":      "fs:write_file",
			"arguments": map[string]interface{}{"path": "/tmp/x"},
		},
	})
	resp := h.readResponse()
	if resp.Error != nil {
		t.Fatalf("got JSON-RPC error, expected approval-required result: %+v", resp.Error)
	}
	// Decode raw to inspect _meta.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(resp.Result, &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	metaRaw, ok := raw["_meta"]
	if !ok {
		t.Fatalf("missing _meta in approval response: %s", string(resp.Result))
	}
	var meta map[string]string
	if err := json.Unmarshal(metaRaw, &meta); err != nil {
		t.Fatalf("decode _meta: %v", err)
	}
	if meta[MetaApprovalIDKey] != "ap_abc123" {
		t.Errorf("approval_id in meta: got %q", meta[MetaApprovalIDKey])
	}
}

func TestBridge_AuditHookFires(t *testing.T) {
	up := newFakeUpstream("fs")
	up.handleSend = func(req *Request) *Response {
		return &Response{Result: mustMarshal(t, ToolsCallResult{
			Content: []ContentBlock{{Type: "text", Text: "ok"}},
		})}
	}
	b := newTestBridge(t, up)

	var entries []AuditEntry
	var entriesMu sync.Mutex
	b.AuditEmit = func(entry AuditEntry) {
		entriesMu.Lock()
		entries = append(entries, entry)
		entriesMu.Unlock()
	}
	b.PolicyCheck = func(ctx context.Context, req *ToolsCallRequest) (Decision, error) {
		return Decision{Allow: true, Rule: "allow:test", Reason: "ok"}, nil
	}
	h := newBridgeHarness(t, b)

	h.send(map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]interface{}{
			"name":      "fs:read_file",
			"arguments": map[string]interface{}{"path": "/tmp/x"},
		},
	})
	_ = h.readResponse()

	entriesMu.Lock()
	defer entriesMu.Unlock()
	if len(entries) != 1 {
		t.Fatalf("audit entries: got %d, want 1", len(entries))
	}
	e := entries[0]
	if e.Decision != "ALLOW" {
		t.Errorf("decision: got %q", e.Decision)
	}
	if e.Scope != "mcp_tool" {
		t.Errorf("scope: got %q", e.Scope)
	}
	if e.Command != "fs:read_file" {
		t.Errorf("command: got %q", e.Command)
	}
	if e.Path != "/tmp/x" {
		t.Errorf("path: got %q", e.Path)
	}
	if ns, _ := e.Meta["namespace"].(string); ns != "fs" {
		t.Errorf("meta.namespace: got %v", e.Meta["namespace"])
	}
}

func TestBridge_MalformedFrameDoesNotKillBridge(t *testing.T) {
	up := newFakeUpstream("fs")
	b := newTestBridge(t, up)
	h := newBridgeHarness(t, b)

	// Garbage frame.
	if _, err := h.stdinW.Write([]byte("not json at all\n")); err != nil {
		t.Fatalf("write garbage: %v", err)
	}
	// Frame with no method (invalid request).
	if _, err := h.stdinW.Write([]byte(`{"jsonrpc":"2.0","id":99}` + "\n")); err != nil {
		t.Fatalf("write no-method: %v", err)
	}

	// A subsequent valid frame should still get a response.
	h.send(map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "ping", "params": map[string]interface{}{},
	})
	resp := h.readResponse()
	if resp.Error != nil {
		t.Fatalf("ping returned error: %+v", resp.Error)
	}
}

// TestBridge_PolicyApprovalRoundTrip simulates the approval retry
// flow: first call returns REQUIRE_APPROVAL with an approval_id;
// client retries with `_meta.dev.agentguard/approval_id` populated;
// PolicyCheck sees the approval id on the second call and returns
// ALLOW; bridge forwards to upstream.
func TestBridge_PolicyApprovalRoundTrip(t *testing.T) {
	up := newFakeUpstream("fs")
	upCalls := atomic.Int32{}
	up.handleSend = func(req *Request) *Response {
		if req.Method == MethodToolsCall {
			upCalls.Add(1)
			// Verify the dev.agentguard/* keys were stripped before
			// forwarding upstream.
			var p ToolsCallParams
			_ = json.Unmarshal(req.Params, &p)
			for k := range p.Meta {
				if strings.HasPrefix(k, MetaPrefixAgentGuard) {
					t.Errorf("upstream saw dev.agentguard key %q (should be stripped)", k)
				}
			}
		}
		return &Response{Result: mustMarshal(t, ToolsCallResult{
			Content: []ContentBlock{{Type: "text", Text: "ok"}},
		})}
	}
	b := newTestBridge(t, up)

	var hookCalls atomic.Int32
	b.PolicyCheck = func(ctx context.Context, req *ToolsCallRequest) (Decision, error) {
		n := hookCalls.Add(1)
		if n == 1 {
			// First call: no approval id present → require approval.
			if req.ApprovalID != "" {
				return Decision{}, errors.New("first call should not have approval id")
			}
			return Decision{
				RequiresApproval: true,
				ApprovalID:       "ap_test_round",
				ApprovalURL:      "http://127.0.0.1:8080/dashboard?approval=ap_test_round",
				Reason:           "needs approval",
				Rule:             "require_approval:fs:write",
			}, nil
		}
		// Second call: approval id should be populated.
		if req.ApprovalID != "ap_test_round" {
			return Decision{}, fmt.Errorf("second call: ApprovalID=%q, want %q", req.ApprovalID, "ap_test_round")
		}
		// Operator approved → ALLOW.
		return Decision{Allow: true, Rule: "allow:approved", Reason: "operator approved"}, nil
	}
	h := newBridgeHarness(t, b)

	// First call.
	h.send(map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]interface{}{
			"name":      "fs:write_file",
			"arguments": map[string]interface{}{"path": "/tmp/x"},
		},
	})
	r1 := h.readResponse()
	if r1.Error != nil {
		t.Fatalf("first call error: %+v", r1.Error)
	}

	// Second call with the approval id echoed in _meta.
	h.send(map[string]interface{}{
		"jsonrpc": "2.0", "id": 2, "method": "tools/call",
		"params": map[string]interface{}{
			"name":      "fs:write_file",
			"arguments": map[string]interface{}{"path": "/tmp/x"},
			"_meta": map[string]interface{}{
				MetaApprovalIDKey: "ap_test_round",
			},
		},
	})
	r2 := h.readResponse()
	if r2.Error != nil {
		t.Fatalf("second call JSON-RPC error: %+v", r2.Error)
	}
	if hookCalls.Load() != 2 {
		t.Errorf("hook called %d times, want 2", hookCalls.Load())
	}
	if upCalls.Load() != 1 {
		t.Errorf("upstream called %d times, want 1 (only after approval)", upCalls.Load())
	}
}

func TestBridge_DegradedNamespaceReturnsUnavailable(t *testing.T) {
	up := newFakeUpstream("fs")
	up.status.Store(StatusDegraded)
	b := newTestBridge(t, up)
	h := newBridgeHarness(t, b)

	h.send(map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]interface{}{
			"name":      "fs:read_file",
			"arguments": map[string]interface{}{},
		},
	})
	resp := h.readResponse()
	if resp.Error == nil {
		t.Fatalf("expected error response")
	}
	if resp.Error.Code != ErrCodeUpstreamUnavail {
		t.Errorf("error code: got %d, want %d", resp.Error.Code, ErrCodeUpstreamUnavail)
	}
}

func TestBridge_StripAgentGuardMeta(t *testing.T) {
	cases := []struct {
		name string
		in   map[string]interface{}
		want map[string]interface{}
	}{
		{
			name: "no meta",
			in:   nil,
			want: nil,
		},
		{
			name: "only agentguard keys -> nil",
			in:   map[string]interface{}{MetaApprovalIDKey: "ap_x"},
			want: nil,
		},
		{
			name: "mixed -> only non-agentguard",
			in: map[string]interface{}{
				MetaApprovalIDKey: "ap_x",
				"trace-id":        "t-123",
			},
			want: map[string]interface{}{
				"trace-id": "t-123",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := stripAgentGuardMeta(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("len: got %d, want %d (%v vs %v)", len(got), len(tc.want), got, tc.want)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Errorf("key %q: got %v, want %v", k, got[k], v)
				}
			}
		})
	}
}

func TestBridge_SplitNamespacedName(t *testing.T) {
	cases := []struct {
		in   string
		ns   string
		tool string
		ok   bool
	}{
		{in: "fs:read_file", ns: "fs", tool: "read_file", ok: true},
		{in: "github:create_issue", ns: "github", tool: "create_issue", ok: true},
		{in: "complex:tool.with.dots", ns: "complex", tool: "tool.with.dots", ok: true},
		{in: "two:colons:here", ns: "two", tool: "colons:here", ok: true}, // first colon wins
		{in: "no_colon", ok: false},
		{in: ":empty_ns", ok: false},
		{in: "empty_tool:", ok: false},
		{in: "", ok: false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			ns, tool, ok := splitNamespacedName(tc.in)
			if ok != tc.ok || (ok && (ns != tc.ns || tool != tc.tool)) {
				t.Errorf("got (%q, %q, %v), want (%q, %q, %v)", ns, tool, ok, tc.ns, tc.tool, tc.ok)
			}
		})
	}
}

// mustMarshal is a test helper that fails immediately on json.Marshal
// error, returning a json.RawMessage suitable for embedding in a
// Response.Result.
func mustMarshal(t *testing.T, v interface{}) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return data
}

// TestBridge_ForwardsListChangedToHost: only tools/list_changed is
// re-emitted to the host (one frame, newline-terminated, valid JSON);
// other upstream notifications stay gateway-internal.
func TestBridge_ForwardsListChangedToHost(t *testing.T) {
	var out bytes.Buffer
	b := NewBridge(&Config{LogLevel: "info"}, io.Discard, "test")
	b.output = &out

	b.onUpstreamNotification("fs", "notifications/progress")
	if out.Len() != 0 {
		t.Fatalf("non-list_changed notification must not be forwarded; got %q", out.String())
	}

	b.onUpstreamNotification("fs", NotificationToolsListChanged)
	line := strings.TrimSpace(out.String())
	var note Notification
	if err := json.Unmarshal([]byte(line), &note); err != nil {
		t.Fatalf("forwarded frame is not valid JSON: %v (%q)", err, line)
	}
	if note.JSONRPC != JSONRPCVersion || note.Method != NotificationToolsListChanged {
		t.Errorf("frame = %+v, want jsonrpc=%q method=%q", note, JSONRPCVersion, NotificationToolsListChanged)
	}
}
