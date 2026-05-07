package mcpgw

// AT (Test Wrangler) — real MCP protocol exchange tests against the
// Phase 4B stub_server (testdata/stub_server/main.go) driven by the
// REAL StdioUpstream, NOT a fakeUpstream. The plan called for
// `npx @modelcontextprotocol/server-everything`; we substitute the
// Go stub for offline-deterministic CI behaviour. The substitution is
// documented in .audit/v05_test_coverage.md.
//
// Why this matters: A17's bridge_test.go uses fakeUpstream (in-process,
// no subprocess). transport_test.go drives the StdioUpstream directly
// without the bridge. This file covers the layered case — Bridge.Run +
// real StdioUpstream + real subprocess — which is the same code path
// production agents-guarding-Claude-Desktop will hit.

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"
)

// realUpstreamHarness is a bridgeHarness extended to wire one or more
// real StdioUpstream instances via the stub binary. Returns the
// harness + a teardown.
type realUpstreamHarness struct {
	*bridgeHarness
	bridge *Bridge
}

// newRealUpstreamHarness constructs a bridge with `nUpstreams` real
// stub-server subprocesses, each in its own namespace. Tools are
// configured per-namespace via toolPerNs (parallel slice).
func newRealUpstreamHarness(t *testing.T, namespaces []string, toolPerNs []string) *realUpstreamHarness {
	t.Helper()
	if len(namespaces) != len(toolPerNs) {
		t.Fatalf("AT helper: len(namespaces)=%d != len(toolPerNs)=%d", len(namespaces), len(toolPerNs))
	}

	cfg := &Config{
		GuardURL:                  "http://127.0.0.1:8080",
		TenantID:                  "local",
		FailMode:                  "deny",
		PolicyMode:                "fast",
		LogLevel:                  "info",
		UpstreamTimeout:           10 * time.Second,
		ReconnectCap:              60 * time.Second,
		SupportedProtocolVersions: append([]string{}, DefaultSupportedProtocolVersions...),
	}

	for _, ns := range namespaces {
		cfg.Upstreams = append(cfg.Upstreams, UpstreamSpec{
			Namespace: ns,
			Command:   "stub-server",
			Transport: "stdio",
		})
	}

	b := NewBridge(cfg, io.Discard, "0.5.0-AT")

	// Inject a real StdioUpstream backed by the stub binary for each
	// namespace. We bypass the bridge's own auto-spawn (which would
	// try to exec the literal "stub-server" command) by SetUpstream'ing
	// before Run().
	//
	// The bridge's Run() will Start() any upstream not already wired
	// in cfg.Upstreams; we pre-Start here and pre-Initialize so the
	// upstream is StatusOK before the harness drives the first
	// tools/list. The bridge's handleInitialize will then re-Initialize
	// the upstream when the host sends `initialize` — that's fine: the
	// stub_server handles repeated initialize idempotently and tests
	// production behaviour where the gateway forwards initialize after
	// already having spawned the subprocess.
	startCtx, startCancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(startCancel)
	for i, ns := range namespaces {
		factory := stubFactory(t,
			"--name", "stub-"+ns,
			"--tool", toolPerNs[i],
			"--proto-version", "2025-11-25",
		)
		up := NewStdioUpstreamWithOptions(UpstreamSpec{
			Namespace: ns,
			Command:   "stub-server",
		}, StdioUpstreamOptions{
			CommandFactory: factory,
			Backoff:        []time.Duration{100 * time.Millisecond},
		})
		if err := up.Start(startCtx); err != nil {
			t.Fatalf("Start upstream %q: %v", ns, err)
		}
		// Drive the upstream's own Initialize so it is StatusOK by
		// the time the harness sends a tools/list to the bridge.
		if _, err := up.Initialize(startCtx, "2025-11-25", map[string]interface{}{}, ClientInfo{Name: "AT"}); err != nil {
			t.Fatalf("Initialize upstream %q: %v", ns, err)
		}
		b.SetUpstream(up)
		// Capture in a local for the closure.
		upx := up
		t.Cleanup(func() { _ = upx.Close() })
	}

	h := newBridgeHarness(t, b)
	return &realUpstreamHarness{bridgeHarness: h, bridge: b}
}

// TestAT_RealProtocol_FullSession drives the full handshake +
// tools/list + tools/call sequence through Bridge.Run with a single
// real stub_server upstream. This is the headline integration test:
// it exercises every layer (subprocess spawn, JSON-RPC framing,
// bridge dispatch, namespace prefix, response round-trip).
func TestAT_RealProtocol_FullSession(t *testing.T) {
	if testing.Short() {
		t.Skip("skip in short mode (spawns real subprocess)")
	}

	h := newRealUpstreamHarness(t, []string{"fs"}, []string{"echo"})

	// 1. initialize: bridge handles, returns gateway ServerInfo +
	//    merged caps.
	h.send(map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2025-11-25",
			"capabilities":    map[string]interface{}{},
			"clientInfo":      map[string]interface{}{"name": "AT-realprotocol"},
		},
	})
	resp := h.readResponse()
	if resp.Error != nil {
		t.Fatalf("initialize error: %+v", resp.Error)
	}
	var ir InitializeResult
	if err := json.Unmarshal(resp.Result, &ir); err != nil {
		t.Fatalf("decode initialize: %v", err)
	}
	if ir.ServerInfo.Name != GatewayServerName {
		t.Errorf("ServerInfo.Name = %q; want %q (gateway must not impersonate upstream)", ir.ServerInfo.Name, GatewayServerName)
	}
	if ir.ProtocolVersion != "2025-11-25" {
		t.Errorf("ProtocolVersion = %q; want 2025-11-25", ir.ProtocolVersion)
	}

	// 2. tools/list: bridge fans out to upstream(s), prefixes names.
	h.send(map[string]interface{}{
		"jsonrpc": "2.0", "id": 2, "method": "tools/list",
		"params": map[string]interface{}{},
	})
	resp = h.readResponse()
	if resp.Error != nil {
		t.Fatalf("tools/list error: %+v", resp.Error)
	}
	var list ToolsListResult
	if err := json.Unmarshal(resp.Result, &list); err != nil {
		t.Fatalf("decode tools/list: %v", err)
	}
	if len(list.Tools) != 1 {
		t.Fatalf("expected exactly 1 tool, got %d (%+v)", len(list.Tools), list.Tools)
	}
	if list.Tools[0].Name != "fs:echo" {
		t.Errorf("tool name = %q; want fs:echo", list.Tools[0].Name)
	}
	// The stub's input schema MUST round-trip through the bridge.
	if list.Tools[0].InputSchema == nil {
		t.Errorf("inputSchema dropped by bridge: %+v", list.Tools[0])
	}

	// 3. tools/call: bridge strips ns prefix, forwards, response
	//    surfaces with the gateway's id (3).
	h.send(map[string]interface{}{
		"jsonrpc": "2.0", "id": 3, "method": "tools/call",
		"params": map[string]interface{}{
			"name":      "fs:echo",
			"arguments": map[string]interface{}{"text": "hello-AT"},
		},
	})
	resp = h.readResponse()
	if resp.Error != nil {
		t.Fatalf("tools/call error: %+v", resp.Error)
	}
	var tcr ToolsCallResult
	if err := json.Unmarshal(resp.Result, &tcr); err != nil {
		t.Fatalf("decode tools/call: %v", err)
	}
	if tcr.IsError {
		t.Errorf("isError=true on legitimate tools/call: %+v", tcr)
	}
	if len(tcr.Content) == 0 || tcr.Content[0].Type != "text" {
		t.Fatalf("expected at least one text content block, got %+v", tcr.Content)
	}
	if !strings.Contains(tcr.Content[0].Text, "hello-AT") {
		t.Errorf("response text did not echo arg: %q", tcr.Content[0].Text)
	}
	// The stub strips the namespace prefix, so the response should
	// reference the un-prefixed tool name "echo".
	if !strings.Contains(tcr.Content[0].Text, `"echo"`) {
		t.Errorf("response did not reference unprefixed tool name: %q", tcr.Content[0].Text)
	}
}

// TestAT_RealProtocol_TwoUpstreamsAggregateCorrectly registers two
// stub_server instances under different namespaces and asserts:
//   - tools/list returns the union with correct prefixes
//   - tools/call against each routes to the correct upstream (the
//     stub echoes its --name flag in the response so we can tell)
func TestAT_RealProtocol_TwoUpstreamsAggregateCorrectly(t *testing.T) {
	if testing.Short() {
		t.Skip("skip in short mode (spawns real subprocesses)")
	}

	h := newRealUpstreamHarness(t,
		[]string{"alpha", "beta"},
		[]string{"alphatool", "betatool"},
	)

	// initialize.
	h.send(map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2025-11-25",
			"capabilities":    map[string]interface{}{},
			"clientInfo":      map[string]interface{}{"name": "AT-twoups"},
		},
	})
	_ = h.readResponse()

	// tools/list.
	h.send(map[string]interface{}{
		"jsonrpc": "2.0", "id": 2, "method": "tools/list",
		"params": map[string]interface{}{},
	})
	resp := h.readResponse()
	if resp.Error != nil {
		t.Fatalf("tools/list: %+v", resp.Error)
	}
	var list ToolsListResult
	_ = json.Unmarshal(resp.Result, &list)

	got := map[string]bool{}
	for _, tool := range list.Tools {
		got[tool.Name] = true
	}
	if !got["alpha:alphatool"] {
		t.Errorf("missing alpha:alphatool in %+v", list.Tools)
	}
	if !got["beta:betatool"] {
		t.Errorf("missing beta:betatool in %+v", list.Tools)
	}

	// tools/call alpha:alphatool — stub identifies via --name "stub-alpha"
	// in the printed text.
	h.send(map[string]interface{}{
		"jsonrpc": "2.0", "id": 3, "method": "tools/call",
		"params": map[string]interface{}{
			"name":      "alpha:alphatool",
			"arguments": map[string]interface{}{"text": "to-alpha"},
		},
	})
	resp = h.readResponse()
	if resp.Error != nil {
		t.Fatalf("alpha tools/call: %+v", resp.Error)
	}
	var alphaResp ToolsCallResult
	_ = json.Unmarshal(resp.Result, &alphaResp)
	if !strings.Contains(alphaResp.Content[0].Text, "to-alpha") {
		t.Errorf("alpha tools/call did not echo arg: %q", alphaResp.Content[0].Text)
	}

	// tools/call beta:betatool — different upstream.
	h.send(map[string]interface{}{
		"jsonrpc": "2.0", "id": 4, "method": "tools/call",
		"params": map[string]interface{}{
			"name":      "beta:betatool",
			"arguments": map[string]interface{}{"text": "to-beta"},
		},
	})
	resp = h.readResponse()
	if resp.Error != nil {
		t.Fatalf("beta tools/call: %+v", resp.Error)
	}
	var betaResp ToolsCallResult
	_ = json.Unmarshal(resp.Result, &betaResp)
	if !strings.Contains(betaResp.Content[0].Text, "to-beta") {
		t.Errorf("beta tools/call did not echo arg: %q", betaResp.Content[0].Text)
	}
	// Cross-check: alpha response must NOT mention "betatool" and
	// vice versa (proves routing is per-namespace, not broadcast).
	if strings.Contains(alphaResp.Content[0].Text, "betatool") {
		t.Errorf("alpha response referenced betatool: %q", alphaResp.Content[0].Text)
	}
	if strings.Contains(betaResp.Content[0].Text, "alphatool") {
		t.Errorf("beta response referenced alphatool: %q", betaResp.Content[0].Text)
	}
}

// TestAT_RealProtocol_NotificationsForward sends notifications/initialized
// after the handshake and asserts the bridge does NOT emit a response
// frame (notifications are one-way per JSON-RPC). We use a short
// follow-up ping to prove the bridge is still alive.
func TestAT_RealProtocol_NotificationsForward(t *testing.T) {
	if testing.Short() {
		t.Skip("skip in short mode (spawns real subprocess)")
	}

	h := newRealUpstreamHarness(t, []string{"fs"}, []string{"echo"})

	// Drive initialize (the bridge needs ClientInfo cached for ping
	// agent-id derivation).
	h.send(map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2025-11-25",
			"capabilities":    map[string]interface{}{},
			"clientInfo":      map[string]interface{}{"name": "AT-notif"},
		},
	})
	_ = h.readResponse()

	// Send a notifications/initialized — no id, no response expected.
	notification := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	}
	h.send(notification)

	// We cannot peek at the bridge's stdout without consuming bytes.
	// Instead, send a follow-up ping with a known id and assert that
	// the FIRST response we see has that id (i.e. the bridge produced
	// no frame at all for the notification — it didn't consume the id
	// space, didn't echo, didn't error). Any spurious frame the bridge
	// emitted for the notification would arrive before the ping reply
	// and trip the assertion below.
	h.send(map[string]interface{}{
		"jsonrpc": "2.0", "id": 99, "method": "ping",
		"params": map[string]interface{}{},
	})
	resp := h.readResponse()
	if resp.Error != nil {
		t.Fatalf("ping after notification failed: %+v", resp.Error)
	}
	if got := normaliseID(resp.ID); got != "99" {
		t.Errorf("first response after notification had id %q (raw %T %v); want \"99\". A non-99 id would mean the bridge emitted a frame for the notification.",
			got, resp.ID, resp.ID)
	}
}

// normaliseID stringifies a JSON-RPC id (post-decode it can be
// float64 or string) for ergonomic comparison.
func normaliseID(id interface{}) string {
	switch v := id.(type) {
	case float64:
		if v == float64(int64(v)) {
			return strconvI64(int64(v))
		}
	case string:
		return v
	}
	return ""
}

func strconvI64(n int64) string {
	const digits = "0123456789"
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = digits[n%10]
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
