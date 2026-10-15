package mcpgw

import (
	"context"
	"encoding/hex"
	"testing"
)

// Each gateway process gets its own random connection id; the session id
// stays the one derived from the client name, so cost limits keyed on it
// are unchanged.
func TestBridge_ToolCallsCarryTheGatewayConnection(t *testing.T) {
	up := newFakeUpstream("fs")
	up.handleSend = func(req *Request) *Response {
		return &Response{Result: mustMarshal(t, ToolsCallResult{})}
	}
	b := newTestBridge(t, up)
	var seen *ToolsCallRequest
	b.PolicyCheck = func(ctx context.Context, req *ToolsCallRequest) (Decision, error) {
		seen = req
		return Decision{Allow: true}, nil
	}
	h := newBridgeHarness(t, b)
	h.send(map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]interface{}{"name": "fs:read_file", "arguments": map[string]interface{}{}},
	})
	h.readResponse()

	if seen == nil {
		t.Fatal("policy hook not called")
	}
	if id, err := hex.DecodeString(seen.ConnectionID); err != nil || len(id) != 8 {
		t.Errorf("connection id = %q, want 16 hex characters", seen.ConnectionID)
	}
	if seen.SessionID != b.deriveSessionID() {
		t.Errorf("session id = %q, want the client-derived %q", seen.SessionID, b.deriveSessionID())
	}
	if other := newTestBridge(t); other.connID == b.connID {
		t.Errorf("two bridges share connection id %q", b.connID)
	}
}

func TestBuildMcpMeta_GatewayConnection(t *testing.T) {
	req := toolsCallReq("fs:read_file", map[string]interface{}{"gateway_connection": "spoof"})
	if _, ok := buildMcpMeta(req)[MetaGatewayConnectionKey]; ok {
		t.Error("meta has gateway_connection without a connection id")
	}
	req.ConnectionID = "0123456789abcdef"
	meta := buildMcpMeta(req)
	if meta[MetaGatewayConnectionKey] != "0123456789abcdef" {
		t.Errorf("gateway_connection = %q", meta[MetaGatewayConnectionKey])
	}
	// A tool argument with the same name lands under arg_ and can't
	// overwrite it.
	if meta["arg_gateway_connection"] != "spoof" {
		t.Errorf("arg_gateway_connection = %q", meta["arg_gateway_connection"])
	}

	// Both checks of a strict-mode call carry it to the server.
	m := newMockGuardServer(t)
	gate := newGateForTest(t, m, "strict", nil)
	if _, err := gate.Check(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if len(m.receivedReqs) == 0 {
		t.Fatal("no /v1/check call")
	}
	for _, ar := range m.receivedReqs {
		if ar.Meta[MetaGatewayConnectionKey] != "0123456789abcdef" || ar.SessionID != "mcp-gateway:test" {
			t.Errorf("%s check: meta %v session %q", ar.Scope, ar.Meta, ar.SessionID)
		}
	}
}
