package mcpgw

// AT (Test Wrangler) protocol-negotiation matrix at the bridge level.
// A17 already covers the pure NegotiateProtocolVersion function in
// protocol_test.go. This file drives a real `initialize` request
// through the in-process bridge harness so we exercise:
//
//   - the JSON unmarshal of InitializeParams (handleInitialize),
//   - the call into NegotiateProtocolVersion against the configured
//     SupportedProtocolVersions,
//   - the bridge's downgrade-to-lowest-common-denominator logic when
//     the upstream pins an older version,
//   - the encoding of the InitializeResult on the wire.
//
// The bridge's negotiation is the layer Claude Desktop / Cursor / IDE
// plugins actually hit, so this matrix is the operator-facing wire
// contract.

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestAT_BridgeProtocolNegotiation_Matrix runs the bridge through the
// matrix from docs/MCP_GATEWAY.md § 3.2 with real fakeUpstream(s)
// behind it.
func TestAT_BridgeProtocolNegotiation_Matrix(t *testing.T) {
	// Pin the gateway's supported set so the test isn't sensitive to
	// changes in DefaultSupportedProtocolVersions.
	supported := []string{"2024-11-05", "2025-03-26", "2025-11-25"}

	cases := []struct {
		name       string
		requested  string
		upstreamPV string // protocolVersion the fake upstream pins on initialize
		want       string
		wantErr    bool
	}{
		{
			name:       "exact_current_spec",
			requested:  "2025-11-25",
			upstreamPV: "2025-11-25",
			want:       "2025-11-25",
		},
		{
			name:       "exact_legacy",
			requested:  "2024-11-05",
			upstreamPV: "2024-11-05",
			want:       "2024-11-05",
		},
		{
			name:       "client_newer_than_gateway_returns_highest",
			requested:  "2099-12-31",
			upstreamPV: "2025-11-25",
			want:       "2025-11-25",
		},
		{
			name:       "client_in_between_returns_highest_le",
			requested:  "2025-06-15",
			upstreamPV: "2025-03-26",
			want:       "2025-03-26",
		},
		{
			name:       "client_older_than_gateway_lowest_negotiation_fails",
			requested:  "1999-01-01",
			upstreamPV: "2025-11-25",
			wantErr:    true,
		},
		{
			name:       "garbage_string_treated_as_lex_compare_lower_than_anything",
			requested:  "garbage",
			upstreamPV: "2025-11-25",
			// "garbage" lexically compares > all dated versions, so by
			// the negotiation algorithm it's "newer than everything we
			// know" → returns highest. This pins the v0.5 design choice;
			// future versions may add a strict YYYY-MM-DD validator.
			want: "2025-11-25",
		},
		{
			name:       "downgrade_when_upstream_pins_older",
			requested:  "2025-11-25",
			upstreamPV: "2024-11-05",
			// Per docs/MCP_GATEWAY.md § 3.2 step 3: gateway downgrades
			// the session to the lowest common denominator across
			// upstreams.
			want: "2024-11-05",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			up := newFakeUpstream("fs")
			up.initResult = &InitializeResult{
				ProtocolVersion: tc.upstreamPV,
				Capabilities:    map[string]interface{}{"tools": map[string]interface{}{}},
				ServerInfo:      ServerInfo{Name: "fake-fs", Version: "0"},
			}

			b := newTestBridge(t, up)
			b.cfg.SupportedProtocolVersions = supported
			h := newBridgeHarness(t, b)

			h.send(map[string]interface{}{
				"jsonrpc": "2.0", "id": 1, "method": "initialize",
				"params": map[string]interface{}{
					"protocolVersion": tc.requested,
					"capabilities":    map[string]interface{}{},
					"clientInfo":      map[string]interface{}{"name": "AT-test"},
				},
			})
			resp := h.readResponse()

			if tc.wantErr {
				if resp.Error == nil {
					t.Fatalf("expected error response, got result %s", string(resp.Result))
				}
				if resp.Error.Code != ErrCodeInvalidParams {
					t.Errorf("error code = %d; want %d", resp.Error.Code, ErrCodeInvalidParams)
				}
				if !strings.Contains(resp.Error.Message, "Unsupported protocol version") {
					t.Errorf("error message = %q; want \"Unsupported protocol version\"", resp.Error.Message)
				}
				return
			}

			if resp.Error != nil {
				t.Fatalf("unexpected error: %+v", resp.Error)
			}
			var ir InitializeResult
			if err := json.Unmarshal(resp.Result, &ir); err != nil {
				t.Fatalf("decode result: %v", err)
			}
			if ir.ProtocolVersion != tc.want {
				t.Errorf("ProtocolVersion = %q; want %q (requested=%q upstreamPV=%q)",
					ir.ProtocolVersion, tc.want, tc.requested, tc.upstreamPV)
			}
			if ir.ServerInfo.Name != GatewayServerName {
				t.Errorf("ServerInfo.Name = %q; want %q (gateway must not impersonate upstream)",
					ir.ServerInfo.Name, GatewayServerName)
			}
		})
	}
}

// TestAT_ProtocolNegotiation_EmptyRequestedReturnsHighest pins the
// behaviour for clients that omit protocolVersion (some older MCP
// hosts in the wild). The bridge MUST advertise its highest supported
// version in that case so the host can decide whether to retry.
func TestAT_ProtocolNegotiation_EmptyRequestedReturnsHighest(t *testing.T) {
	up := newFakeUpstream("fs")
	b := newTestBridge(t, up)
	b.cfg.SupportedProtocolVersions = []string{"2024-11-05", "2025-11-25"}
	h := newBridgeHarness(t, b)

	h.send(map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]interface{}{
			// protocolVersion deliberately omitted.
			"capabilities": map[string]interface{}{},
			"clientInfo":   map[string]interface{}{"name": "no-pv"},
		},
	})
	resp := h.readResponse()
	if resp.Error != nil {
		t.Fatalf("error: %+v", resp.Error)
	}
	var ir InitializeResult
	if err := json.Unmarshal(resp.Result, &ir); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ir.ProtocolVersion != "2025-11-25" {
		t.Errorf("empty requested -> ProtocolVersion = %q; want highest (2025-11-25)", ir.ProtocolVersion)
	}
}
