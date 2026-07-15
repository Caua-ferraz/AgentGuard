package audit

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// TestEntry_UnmarshalPreV05_DefaultsTransport asserts that an audit
// line written by a pre-v0.5 binary (no `transport` field on the
// wire) decodes cleanly and reads back as the SDK default via
// EffectiveTransport. This is the primary back-compat coupon: a
// long-running deployment upgrades from v0.4.1 to v0.5 and keeps
// reading entries from before the transport tag landed.
func TestEntry_UnmarshalPreV05_DefaultsTransport(t *testing.T) {
	// Hand-rolled JSON without the `transport` field — exactly what a
	// v0.4.1 FileLogger.Log() would have written.
	wire := `{
		"timestamp": "2026-05-04T12:00:00Z",
		"session_id": "sess-1",
		"agent_id": "bot-a",
		"request": {"scope": "shell", "command": "ls"},
		"result": {"decision": "ALLOW", "reason": "ok"},
		"duration_ms": 1
	}`
	var e Entry
	if err := json.Unmarshal([]byte(wire), &e); err != nil {
		t.Fatalf("unmarshal pre-v0.5 entry: %v", err)
	}
	if e.Transport != "" {
		t.Errorf("expected pre-v0.5 entry to deserialise with empty Transport, got %q", e.Transport)
	}
	if got := e.EffectiveTransport(); got != TransportSDK {
		t.Errorf("EffectiveTransport on pre-v0.5 entry = %q; want %q (SDK default)", got, TransportSDK)
	}
}

// TestEntry_UnmarshalV05_RoundTrip asserts that an entry written
// with Transport="mcp_gateway" round-trips cleanly through JSON.
func TestEntry_UnmarshalV05_RoundTrip(t *testing.T) {
	original := Entry{
		Timestamp: time.Date(2026, 5, 5, 10, 0, 0, 0, time.UTC),
		SessionID: "sess-mcp-1",
		AgentID:   "mcp-gateway:claude-desktop",
		Request: policy.ActionRequest{
			Scope:   "mcp_tool",
			Command: "fs:read_file",
		},
		Result: policy.CheckResult{
			Decision: policy.Allow,
			Reason:   "allowed by mcp_tool rule",
		},
		DurationMs: 3,
		Transport:  TransportMCPGateway,
	}

	raw, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"transport":"mcp_gateway"`) {
		t.Errorf("marshaled entry missing transport field; raw=%s", raw)
	}

	var decoded Entry
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Transport != TransportMCPGateway {
		t.Errorf("Transport round-trip = %q; want %q", decoded.Transport, TransportMCPGateway)
	}
	if got := decoded.EffectiveTransport(); got != TransportMCPGateway {
		t.Errorf("EffectiveTransport round-trip = %q; want %q", got, TransportMCPGateway)
	}
}

// TestEntry_TransportOmitempty asserts that an Entry with Transport
// unset marshals WITHOUT the `transport` JSON key. This keeps the
// wire identical to v0.4.x for SDK callers that didn't set the
// field, so any external consumer parsing the audit log strictly
// sees no schema drift.
func TestEntry_TransportOmitempty(t *testing.T) {
	e := Entry{
		Timestamp: time.Date(2026, 5, 5, 10, 0, 0, 0, time.UTC),
		AgentID:   "bot",
		Request:   policy.ActionRequest{Scope: "shell", Command: "ls"},
		Result:    policy.CheckResult{Decision: policy.Allow},
		// Transport intentionally unset.
	}
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), `"transport"`) {
		t.Errorf("expected transport key absent on omitempty entry; raw=%s", raw)
	}
}

// TestEntry_EffectiveTransport_ExplicitValuesPassThrough is a
// belt-and-braces check that EffectiveTransport returns the
// explicit value when set, not the SDK default.
func TestEntry_EffectiveTransport_ExplicitValuesPassThrough(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"sdk", TransportSDK, TransportSDK},
		{"mcp_gateway", TransportMCPGateway, TransportMCPGateway},
		{"llm_api_proxy", TransportLLMAPIProxy, TransportLLMAPIProxy},
		{"unknown-string-passes-through", "future_transport", "future_transport"},
		{"empty-defaults-to-sdk", "", TransportSDK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := Entry{Transport: tc.in}
			if got := e.EffectiveTransport(); got != tc.want {
				t.Errorf("EffectiveTransport(%q) = %q; want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestQueryFilter_TransportFiltersEffective asserts that a
// QueryFilter with Transport set excludes entries whose
// EffectiveTransport doesn't match. Specifically, a filter for
// "sdk" SHOULD include pre-v0.5 entries (Transport="" on disk)
// because EffectiveTransport defaults them to "sdk".
func TestQueryFilter_TransportFiltersEffective(t *testing.T) {
	preV05 := Entry{Request: policy.ActionRequest{Scope: "shell"}}                               // Transport=""
	sdkExplicit := Entry{Transport: TransportSDK, Request: policy.ActionRequest{Scope: "shell"}} // Transport="sdk"
	mcp := Entry{Transport: TransportMCPGateway, Request: policy.ActionRequest{Scope: "mcp_tool"}}

	if !matchesFilter(preV05, QueryFilter{Transport: TransportSDK}) {
		t.Errorf("expected pre-v0.5 entry to match Transport=sdk filter (default)")
	}
	if !matchesFilter(sdkExplicit, QueryFilter{Transport: TransportSDK}) {
		t.Errorf("expected explicit-sdk entry to match Transport=sdk filter")
	}
	if matchesFilter(mcp, QueryFilter{Transport: TransportSDK}) {
		t.Errorf("did not expect mcp_gateway entry to match Transport=sdk filter")
	}

	if !matchesFilter(mcp, QueryFilter{Transport: TransportMCPGateway}) {
		t.Errorf("expected mcp_gateway entry to match Transport=mcp_gateway filter")
	}
	if matchesFilter(preV05, QueryFilter{Transport: TransportMCPGateway}) {
		t.Errorf("did not expect pre-v0.5 entry to match Transport=mcp_gateway filter")
	}

	// Empty filter passes everything through.
	if !matchesFilter(preV05, QueryFilter{}) || !matchesFilter(mcp, QueryFilter{}) {
		t.Errorf("empty Transport filter should not exclude entries")
	}
}
