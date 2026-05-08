package mcpgw

import (
	"testing"
)

// TestGatewayLevelAuditDeferred locks in the decision to leave
// gateway-level audit/SSE wiring nil by default. If a future PR wires
// bridge.AuditEmit / bridge.SSEEmit by default, this test will need to
// be replaced — but the deletion should be deliberate.
//
// What we assert: NewBridge returns a Bridge whose AuditEmit and
// SSEEmit hooks are nil. Tool-call-level audit + SSE go through the
// central server's /v1/check flow.
//
// See pkg/mcpgw/audit.go for the rationale and the follow-up TODO.
func TestGatewayLevelAuditDeferred(t *testing.T) {
	cfg := &Config{
		PolicyMode:                "fast",
		FailMode:                  "deny",
		TenantID:                  "local",
		LogLevel:                  "info",
		SupportedProtocolVersions: []string{"2025-11-25"},
	}
	b := NewBridge(cfg, nil, "test")

	if b.AuditEmit != nil {
		t.Errorf("expected AuditEmit nil by default; got non-nil hook")
	}
	if b.SSEEmit != nil {
		t.Errorf("expected SSEEmit nil by default; got non-nil hook")
	}
}
