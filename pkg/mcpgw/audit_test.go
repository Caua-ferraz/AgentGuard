package mcpgw

import (
	"testing"
)

// TestGatewayLevelAuditDeferred is a coupon test that locks in the
// v0.5 decision to defer gateway-level audit/SSE wiring. If a future
// PR wires bridge.AuditEmit / bridge.SSEEmit by default, this test
// will need to be replaced — but the deletion should be deliberate
// and the v0.5 → v0.6 audit decision should be revisited.
//
// What we assert:
//   - A NewBridge call returns a Bridge whose AuditEmit and SSEEmit
//     hooks are nil. Tool-call-level audit + SSE go through the
//     central server's /v1/check flow (A19's transport-tag plumbing).
//
// See pkg/mcpgw/audit.go for the rationale and the v0.6 follow-up.
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
		t.Errorf("expected AuditEmit nil by default (gateway-level audit deferred to v0.6); got non-nil hook")
	}
	if b.SSEEmit != nil {
		t.Errorf("expected SSEEmit nil by default (gateway-level audit deferred to v0.6); got non-nil hook")
	}
}
