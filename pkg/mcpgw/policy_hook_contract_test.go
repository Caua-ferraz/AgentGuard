package mcpgw

// Contract tests for the nil-PolicyCheck behaviour.
//
// A Bridge constructed without PolicyCheck ALLOWS every tools/call. That is a
// deliberate test-ergonomics default, not an accident — but it is an S1
// fail-open shape and, until now, nothing in the tree pinned it. Both halves
// were unpinned: that it allows, and that it is *identifiable* when it does.
//
// These tests are tripwires, not cages. They do not argue the default should
// stay; they make changing it a deliberate act. If a future change makes the
// unwired bridge fail closed (the recommended B5 direction — an additive
// RequirePolicyHook opt-in), these tests SHOULD fail, and the fix is to update
// them together with a CHANGELOG entry, because that flips an
// externally-observable default for library embedders.

import (
	"context"
	"strings"
	"testing"
)

// TestRunPolicyCheck_NilHookAllows pins the fail-open default itself.
func TestRunPolicyCheck_NilHookAllows(t *testing.T) {
	b := NewBridge(&Config{LogLevel: "info"}, nil, "test")
	if b.PolicyCheck != nil {
		t.Fatal("precondition: a freshly constructed Bridge must have no PolicyCheck wired")
	}

	dec, err := b.runPolicyCheck(context.Background(), &ToolsCallRequest{
		Namespace: "fs", ToolName: "read_file", FullName: "fs:read_file",
	})
	if err != nil {
		t.Fatalf("runPolicyCheck with a nil hook returned an error: %v", err)
	}
	if !dec.Allow {
		t.Fatal("the unwired default is documented as ALLOW; if this changed deliberately, " +
			"update this test AND the CHANGELOG — it flips an observable default for embedders (B5)")
	}
}

// TestRunPolicyCheck_NilHookIsIdentifiable is the half that actually matters
// operationally. With no startup guard, the ONLY signal that a firewall is
// running unwired is the rule string stamped on each allowed decision. If that
// string stops being distinctive, an unwired deployment becomes invisible —
// indistinguishable from a policy that legitimately allows.
//
// Deliberately permissive about the exact wording: it asserts the marker is
// present and identifiable, not a byte-exact string, so the message can be
// reworded without breaking the test.
func TestRunPolicyCheck_NilHookIsIdentifiable(t *testing.T) {
	b := NewBridge(&Config{LogLevel: "info"}, nil, "test")

	dec, err := b.runPolicyCheck(context.Background(), &ToolsCallRequest{
		Namespace: "fs", ToolName: "read_file", FullName: "fs:read_file",
	})
	if err != nil {
		t.Fatalf("runPolicyCheck: %v", err)
	}
	if dec.Rule == "" {
		t.Fatal("an unwired allow carries no rule string; the only trace that the firewall " +
			"is not actually enforcing would be gone (B5)")
	}
	if !strings.Contains(dec.Rule, "unwired") {
		t.Errorf("rule = %q; the unwired allow must stay greppable/alertable — an operator "+
			"has no other way to detect that the gate was never wired", dec.Rule)
	}
	// It must not masquerade as a normal policy allow.
	if dec.Rule == "allow" || strings.HasPrefix(dec.Rule, "allow:shell") {
		t.Errorf("rule = %q looks like an ordinary policy verdict; unwired must be distinguishable", dec.Rule)
	}
}

// TestRunPolicyCheck_WiredHookIsAuthoritative is the negative control: the
// nil-safe default must never shadow a wired hook. A regression here would be
// catastrophic and silent — every decision replaced by ALLOW.
func TestRunPolicyCheck_WiredHookIsAuthoritative(t *testing.T) {
	b := NewBridge(&Config{LogLevel: "info"}, nil, "test")

	var sawCall bool
	b.PolicyCheck = func(ctx context.Context, req *ToolsCallRequest) (Decision, error) {
		sawCall = true
		return Decision{Allow: false, Reason: "denied by test", Rule: "deny:test:rule"}, nil
	}

	dec, err := b.runPolicyCheck(context.Background(), &ToolsCallRequest{
		Namespace: "fs", ToolName: "read_file", FullName: "fs:read_file",
	})
	if err != nil {
		t.Fatalf("runPolicyCheck: %v", err)
	}
	if !sawCall {
		t.Fatal("the wired PolicyCheck hook was never invoked")
	}
	if dec.Allow {
		t.Fatal("a wired hook's DENY was overridden by the nil-safe ALLOW default")
	}
	if dec.Rule != "deny:test:rule" {
		t.Errorf("rule = %q, want the hook's verdict to pass through unmodified", dec.Rule)
	}
}
