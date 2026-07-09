package llmproxy

// Malformed-verdict tests for the gate (review item H1).
//
// gate_test.go already covers an UNREACHABLE central server (the fail-mode
// branches) and a non-2xx status (TestLLMHTTPPolicyClient_Non2xxSurfacesAsFailMode).
// The dangerous gap these close is a REACHABLE server that answers 200 with
// bytes the gate cannot trust:
//
//   - a body that does not decode (garbage / truncated / empty), which must be
//     treated as a transport failure and resolved by --fail-mode (DENY by
//     default), never silently ALLOWed; and
//   - a well-formed body carrying an UNRECOGNISED decision, which must be a hard
//     DENY stamped InvalidResponseRule *regardless of --fail-mode* — a guardrail
//     must not let "fail-mode allow" turn an unparseable verdict into an allow.

import (
	"context"
	"strings"
	"testing"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// TestLLMHTTPPolicyClient_MalformedBodyFailsClosed: a 200 response whose body
// cannot be decoded is a transport-level failure. Under the default fail-mode
// deny it must surface an error AND return a fail-closed DENY — never ALLOW.
func TestLLMHTTPPolicyClient_MalformedBodyFailsClosed(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"garbage", "this is not json at all"},
		{"truncated", `{"schema_version":"v1","decision":"AL`},
		{"whitespace-only", " "},
		{"wrong-type", `{"decision": 12345}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := newMockGuardServer(t)
			m.SetHandler(func(policy.ActionRequest) (int, policy.CheckResult, string) {
				return 200, policy.CheckResult{}, c.body // raw body wins over result
			})
			gate := newGateForTest(t, m, "deny", nil)

			dec, err := gate.Check(context.Background(),
				toolCall("openai", "bash", map[string]interface{}{"command": "ls"}))
			if err == nil {
				t.Errorf("malformed body must surface a decode error, got nil")
			}
			if dec.Allow {
				t.Fatalf("malformed body with fail-mode deny must DENY, got %+v", dec)
			}
			if dec.Rule != FailModeRuleClosed {
				t.Errorf("expected fail-closed rule %q, got %q", FailModeRuleClosed, dec.Rule)
			}
		})
	}
}

// TestLLMHTTPPolicyClient_UnknownDecisionIsHardDenyEvenInFailModeAllow pins the
// strongest invariant: a reachable server returning a 200 with a syntactically
// valid but UNRECOGNISED decision is a hard DENY stamped InvalidResponseRule —
// and crucially this is NOT subject to --fail-mode, so even the most permissive
// posture ("allow") cannot be tricked into allowing an unparseable verdict.
// There is no transport error here (the response decoded fine), so err is nil.
func TestLLMHTTPPolicyClient_UnknownDecisionIsHardDenyEvenInFailModeAllow(t *testing.T) {
	m := newMockGuardServer(t)
	m.SetHandler(func(policy.ActionRequest) (int, policy.CheckResult, string) {
		// Empty Reason on purpose: exercises the gate's own attribution of an
		// unrecognised verdict (it synthesises "unknown decision: <value>").
		return 200, policy.CheckResult{
			SchemaVersion: "v1",
			Decision:      policy.Decision("MAYBE"), // not ALLOW/DENY/REQUIRE_APPROVAL
		}, ""
	})
	// fail-mode ALLOW deliberately — the most dangerous posture.
	gate := newGateForTest(t, m, "allow", nil)

	dec, err := gate.Check(context.Background(),
		toolCall("openai", "bash", map[string]interface{}{"command": "ls"}))
	if err != nil {
		t.Fatalf("a decodable (if nonsensical) response is not a transport error: %v", err)
	}
	if dec.Allow {
		t.Fatalf("unrecognised decision must DENY even in fail-mode allow, got %+v", dec)
	}
	if dec.Rule != InvalidResponseRule {
		t.Errorf("expected Rule=%q for an unknown decision, got %q", InvalidResponseRule, dec.Rule)
	}
	if !strings.Contains(dec.Reason, "MAYBE") {
		t.Errorf("expected reason to name the bad decision, got %q", dec.Reason)
	}
}
