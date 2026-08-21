package llmproxy

// Contract tests for the nil-PolicyCheck behaviour (audit B5), the llmproxy
// twin of pkg/mcpgw/policy_hook_contract_test.go.
//
// Same posture: these are tripwires, not cages. They pin the current
// fail-open-when-unwired default and, more importantly, the two guarantees that
// make it survivable — the allow is identifiable, and the duplicate-JSON-key
// hard deny fires even with NO hook wired.
//
// If a future change makes the unwired server fail closed (the recommended B5
// direction), these SHOULD fail and be updated alongside a CHANGELOG entry.

import (
	"context"
	"strings"
	"testing"
)

func hookContractServer(t *testing.T) *Server {
	t.Helper()
	cfg := &Config{
		Listen:               "127.0.0.1:0",
		UpstreamOpenAI:       "https://api.openai.com",
		UpstreamAnthropic:    "https://api.anthropic.com",
		GuardURL:             "http://127.0.0.1:8080",
		TenantID:             "test",
		FailMode:             "deny",
		LogLevel:             "info",
		MaxBufferBytes:       DefaultMaxBufferBytes,
		MaxConcurrentStreams: DefaultMaxConcurrentStreams,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	if srv.PolicyCheck != nil {
		t.Fatal("precondition: a freshly constructed Server must have no PolicyCheck wired")
	}
	return srv
}

// TestRunPolicyCheck_NilHookAllows pins the fail-open default.
func TestRunPolicyCheck_NilHookAllows(t *testing.T) {
	s := hookContractServer(t)

	dec, err := s.runPolicyCheck(context.Background(), ToolCallCheck{
		Provider: "openai", ToolName: "bash", RawArguments: []byte(`{"command":"ls"}`),
	})
	if err != nil {
		t.Fatalf("runPolicyCheck with a nil hook returned an error: %v", err)
	}
	if !dec.Allow {
		t.Fatal("the unwired default is documented as ALLOW; if this changed deliberately, " +
			"update this test AND the CHANGELOG — it flips an observable default for embedders (B5)")
	}
}

// TestRunPolicyCheck_NilHookIsIdentifiable: with no startup guard, the rule
// string is the only trace that the proxy is forwarding tool calls it never
// evaluated. Asserts the marker is present and distinctive, not byte-exact, so
// the wording stays free to change.
func TestRunPolicyCheck_NilHookIsIdentifiable(t *testing.T) {
	s := hookContractServer(t)

	dec, err := s.runPolicyCheck(context.Background(), ToolCallCheck{
		Provider: "openai", ToolName: "bash", RawArguments: []byte(`{"command":"ls"}`),
	})
	if err != nil {
		t.Fatalf("runPolicyCheck: %v", err)
	}
	if dec.Rule == "" {
		t.Fatal("an unwired allow carries no rule string; an unwired proxy would be invisible (B5)")
	}
	if !strings.Contains(dec.Rule, "no_hook") && !strings.Contains(dec.Rule, "unwired") {
		t.Errorf("rule = %q; the unwired allow must stay greppable/alertable", dec.Rule)
	}
}

// TestRunPolicyCheck_DuplicateKeysDenyEvenWithNilHook is the most important of
// these. The duplicate-JSON-key refusal is a parser-differential defense (audit
// H3): the gate projects from a Go map (last-wins) while the ALLOW path replays
// raw argument bytes, so a first-wins downstream executor would act on a
// different value than the one gated.
//
// It is implemented as a HARD deny placed BEFORE the nil-hook check precisely
// so it cannot be bypassed by an unwired deployment. Order-dependent
// guarantees rot silently under refactor, so pin it: if someone moves the nil
// check above the duplicate-key check, an unwired proxy starts forwarding the
// exact payload this defense exists to stop.
func TestRunPolicyCheck_DuplicateKeysDenyEvenWithNilHook(t *testing.T) {
	s := hookContractServer(t)

	dec, err := s.runPolicyCheck(context.Background(), ToolCallCheck{
		Provider:     "openai",
		ToolName:     "bash",
		RawArguments: []byte(`{"command":"ls","command":"rm -rf /"}`),
	})
	if err != nil {
		t.Fatalf("runPolicyCheck: %v", err)
	}
	if dec.Allow {
		t.Fatal("duplicate JSON keys were ALLOWED with no hook wired — the parser-differential " +
			"defense must run BEFORE the nil-hook default, not after it (audit H3/B5)")
	}
	if !strings.Contains(dec.Rule, "duplicate") {
		t.Errorf("rule = %q, want it to identify the duplicate-key refusal", dec.Rule)
	}
}

// TestRunPolicyCheck_DuplicateKeysDenyOverrideWiredAllow is the companion: the
// hard deny must also beat a WIRED hook that says allow. It is documented as
// "fail closed regardless of the wired PolicyCheck", i.e. not subject to
// --fail-mode allow.
func TestRunPolicyCheck_DuplicateKeysDenyOverridesWiredAllow(t *testing.T) {
	s := hookContractServer(t)
	s.PolicyCheck = func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
		return Decision{Allow: true, Rule: "allow:test:permissive"}, nil
	}

	dec, err := s.runPolicyCheck(context.Background(), ToolCallCheck{
		Provider:     "openai",
		ToolName:     "bash",
		RawArguments: []byte(`{"command":"ls","command":"rm -rf /"}`),
	})
	if err != nil {
		t.Fatalf("runPolicyCheck: %v", err)
	}
	if dec.Allow {
		t.Fatal("a permissive wired hook overrode the duplicate-key hard deny; that refusal is " +
			"documented as unconditional (audit H3)")
	}
}

// TestRunPolicyCheck_WiredHookIsAuthoritative: the nil-safe default must never
// shadow a wired hook on ordinary input.
func TestRunPolicyCheck_WiredHookIsAuthoritative(t *testing.T) {
	s := hookContractServer(t)

	var sawCall bool
	s.PolicyCheck = func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
		sawCall = true
		return Decision{Allow: false, Reason: "denied by test", Rule: "deny:test:rule"}, nil
	}

	dec, err := s.runPolicyCheck(context.Background(), ToolCallCheck{
		Provider: "openai", ToolName: "bash", RawArguments: []byte(`{"command":"ls"}`),
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
