package policy

import (
	"strings"
	"testing"
)

// Tests for the `data` scope, used by the browser-use adapter's
// check_form_input / GuardedPage.fill flow.
//
// The engine treats `data` as a generic scope: standard Pattern, Action,
// and Domain matching apply with no scope-specific custom logic. The
// tests below pin that contract so a future engine refactor cannot
// silently regress.

func TestEngineCheck_DataScope_AllowsBenignValue(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "data-allow",
		Rules: []RuleSet{
			{
				Scope: "data",
				Allow: []Rule{
					{Pattern: "*"},
				},
			},
		},
	}
	engine := NewEngineFromPolicy(pol)

	res := engine.Check(ActionRequest{
		Scope:   "data",
		Command: "hello",
		URL:     "https://example.com/form",
		Action:  "form_input",
	}, "local")

	if res.Decision != Allow {
		t.Fatalf("expected ALLOW for benign data value, got %s (reason=%s, rule=%s)",
			res.Decision, res.Reason, res.Rule)
	}
}

func TestEngineCheck_DataScope_DeniesPIIPattern(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "data-deny-pii",
		Rules: []RuleSet{
			{
				Scope: "data",
				Deny: []Rule{
					{Pattern: "*ssn:*", Message: "SSN values are forbidden"},
				},
				Allow: []Rule{
					{Pattern: "*"},
				},
			},
		},
	}
	engine := NewEngineFromPolicy(pol)

	cases := []struct {
		name    string
		command string
		want    Decision
	}{
		{"contains ssn marker", "ssn:123-45-6789", Deny},
		{"benign value", "alice@example.com", Allow},
		{"prefix match", "hello ssn:123 here", Deny},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := engine.Check(ActionRequest{
				Scope:   "data",
				Command: tc.command,
				Action:  "form_input",
			}, "local")
			if res.Decision != tc.want {
				t.Fatalf("for %q want %s, got %s (reason=%s, rule=%s)",
					tc.command, tc.want, res.Decision, res.Reason, res.Rule)
			}
			if tc.want == Deny && !strings.Contains(res.Rule, "deny:data") {
				t.Errorf("expected matched_rule prefix deny:data, got %q", res.Rule)
			}
		})
	}
}

func TestEngineCheck_DataScope_DefaultDenyForUnconfigured(t *testing.T) {
	// Policy with no `data` rules at all — the previous behavior was a
	// silent default-deny with the generic "No matching allow rule"
	// reason, which made debugging impossible. The contract pinned here
	// is: default-deny still fires (we don't fail-open), but the result
	// is identifiable so adapters and operators can tell when their
	// engine is missing the scope rules.
	pol := &Policy{
		Version: "1",
		Name:    "no-data-rules",
		Rules: []RuleSet{
			{
				Scope: "shell",
				Allow: []Rule{{Pattern: "*"}},
			},
		},
	}
	engine := NewEngineFromPolicy(pol)

	res := engine.Check(ActionRequest{
		Scope:   "data",
		Command: "anything",
		Action:  "form_input",
	}, "local")

	if res.Decision != Deny {
		t.Fatalf("expected DENY for unconfigured data scope, got %s", res.Decision)
	}
	// The generic default-deny path returns "No matching allow rule
	// (default deny)". Pinning this here makes the regression coupon
	// explicit: if a future engine adds a permissive default for
	// unknown scopes, this test fires.
	if !strings.Contains(strings.ToLower(res.Reason), "default deny") {
		t.Errorf("expected default-deny reason, got %q", res.Reason)
	}
}

func TestEngineCheck_DataScope_DomainMatching(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "data-domain",
		Rules: []RuleSet{
			{
				Scope: "data",
				Allow: []Rule{
					{Domain: "*.internal.com"},
				},
				Deny: []Rule{
					{Pattern: "*"}, // catch-all deny so external requests fall to it via first-match precedence
				},
			},
		},
	}
	engine := NewEngineFromPolicy(pol)

	allow := engine.Check(ActionRequest{
		Scope:   "data",
		Command: "anything",
		Domain:  "api.internal.com",
		URL:     "https://api.internal.com/form",
		Action:  "form_input",
	}, "local")
	if allow.Decision != Deny {
		// Note: deny rules are evaluated BEFORE allow rules (first-match
		// per phase). Since the catch-all `pattern: "*"` deny appears
		// here, the *.internal.com allow would never fire. We pin this
		// to document the gotcha rather than to validate it as the only
		// safe pattern.
		t.Fatalf("with deny:* before allow:domain, expected DENY, got %s", allow.Decision)
	}

	// The intended allow-domain pattern: deny-list specific bad cases,
	// allow-list specific good ones, and let default-deny catch the rest.
	pol2 := &Policy{
		Version: "1",
		Name:    "data-domain-allow",
		Rules: []RuleSet{
			{
				Scope: "data",
				Allow: []Rule{
					{Domain: "*.internal.com"},
				},
			},
		},
	}
	engine2 := NewEngineFromPolicy(pol2)

	internal := engine2.Check(ActionRequest{
		Scope:   "data",
		Command: "value",
		Domain:  "api.internal.com",
		URL:     "https://api.internal.com/form",
		Action:  "form_input",
	}, "local")
	if internal.Decision != Allow {
		t.Errorf("expected ALLOW for *.internal.com domain, got %s (reason=%s)",
			internal.Decision, internal.Reason)
	}

	external := engine2.Check(ActionRequest{
		Scope:   "data",
		Command: "value",
		Domain:  "external.com",
		URL:     "https://external.com/form",
		Action:  "form_input",
	}, "local")
	if external.Decision != Deny {
		t.Errorf("expected DENY for external.com (default deny), got %s", external.Decision)
	}
}

func TestEngineCheck_DataScope_ActionMatching(t *testing.T) {
	// Verify the standard Action-field matching applies on the data
	// scope. The browser-use adapter sends Action="form_input" so a
	// rule keyed on Action should match without needing Pattern.
	pol := &Policy{
		Version: "1",
		Name:    "data-action",
		Rules: []RuleSet{
			{
				Scope: "data",
				Deny: []Rule{
					{Action: "form_input", Message: "form input blocked"},
				},
			},
		},
	}
	engine := NewEngineFromPolicy(pol)

	res := engine.Check(ActionRequest{
		Scope:   "data",
		Command: "value",
		Action:  "form_input",
	}, "local")
	if res.Decision != Deny {
		t.Fatalf("expected DENY for action=form_input, got %s", res.Decision)
	}
	if !strings.Contains(res.Reason, "form input blocked") {
		t.Errorf("expected custom message, got %q", res.Reason)
	}
}
