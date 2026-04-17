package policy

import (
	"testing"
)

func TestEngineCheck_PerAgentOverride(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "test",
		Rules: []RuleSet{
			{
				Scope: "network",
				Allow: []Rule{
					{Domain: "api.openai.com"},
				},
			},
		},
		Agents: map[string]AgentCfg{
			"research-bot": {
				Extends: "default",
				Override: []RuleSet{
					{
						Scope: "network",
						Allow: []Rule{
							{Domain: "scholar.google.com"},
							{Domain: "*.arxiv.org"},
						},
					},
				},
			},
		},
	}

	engine := NewEngine(pol)

	// Default agent: api.openai.com allowed
	result := engine.Check(ActionRequest{Scope: "network", Domain: "api.openai.com"})
	if result.Decision != Allow {
		t.Errorf("default: expected ALLOW for api.openai.com, got %s", result.Decision)
	}

	// Default agent: scholar.google.com denied (not in base rules)
	result = engine.Check(ActionRequest{Scope: "network", Domain: "scholar.google.com"})
	if result.Decision != Deny {
		t.Errorf("default: expected DENY for scholar.google.com, got %s", result.Decision)
	}

	// research-bot: scholar.google.com allowed (override)
	result = engine.Check(ActionRequest{
		Scope:   "network",
		Domain:  "scholar.google.com",
		AgentID: "research-bot",
	})
	if result.Decision != Allow {
		t.Errorf("research-bot: expected ALLOW for scholar.google.com, got %s", result.Decision)
	}

	// research-bot: api.openai.com denied (override replaces base network rules)
	result = engine.Check(ActionRequest{
		Scope:   "network",
		Domain:  "api.openai.com",
		AgentID: "research-bot",
	})
	if result.Decision != Deny {
		t.Errorf("research-bot: expected DENY for api.openai.com (overridden), got %s", result.Decision)
	}
}

func TestEngineCheck_AgentOverridePreservesOtherScopes(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "test",
		Rules: []RuleSet{
			{
				Scope: "shell",
				Allow: []Rule{{Pattern: "ls *"}},
			},
			{
				Scope: "network",
				Allow: []Rule{{Domain: "api.openai.com"}},
			},
		},
		Agents: map[string]AgentCfg{
			"bot": {
				Override: []RuleSet{
					{
						Scope: "network",
						Allow: []Rule{{Domain: "example.com"}},
					},
				},
			},
		},
	}

	engine := NewEngine(pol)

	// bot: shell rules should still work (not overridden)
	result := engine.Check(ActionRequest{
		Scope:   "shell",
		Command: "ls -la",
		AgentID: "bot",
	})
	if result.Decision != Allow {
		t.Errorf("bot shell: expected ALLOW for ls, got %s", result.Decision)
	}

	// bot: network override active
	result = engine.Check(ActionRequest{
		Scope:   "network",
		Domain:  "example.com",
		AgentID: "bot",
	})
	if result.Decision != Allow {
		t.Errorf("bot network: expected ALLOW for example.com, got %s", result.Decision)
	}
}

func TestEngineCheck_CostScope(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "test",
		Rules: []RuleSet{
			{
				Scope: "cost",
				Limits: &CostLimits{
					MaxPerAction:   "$0.50",
					AlertThreshold: "$0.25",
				},
			},
		},
	}

	// No session_id → reservations are no-ops, so each check is independent.
	engine := NewEngine(pol)

	result := engine.Check(ActionRequest{Scope: "cost", EstCost: 0.10})
	if result.Decision != Allow {
		t.Errorf("expected ALLOW for $0.10, got %s: %s", result.Decision, result.Reason)
	}

	result = engine.Check(ActionRequest{Scope: "cost", EstCost: 0.30})
	if result.Decision != RequireApproval {
		t.Errorf("expected REQUIRE_APPROVAL for $0.30, got %s: %s", result.Decision, result.Reason)
	}

	result = engine.Check(ActionRequest{Scope: "cost", EstCost: 1.00})
	if result.Decision != Deny {
		t.Errorf("expected DENY for $1.00, got %s: %s", result.Decision, result.Reason)
	}
}

func TestEngineCheck_CostNoEstimate(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "test",
		Rules: []RuleSet{
			{
				Scope: "cost",
				Limits: &CostLimits{
					MaxPerAction: "$0.50",
				},
			},
		},
	}

	engine := NewEngine(pol)

	// No cost estimate -> allow (can't evaluate)
	result := engine.Check(ActionRequest{Scope: "cost"})
	if result.Decision != Allow {
		t.Errorf("expected ALLOW with no estimate, got %s", result.Decision)
	}
}

func TestEngineRateLimitConfig(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "test",
		Rules: []RuleSet{
			{
				Scope:     "network",
				RateLimit: &RateLimitCfg{MaxRequests: 60, Window: "1m"},
			},
			{
				Scope: "shell",
			},
		},
	}

	engine := NewEngine(pol)

	rl := engine.RateLimitConfig("network", "")
	if rl == nil {
		t.Fatal("expected rate limit config for network scope")
	}
	if rl.MaxRequests != 60 {
		t.Errorf("expected 60 max requests, got %d", rl.MaxRequests)
	}

	rl = engine.RateLimitConfig("shell", "")
	if rl != nil {
		t.Error("expected no rate limit config for shell scope")
	}
}
