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

	engine := NewEngineFromPolicy(pol)

	// Default agent: api.openai.com allowed
	result := engine.Check(ActionRequest{Scope: "network", Domain: "api.openai.com"}, "local")
	if result.Decision != Allow {
		t.Errorf("default: expected ALLOW for api.openai.com, got %s", result.Decision)
	}

	// Default agent: scholar.google.com denied (not in base rules)
	result = engine.Check(ActionRequest{Scope: "network", Domain: "scholar.google.com"}, "local")
	if result.Decision != Deny {
		t.Errorf("default: expected DENY for scholar.google.com, got %s", result.Decision)
	}

	// research-bot: scholar.google.com allowed (override)
	result = engine.Check(ActionRequest{
		Scope:   "network",
		Domain:  "scholar.google.com",
		AgentID: "research-bot",
	}, "local")
	if result.Decision != Allow {
		t.Errorf("research-bot: expected ALLOW for scholar.google.com, got %s", result.Decision)
	}

	// research-bot: api.openai.com denied (override replaces base network rules)
	result = engine.Check(ActionRequest{
		Scope:   "network",
		Domain:  "api.openai.com",
		AgentID: "research-bot",
	}, "local")
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

	engine := NewEngineFromPolicy(pol)

	// bot: shell rules should still work (not overridden)
	result := engine.Check(ActionRequest{
		Scope:   "shell",
		Command: "ls -la",
		AgentID: "bot",
	}, "local")
	if result.Decision != Allow {
		t.Errorf("bot shell: expected ALLOW for ls, got %s", result.Decision)
	}

	// bot: network override active
	result = engine.Check(ActionRequest{
		Scope:   "network",
		Domain:  "example.com",
		AgentID: "bot",
	}, "local")
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
	engine := NewEngineFromPolicy(pol)

	result := engine.Check(ActionRequest{Scope: "cost", EstCost: 0.10}, "local")
	if result.Decision != Allow {
		t.Errorf("expected ALLOW for $0.10, got %s: %s", result.Decision, result.Reason)
	}

	result = engine.Check(ActionRequest{Scope: "cost", EstCost: 0.30}, "local")
	if result.Decision != RequireApproval {
		t.Errorf("expected REQUIRE_APPROVAL for $0.30, got %s: %s", result.Decision, result.Reason)
	}

	result = engine.Check(ActionRequest{Scope: "cost", EstCost: 1.00}, "local")
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

	engine := NewEngineFromPolicy(pol)

	// No cost estimate -> allow (can't evaluate)
	result := engine.Check(ActionRequest{Scope: "cost"}, "local")
	if result.Decision != Allow {
		t.Errorf("expected ALLOW with no estimate, got %s", result.Decision)
	}
}

// TestOverrideDenyInheritance closes R2 E5 / T11. The default override mode
// ("merge") inherits Deny rules from the base policy, so an agent override
// that only widens the Allow list cannot accidentally bypass a base deny
// such as `rm -rf *`. The "replace" mode opts out of inheritance and
// reproduces the v0.4.x behavior — required for narrowly-scoped privileged
// agents.
func TestOverrideDenyInheritance(t *testing.T) {
	build := func(mode string) *Policy {
		return &Policy{
			Version: "1",
			Name:    "override-deny-inherit",
			Rules: []RuleSet{
				{
					Scope: "shell",
					Deny: []Rule{
						{Pattern: "rm -rf *", Message: "base deny"},
					},
					Allow: []Rule{{Pattern: "ls *"}},
				},
			},
			Agents: map[string]AgentCfg{
				"bot1": {
					OverrideMode: mode,
					Override: []RuleSet{
						{
							Scope: "shell",
							Allow: []Rule{{Pattern: "echo *"}},
						},
					},
				},
			},
		}
	}

	// Default mode (empty string → merge): the base deny must still fire
	// for bot1, and bot1's narrowed Allow list takes effect.
	t.Run("merge_default_inherits_deny", func(t *testing.T) {
		eng := NewEngineFromPolicy(build("")) // empty == merge
		got := eng.Check(ActionRequest{
			Scope: "shell", Command: "rm -rf /", AgentID: "bot1",
		}, "local")
		if got.Decision != Deny {
			t.Errorf("merge default: expected DENY (inherited base deny), got %s: %s", got.Decision, got.Reason)
		}

		// bot1's override should ALSO grant `echo *` even though base
		// only had `ls *` — the override Allow narrows to its own list.
		got = eng.Check(ActionRequest{
			Scope: "shell", Command: "echo hi", AgentID: "bot1",
		}, "local")
		if got.Decision != Allow {
			t.Errorf("merge default: expected ALLOW for echo hi, got %s: %s", got.Decision, got.Reason)
		}

		// And `ls -la` (only in base allow, NOT in override allow) must
		// fall through to default-deny because merge intentionally does
		// not inherit base allows.
		got = eng.Check(ActionRequest{
			Scope: "shell", Command: "ls -la", AgentID: "bot1",
		}, "local")
		if got.Decision != Deny {
			t.Errorf("merge default: expected DENY for ls -la (override does not inherit base allow), got %s", got.Decision)
		}
	})

	t.Run("explicit_merge_inherits_deny", func(t *testing.T) {
		eng := NewEngineFromPolicy(build(OverrideModeMerge))
		got := eng.Check(ActionRequest{
			Scope: "shell", Command: "rm -rf /", AgentID: "bot1",
		}, "local")
		if got.Decision != Deny {
			t.Errorf("explicit merge: expected DENY (inherited base deny), got %s", got.Decision)
		}
	})

	t.Run("replace_drops_base_deny", func(t *testing.T) {
		eng := NewEngineFromPolicy(build(OverrideModeReplace))
		// echo allowed because override declares it.
		got := eng.Check(ActionRequest{
			Scope: "shell", Command: "echo hi", AgentID: "bot1",
		}, "local")
		if got.Decision != Allow {
			t.Errorf("replace: expected ALLOW for echo, got %s", got.Decision)
		}
		// rm -rf — base deny is GONE. The override has no allow that
		// matches "rm -rf /", so the result is default-deny (not the
		// `base deny` message). The point of this assertion is that the
		// matched Rule is no longer the inherited deny.
		got = eng.Check(ActionRequest{
			Scope: "shell", Command: "rm -rf /", AgentID: "bot1",
		}, "local")
		if got.Reason == "base deny" {
			t.Errorf("replace mode: expected base deny NOT to fire, but it did: %s", got.Reason)
		}
	})

	t.Run("no_agent_id_uses_base_deny", func(t *testing.T) {
		eng := NewEngineFromPolicy(build(""))
		// No AgentID: base policy applies and the deny fires.
		got := eng.Check(ActionRequest{
			Scope: "shell", Command: "rm -rf /",
		}, "local")
		if got.Decision != Deny || got.Reason != "base deny" {
			t.Errorf("no agent: expected base DENY, got %s: %s", got.Decision, got.Reason)
		}
	})
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

	engine := NewEngineFromPolicy(pol)

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
