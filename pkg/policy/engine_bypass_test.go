package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

// TestGlobMatch_SegmentBoundaries locks in the segment-matching semantics of
// `**`: the literal between `**`s must match a full path component, never an
// arbitrary substring. These cases all tripped the old HasPrefix/Index impl.
func TestGlobMatch_SegmentBoundaries(t *testing.T) {
	cases := []struct {
		pattern string
		value   string
		want    bool
	}{
		// Bypass cases — must NOT match.
		{"**/workspace/**", "/notworkspace/evil.txt", false},
		{"**/etc/**", "/home/fake_etc_backup/file", false},
		{"**/.ssh/**", "/home/user/my.ssh.backup/stuff", false},
		{"**/secret/**", "/notsecret/x", false},
		{"**/public/**", "/publicly/data", false},
		{"**/logs", "/weblogs", false},

		// Real matches — must still match.
		{"**/workspace/**", "/home/user/workspace/src/main.go", true},
		{"**/etc/**", "/etc/passwd", true},
		{"**/.ssh/**", "/home/user/.ssh/id_rsa", true},
		{"**/secret/**", "/a/b/secret/c/d", true},
		{"/home/**/.ssh/**", "/home/alice/.ssh/id_rsa", true},
		{"/home/**/.ssh/**", "/root/.ssh/id_rsa", false},

		// Anchored prefix patterns continue to work (regression).
		{"./workspace/**", "./workspace/ok.txt", true},
		{"./workspace/**", "/elsewhere/x", false},

		// Bare `**` still matches everything.
		{"**", "/anything/at/all", true},
	}

	for _, tc := range cases {
		got := globMatch(tc.pattern, tc.value)
		if got != tc.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", tc.pattern, tc.value, got, tc.want)
		}
	}
}

// TestGlobSemantics locks in the v0.5 stable contract for `globMatch`
// (closes R3 #11). It documents the asymmetry between path `**` and
// domain `*` semantics so a future refactor that "fixes" one of them
// breaks this test instead of silently breaking deployed policies.
//
// See the block comment at globMatch in engine.go for the full contract.
func TestGlobSemantics(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		value   string
		want    bool
	}{
		// --- Path patterns: ** matches zero or more whole segments. ---
		{"path:/etc/** matches /etc/passwd", "/etc/**", "/etc/passwd", true},
		// Documented asymmetry: `**` consumes zero segments, so
		// `/etc/**` ALSO matches `/etc` itself. Operators who want
		// "at least one segment under /etc" must list /etc separately.
		{"path:/etc/** matches /etc itself (zero-segment case)", "/etc/**", "/etc", true},
		{"path:/etc/** does not match /etcetera", "/etc/**", "/etcetera", false},
		// Bare `**` matches anything.
		{"path:** matches /a/b/c", "**", "/a/b/c", true},

		// --- Domain patterns: *.host.com requires at least one segment. ---
		{"domain:*.foo.com matches api.foo.com", "*.foo.com", "api.foo.com", true},
		// Documented asymmetry: bare `*` is character-greedy and
		// requires at least one character before the literal, so
		// `*.foo.com` does NOT match `foo.com`.
		{"domain:*.foo.com does NOT match foo.com (asymmetry)", "*.foo.com", "foo.com", false},
		{"domain:*.foo.com matches deep.api.foo.com", "*.foo.com", "deep.api.foo.com", true},
		{"domain:literal foo.com matches itself", "foo.com", "foo.com", true},

		// --- Shell-command patterns: * is greedy across spaces. ---
		{"shell:rm -rf * matches rm -rf /home/x", "rm -rf *", "rm -rf /home/x", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := globMatch(tc.pattern, tc.value); got != tc.want {
				t.Errorf("globMatch(%q, %q) = %v, want %v", tc.pattern, tc.value, got, tc.want)
			}
		})
	}
}

// TestSessionCost_ConcurrentCheckAndReserve verifies the atomic
// check-and-reserve: N goroutines racing on the same session_id must
// collectively stay at or under max_per_session.
func TestSessionCost_ConcurrentCheckAndReserve(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "cost-race",
		Rules: []RuleSet{
			{
				Scope: "cost",
				Limits: &CostLimits{
					MaxPerAction:  "$100.00",
					MaxPerSession: "$10.00",
				},
			},
		},
	}

	engine := NewEngineFromPolicy(pol)

	const workers = 64
	const costPerCheck = 1.00

	var allowed, denied int64
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := engine.Check(ActionRequest{
				Scope:     "cost",
				EstCost:   costPerCheck,
				SessionID: "race-session",
			}, "local")
			switch r.Decision {
			case Allow:
				atomic.AddInt64(&allowed, 1)
			case Deny:
				atomic.AddInt64(&denied, 1)
			}
		}()
	}
	wg.Wait()

	// Exactly 10 allows are possible (limit $10 / $1 each). Anything more is
	// a TOCTOU bug; anything less means we're under-allowing.
	if allowed != 10 {
		t.Errorf("expected exactly 10 allowed, got %d (denied=%d, reserved=$%.2f)",
			allowed, denied, engine.SessionCost("race-session"))
	}
	if engine.SessionCost("race-session") > 10.0 {
		t.Errorf("sessionCosts exceeded max_per_session: $%.2f", engine.SessionCost("race-session"))
	}
}

// TestEstCostZeroBypass closes R3 #4: an agent that always reports
// est_cost=0 cannot escape max_per_session. Once a session has accumulated
// real cost up to (or past) the limit, any subsequent check — including
// est_cost=0 — must be denied. Exactly-at-cap is still allowed (the literal
// limit value is a valid post-state); the bug only kicks in once cumulative
// strictly exceeds the cap.
func TestEstCostZeroBypass(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "est-cost-zero-bypass",
		Rules: []RuleSet{
			{Scope: "cost", Limits: &CostLimits{MaxPerSession: "$10.00"}},
		},
	}
	engine := NewEngineFromPolicy(pol)

	// 5 ALLOW reservations of $2 each → cumulative = $10 (exactly at cap).
	for i := 0; i < 5; i++ {
		r := engine.Check(ActionRequest{
			Scope:     "cost",
			EstCost:   2.00,
			SessionID: "s",
		}, "local")
		if r.Decision != Allow {
			t.Fatalf("call %d expected ALLOW, got %s: %s", i, r.Decision, r.Reason)
		}
	}
	if got := engine.SessionCost("s"); got != 10.00 {
		t.Fatalf("expected cumulative $10.00 after seeding, got $%.2f", got)
	}

	// est_cost=0 at exactly the cap is allowed: cumulative + 0 == cap, not >.
	r := engine.Check(ActionRequest{Scope: "cost", EstCost: 0, SessionID: "s"}, "local")
	if r.Decision != Allow {
		t.Errorf("est_cost=0 exactly at cap: expected ALLOW, got %s: %s", r.Decision, r.Reason)
	}

	// est_cost=0.01 over the cap must be denied (cumulative+0.01 > cap).
	r = engine.Check(ActionRequest{Scope: "cost", EstCost: 0.01, SessionID: "s"}, "local")
	if r.Decision != Deny {
		t.Errorf("est_cost=0.01 over cap: expected DENY, got %s: %s", r.Decision, r.Reason)
	}
	if r.Rule != "deny:cost:max_per_session" {
		t.Errorf("expected deny:cost:max_per_session, got rule=%q", r.Rule)
	}

	// Now push cumulative past the cap manually (simulate out-of-band
	// accounting via RecordCost) and verify est_cost=0 is denied.
	engine.RecordCost("s", 1.00) // cumulative = $11.00 > $10
	if got := engine.SessionCost("s"); got <= 10.00 {
		t.Fatalf("setup: expected cumulative > $10, got $%.2f", got)
	}
	r = engine.Check(ActionRequest{Scope: "cost", EstCost: 0, SessionID: "s"}, "local")
	if r.Decision != Deny {
		t.Errorf("est_cost=0 with cumulative over cap: expected DENY, got %s: %s", r.Decision, r.Reason)
	}
	if r.Rule != "deny:cost:max_per_session" {
		t.Errorf("expected deny:cost:max_per_session, got rule=%q", r.Rule)
	}
}

// TestRefundCost lets callers roll back a reservation if a downstream action
// failed after policy allowed it.
func TestRefundCost(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "refund",
		Rules: []RuleSet{
			{Scope: "cost", Limits: &CostLimits{MaxPerSession: "$5.00"}},
		},
	}
	engine := NewEngineFromPolicy(pol)

	for i := 0; i < 5; i++ {
		if r := engine.Check(ActionRequest{Scope: "cost", EstCost: 1.00, SessionID: "s"}, "local"); r.Decision != Allow {
			t.Fatalf("check %d should allow, got %s", i, r.Decision)
		}
	}
	// At limit; next is denied.
	if r := engine.Check(ActionRequest{Scope: "cost", EstCost: 1.00, SessionID: "s"}, "local"); r.Decision != Deny {
		t.Fatalf("expected DENY at limit, got %s", r.Decision)
	}

	// Refund $2 — should now allow at least one more $1 action.
	engine.RefundCost("s", 2.00)
	if r := engine.Check(ActionRequest{Scope: "cost", EstCost: 1.00, SessionID: "s"}, "local"); r.Decision != Allow {
		t.Fatalf("after refund, expected ALLOW, got %s: %s", r.Decision, r.Reason)
	}

	// Over-refund must clamp to zero, never go negative.
	engine.RefundCost("s", 1000.0)
	if got := engine.SessionCost("s"); got < 0 {
		t.Errorf("sessionCost must not go negative, got %.2f", got)
	}
}

// TestNormalizeRequest_NullByte ensures a null-byte-injected path is stripped
// before matching, so rule patterns can't be bypassed by truncation tricks.
func TestNormalizeRequest_NullByte(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "nullbyte",
		Rules: []RuleSet{
			{
				Scope: "filesystem",
				Deny: []Rule{
					{Action: "read", Paths: []string{"/etc/**"}},
				},
				Allow: []Rule{
					{Action: "read", Paths: []string{"./workspace/**"}},
				},
			},
		},
	}
	engine := NewEngineFromPolicy(pol)

	// A naive agent sends a null-byte-laced path; after stripping control
	// chars, the path is "/etc/passwd" — the deny rule fires.
	r := engine.Check(ActionRequest{
		Scope:  "filesystem",
		Action: "read",
		Path:   "/etc/passwd\x00/spoofed-allowed",
	}, "local")
	if r.Decision != Deny {
		t.Errorf("null-byte path must be denied, got %s: %s", r.Decision, r.Reason)
	}
}

// TestNormalizeRequest_URLEncoded ensures percent-encoded traversal is decoded
// before the ".." guard, instead of letting the encoded form slip through.
func TestNormalizeRequest_URLEncoded(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "urlenc",
		Rules: []RuleSet{
			{
				Scope: "filesystem",
				Allow: []Rule{
					{Action: "read", Paths: []string{"./workspace/**"}},
				},
			},
		},
	}
	engine := NewEngineFromPolicy(pol)

	// %2E%2E == "..". After decode + Clean, this is outside workspace, so
	// it should not match the allow rule, and therefore falls to default deny.
	r := engine.Check(ActionRequest{
		Scope:  "filesystem",
		Action: "read",
		Path:   "./workspace/%2E%2E/etc/passwd",
	}, "local")
	if r.Decision != Deny {
		t.Errorf("URL-encoded traversal must be denied, got %s: %s", r.Decision, r.Reason)
	}
}

// TestPolicyLoadRejectsTimeWindowWithoutPrior closes R2 S11. v0.4.x WARNed
// on a time_window without require_prior and let the load succeed; v0.5
// hard-fails so silent no-op rules cannot ship to production.
func TestPolicyLoadRejectsTimeWindowWithoutPrior(t *testing.T) {
	orphan := `
version: "1"
name: "orphan-tw"
rules:
  - scope: shell
    allow:
      - pattern: "deploy *"
        conditions:
          - time_window: "1h"
`
	clean := `
version: "1"
name: "clean"
rules:
  - scope: shell
    allow:
      - pattern: "ls *"
`

	dir := t.TempDir()
	orphanPath := filepath.Join(dir, "orphan.yaml")
	cleanPath := filepath.Join(dir, "clean.yaml")
	if err := os.WriteFile(orphanPath, []byte(orphan), 0600); err != nil {
		t.Fatalf("write orphan: %v", err)
	}
	if err := os.WriteFile(cleanPath, []byte(clean), 0600); err != nil {
		t.Fatalf("write clean: %v", err)
	}

	if _, err := LoadFromFile(orphanPath); err == nil {
		t.Fatal("LoadFromFile(orphan): expected error for time_window without require_prior, got nil")
	}
	// Sanity: a policy with no orphan condition still loads cleanly.
	if _, err := LoadFromFile(cleanPath); err != nil {
		t.Fatalf("LoadFromFile(clean): %v", err)
	}
}

// TestPolicyLoadValidatesDurations closes R3 #5 / R3 #15. Malformed durations
// or non-positive counts in rate-limit and condition.time_window must be
// rejected at load time so `agentguard validate` actually validates.
func TestPolicyLoadValidatesDurations(t *testing.T) {
	cases := []struct {
		name string
		yaml string
	}{
		{
			name: "garbage time_window with require_prior",
			yaml: `
version: "1"
name: "bad-time-window"
rules:
  - scope: shell
    allow:
      - pattern: "deploy *"
        conditions:
          - require_prior: "test *"
            time_window: "1minute"
`,
		},
		{
			name: "rate_limit window=0",
			yaml: `
version: "1"
name: "bad-rl-window"
rules:
  - scope: shell
    rate_limit:
      max_requests: 100
      window: "0s"
`,
		},
		{
			name: "rate_limit max_requests=0",
			yaml: `
version: "1"
name: "bad-rl-max"
rules:
  - scope: shell
    rate_limit:
      max_requests: 0
      window: "1m"
`,
		},
		{
			name: "rate_limit window unparseable",
			yaml: `
version: "1"
name: "bad-rl-window2"
rules:
  - scope: shell
    rate_limit:
      max_requests: 10
      window: "garbage"
`,
		},
	}

	dir := t.TempDir()
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(dir, fmt.Sprintf("c%d.yaml", i))
			if err := os.WriteFile(p, []byte(tc.yaml), 0600); err != nil {
				t.Fatalf("write: %v", err)
			}
			if _, err := LoadFromFile(p); err == nil {
				t.Fatalf("LoadFromFile(%q): expected error, got nil", tc.name)
			}
		})
	}
}

// TestConditionalRule_TimeWindowOnly_BackwardCompat: v0.4.0 treated
// conditions with only time_window (no require_prior) as no-ops — the rule
// matched regardless. v0.4.1 keeps that behavior for backward compat and
// emits a load-time warning instead of fail-closing. This test locks in the
// backward-compat contract.
func TestConditionalRule_TimeWindowOnly_BackwardCompat(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "time-only",
		Rules: []RuleSet{
			{
				Scope: "shell",
				Allow: []Rule{
					{
						Pattern:    "deploy *",
						Conditions: []Condition{{TimeWindow: "1h"}},
					},
				},
			},
		},
	}
	engine := NewEngineFromPolicy(pol)
	engine.SetHistoryQuerier(&mockHistory{entries: nil})

	r := engine.Check(ActionRequest{Scope: "shell", Command: "deploy prod"}, "local")
	// No RequirePrior set — the condition is a no-op, rule matches, ALLOW.
	if r.Decision != Allow {
		t.Errorf("expected ALLOW for time_window-only condition (backward compat), got %s: %s", r.Decision, r.Reason)
	}
}

// TestSessionCost_LargeSessionCountIsolation is a capacity-style test: lots of
// distinct session IDs must not affect each other's budgets.
func TestSessionCost_LargeSessionCountIsolation(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "cap",
		Rules: []RuleSet{
			{Scope: "cost", Limits: &CostLimits{MaxPerSession: "$2.00"}},
		},
	}
	engine := NewEngineFromPolicy(pol)

	const n = 500
	for i := 0; i < n; i++ {
		sid := fmt.Sprintf("sess-%d", i)
		if r := engine.Check(ActionRequest{Scope: "cost", EstCost: 1.00, SessionID: sid}, "local"); r.Decision != Allow {
			t.Fatalf("sess-%d first check expected ALLOW, got %s", i, r.Decision)
		}
	}
	// Second pass — all still under the $2 limit.
	for i := 0; i < n; i++ {
		sid := fmt.Sprintf("sess-%d", i)
		if r := engine.Check(ActionRequest{Scope: "cost", EstCost: 1.00, SessionID: sid}, "local"); r.Decision != Allow {
			t.Fatalf("sess-%d second check expected ALLOW, got %s", i, r.Decision)
		}
	}
	// Third pass — each session is now at $2 and the next $0.01 must deny.
	for i := 0; i < n; i++ {
		sid := fmt.Sprintf("sess-%d", i)
		if r := engine.Check(ActionRequest{Scope: "cost", EstCost: 0.01, SessionID: sid}, "local"); r.Decision != Deny {
			t.Fatalf("sess-%d third check expected DENY, got %s", i, r.Decision)
		}
	}
}

// TestMultiAgent_ScopedOverridesDontLeak verifies that an agent's override for
// one scope doesn't affect another agent, and doesn't leak to the default
// agent either.
func TestMultiAgent_ScopedOverridesDontLeak(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "multi-agent",
		Rules: []RuleSet{
			{
				Scope: "network",
				Allow: []Rule{{Domain: "api.openai.com"}},
			},
		},
		Agents: map[string]AgentCfg{
			"research": {
				Override: []RuleSet{
					{
						Scope: "network",
						Allow: []Rule{{Domain: "scholar.google.com"}, {Domain: "*.arxiv.org"}},
					},
				},
			},
			"trader": {
				Override: []RuleSet{
					{
						Scope: "network",
						Allow: []Rule{{Domain: "api.alpaca.markets"}},
					},
				},
			},
		},
	}
	engine := NewEngineFromPolicy(pol)

	check := func(agent, domain string) Decision {
		return engine.Check(ActionRequest{Scope: "network", Domain: domain, AgentID: agent}, "local").Decision
	}

	// Default agent unchanged.
	if d := check("", "api.openai.com"); d != Allow {
		t.Errorf("default: openai should ALLOW, got %s", d)
	}
	if d := check("", "scholar.google.com"); d != Deny {
		t.Errorf("default: scholar should DENY, got %s", d)
	}

	// Research agent: scholar allowed, openai removed.
	if d := check("research", "scholar.google.com"); d != Allow {
		t.Errorf("research: scholar should ALLOW, got %s", d)
	}
	if d := check("research", "api.openai.com"); d != Deny {
		t.Errorf("research: openai should DENY (overridden), got %s", d)
	}
	if d := check("research", "api.alpaca.markets"); d != Deny {
		t.Errorf("research: alpaca must not leak from trader agent, got %s", d)
	}

	// Trader agent: alpaca allowed, others blocked.
	if d := check("trader", "api.alpaca.markets"); d != Allow {
		t.Errorf("trader: alpaca should ALLOW, got %s", d)
	}
	if d := check("trader", "scholar.google.com"); d != Deny {
		t.Errorf("trader: scholar must not leak from research agent, got %s", d)
	}

	// Unknown agent falls back to default policy.
	if d := check("unknown", "api.openai.com"); d != Allow {
		t.Errorf("unknown agent should get default policy ALLOW for openai, got %s", d)
	}
}

// TestMultiAgent_ConcurrentChecks runs many parallel checks across a few
// agents to verify resolveRules + Check are race-clean under the race detector.
func TestMultiAgent_ConcurrentChecks(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "multi",
		Rules: []RuleSet{
			{Scope: "shell", Allow: []Rule{{Pattern: "ls *"}}},
		},
		Agents: map[string]AgentCfg{
			"a": {Override: []RuleSet{{Scope: "shell", Allow: []Rule{{Pattern: "echo *"}}}}},
			"b": {Override: []RuleSet{{Scope: "shell", Allow: []Rule{{Pattern: "cat *"}}}}},
			"c": {Override: []RuleSet{{Scope: "shell", Allow: []Rule{{Pattern: "grep *"}}}}},
		},
	}
	engine := NewEngineFromPolicy(pol)

	const goroutines = 64
	const iterations = 200

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(gi int) {
			defer wg.Done()
			agents := []string{"", "a", "b", "c"}
			for i := 0; i < iterations; i++ {
				agent := agents[(gi+i)%len(agents)]
				cmd := []string{"ls -la", "echo hi", "cat x", "grep -r ."}[(gi+i)%4]
				_ = engine.Check(ActionRequest{Scope: "shell", Command: cmd, AgentID: agent}, "local")
			}
		}(g)
	}
	wg.Wait()
}
