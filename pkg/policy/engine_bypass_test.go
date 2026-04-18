package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Caua-ferraz/AgentGuard/pkg/deprecation"
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

	engine := NewEngine(pol)

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
			})
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
	engine := NewEngine(pol)

	for i := 0; i < 5; i++ {
		if r := engine.Check(ActionRequest{Scope: "cost", EstCost: 1.00, SessionID: "s"}); r.Decision != Allow {
			t.Fatalf("check %d should allow, got %s", i, r.Decision)
		}
	}
	// At limit; next is denied.
	if r := engine.Check(ActionRequest{Scope: "cost", EstCost: 1.00, SessionID: "s"}); r.Decision != Deny {
		t.Fatalf("expected DENY at limit, got %s", r.Decision)
	}

	// Refund $2 — should now allow at least one more $1 action.
	engine.RefundCost("s", 2.00)
	if r := engine.Check(ActionRequest{Scope: "cost", EstCost: 1.00, SessionID: "s"}); r.Decision != Allow {
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
	engine := NewEngine(pol)

	// A naive agent sends a null-byte-laced path; after stripping control
	// chars, the path is "/etc/passwd" — the deny rule fires.
	r := engine.Check(ActionRequest{
		Scope:  "filesystem",
		Action: "read",
		Path:   "/etc/passwd\x00/spoofed-allowed",
	})
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
	engine := NewEngine(pol)

	// %2E%2E == "..". After decode + Clean, this is outside workspace, so
	// it should not match the allow rule, and therefore falls to default deny.
	r := engine.Check(ActionRequest{
		Scope:  "filesystem",
		Action: "read",
		Path:   "./workspace/%2E%2E/etc/passwd",
	})
	if r.Decision != Deny {
		t.Errorf("URL-encoded traversal must be denied, got %s: %s", r.Decision, r.Reason)
	}
}

// TestConditionalRule_TimeWindowOnly_DeprecationCounter verifies that loading
// a policy with an orphan time_window (no require_prior) bumps the
// deprecation counter exposed by pkg/deprecation. This is the signal
// operators scrape before upgrading to v0.5.0, which will turn the warning
// into a load error.
//
// Contract under test:
//   - Each LoadFromFile call that observes at least one orphan rule
//     increments the counter by exactly 1 (not once per orphan rule — see
//     the comment in warnTimeWindowOnlyConditions).
//   - A policy with no orphan rules does NOT increment the counter.
//   - Evaluation behavior is unchanged (covered by
//     TestConditionalRule_TimeWindowOnly_BackwardCompat below).
func TestConditionalRule_TimeWindowOnly_DeprecationCounter(t *testing.T) {
	const featureKey = "policy.time_window_without_require_prior"
	deprecation.Reset()

	// Orphan policy: time_window present, require_prior absent.
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
	// Clean policy: no conditions.
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

	if _, err := LoadFromFile(orphanPath); err != nil {
		t.Fatalf("load orphan: %v", err)
	}
	if got := deprecation.Count(featureKey); got != 1 {
		t.Errorf("after first orphan load: count = %d, want 1", got)
	}

	if _, err := LoadFromFile(orphanPath); err != nil {
		t.Fatalf("reload orphan: %v", err)
	}
	if got := deprecation.Count(featureKey); got != 2 {
		t.Errorf("after second orphan load: count = %d, want 2 (one increment per load)", got)
	}

	if _, err := LoadFromFile(cleanPath); err != nil {
		t.Fatalf("load clean: %v", err)
	}
	if got := deprecation.Count(featureKey); got != 2 {
		t.Errorf("clean load must not bump counter: count = %d, want 2", got)
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
	engine := NewEngine(pol)
	engine.SetHistoryQuerier(&mockHistory{entries: nil})

	r := engine.Check(ActionRequest{Scope: "shell", Command: "deploy prod"})
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
	engine := NewEngine(pol)

	const n = 500
	for i := 0; i < n; i++ {
		sid := fmt.Sprintf("sess-%d", i)
		if r := engine.Check(ActionRequest{Scope: "cost", EstCost: 1.00, SessionID: sid}); r.Decision != Allow {
			t.Fatalf("sess-%d first check expected ALLOW, got %s", i, r.Decision)
		}
	}
	// Second pass — all still under the $2 limit.
	for i := 0; i < n; i++ {
		sid := fmt.Sprintf("sess-%d", i)
		if r := engine.Check(ActionRequest{Scope: "cost", EstCost: 1.00, SessionID: sid}); r.Decision != Allow {
			t.Fatalf("sess-%d second check expected ALLOW, got %s", i, r.Decision)
		}
	}
	// Third pass — each session is now at $2 and the next $0.01 must deny.
	for i := 0; i < n; i++ {
		sid := fmt.Sprintf("sess-%d", i)
		if r := engine.Check(ActionRequest{Scope: "cost", EstCost: 0.01, SessionID: sid}); r.Decision != Deny {
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
	engine := NewEngine(pol)

	check := func(agent, domain string) Decision {
		return engine.Check(ActionRequest{Scope: "network", Domain: domain, AgentID: agent}).Decision
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
	engine := NewEngine(pol)

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
				_ = engine.Check(ActionRequest{Scope: "shell", Command: cmd, AgentID: agent})
			}
		}(g)
	}
	wg.Wait()
}
