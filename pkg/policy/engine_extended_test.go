package policy

import (
	"testing"
	"time"
)

// Tests for multi-** glob pattern matching (audit fix #10).
func TestGlobMatch_MultiDoubleStar(t *testing.T) {
	tests := []struct {
		pattern string
		value   string
		want    bool
	}{
		// Two ** segments
		{"**/sensitive/**", "/home/user/sensitive/data.txt", true},
		{"**/sensitive/**", "/sensitive/file", true},
		{"**/sensitive/**", "/home/user/other/data.txt", false},

		// Prefix + ** + middle + **
		{"/home/**/.ssh/**", "/home/user/.ssh/id_rsa", true},
		{"/home/**/.ssh/**", "/home/user/.ssh/config", true},
		{"/home/**/.ssh/**", "/root/.ssh/id_rsa", false},

		// Three ** segments
		{"**/.config/**/secrets/**", "/home/user/.config/app/secrets/key.pem", true},
		{"**/.config/**/secrets/**", "/home/user/.config/secrets/token", true},
		{"**/.config/**/secrets/**", "/home/user/.config/app/data.txt", false},

		// Single ** still works (regression check)
		{"/etc/**", "/etc/passwd", true},
		{"/etc/**", "/etc/ssh/sshd_config", true},
		{"/etc/**", "/home/user/.bashrc", false},
		{"**", "/anything/at/all", true},
		{"./workspace/**", "./workspace/src/main.go", true},
		{"./workspace/**", "./other/file.txt", false},

		// Edge: ** at start and end with middle text
		{"**/node_modules/**", "/project/node_modules/express/index.js", true},
		{"**/node_modules/**", "/project/src/app.js", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_vs_"+tt.value, func(t *testing.T) {
			got := globMatch(tt.pattern, tt.value)
			if got != tt.want {
				t.Errorf("globMatch(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
			}
		})
	}
}

// Tests for parseDollar error handling (audit fix #3).
func TestParseDollar(t *testing.T) {
	tests := []struct {
		input   string
		wantVal float64
		wantErr bool
	}{
		{"$0.50", 0.50, false},
		{"$1.00", 1.00, false},
		{"0.25", 0.25, false},
		{"$0", 0, false},
		{"", 0, false},
		{"  $0.75  ", 0.75, false},

		// Invalid values must error (audit fix — was silently returning 0)
		{"$abc", 0, true},
		{"$", 0, false},          // just a dollar sign with no number = empty string = 0
		{"not_a_number", 0, true},
		{"$1.2.3", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parseDollar(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseDollar(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.wantVal {
				t.Errorf("parseDollar(%q) = %v, want %v", tt.input, got, tt.wantVal)
			}
		})
	}
}

// Test that invalid cost config in policy returns DENY (not silent allow).
func TestEngineCheck_CostInvalidConfig(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "test-invalid-cost",
		Rules: []RuleSet{
			{
				Scope: "cost",
				Limits: &CostLimits{
					MaxPerAction: "$abc", // Invalid
				},
			},
		},
	}

	engine := NewEngine(pol)
	result := engine.Check(ActionRequest{Scope: "cost", EstCost: 0.10})
	if result.Decision != Deny {
		t.Errorf("expected DENY for invalid cost config, got %s: %s", result.Decision, result.Reason)
	}
	if result.Rule != "deny:cost:invalid_config" {
		t.Errorf("expected rule deny:cost:invalid_config, got %s", result.Rule)
	}
}

func TestEngineCheck_CostInvalidAlertThreshold(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "test-invalid-threshold",
		Rules: []RuleSet{
			{
				Scope: "cost",
				Limits: &CostLimits{
					MaxPerAction:   "$1.00",
					AlertThreshold: "$not-a-number",
				},
			},
		},
	}

	engine := NewEngine(pol)
	result := engine.Check(ActionRequest{Scope: "cost", EstCost: 0.10})
	if result.Decision != Deny {
		t.Errorf("expected DENY for invalid alert_threshold, got %s: %s", result.Decision, result.Reason)
	}
}

func TestEngineCheck_CostNegativeValue(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "test-negative-cost",
		Rules: []RuleSet{
			{
				Scope: "cost",
				Limits: &CostLimits{
					MaxPerAction:   "$1.00",
					AlertThreshold: "$0.50",
				},
			},
		},
	}

	engine := NewEngine(pol)

	// Negative cost should be denied
	result := engine.Check(ActionRequest{Scope: "cost", EstCost: -5.00})
	if result.Decision != Deny {
		t.Errorf("expected DENY for negative cost, got %s: %s", result.Decision, result.Reason)
	}
	if result.Rule != "deny:cost:negative_value" {
		t.Errorf("expected rule deny:cost:negative_value, got %s", result.Rule)
	}

	// Zero cost should be allowed (no bypass)
	result = engine.Check(ActionRequest{Scope: "cost", EstCost: 0})
	if result.Decision != Allow {
		t.Errorf("expected ALLOW for zero cost, got %s: %s", result.Decision, result.Reason)
	}
}

// Test the default policy loads and key rules work as expected after fixes.
func TestDefaultPolicy_LoadAndBasicRules(t *testing.T) {
	pol, err := LoadFromFile("../../configs/default.yaml")
	if err != nil {
		t.Fatalf("Failed to load default policy: %v", err)
	}

	engine := NewEngine(pol)

	tests := []struct {
		name     string
		req      ActionRequest
		expected Decision
	}{
		// Shell: safe commands allowed
		{"ls allowed", ActionRequest{Scope: "shell", Command: "ls -la"}, Allow},
		{"cat allowed", ActionRequest{Scope: "shell", Command: "cat /tmp/file"}, Allow},
		{"git allowed", ActionRequest{Scope: "shell", Command: "git status"}, Allow},

		// Shell: python .py file allowed, python -c requires approval
		{"python file allowed", ActionRequest{Scope: "shell", Command: "python script.py"}, Allow},
		{"python3 file allowed", ActionRequest{Scope: "shell", Command: "python3 test.py"}, Allow},
		{"python -c needs approval", ActionRequest{Scope: "shell", Command: "python -c import os"}, RequireApproval},
		{"python3 -m needs approval", ActionRequest{Scope: "shell", Command: "python3 -m http.server"}, RequireApproval},
		{"node -e needs approval", ActionRequest{Scope: "shell", Command: "node -e console.log(1)"}, RequireApproval},

		// Shell: dangerous commands denied or require approval
		{"fork bomb denied", ActionRequest{Scope: "shell", Command: ":(){ :|:& };:"}, Deny},
		{"sudo requires approval", ActionRequest{Scope: "shell", Command: "sudo apt install vim"}, RequireApproval},
		{"rm -rf requires approval", ActionRequest{Scope: "shell", Command: "rm -rf /tmp"}, RequireApproval},

		// Network: allowed domains
		{"openai allowed", ActionRequest{Scope: "network", Domain: "api.openai.com"}, Allow},
		{"anthropic allowed", ActionRequest{Scope: "network", Domain: "api.anthropic.com"}, Allow},
		{"googleapis allowed", ActionRequest{Scope: "network", Domain: "maps.googleapis.com"}, Allow},

		// Network: denied domains
		{"production denied", ActionRequest{Scope: "network", Domain: "db.production.internal"}, Deny},
		{"unknown denied", ActionRequest{Scope: "network", Domain: "evil.example.com"}, Deny},

		// Filesystem: workspace allowed
		{"workspace read", ActionRequest{Scope: "filesystem", Action: "read", Path: "./workspace/file.txt"}, Allow},
		{"workspace write", ActionRequest{Scope: "filesystem", Action: "write", Path: "./workspace/output.txt"}, Allow},

		// Filesystem: system dirs denied
		{"etc write denied", ActionRequest{Scope: "filesystem", Action: "write", Path: "/etc/passwd"}, Deny},
		{"usr write denied", ActionRequest{Scope: "filesystem", Action: "write", Path: "/usr/bin/evil"}, Deny},

		// Filesystem: credential dirs denied (expanded tilde fix)
		{"home ssh denied", ActionRequest{Scope: "filesystem", Action: "write", Path: "/home/user/.ssh/id_rsa"}, Deny},
		{"root ssh denied", ActionRequest{Scope: "filesystem", Action: "write", Path: "/root/.ssh/authorized_keys"}, Deny},
		{"home aws denied", ActionRequest{Scope: "filesystem", Action: "write", Path: "/home/user/.aws/credentials"}, Deny},
		{"root aws denied", ActionRequest{Scope: "filesystem", Action: "write", Path: "/root/.aws/config"}, Deny},

		// Filesystem: delete always denied
		{"delete denied", ActionRequest{Scope: "filesystem", Action: "delete", Path: "./workspace/file.txt"}, Deny},

		// Browser: allowed sites
		{"wikipedia allowed", ActionRequest{Scope: "browser", Domain: "en.wikipedia.org"}, Allow},
		{"stackoverflow allowed", ActionRequest{Scope: "browser", Domain: "www.stackoverflow.com"}, Allow},

		// Browser: denied sites
		{"bank denied", ActionRequest{Scope: "browser", Domain: "www.bank.com"}, Deny},
		{"gmail denied", ActionRequest{Scope: "browser", Domain: "mail.google.com"}, Deny},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.Check(tt.req)
			if result.Decision != tt.expected {
				t.Errorf("Check(%+v) = %s, want %s (reason: %s, rule: %s)",
					tt.req, result.Decision, tt.expected, result.Reason, result.Rule)
			}
		})
	}
}

// Test concurrent engine checks (race detector stress test).
func TestEngineCheck_ConcurrentSafety(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "concurrent-test",
		Rules: []RuleSet{
			{
				Scope: "shell",
				Allow: []Rule{{Pattern: "ls *"}},
				Deny:  []Rule{{Pattern: "rm *", Message: "blocked"}},
			},
			{
				Scope: "network",
				Allow: []Rule{{Domain: "api.openai.com"}},
			},
		},
	}

	engine := NewEngine(pol)
	done := make(chan struct{})

	// Run 100 concurrent checks
	for i := 0; i < 100; i++ {
		go func(n int) {
			defer func() { done <- struct{}{} }()
			if n%3 == 0 {
				r := engine.Check(ActionRequest{Scope: "shell", Command: "ls -la"})
				if r.Decision != Allow {
					t.Errorf("expected ALLOW for ls, got %s", r.Decision)
				}
			} else if n%3 == 1 {
				r := engine.Check(ActionRequest{Scope: "shell", Command: "rm file"})
				if r.Decision != Deny {
					t.Errorf("expected DENY for rm, got %s", r.Decision)
				}
			} else {
				r := engine.Check(ActionRequest{Scope: "network", Domain: "api.openai.com"})
				if r.Decision != Allow {
					t.Errorf("expected ALLOW for openai, got %s", r.Decision)
				}
			}
		}(i)
	}

	for i := 0; i < 100; i++ {
		<-done
	}
}

// --- Conditional rules (require_prior + time_window) ---

// mockHistory implements HistoryQuerier for testing.
type mockHistory struct {
	entries []HistoryEntry
}

func (m *mockHistory) RecentActions(agentID string, scope string, since time.Time) ([]HistoryEntry, error) {
	return m.entries, nil
}

func TestConditionalRule_RequirePrior_Met(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "cond-test",
		Rules: []RuleSet{
			{
				Scope: "shell",
				Allow: []Rule{
					{
						Pattern: "deploy *",
						Conditions: []Condition{
							{RequirePrior: "test *", TimeWindow: "1h"},
						},
					},
					{Pattern: "test *"},
				},
			},
		},
	}

	engine := NewEngine(pol)
	engine.SetHistoryQuerier(&mockHistory{
		entries: []HistoryEntry{
			{Command: "test all", Decision: Allow},
		},
	})

	// Deploy should be allowed because "test *" was recently allowed
	result := engine.Check(ActionRequest{Scope: "shell", Command: "deploy prod", AgentID: "bot"})
	if result.Decision != Allow {
		t.Errorf("expected ALLOW (prior condition met), got %s: %s", result.Decision, result.Reason)
	}
}

func TestConditionalRule_RequirePrior_NotMet(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "cond-test",
		Rules: []RuleSet{
			{
				Scope: "shell",
				Allow: []Rule{
					{
						Pattern: "deploy *",
						Conditions: []Condition{
							{RequirePrior: "test *", TimeWindow: "1h"},
						},
					},
				},
			},
		},
	}

	engine := NewEngine(pol)
	engine.SetHistoryQuerier(&mockHistory{entries: nil}) // no prior actions

	// Deploy should be denied because no prior "test *" action
	result := engine.Check(ActionRequest{Scope: "shell", Command: "deploy prod", AgentID: "bot"})
	if result.Decision != Deny {
		t.Errorf("expected DENY (prior condition not met), got %s: %s", result.Decision, result.Reason)
	}
}

func TestConditionalRule_RequirePrior_DeniedPriorDoesNotCount(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "cond-test",
		Rules: []RuleSet{
			{
				Scope: "shell",
				Allow: []Rule{
					{
						Pattern: "deploy *",
						Conditions: []Condition{
							{RequirePrior: "test *", TimeWindow: "1h"},
						},
					},
				},
			},
		},
	}

	engine := NewEngine(pol)
	engine.SetHistoryQuerier(&mockHistory{
		entries: []HistoryEntry{
			{Command: "test all", Decision: Deny}, // was denied, doesn't count
		},
	})

	result := engine.Check(ActionRequest{Scope: "shell", Command: "deploy prod", AgentID: "bot"})
	if result.Decision != Deny {
		t.Errorf("expected DENY (denied prior doesn't satisfy condition), got %s: %s", result.Decision, result.Reason)
	}
}

func TestConditionalRule_NoHistoryQuerier(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "cond-test",
		Rules: []RuleSet{
			{
				Scope: "shell",
				Allow: []Rule{
					{
						Pattern: "deploy *",
						Conditions: []Condition{
							{RequirePrior: "test *"},
						},
					},
				},
			},
		},
	}

	engine := NewEngine(pol) // no history querier set

	// Without a querier, conditions can't be verified → rule doesn't match → default deny
	result := engine.Check(ActionRequest{Scope: "shell", Command: "deploy prod"})
	if result.Decision != Deny {
		t.Errorf("expected DENY when no history querier, got %s", result.Decision)
	}
}

// --- Session-level cost tracking (max_per_session) ---

func TestSessionCost_EnforcesLimit(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "session-cost-test",
		Rules: []RuleSet{
			{
				Scope: "cost",
				Limits: &CostLimits{
					MaxPerAction:  "$5.00",
					MaxPerSession: "$10.00",
				},
			},
		},
	}

	engine := NewEngine(pol)

	// Check now atomically reserves the cost on Allow — no manual RecordCost
	// follow-up is needed (that would double-count).
	r1 := engine.Check(ActionRequest{Scope: "cost", EstCost: 4.00, SessionID: "sess-1"})
	if r1.Decision != Allow {
		t.Fatalf("expected ALLOW for $4, got %s: %s", r1.Decision, r1.Reason)
	}

	r2 := engine.Check(ActionRequest{Scope: "cost", EstCost: 4.00, SessionID: "sess-1"})
	if r2.Decision != Allow {
		t.Fatalf("expected ALLOW for $4 (cumulative $8), got %s: %s", r2.Decision, r2.Reason)
	}

	// Third action: $3.00 — denied (cumulative $8 + $3 = $11 > $10)
	r3 := engine.Check(ActionRequest{Scope: "cost", EstCost: 3.00, SessionID: "sess-1"})
	if r3.Decision != Deny {
		t.Fatalf("expected DENY for $3 (would exceed $10 session limit), got %s: %s", r3.Decision, r3.Reason)
	}
	if r3.Rule != "deny:cost:max_per_session" {
		t.Errorf("expected rule deny:cost:max_per_session, got %s", r3.Rule)
	}

	if got := engine.SessionCost("sess-1"); got != 8.00 {
		t.Errorf("expected sessionCosts[sess-1] = 8.00 (reserved twice), got %.2f", got)
	}
}

func TestSessionCost_IndependentSessions(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "session-cost-test",
		Rules: []RuleSet{
			{
				Scope: "cost",
				Limits: &CostLimits{
					MaxPerAction:  "$5.00",
					MaxPerSession: "$10.00",
				},
			},
		},
	}

	engine := NewEngine(pol)

	// Session A: reserve $9 up front (e.g. from prior session state restore).
	engine.RecordCost("sess-a", 9.00)

	// Session B: $4 should be allowed (independent).
	r := engine.Check(ActionRequest{Scope: "cost", EstCost: 4.00, SessionID: "sess-b"})
	if r.Decision != Allow {
		t.Errorf("expected ALLOW for separate session, got %s: %s", r.Decision, r.Reason)
	}

	// Session A: $2 should be denied ($9 + $2 > $10).
	r = engine.Check(ActionRequest{Scope: "cost", EstCost: 2.00, SessionID: "sess-a"})
	if r.Decision != Deny {
		t.Errorf("expected DENY for session A ($9 + $2 > $10), got %s: %s", r.Decision, r.Reason)
	}
}

func TestSessionCost_NoSessionID(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "session-cost-test",
		Rules: []RuleSet{
			{
				Scope: "cost",
				Limits: &CostLimits{
					MaxPerAction:  "$5.00",
					MaxPerSession: "$10.00",
				},
			},
		},
	}

	engine := NewEngine(pol)

	// No session ID → session limit not enforced
	r := engine.Check(ActionRequest{Scope: "cost", EstCost: 4.00})
	if r.Decision != Allow {
		t.Errorf("expected ALLOW without session ID, got %s: %s", r.Decision, r.Reason)
	}
}
