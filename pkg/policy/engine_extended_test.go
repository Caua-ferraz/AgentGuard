package policy

import (
	"testing"
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
