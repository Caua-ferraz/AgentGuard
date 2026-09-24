package policy

import (
	"strings"
	"testing"
)

func TestDuplicateScopeBlocksAreMerged(t *testing.T) {
	cases := map[string]string{
		"allow block first": `
version: "1"
name: t
rules:
  - scope: shell
    allow: [{pattern: "*"}]
  - scope: shell
    deny: [{pattern: "rm *"}]
`,
		"deny block first": `
version: "1"
name: t
rules:
  - scope: shell
    deny: [{pattern: "rm *"}]
  - scope: shell
    allow: [{pattern: "*"}]
`,
	}
	for name, yml := range cases {
		t.Run(name, func(t *testing.T) {
			pol, warnings, err := parsePolicyBytesWithWarnings([]byte(yml))
			if err != nil {
				t.Fatal(err)
			}
			if len(pol.Rules) != 1 {
				t.Fatalf("got %d rule sets, want 1 merged set", len(pol.Rules))
			}
			if len(warnings) != 1 || !strings.Contains(warnings[0], `scope "shell" appears in more than one block`) {
				t.Errorf("warnings = %q", warnings)
			}
			eng := NewEngineFromPolicy(pol)
			if got := eng.Check(ActionRequest{Scope: "shell", Command: "rm -rf /"}, LocalTenantID); got.Decision != Deny {
				t.Errorf("rm -rf / = %s (%s), want DENY", got.Decision, got.Rule)
			}
			if got := eng.Check(ActionRequest{Scope: "shell", Command: "ls"}, LocalTenantID); got.Decision != Allow {
				t.Errorf("ls = %s, want ALLOW", got.Decision)
			}
		})
	}
}

func TestDuplicateScopeBlocks_RateLimitConflict(t *testing.T) {
	conflict := `
version: "1"
name: t
rules:
  - scope: network
    allow: [{domain: "a.com"}]
    rate_limit: {max_requests: 10, window: "1m"}
  - scope: network
    allow: [{domain: "b.com"}]
    rate_limit: {max_requests: 20, window: "1m"}
`
	if _, _, err := parsePolicyBytesWithWarnings([]byte(conflict)); err == nil || !strings.Contains(err.Error(), "rate_limit") {
		t.Fatalf("err = %v, want a rate_limit conflict", err)
	}
	same := strings.Replace(conflict, "max_requests: 20", "max_requests: 10", 1)
	pol, _, err := parsePolicyBytesWithWarnings([]byte(same))
	if err != nil {
		t.Fatalf("identical rate limits should merge: %v", err)
	}
	if rl := pol.Rules[0].RateLimit; rl == nil || rl.MaxRequests != 10 || len(pol.Rules[0].Allow) != 2 {
		t.Errorf("merged set = %+v", pol.Rules[0])
	}
}

func TestDuplicateScopeBlocks_CostLimitsConflict(t *testing.T) {
	yml := `
version: "1"
name: t
rules:
  - scope: cost
    limits: {max_per_action: "$1"}
  - scope: cost
    limits: {max_per_action: "$2"}
`
	if _, _, err := parsePolicyBytesWithWarnings([]byte(yml)); err == nil || !strings.Contains(err.Error(), "limits") {
		t.Fatalf("err = %v, want a limits conflict", err)
	}
}

func TestDuplicateScopeBlocks_AgentOverride(t *testing.T) {
	yml := `
version: "1"
name: t
rules:
  - scope: shell
    allow: [{pattern: "ls *"}]
agents:
  bot:
    override:
      - scope: shell
        allow: [{pattern: "*"}]
      - scope: shell
        deny: [{pattern: "rm *"}]
`
	pol, warnings, err := parsePolicyBytesWithWarnings([]byte(yml))
	if err != nil {
		t.Fatal(err)
	}
	if len(pol.Agents["bot"].Override) != 1 || len(warnings) != 1 || !strings.Contains(warnings[0], "agents.bot.override[1]") {
		t.Fatalf("override = %+v warnings = %q", pol.Agents["bot"].Override, warnings)
	}
	eng := NewEngineFromPolicy(pol)
	if got := eng.Check(ActionRequest{Scope: "shell", Command: "rm -rf /", AgentID: "bot"}, LocalTenantID); got.Decision != Deny {
		t.Errorf("bot rm -rf / = %s, want DENY", got.Decision)
	}
}

func TestLintScopeNames(t *testing.T) {
	yml := `
version: "1"
name: t
rules:
  - scope: shel
    deny: [{pattern: "rm *"}]
  - scope: filesytem
    allow: [{action: read, paths: ["/tmp/**"]}]
  - scope: Shell
    allow: [{pattern: "ls *"}]
  - scope: deploy
    allow: [{pattern: "staging *"}]
  - scope: browser_rl
    allow: [{domain: "*"}]
agents:
  bot:
    override:
      - scope: netwrok
        allow: [{domain: "a.com"}]
`
	_, warnings, err := parsePolicyBytesWithWarnings([]byte(yml))
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(warnings, "\n")
	for _, want := range []string{
		`rules[0] scope "shel" is not a built-in scope — did you mean "shell"?`,
		`rules[1] scope "filesytem" is not a built-in scope — did you mean "filesystem"?`,
		`rules[2] scope "Shell" is not a built-in scope — did you mean "shell"?`,
		`agents.bot.override[0] scope "netwrok" is not a built-in scope — did you mean "network"?`,
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing warning %q in:\n%s", want, joined)
		}
	}
	for _, custom := range []string{`"deploy"`, `"browser_rl"`} {
		if strings.Contains(joined, custom) {
			t.Errorf("custom scope %s should not warn:\n%s", custom, joined)
		}
	}
}
