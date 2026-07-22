package policy

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- F2: case-insensitive domain matching -----------------------------------

// TestDomainMatch_CaseInsensitive_DenyFires locks in the security fix: a deny
// rule written as "evil.com" must fire for DNS-equivalent case variants of the
// request domain. Before the fix the request domain was compared case-
// sensitively, so "EVIL.com" skipped the deny and fell through to the broad
// allow — a true fail-open.
func TestDomainMatch_CaseInsensitive_DenyFires(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "domain-case-deny",
		Rules: []RuleSet{{
			Scope: "network",
			Deny:  []Rule{{Domain: "evil.com"}},
			// Broad allow so a skipped deny would visibly fail open (Allow).
			Allow: []Rule{{Domain: "*"}},
		}},
	}
	eng := NewEngineFromPolicy(pol)

	for _, dom := range []string{"evil.com", "EVIL.com", "Evil.Com", "evil.COM", "eViL.cOm"} {
		got := eng.Check(ActionRequest{Scope: "network", Domain: dom}, "local").Decision
		if got != Deny {
			t.Errorf("domain %q: expected DENY (case-insensitive), got %s", dom, got)
		}
	}

	// A domain that is not the deny target still passes the broad allow —
	// the fix must not over-broaden matching.
	if got := eng.Check(ActionRequest{Scope: "network", Domain: "GOOD.com"}, "local").Decision; got != Allow {
		t.Errorf("non-target domain GOOD.com: expected ALLOW, got %s", got)
	}
}

// TestDomainMatch_CaseInsensitive_WildcardSubdomain confirms wildcard domain
// patterns match case-insensitively: "*.evil.com" denies "API.Evil.com".
func TestDomainMatch_CaseInsensitive_WildcardSubdomain(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "domain-case-wild",
		Rules: []RuleSet{{
			Scope: "network",
			Deny:  []Rule{{Domain: "*.evil.com"}},
			Allow: []Rule{{Domain: "*"}},
		}},
	}
	eng := NewEngineFromPolicy(pol)

	for _, dom := range []string{"api.evil.com", "API.Evil.com", "API.EVIL.COM"} {
		if got := eng.Check(ActionRequest{Scope: "network", Domain: dom}, "local").Decision; got != Deny {
			t.Errorf("subdomain %q: expected DENY, got %s", dom, got)
		}
	}

	// Bare evil.com does NOT match *.evil.com (documented: `*` needs at least
	// one leading label), so the broad allow wins — unchanged by the case fix.
	if got := eng.Check(ActionRequest{Scope: "network", Domain: "Evil.Com"}, "local").Decision; got != Allow {
		t.Errorf("bare Evil.Com under *.evil.com deny: expected ALLOW (no leading label), got %s", got)
	}
}

// TestDomainMatch_LowercaseRuleAndRequest_Unchanged is a regression guard that
// the common all-lowercase path still matches exactly as before.
func TestDomainMatch_LowercaseRuleAndRequest_Unchanged(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "domain-lower",
		Rules: []RuleSet{{
			Scope: "network",
			Allow: []Rule{{Domain: "api.openai.com"}, {Domain: "*.arxiv.org"}},
		}},
	}
	eng := NewEngineFromPolicy(pol)

	if got := eng.Check(ActionRequest{Scope: "network", Domain: "api.openai.com"}, "local").Decision; got != Allow {
		t.Errorf("api.openai.com: expected ALLOW, got %s", got)
	}
	if got := eng.Check(ActionRequest{Scope: "network", Domain: "cs.arxiv.org"}, "local").Decision; got != Allow {
		t.Errorf("cs.arxiv.org: expected ALLOW, got %s", got)
	}
	if got := eng.Check(ActionRequest{Scope: "network", Domain: "other.com"}, "local").Decision; got != Deny {
		t.Errorf("other.com: expected default DENY, got %s", got)
	}
}

// TestNormalizeRuleDomains_LoweredAtLoad verifies the RULE side is folded to
// lower case once at load time (via parsePolicyBytes / LoadFromFile), so a
// policy authored with an uppercase domain still matches a lower-cased request.
func TestNormalizeRuleDomains_LoweredAtLoad(t *testing.T) {
	yamlDoc := []byte(`
version: "1"
name: "upper-domain"
rules:
  - scope: network
    deny:
      - domain: "EVIL.com"
      - domain: "*.BAD.COM"
    allow:
      - domain: "*"
`)
	pol, err := parsePolicyBytes(yamlDoc)
	if err != nil {
		t.Fatalf("parsePolicyBytes: %v", err)
	}
	if got := pol.Rules[0].Deny[0].Domain; got != "evil.com" {
		t.Errorf("rule domain not lowered at load: got %q, want %q", got, "evil.com")
	}
	if got := pol.Rules[0].Deny[1].Domain; got != "*.bad.com" {
		t.Errorf("wildcard rule domain not lowered at load: got %q, want %q", got, "*.bad.com")
	}

	// End-to-end: lowercase requests deny against the (originally uppercase)
	// rules — proving both sides are canonical.
	eng := NewEngineFromPolicy(pol)
	if got := eng.Check(ActionRequest{Scope: "network", Domain: "evil.com"}, "local").Decision; got != Deny {
		t.Errorf("lowercase request vs uppercase-loaded rule: expected DENY, got %s", got)
	}
	if got := eng.Check(ActionRequest{Scope: "network", Domain: "api.bad.com"}, "local").Decision; got != Deny {
		t.Errorf("subdomain of uppercase wildcard rule: expected DENY, got %s", got)
	}
}

// TestNormalizeRuleDomains_AgentOverride confirms per-agent override rulesets
// (map-valued) are normalized too, exercising the shared-backing-array path.
func TestNormalizeRuleDomains_AgentOverride(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "override-domain",
		Rules:   []RuleSet{{Scope: "network", Allow: []Rule{{Domain: "*"}}}},
		Agents: map[string]AgentCfg{
			"bot": {
				OverrideMode: OverrideModeReplace,
				Override: []RuleSet{{
					Scope: "network",
					Deny:  []Rule{{Domain: "EVIL.com"}},
					Allow: []Rule{{Domain: "*"}},
				}},
			},
		},
	}
	normalizeRuleDomains(pol)
	if got := pol.Agents["bot"].Override[0].Deny[0].Domain; got != "evil.com" {
		t.Errorf("agent override domain not lowered: got %q, want %q", got, "evil.com")
	}
}

// BenchmarkEngineCheck_DomainMatch exercises the network/domain hot path where
// the F2 ToLower on the request domain lives. The domain is already lower case
// (the common production case), so strings.ToLower fast-paths and returns the
// input with no allocation — this bench guards that the fix stays alloc-free.
func BenchmarkEngineCheck_DomainMatch(b *testing.B) {
	eng := NewEngineFromPolicy(&Policy{
		Version: "1", Name: "domain-bench",
		Rules: []RuleSet{{
			Scope: "network",
			Deny:  []Rule{{Domain: "evil.com"}, {Domain: "*.evil.com"}},
			Allow: []Rule{{Domain: "api.openai.com"}, {Domain: "*.arxiv.org"}},
		}},
	})
	req := ActionRequest{Scope: "network", Domain: "api.openai.com"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eng.Check(req, LocalTenantID)
	}
}

// --- F3: path-glob lint warning + docs-vs-code correctness ------------------

// TestPathPatternRecursesAcrossSlash pins the lint predicate: a path pattern
// with '/' and '*' but no '**' recurses across '/' and must be flagged.
func TestPathPatternRecursesAcrossSlash(t *testing.T) {
	cases := []struct {
		pattern string
		want    bool
	}{
		{"/workspace/*", true},
		{"/workspace/**", false},
		{"/workspace", false},
		{"/workspace/*/**", false},
		{"/a/b/*", true},
		{"*.txt", false},       // '*' but no '/'
		{"/etc/passwd", false}, // '/' but no '*'
		{"**/secret/**", false},
	}
	for _, tc := range cases {
		if got := pathPatternRecursesAcrossSlash(tc.pattern); got != tc.want {
			t.Errorf("pathPatternRecursesAcrossSlash(%q) = %v, want %v", tc.pattern, got, tc.want)
		}
	}
}

// TestLintPathPatterns_OnlyPaths confirms the lint inspects rule Paths only —
// a '/'+'*' shape in a domain or command pattern is not a path-recursion
// footgun and must not warn.
func TestLintPathPatterns_OnlyPaths(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "lint",
		Rules: []RuleSet{{
			Scope: "filesystem",
			Deny: []Rule{
				{Action: "read", Paths: []string{"/workspace/*"}},  // fires
				{Action: "read", Paths: []string{"/workspace/**"}}, // segment-aware, no warn
				{Pattern: "curl http://*/x"},                       // command pattern, not a path
				{Domain: "*.evil.com"},                             // domain pattern, not a path
			},
		}},
	}
	got := lintPathPatterns(pol)
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 warning, got %d: %v", len(got), got)
	}
	if !strings.Contains(got[0], "/workspace/*") {
		t.Errorf("warning should mention the offending pattern, got %q", got[0])
	}
}

// TestLintPathPatterns_LoggedAtLoadNonFatal verifies the warning is emitted via
// the standard logger at load and that the policy still loads (non-fatal).
func TestLintPathPatterns_LoggedAtLoadNonFatal(t *testing.T) {
	var buf bytes.Buffer
	origOut := log.Writer()
	origFlags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer func() {
		log.SetOutput(origOut)
		log.SetFlags(origFlags)
	}()

	dir := t.TempDir()

	warnDoc := `
version: "1"
name: "warn"
rules:
  - scope: filesystem
    allow:
      - action: read
        paths: ["/workspace/*"]
`
	warnPath := filepath.Join(dir, "warn.yaml")
	if err := os.WriteFile(warnPath, []byte(warnDoc), 0600); err != nil {
		t.Fatalf("write warn policy: %v", err)
	}
	if _, err := LoadFromFile(warnPath); err != nil {
		t.Fatalf("policy with recursive-star path must still load (non-fatal lint): %v", err)
	}
	if !strings.Contains(buf.String(), "/workspace/*") {
		t.Errorf("expected load-time lint warning mentioning /workspace/*, log was: %q", buf.String())
	}
	if !strings.Contains(buf.String(), "matches recursively") {
		t.Errorf("warning should explain recursive matching, log was: %q", buf.String())
	}

	// A '**' pattern is segment-aware and must NOT warn.
	buf.Reset()
	okDoc := `
version: "1"
name: "ok"
rules:
  - scope: filesystem
    allow:
      - action: read
        paths: ["/workspace/**"]
`
	okPath := filepath.Join(dir, "ok.yaml")
	if err := os.WriteFile(okPath, []byte(okDoc), 0600); err != nil {
		t.Fatalf("write ok policy: %v", err)
	}
	if _, err := LoadFromFile(okPath); err != nil {
		t.Fatalf("LoadFromFile(ok): %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("/workspace/** must not warn, but log had: %q", buf.String())
	}
}

// TestGlobMatch_PathStarCrossesSlash_Unchanged pins the CURRENT matching
// behavior. F3 corrects the docs and adds a lint warning but MUST NOT change
// how globMatch/wildcardMatch/doubleStarMatch match (frozen contract).
func TestGlobMatch_PathStarCrossesSlash_Unchanged(t *testing.T) {
	cases := []struct {
		pattern, value string
		want           bool
	}{
		{"/workspace/*", "/workspace/file.txt", true},
		{"/workspace/*", "/workspace/a/b/secret.env", true}, // '*' crosses '/'
		{"/workspace/**", "/workspace/a/b", true},
		{"/workspace/**", "/workspace", true}, // ** consumes zero segments
		{"**/secret/**", "/notsecret/x", false},
	}
	for _, tc := range cases {
		if got := globMatch(tc.pattern, tc.value); got != tc.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", tc.pattern, tc.value, got, tc.want)
		}
	}
}
