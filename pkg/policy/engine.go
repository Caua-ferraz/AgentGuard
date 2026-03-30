package policy

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// Decision represents the outcome of a policy check.
type Decision string

const (
	Allow           Decision = "ALLOW"
	Deny            Decision = "DENY"
	RequireApproval Decision = "REQUIRE_APPROVAL"
)

// CheckResult is the response returned after evaluating an action against policy.
type CheckResult struct {
	Decision    Decision `json:"decision"`
	Reason      string   `json:"reason"`
	Rule        string   `json:"matched_rule,omitempty"`
	ApprovalID  string   `json:"approval_id,omitempty"`
	ApprovalURL string   `json:"approval_url,omitempty"`
}

// Policy is the top-level policy document.
type Policy struct {
	Version       string              `yaml:"version"`
	Name          string              `yaml:"name"`
	Description   string              `yaml:"description"`
	Rules         []RuleSet           `yaml:"rules"`
	Agents        map[string]AgentCfg `yaml:"agents,omitempty"`
	Notifications NotificationCfg     `yaml:"notifications,omitempty"`
}

// RuleSet groups rules by scope.
type RuleSet struct {
	Scope           string        `yaml:"scope"`
	Allow           []Rule        `yaml:"allow,omitempty"`
	Deny            []Rule        `yaml:"deny,omitempty"`
	RequireApproval []Rule        `yaml:"require_approval,omitempty"`
	RateLimit       *RateLimitCfg `yaml:"rate_limit,omitempty"`
	Limits          *CostLimits   `yaml:"limits,omitempty"`
}

// Rule is an individual policy rule.
type Rule struct {
	Action     string      `yaml:"action,omitempty"`
	Pattern    string      `yaml:"pattern,omitempty"`
	Paths      []string    `yaml:"paths,omitempty"`
	Domain     string      `yaml:"domain,omitempty"`
	Message    string      `yaml:"message,omitempty"`
	Conditions []Condition `yaml:"conditions,omitempty"`
}

// Condition is a contextual constraint on a rule.
type Condition struct {
	RequirePrior string `yaml:"require_prior,omitempty"`
	TimeWindow   string `yaml:"time_window,omitempty"`
}

// RateLimitCfg defines rate limiting parameters.
type RateLimitCfg struct {
	MaxRequests int    `yaml:"max_requests"`
	Window      string `yaml:"window"`
}

// CostLimits defines cost guardrails for a scope.
type CostLimits struct {
	MaxPerAction    string `yaml:"max_per_action,omitempty"`
	MaxPerSession   string `yaml:"max_per_session,omitempty"`
	AlertThreshold  string `yaml:"alert_threshold,omitempty"`
}

// AgentCfg defines per-agent policy overrides.
type AgentCfg struct {
	Extends  string    `yaml:"extends"`
	Override []RuleSet `yaml:"override,omitempty"`
}

// NotificationCfg defines where to send alerts.
type NotificationCfg struct {
	ApprovalRequired []NotifyTarget `yaml:"approval_required,omitempty"`
	OnDeny           []NotifyTarget `yaml:"on_deny,omitempty"`
}

// NotifyTarget is a notification destination.
type NotifyTarget struct {
	Type  string `yaml:"type"`  // "webhook", "slack", "console", "log"
	URL   string `yaml:"url,omitempty"`
	Level string `yaml:"level,omitempty"`
}

// LoadFromFile reads and parses a policy YAML file.
func LoadFromFile(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading policy file: %w", err)
	}

	var pol Policy
	if err := yaml.Unmarshal(data, &pol); err != nil {
		return nil, fmt.Errorf("parsing policy YAML: %w", err)
	}

	if pol.Version == "" {
		return nil, fmt.Errorf("policy missing required 'version' field")
	}
	if pol.Name == "" {
		return nil, fmt.Errorf("policy missing required 'name' field")
	}

	return &pol, nil
}

// RuleCount returns the total number of individual rules.
func (p *Policy) RuleCount() int {
	count := 0
	for _, rs := range p.Rules {
		count += len(rs.Allow) + len(rs.Deny) + len(rs.RequireApproval)
	}
	return count
}

// ScopeCount returns the number of unique scopes.
func (p *Policy) ScopeCount() int {
	seen := map[string]bool{}
	for _, rs := range p.Rules {
		seen[rs.Scope] = true
	}
	return len(seen)
}

// Engine evaluates actions against a policy.
type Engine struct {
	mu     sync.RWMutex
	policy *Policy
}

// NewEngine creates a policy engine with the given policy.
func NewEngine(pol *Policy) *Engine {
	return &Engine{policy: pol}
}

// UpdatePolicy hot-swaps the active policy.
func (e *Engine) UpdatePolicy(pol *Policy) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.policy = pol
}

// Policy returns the currently active policy (thread-safe).
func (e *Engine) Policy() *Policy {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.policy
}

// ActionRequest represents an agent's intended action.
type ActionRequest struct {
	Scope     string            `json:"scope"`
	Action    string            `json:"action,omitempty"`
	Command   string            `json:"command,omitempty"`
	Path      string            `json:"path,omitempty"`
	Domain    string            `json:"domain,omitempty"`
	URL       string            `json:"url,omitempty"`
	AgentID   string            `json:"agent_id,omitempty"`
	SessionID string            `json:"session_id,omitempty"`
	EstCost   float64           `json:"est_cost,omitempty"`
	Meta      map[string]string `json:"meta,omitempty"`
}

// Check evaluates an action request against the active policy.
// Order: deny rules -> require_approval rules -> allow rules -> default deny.
// Per-agent overrides are applied when AgentID matches a key in policy.Agents.
func (e *Engine) Check(req ActionRequest) CheckResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	rules := e.resolveRules(req.AgentID)

	for _, rs := range rules {
		if rs.Scope != req.Scope {
			continue
		}

		// Cost scope: evaluate limits instead of pattern rules
		if rs.Scope == "cost" && rs.Limits != nil {
			return e.checkCost(rs, req)
		}

		// 1. Check deny rules first
		for _, rule := range rs.Deny {
			if matchRule(rule, req) {
				msg := rule.Message
				if msg == "" {
					msg = fmt.Sprintf("Action denied by %s deny rule", rs.Scope)
				}
				return CheckResult{
					Decision: Deny,
					Reason:   msg,
					Rule:     formatRule("deny", rs.Scope, rule),
				}
			}
		}

		// 2. Check require_approval rules
		for _, rule := range rs.RequireApproval {
			if matchRule(rule, req) {
				return CheckResult{
					Decision: RequireApproval,
					Reason:   fmt.Sprintf("Matches approval rule in %s scope", rs.Scope),
					Rule:     formatRule("require_approval", rs.Scope, rule),
				}
			}
		}

		// 3. Check allow rules
		for _, rule := range rs.Allow {
			if matchRule(rule, req) {
				return CheckResult{
					Decision: Allow,
					Reason:   fmt.Sprintf("Allowed by %s rule", rs.Scope),
					Rule:     formatRule("allow", rs.Scope, rule),
				}
			}
		}
	}

	// Default deny
	return CheckResult{
		Decision: Deny,
		Reason:   "No matching allow rule (default deny)",
	}
}

// RateLimitConfig returns the rate limit config for a given scope, considering
// per-agent overrides. Returns nil if no rate limit is configured.
func (e *Engine) RateLimitConfig(scope, agentID string) *RateLimitCfg {
	e.mu.RLock()
	defer e.mu.RUnlock()

	rules := e.resolveRules(agentID)
	for _, rs := range rules {
		if rs.Scope == scope && rs.RateLimit != nil {
			return rs.RateLimit
		}
	}
	return nil
}

// resolveRules returns the effective rule list for a given agent.
// If the agent has overrides in the policy, scope-level overrides replace
// the base rules for those scopes; non-overridden scopes use the base rules.
func (e *Engine) resolveRules(agentID string) []RuleSet {
	if agentID == "" || e.policy.Agents == nil {
		return e.policy.Rules
	}

	agentCfg, ok := e.policy.Agents[agentID]
	if !ok {
		return e.policy.Rules
	}

	// Build a map of overridden scopes
	overridden := make(map[string]RuleSet, len(agentCfg.Override))
	for _, rs := range agentCfg.Override {
		overridden[rs.Scope] = rs
	}

	// Merge: use override for scopes that have one, base for the rest
	var merged []RuleSet
	seen := make(map[string]bool)

	for _, rs := range e.policy.Rules {
		if override, ok := overridden[rs.Scope]; ok {
			merged = append(merged, override)
			seen[rs.Scope] = true
		} else {
			merged = append(merged, rs)
			seen[rs.Scope] = true
		}
	}

	// Add any override scopes not in the base (agent adds a new scope)
	for scope, rs := range overridden {
		if !seen[scope] {
			merged = append(merged, rs)
		}
	}

	return merged
}

// checkCost evaluates cost limits for a request.
func (e *Engine) checkCost(rs RuleSet, req ActionRequest) CheckResult {
	if rs.Limits == nil {
		return CheckResult{Decision: Allow, Reason: "No cost limits configured"}
	}

	maxPerAction, err := parseDollar(rs.Limits.MaxPerAction)
	if err != nil {
		return CheckResult{
			Decision: Deny,
			Reason:   fmt.Sprintf("Invalid max_per_action in policy: %v", err),
			Rule:     "deny:cost:invalid_config",
		}
	}

	if req.EstCost > 0 && maxPerAction > 0 && req.EstCost > maxPerAction {
		return CheckResult{
			Decision: Deny,
			Reason:   fmt.Sprintf("Estimated cost $%.2f exceeds per-action limit of %s", req.EstCost, rs.Limits.MaxPerAction),
			Rule:     "deny:cost:max_per_action",
		}
	}

	alertThreshold, err := parseDollar(rs.Limits.AlertThreshold)
	if err != nil {
		return CheckResult{
			Decision: Deny,
			Reason:   fmt.Sprintf("Invalid alert_threshold in policy: %v", err),
			Rule:     "deny:cost:invalid_config",
		}
	}
	if req.EstCost > 0 && alertThreshold > 0 && req.EstCost > alertThreshold {
		return CheckResult{
			Decision: RequireApproval,
			Reason:   fmt.Sprintf("Estimated cost $%.2f exceeds alert threshold of %s", req.EstCost, rs.Limits.AlertThreshold),
			Rule:     "require_approval:cost:alert_threshold",
		}
	}

	return CheckResult{
		Decision: Allow,
		Reason:   "Cost within limits",
		Rule:     "allow:cost:within_limits",
	}
}

// parseDollar extracts a float from a string like "$0.50".
// Returns an error if the string is non-empty but not a valid number.
func parseDollar(s string) (float64, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "$")
	if s == "" {
		return 0, nil
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid cost value %q: %w", s, err)
	}
	return v, nil
}

// matchRule checks if an action request matches a specific rule.
func matchRule(rule Rule, req ActionRequest) bool {
	// Match by command pattern
	if rule.Pattern != "" && req.Command != "" {
		if globMatch(rule.Pattern, req.Command) {
			return true
		}
	}

	// Match by action + paths
	if rule.Action != "" && rule.Action == req.Action {
		if len(rule.Paths) == 0 {
			return true
		}
		for _, p := range rule.Paths {
			if globMatch(p, req.Path) {
				return true
			}
		}
	}

	// Match by domain
	if rule.Domain != "" && req.Domain != "" {
		if globMatch(rule.Domain, req.Domain) {
			return true
		}
	}

	return false
}

// globMatch performs simple glob pattern matching supporting * and **.
// Unlike filepath.Match, the single * wildcard matches any character including
// path separators, which is required for shell command patterns like "rm -rf *"
// matching "rm -rf /tmp/data".
// Supports multiple ** segments (e.g., "**/sensitive/**").
func globMatch(pattern, value string) bool {
	// Handle ** (match any number of path segments)
	if strings.Contains(pattern, "**") {
		parts := strings.Split(pattern, "**")
		// Clean up separators around ** segments
		for i := range parts {
			if i > 0 {
				parts[i] = strings.TrimPrefix(parts[i], "/")
			}
			if i < len(parts)-1 {
				parts[i] = strings.TrimSuffix(parts[i], "/")
			}
		}

		// Match each segment sequentially against the value
		remaining := value
		for i, part := range parts {
			if part == "" {
				continue
			}
			if i == 0 {
				// First segment must match the prefix
				if !strings.HasPrefix(remaining, part) {
					return false
				}
				remaining = remaining[len(part):]
			} else if i == len(parts)-1 {
				// Last segment must match the suffix
				if !strings.HasSuffix(remaining, part) {
					return false
				}
			} else {
				// Middle segments: find the segment anywhere in the remaining string
				idx := strings.Index(remaining, part)
				if idx < 0 {
					return false
				}
				remaining = remaining[idx+len(part):]
			}
		}
		return true
	}

	// Simple wildcard match: * matches zero or more of any character (including /)
	return wildcardMatch(pattern, value)
}

// wildcardMatch matches a pattern with * (any chars) and ? (single char) wildcards.
func wildcardMatch(pattern, value string) bool {
	px, vx := 0, 0
	starPx, starVx := -1, -1

	for vx < len(value) {
		if px < len(pattern) && (pattern[px] == '?' || pattern[px] == value[vx]) {
			px++
			vx++
		} else if px < len(pattern) && pattern[px] == '*' {
			starPx = px
			starVx = vx
			px++
		} else if starPx >= 0 {
			starVx++
			vx = starVx
			px = starPx + 1
		} else {
			return false
		}
	}

	for px < len(pattern) && pattern[px] == '*' {
		px++
	}

	return px == len(pattern)
}

func formatRule(decision, scope string, rule Rule) string {
	identifier := rule.Pattern
	if identifier == "" {
		identifier = rule.Action
	}
	if identifier == "" {
		identifier = rule.Domain
	}
	return fmt.Sprintf("%s:%s:%s", decision, scope, identifier)
}
