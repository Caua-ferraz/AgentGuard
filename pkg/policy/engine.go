package policy

import (
	"fmt"
	"os"
	"path/filepath"
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
	Type  string `yaml:"type"`  // "webhook", "console", "log"
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

// ActionRequest represents an agent's intended action.
type ActionRequest struct {
	Scope   string            `json:"scope"`
	Action  string            `json:"action,omitempty"`
	Command string            `json:"command,omitempty"`
	Path    string            `json:"path,omitempty"`
	Domain  string            `json:"domain,omitempty"`
	URL     string            `json:"url,omitempty"`
	AgentID string            `json:"agent_id,omitempty"`
	Meta    map[string]string `json:"meta,omitempty"`
}

// Check evaluates an action request against the active policy.
// Order: deny rules → require_approval rules → allow rules → default deny.
func (e *Engine) Check(req ActionRequest) CheckResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, rs := range e.policy.Rules {
		if rs.Scope != req.Scope {
			continue
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
func globMatch(pattern, value string) bool {
	// Use filepath.Match for simple globs
	if !strings.Contains(pattern, "**") {
		matched, _ := filepath.Match(pattern, value)
		return matched
	}

	// Handle ** (match any number of path segments)
	parts := strings.Split(pattern, "**")
	if len(parts) == 2 {
		prefix := strings.TrimSuffix(parts[0], "/")
		suffix := strings.TrimPrefix(parts[1], "/")

		hasPrefix := prefix == "" || strings.HasPrefix(value, prefix)
		hasSuffix := suffix == "" || strings.HasSuffix(value, suffix)
		return hasPrefix && hasSuffix
	}

	return false
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
