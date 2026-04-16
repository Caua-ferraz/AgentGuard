package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

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

	// Reject filesystem rule patterns containing ".." after normalization.
	// This prevents policy authors from accidentally writing traversal-prone
	// patterns like "./workspace/../../etc/**".
	for _, rs := range pol.Rules {
		if rs.Scope != "filesystem" {
			continue
		}
		for _, rules := range [][]Rule{rs.Allow, rs.Deny, rs.RequireApproval} {
			for _, rule := range rules {
				for _, p := range rule.Paths {
					cleaned := filepath.ToSlash(filepath.Clean(p))
					if containsDotDot(cleaned) {
						return nil, fmt.Errorf("filesystem rule pattern %q contains '..' after normalization — this is a path traversal risk", p)
					}
				}
			}
		}
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

// HistoryEntry is a minimal record of a past action, used for conditional rule evaluation.
type HistoryEntry struct {
	Action   string
	Command  string
	Decision Decision
	EstCost  float64
}

// HistoryQuerier provides access to recent action history for conditional rules.
// Implemented by the audit logger (via an adapter to avoid circular imports).
type HistoryQuerier interface {
	RecentActions(agentID string, scope string, since time.Time) ([]HistoryEntry, error)
}

// Engine evaluates actions against a policy.
type Engine struct {
	mu           sync.RWMutex
	policy       *Policy
	history      HistoryQuerier
	sessionCosts map[string]float64 // session_id -> cumulative cost
}

// NewEngine creates a policy engine with the given policy.
func NewEngine(pol *Policy) *Engine {
	return &Engine{
		policy:       pol,
		sessionCosts: make(map[string]float64),
	}
}

// SetHistoryQuerier sets the history querier for conditional rule evaluation.
func (e *Engine) SetHistoryQuerier(h HistoryQuerier) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.history = h
}

// RecordCost adds the cost of a completed action to the session accumulator.
// Called by the proxy after a check returns ALLOW for a cost-scoped request.
func (e *Engine) RecordCost(sessionID string, cost float64) {
	if sessionID == "" || cost <= 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.sessionCosts[sessionID] += cost
}

// SessionCost returns the accumulated cost for a session (for testing).
func (e *Engine) SessionCost(sessionID string) float64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.sessionCosts[sessionID]
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

		// Filesystem scope: reject paths that still contain ".." after
		// filepath.Clean. This catches traversal attempts that Clean
		// cannot resolve (e.g. the path is already absolute-looking but
		// crafted to escape an allowed directory).
		if rs.Scope == "filesystem" && req.Path != "" {
			cleaned := filepath.ToSlash(filepath.Clean(req.Path))
			if containsDotDot(cleaned) {
				return CheckResult{
					Decision: Deny,
					Reason:   fmt.Sprintf("path traversal detected: %s", req.Path),
					Rule:     "deny:filesystem:path_traversal",
				}
			}
		}

		// 1. Check deny rules first
		for _, rule := range rs.Deny {
			if matchRule(rule, req) && e.matchConditions(rule, req) {
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
			if matchRule(rule, req) && e.matchConditions(rule, req) {
				return CheckResult{
					Decision: RequireApproval,
					Reason:   fmt.Sprintf("Matches approval rule in %s scope", rs.Scope),
					Rule:     formatRule("require_approval", rs.Scope, rule),
				}
			}
		}

		// 3. Check allow rules
		for _, rule := range rs.Allow {
			if matchRule(rule, req) && e.matchConditions(rule, req) {
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

	// Reject negative cost values — they could bypass limits
	if req.EstCost < 0 {
		return CheckResult{
			Decision: Deny,
			Reason:   fmt.Sprintf("Negative cost value not allowed: $%.2f", req.EstCost),
			Rule:     "deny:cost:negative_value",
		}
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

	// Session-level cost enforcement
	maxPerSession, err := parseDollar(rs.Limits.MaxPerSession)
	if err != nil {
		return CheckResult{
			Decision: Deny,
			Reason:   fmt.Sprintf("Invalid max_per_session in policy: %v", err),
			Rule:     "deny:cost:invalid_config",
		}
	}
	if req.SessionID != "" && maxPerSession > 0 && req.EstCost > 0 {
		cumulative := e.sessionCosts[req.SessionID]
		if cumulative+req.EstCost > maxPerSession {
			return CheckResult{
				Decision: Deny,
				Reason:   fmt.Sprintf("Session cost $%.2f + $%.2f would exceed limit of %s", cumulative, req.EstCost, rs.Limits.MaxPerSession),
				Rule:     "deny:cost:max_per_session",
			}
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

	// Match by action + paths.
	// For path-based rules the request path is normalized with filepath.Clean
	// and converted to forward slashes before matching. This ensures that
	// traversal sequences like "../" are resolved so deny rules on target
	// directories (e.g. /etc/**) fire even when the raw path started inside
	// an allowed prefix (e.g. ./workspace/../etc/passwd).
	if rule.Action != "" && rule.Action == req.Action {
		if len(rule.Paths) == 0 {
			return true
		}
		// Normalize both pattern and value so that "./workspace/ok.txt" and
		// "workspace/ok.txt" are treated identically. filepath.Clean collapses
		// "." and ".." segments; ToSlash ensures forward slashes on Windows.
		cleanedPath := filepath.ToSlash(filepath.Clean(req.Path))
		for _, p := range rule.Paths {
			cleanedPattern := filepath.ToSlash(filepath.Clean(p))
			if globMatch(cleanedPattern, cleanedPath) {
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

// matchConditions evaluates the conditions attached to a rule.
// Returns true if all conditions are satisfied (or if there are no conditions).
// Must be called with e.mu held (at least RLock).
func (e *Engine) matchConditions(rule Rule, req ActionRequest) bool {
	if len(rule.Conditions) == 0 {
		return true
	}

	for _, cond := range rule.Conditions {
		if cond.RequirePrior != "" {
			if !e.checkRequirePrior(cond, req) {
				return false
			}
		}
	}
	return true
}

// checkRequirePrior verifies that a prior action matching the condition was
// recently allowed. Uses the history querier if available; returns false
// (condition not met) if no querier is configured.
func (e *Engine) checkRequirePrior(cond Condition, req ActionRequest) bool {
	if e.history == nil {
		return false
	}

	window := 1 * time.Hour // default lookback
	if cond.TimeWindow != "" {
		if d, err := time.ParseDuration(cond.TimeWindow); err == nil {
			window = d
		}
	}

	since := time.Now().Add(-window)
	entries, err := e.history.RecentActions(req.AgentID, req.Scope, since)
	if err != nil {
		return false
	}

	for _, entry := range entries {
		prior := cond.RequirePrior
		if entry.Decision == Allow && (entry.Action == prior || entry.Command == prior ||
			globMatch(prior, entry.Action) || globMatch(prior, entry.Command)) {
			return true
		}
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

// containsDotDot reports whether the slash-separated path contains a ".."
// segment. It checks for standalone ".." as a path component, not as a
// substring of a longer name (e.g. "my..file" is fine).
func containsDotDot(path string) bool {
	for _, seg := range strings.Split(path, "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}
