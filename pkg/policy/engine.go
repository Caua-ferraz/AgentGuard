package policy

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Caua-ferraz/AgentGuard/pkg/deprecation"
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
	// Proxy carries server-side tunables (session TTL, request body limit,
	// audit query bounds). All subfields are optional; unset values fall
	// back to the Default* constants below, which match v0.4.0 behavior.
	Proxy ProxyCfg `yaml:"proxy,omitempty"`
}

// Defaults applied when the corresponding config key is unset. These
// preserve v0.4.0 behavior so a policy file written against v0.4.0 keeps
// its exact runtime semantics after upgrade.
const (
	DefaultSessionTTL            = 1 * time.Hour
	DefaultMaxRequestBodyBytes   = int64(1 << 20) // 1 MiB
	DefaultAuditDefaultLimit     = 100
	DefaultAuditMaxLimit         = 1000
	DefaultNotifyDispatchTimeout = 10 * time.Second
)

// ProxyCfg groups server-side tunables under the `proxy:` YAML key. Each
// subsection is independently optional.
type ProxyCfg struct {
	Session SessionCfg `yaml:"session,omitempty"`
	Request RequestCfg `yaml:"request,omitempty"`
	Audit   AuditCfg   `yaml:"audit,omitempty"`
}

// SessionCfg tunes the dashboard session store.
type SessionCfg struct {
	// TTL is how long a /auth/login session stays valid. Parsed as a Go
	// duration string ("1h", "30m"). Empty string => DefaultSessionTTL.
	TTL string `yaml:"ttl,omitempty"`
}

// RequestCfg tunes incoming-request acceptance limits.
type RequestCfg struct {
	// MaxBodyBytes caps POST /v1/check body size. 0 => DefaultMaxRequestBodyBytes.
	// Requests larger than this receive 413 and increment
	// agentguard_request_rejected_total{reason="body_too_large"}.
	MaxBodyBytes int64 `yaml:"max_body_bytes,omitempty"`
}

// AuditCfg tunes the /v1/audit query endpoint.
type AuditCfg struct {
	// DefaultLimit is the row count returned when the caller omits ?limit=.
	// 0 => DefaultAuditDefaultLimit.
	DefaultLimit int `yaml:"default_limit,omitempty"`
	// MaxLimit is the hard ceiling; ?limit= values above it are clamped.
	// 0 => DefaultAuditMaxLimit. Must be >= DefaultLimit if both are set.
	MaxLimit int `yaml:"max_limit,omitempty"`
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
	Redaction        RedactionCfg   `yaml:"redaction,omitempty"`
	// DispatchTimeout is the default per-notification HTTP timeout applied
	// to webhook and Slack targets that do not set their own `timeout`.
	// Parsed as a Go duration string. Empty => DefaultNotifyDispatchTimeout.
	DispatchTimeout string `yaml:"dispatch_timeout,omitempty"`
}

// RedactionCfg tunes the secret-redactor used by the notify dispatcher.
//
// ExtraPatterns are appended to the built-in DefaultRedactor list. Operators
// use this to mask org-specific secret formats (e.g. internal API key prefixes)
// without patching the binary. Patterns are Go regexp syntax (RE2); invalid
// patterns are rejected at policy load.
type RedactionCfg struct {
	ExtraPatterns []string `yaml:"extra_patterns,omitempty"`
}

// NotifyTarget is a notification destination.
type NotifyTarget struct {
	Type  string `yaml:"type"` // "webhook", "slack", "console", "log"
	URL   string `yaml:"url,omitempty"`
	Level string `yaml:"level,omitempty"`
	// Timeout optionally overrides NotificationCfg.DispatchTimeout for this
	// specific target. Only webhook and slack notifiers honor it; console
	// and log targets are synchronous and local. Empty string => inherit
	// the notifications.dispatch_timeout value (which itself defaults to
	// DefaultNotifyDispatchTimeout when unset).
	Timeout string `yaml:"timeout,omitempty"`
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

	// Validate notification redaction patterns compile as RE2 regexes.
	// Fail fast at load rather than at first notification dispatch.
	for i, p := range pol.Notifications.Redaction.ExtraPatterns {
		if _, err := regexp.Compile(p); err != nil {
			return nil, fmt.Errorf("notifications.redaction.extra_patterns[%d]: invalid regex %q: %w", i, p, err)
		}
	}

	// Validate proxy and notification tunables: parse durations, bound-check
	// integers. Fail at load so an operator who types "1hr" instead of "1h"
	// finds out before a session tries to expire.
	if err := validateTunables(&pol); err != nil {
		return nil, err
	}

	// Warn (but don't fail) on conditions with time_window and no require_prior.
	// These are effectively no-ops at runtime — TimeWindow has nothing to
	// time-bound. We keep v0.4.0 pass-through behavior here for backward
	// compat and let the operator know about the mistake.
	warnTimeWindowOnlyConditions(&pol)

	return &pol, nil
}

// warnTimeWindowOnlyConditions scans every rule for conditions that set
// TimeWindow but not RequirePrior and emits a log line naming each offender.
// It does NOT fail the load.
//
// As of v0.4.1 this pattern is a deprecation: v0.5.0 will reject such
// policies at load time. We fire deprecation.Warn once per policy load
// that contains any orphan rule — that increments
// agentguard_deprecations_used_total{feature="policy.time_window_without_require_prior"}
// once per load, which is the right cardinality for "is this still in use"
// (a policy with 3 orphan rules reloaded once is one usage event, not three).
//
// See docs/DEPRECATIONS.md for removal target and migration path.
func warnTimeWindowOnlyConditions(pol *Policy) {
	hasOrphan := false
	check := func(scope, kind string, rules []Rule) {
		for _, r := range rules {
			for _, c := range r.Conditions {
				if c.RequirePrior == "" && c.TimeWindow != "" {
					hasOrphan = true
					id := r.Pattern
					if id == "" {
						id = r.Action
					}
					if id == "" {
						id = r.Domain
					}
					log.Printf("WARNING: policy condition with time_window=%q but no require_prior in %s:%s rule %q — condition will be ignored at runtime", c.TimeWindow, scope, kind, id)
				}
			}
		}
	}
	for _, rs := range pol.Rules {
		check(rs.Scope, "allow", rs.Allow)
		check(rs.Scope, "deny", rs.Deny)
		check(rs.Scope, "require_approval", rs.RequireApproval)
	}
	for agentID, cfg := range pol.Agents {
		for _, rs := range cfg.Override {
			check("agents."+agentID+"/"+rs.Scope, "allow", rs.Allow)
			check("agents."+agentID+"/"+rs.Scope, "deny", rs.Deny)
			check("agents."+agentID+"/"+rs.Scope, "require_approval", rs.RequireApproval)
		}
	}

	if hasOrphan {
		deprecation.Warn(
			"policy.time_window_without_require_prior",
			"deprecated in v0.4.1, will error in v0.5.0; pair time_window with require_prior or remove it. See docs/DEPRECATIONS.md.",
		)
	}
}

// validateTunables bounds-checks every Phase-4 config key. Durations must
// parse with time.ParseDuration and be strictly positive when present; byte
// and row limits must be strictly positive when present; audit MaxLimit, if
// set, must be >= audit DefaultLimit (including the case where one is set
// explicitly and the other relies on its default).
//
// Called from LoadFromFile after schema-level parsing. Errors returned here
// include the YAML path so operators can fix the right key without greping.
func validateTunables(pol *Policy) error {
	if s := pol.Proxy.Session.TTL; s != "" {
		d, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("proxy.session.ttl: %w", err)
		}
		if d <= 0 {
			return fmt.Errorf("proxy.session.ttl: must be > 0, got %q", s)
		}
	}
	if n := pol.Proxy.Request.MaxBodyBytes; n < 0 {
		return fmt.Errorf("proxy.request.max_body_bytes: must be > 0, got %d", n)
	}
	if n := pol.Proxy.Audit.DefaultLimit; n < 0 {
		return fmt.Errorf("proxy.audit.default_limit: must be > 0, got %d", n)
	}
	if n := pol.Proxy.Audit.MaxLimit; n < 0 {
		return fmt.Errorf("proxy.audit.max_limit: must be > 0, got %d", n)
	}
	// Resolve both limits through their defaults so an explicit DefaultLimit
	// paired with an unset MaxLimit still validates against the default
	// ceiling (and vice versa).
	dl := pol.Proxy.Audit.DefaultLimit
	if dl == 0 {
		dl = DefaultAuditDefaultLimit
	}
	ml := pol.Proxy.Audit.MaxLimit
	if ml == 0 {
		ml = DefaultAuditMaxLimit
	}
	if ml < dl {
		return fmt.Errorf("proxy.audit.max_limit (%d) must be >= proxy.audit.default_limit (%d)", ml, dl)
	}
	if s := pol.Notifications.DispatchTimeout; s != "" {
		d, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("notifications.dispatch_timeout: %w", err)
		}
		if d <= 0 {
			return fmt.Errorf("notifications.dispatch_timeout: must be > 0, got %q", s)
		}
	}
	for i, t := range pol.Notifications.ApprovalRequired {
		if err := validateTargetTimeout(t, fmt.Sprintf("notifications.approval_required[%d].timeout", i)); err != nil {
			return err
		}
	}
	for i, t := range pol.Notifications.OnDeny {
		if err := validateTargetTimeout(t, fmt.Sprintf("notifications.on_deny[%d].timeout", i)); err != nil {
			return err
		}
	}
	return nil
}

func validateTargetTimeout(t NotifyTarget, path string) error {
	if t.Timeout == "" {
		return nil
	}
	d, err := time.ParseDuration(t.Timeout)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if d <= 0 {
		return fmt.Errorf("%s: must be > 0, got %q", path, t.Timeout)
	}
	return nil
}

// SessionTTL returns the configured session TTL or DefaultSessionTTL when
// unset. Guarantees a positive duration.
func (p *Policy) SessionTTL() time.Duration {
	if d, ok := parsePositiveDuration(p.Proxy.Session.TTL); ok {
		return d
	}
	return DefaultSessionTTL
}

// MaxRequestBodyBytes returns the configured request body cap, or
// DefaultMaxRequestBodyBytes when unset.
func (p *Policy) MaxRequestBodyBytes() int64 {
	if p.Proxy.Request.MaxBodyBytes > 0 {
		return p.Proxy.Request.MaxBodyBytes
	}
	return DefaultMaxRequestBodyBytes
}

// AuditDefaultLimit returns the configured default audit page size, or
// DefaultAuditDefaultLimit when unset.
func (p *Policy) AuditDefaultLimit() int {
	if p.Proxy.Audit.DefaultLimit > 0 {
		return p.Proxy.Audit.DefaultLimit
	}
	return DefaultAuditDefaultLimit
}

// AuditMaxLimit returns the configured hard ceiling on audit page size, or
// DefaultAuditMaxLimit when unset.
func (p *Policy) AuditMaxLimit() int {
	if p.Proxy.Audit.MaxLimit > 0 {
		return p.Proxy.Audit.MaxLimit
	}
	return DefaultAuditMaxLimit
}

// NotifyDispatchTimeout returns the global dispatch HTTP timeout or
// DefaultNotifyDispatchTimeout when unset.
func (p *Policy) NotifyDispatchTimeout() time.Duration {
	if d, ok := parsePositiveDuration(p.Notifications.DispatchTimeout); ok {
		return d
	}
	return DefaultNotifyDispatchTimeout
}

// ResolvedTimeout returns the effective per-target HTTP timeout, falling
// back to the supplied dispatch-level default when the target did not set
// its own. Invalid durations (which LoadFromFile already rejects, but
// callers that construct NotifyTarget directly in tests can bypass) fall
// through to the default.
func (t NotifyTarget) ResolvedTimeout(fallback time.Duration) time.Duration {
	if d, ok := parsePositiveDuration(t.Timeout); ok {
		return d
	}
	return fallback
}

func parsePositiveDuration(s string) (time.Duration, bool) {
	if s == "" {
		return 0, false
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, false
	}
	return d, true
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

// sessionCostEntry tracks cumulative cost for a session plus the last time
// the entry was touched. lastUpdated enables TTL-based eviction of stale
// session accumulators; without it, long-running processes would accrete
// one entry per session_id forever.
type sessionCostEntry struct {
	cost        float64
	lastUpdated time.Time
}

// Engine evaluates actions against a policy.
type Engine struct {
	mu           sync.RWMutex
	policy       *Policy
	history      HistoryQuerier
	sessionCosts map[string]sessionCostEntry // session_id -> entry
}

// NewEngine creates a policy engine with the given policy.
func NewEngine(pol *Policy) *Engine {
	return &Engine{
		policy:       pol,
		sessionCosts: make(map[string]sessionCostEntry),
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
//
// Note: callers should prefer CheckAndReserve in Check() when possible, which
// updates the accumulator atomically with the Allow decision. RecordCost is
// retained for backfill or out-of-band accounting.
func (e *Engine) RecordCost(sessionID string, cost float64) {
	if sessionID == "" || cost <= 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	entry := e.sessionCosts[sessionID]
	entry.cost += cost
	entry.lastUpdated = time.Now()
	e.sessionCosts[sessionID] = entry
}

// RefundCost subtracts from the session accumulator. Used if a reserved cost
// is rolled back (e.g. a downstream action failed after the policy allowed it).
func (e *Engine) RefundCost(sessionID string, cost float64) {
	if sessionID == "" || cost <= 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	entry := e.sessionCosts[sessionID]
	entry.cost -= cost
	if entry.cost < 0 {
		entry.cost = 0
	}
	entry.lastUpdated = time.Now()
	e.sessionCosts[sessionID] = entry
}

// SessionCost returns the accumulated cost for a session (for testing).
func (e *Engine) SessionCost(sessionID string) float64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.sessionCosts[sessionID].cost
}

// SweepSessionCosts removes session-cost entries whose last update was more
// than maxAge ago. Returns the number of entries evicted. A non-positive
// maxAge is treated as "disabled" and returns 0 without scanning.
//
// Called by a periodic goroutine in the proxy; exposed here so engine-only
// tests and out-of-band callers can trigger a sweep directly.
func (e *Engine) SweepSessionCosts(maxAge time.Duration) int {
	if maxAge <= 0 {
		return 0
	}
	cutoff := time.Now().Add(-maxAge)
	e.mu.Lock()
	defer e.mu.Unlock()
	n := 0
	for id, entry := range e.sessionCosts {
		if entry.lastUpdated.Before(cutoff) {
			delete(e.sessionCosts, id)
			n++
		}
	}
	return n
}

// SessionCostCount returns the number of tracked session cost entries
// (useful for metrics and tests).
func (e *Engine) SessionCostCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.sessionCosts)
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
//
// For cost-scoped requests that are ALLOWed, the session accumulator is
// incremented atomically under the same write lock as the decision, so
// concurrent checks on the same session_id cannot collectively exceed the
// configured max_per_session limit (TOCTOU fix).
func (e *Engine) Check(req ActionRequest) CheckResult {
	// Normalize request inputs (Unicode, URL-encoding, null bytes) before
	// matching. Callers should ideally do this at the proxy boundary, but we
	// do it here as a belt-and-suspenders defense.
	req = normalizeRequest(req)

	// Cost-scoped requests that may write to sessionCosts need the write lock
	// to make check-and-reserve atomic. For all other scopes a read lock
	// suffices.
	if req.Scope == "cost" {
		e.mu.Lock()
		defer e.mu.Unlock()
	} else {
		e.mu.RLock()
		defer e.mu.RUnlock()
	}

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

// checkCost evaluates cost limits for a request. MUST be called with e.mu
// held for write, because an Allow decision reserves the cost atomically
// against the session accumulator.
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
		cumulative := e.sessionCosts[req.SessionID].cost
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
		// Approval requests do NOT reserve cost — the reservation happens
		// when the approver releases the action (by re-submitting the check).
		return CheckResult{
			Decision: RequireApproval,
			Reason:   fmt.Sprintf("Estimated cost $%.2f exceeds alert threshold of %s", req.EstCost, rs.Limits.AlertThreshold),
			Rule:     "require_approval:cost:alert_threshold",
		}
	}

	// Allow — reserve the cost against the session accumulator atomically.
	if req.SessionID != "" && req.EstCost > 0 {
		entry := e.sessionCosts[req.SessionID]
		entry.cost += req.EstCost
		entry.lastUpdated = time.Now()
		e.sessionCosts[req.SessionID] = entry
	}

	return CheckResult{
		Decision: Allow,
		Reason:   "Cost within limits",
		Rule:     "allow:cost:within_limits",
	}
}

// normalizeRequest canonicalizes the user-supplied fields that participate in
// policy matching. Goals:
//   - Strip NUL and C0 control bytes that would cause downstream truncation
//     (null-byte injection) or obscure traversal sequences.
//   - URL-decode path/url once so "%2E%2E" traversal attempts are visible to
//     filepath.Clean and the ".." guard.
//   - Leave glob metacharacters intact (no decoding of `*`/`?`).
func normalizeRequest(req ActionRequest) ActionRequest {
	req.Command = stripControl(req.Command)
	req.Action = stripControl(req.Action)
	req.Domain = stripControl(req.Domain)
	req.URL = stripControl(req.URL)
	req.Path = normalizePath(req.Path)
	return req
}

// stripControl removes NUL and other C0 control characters (0x00-0x1F and 0x7F)
// except tab (0x09), which is legitimately used in shell command strings.
//
// Fast-path: well-formed strings contain no control bytes, so we scan once
// and return the input unchanged (no allocation). Only when a control byte
// is found do we allocate a sanitized copy.
func stripControl(s string) string {
	if s == "" {
		return s
	}
	// Fast scan — bytewise is fine here because C0/DEL are single-byte code
	// points; multi-byte UTF-8 sequences never contain bytes ≤ 0x7F in
	// continuation positions.
	clean := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == 0x09 {
			continue
		}
		if c < 0x20 || c == 0x7F {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	// Slow path: rebuild without the offending bytes.
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == 0x09 || (r >= 0x20 && r != 0x7F) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// normalizePath URL-decodes a single layer of percent-encoding (common bypass),
// strips control characters, and returns the canonical form. filepath.Clean is
// applied by the path-matching code in matchRule/Check; we do not clean here
// to preserve the original structure for clear error messages.
func normalizePath(p string) string {
	if p == "" {
		return p
	}
	p = stripControl(p)
	// Single-pass URL decode. Double-encoded escapes are intentionally not
	// decoded recursively — a single decode is enough to expose common
	// traversal tricks while not masking pathological policy input.
	if decoded, err := urlUnescape(p); err == nil {
		p = decoded
	}
	return p
}

// urlUnescape is a minimal decoder for %HH sequences. We avoid net/url here
// because PathUnescape has opinions about `+` that don't apply to filesystem
// paths.
func urlUnescape(s string) (string, error) {
	if !strings.Contains(s, "%") {
		return s, nil
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '%' {
			if i+2 >= len(s) {
				return s, fmt.Errorf("truncated percent escape")
			}
			hi, ok1 := hexDigit(s[i+1])
			lo, ok2 := hexDigit(s[i+2])
			if !ok1 || !ok2 {
				return s, fmt.Errorf("invalid percent escape")
			}
			b.WriteByte(hi<<4 | lo)
			i += 2
		} else {
			b.WriteByte(c)
		}
	}
	return b.String(), nil
}

func hexDigit(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, true
	}
	return 0, false
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

// globMatch performs glob pattern matching supporting * and **.
//
// Semantics:
//   - A literal segment (between `/` separators) is matched with wildcardMatch,
//     so `*` matches any character including `/` within a shell-command pattern
//     like "rm -rf *".
//   - `**` matches zero or more whole path segments.
//
// For non-path patterns that have no `/` separators (e.g., shell command
// patterns, domain globs), globMatch falls through to wildcardMatch so `*`
// still matches any run of characters including spaces or dots.
//
// The important security property: when `**` appears in a pattern, it only
// matches at path-component boundaries — "**/secret/**" does NOT match
// "/notsecret/x". The old implementation substring-matched and over-reported.
func globMatch(pattern, value string) bool {
	// Patterns without ** use simple wildcard matching (anchored both ends).
	if !strings.Contains(pattern, "**") {
		return wildcardMatch(pattern, value)
	}

	// Patterns with ** are matched as path-component globs.
	return doubleStarMatch(pattern, value)
}

// doubleStarMatch matches patterns containing `**` against `value` by walking
// path components (split on `/`). Each non-`**` component is matched with
// wildcardMatch; `**` matches zero or more whole components.
func doubleStarMatch(pattern, value string) bool {
	patSegs := splitSegments(pattern)
	valSegs := splitSegments(value)
	return matchSegments(patSegs, valSegs)
}

// splitSegments splits s on `/` but preserves a leading empty segment so that
// "/etc/passwd" → ["", "etc", "passwd"] and "etc/passwd" → ["etc", "passwd"].
// This keeps absolute-vs-relative distinction meaningful in matching.
func splitSegments(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, "/")
}

// matchSegments does the recursive/iterative matching between pattern and
// value segment lists. `**` can match zero or more consecutive segments.
func matchSegments(pat, val []string) bool {
	pi, vi := 0, 0
	starPi, starVi := -1, -1

	for vi < len(val) {
		if pi < len(pat) && pat[pi] == "**" {
			starPi = pi
			starVi = vi
			pi++
			continue
		}
		if pi < len(pat) && wildcardMatch(pat[pi], val[vi]) {
			pi++
			vi++
			continue
		}
		if starPi >= 0 {
			// Backtrack: let ** consume one more value segment.
			starVi++
			vi = starVi
			pi = starPi + 1
			continue
		}
		return false
	}

	// Consume any trailing `**` segments in the pattern.
	for pi < len(pat) && pat[pi] == "**" {
		pi++
	}
	return pi == len(pat)
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
//
// Backward-compat note (v0.4.1): a condition with a TimeWindow but no
// RequirePrior is effectively a no-op — there's nothing to time-bound. The
// v0.4.0 engine treated such conditions as "always satisfied"; we retain
// that behavior here so policies written against v0.4.0 don't suddenly
// fail-closed. `LoadFromFile` logs a warning when it sees such a rule so
// authors learn about the mistake without production breakage.
func (e *Engine) matchConditions(rule Rule, req ActionRequest) bool {
	if len(rule.Conditions) == 0 {
		return true
	}

	for _, cond := range rule.Conditions {
		if cond.RequirePrior == "" {
			// TimeWindow-only (or empty Condition): nothing to verify.
			// Pass through — matches v0.4.0 behavior.
			continue
		}
		if !e.checkRequirePrior(cond, req) {
			return false
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
