package policy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
//
// SchemaVersion identifies the wire-format version. The proxy always emits
// "v1" at response time; clients may use it to negotiate forward-
// compatibility. The `omitempty` tag is kept so test fixtures that decode
// the response and assert on the JSON shape stay byte-stable. The full
// schema is documented in pkg/proxy/schema/v1/schema.json.
type CheckResult struct {
	SchemaVersion string   `json:"schema_version,omitempty"`
	Decision      Decision `json:"decision"`
	Reason        string   `json:"reason"`
	Rule          string   `json:"matched_rule,omitempty"`
	ApprovalID    string   `json:"approval_id,omitempty"`
	ApprovalURL   string   `json:"approval_url,omitempty"`
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
	// back to the Default* constants below.
	Proxy ProxyCfg `yaml:"proxy,omitempty"`

	// ToolScopeMap maps MCP tool names to existing policy scopes for the
	// MCP Gateway's dual-check pattern. Patterns are glob-matched (same
	// matcher as rule patterns); the gateway's --policy-mode strict
	// (default) fires a second Engine.Check against the mapped scope per
	// tool call so existing filesystem/network/shell rules apply to MCP
	// traffic without duplication. See docs/MCP_GATEWAY.md § 4.4 and
	// docs/POLICY_REFERENCE.md#mcp_tool-scope.
	//
	// Order matters: first match wins. Operators put more-specific
	// patterns before broader ones.
	//
	// Example:
	//
	//   tool_scope_map:
	//     - pattern: "fs:read_file"
	//       scope: filesystem
	//     - pattern: "fs:*"
	//       scope: filesystem
	//     - pattern: "github:*"
	//       scope: network
	//     - pattern: "*:execute_*"
	//       scope: shell
	ToolScopeMap []ToolScopeMapping `yaml:"tool_scope_map,omitempty" json:"tool_scope_map,omitempty"`
}

// ToolScopeMapping is one entry in Policy.ToolScopeMap. The list form
// (rather than an inline map) is chosen so YAML iteration order is
// deterministic — the gateway's first-match-wins resolution depends on
// it. Operators write a few extra lines per entry; the gateway
// guarantees the same scope for the same tool name on every host
// regardless of YAML library quirks.
type ToolScopeMapping struct {
	Pattern string `yaml:"pattern" json:"pattern"`
	Scope   string `yaml:"scope" json:"scope"`
}

// Defaults applied when the corresponding config key is unset.
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
	MaxPerAction   string `yaml:"max_per_action,omitempty"`
	MaxPerSession  string `yaml:"max_per_session,omitempty"`
	AlertThreshold string `yaml:"alert_threshold,omitempty"`
}

// AgentCfg defines per-agent policy overrides.
//
// OverrideMode controls how a per-scope override RuleSet combines with its
// base counterpart. The default ("merge") inherits Deny and RequireApproval
// rules from base while letting the override's Allow list narrow the scope.
// Setting "replace" makes the override fully supplant the base RuleSet for
// that scope (used when an agent's policy must explicitly drop a base
// deny rule, with operator awareness).
type AgentCfg struct {
	Extends      string    `yaml:"extends"`
	Override     []RuleSet `yaml:"override,omitempty"`
	OverrideMode string    `yaml:"override_mode,omitempty"`
}

// Override-mode constants. We accept the literal strings in YAML; an unknown
// value falls back to the merge default with a warning at load time.
const (
	OverrideModeMerge   = "merge"
	OverrideModeReplace = "replace"
)

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

// LoadFromFile reads and parses a policy YAML file. The file is read,
// parsed, and validated by the same code path that PolicyProvider.Validate
// invokes for raw bytes — only the os.ReadFile step is unique to this
// function. Validation errors include the YAML path so operators can find
// the failing field without grepping.
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

	if err := validateFilesystemPaths(&pol); err != nil {
		return nil, err
	}
	if err := validateRedactionPatterns(&pol); err != nil {
		return nil, err
	}
	if err := validateToolScopeMap(&pol); err != nil {
		return nil, err
	}

	// Validate proxy and notification tunables: parse durations, bound-check
	// integers. Fail at load so an operator who types "1hr" instead of "1h"
	// finds out before a session tries to expire.
	if err := validateTunables(&pol); err != nil {
		return nil, err
	}

	// Validate every rule-level rate_limit and condition.time_window
	// duration at load time. Lazy parsing on the request path silently
	// fell through on bad input, so a typo like `window: "1minute"`
	// produced a no-op rule. window=0 (panic in the limiter) is also
	// rejected here.
	if err := validateRuleDurationsAndCounts(&pol); err != nil {
		return nil, err
	}

	// Reject conditions with time_window but no require_prior. Such a
	// condition is inert at runtime; we hard-fail at load so a footgun
	// in production cannot hide behind a one-line typo.
	if err := errorTimeWindowOnlyConditions(&pol); err != nil {
		return nil, err
	}

	return &pol, nil
}

// validateFilesystemPaths rejects filesystem rule patterns containing ".."
// after normalization. This prevents policy authors from accidentally
// writing traversal-prone patterns like "./workspace/../../etc/**".
// Factored out of LoadFromFile so PolicyProvider.Validate can reuse it.
func validateFilesystemPaths(pol *Policy) error {
	for _, rs := range pol.Rules {
		if rs.Scope != "filesystem" {
			continue
		}
		for _, rules := range [][]Rule{rs.Allow, rs.Deny, rs.RequireApproval} {
			for _, rule := range rules {
				for _, p := range rule.Paths {
					cleaned := filepath.ToSlash(filepath.Clean(p))
					if containsDotDot(cleaned) {
						return fmt.Errorf("filesystem rule pattern %q contains '..' after normalization — this is a path traversal risk", p)
					}
				}
			}
		}
	}
	return nil
}

// knownPolicyScopes is the set of scopes that AgentGuard recognises for
// rule dispatch (engine.Check) and for tool_scope_map values. Rule
// scopes outside this set still load (the engine's generic dispatch
// matches any scope by Pattern/Action+Paths/Domain), but a
// tool_scope_map entry pointing at an unknown scope is rejected at
// load — it is almost certainly an operator typo and the gateway's
// dual-check would silently skip the second Engine.Check otherwise.
//
// The "mcp_tool" scope is the MCP Gateway's primary scope for the first
// half of the dual-check pattern. The gateway dispatches "mcp_tool"
// through the engine's generic path (no scope-specific handling), like
// the "data" scope.
var knownPolicyScopes = map[string]struct{}{
	"shell":      {},
	"filesystem": {},
	"network":    {},
	"browser":    {},
	"data":       {},
	"cost":       {},
	"mcp_tool":   {},
}

// validateToolScopeMap rejects a tool_scope_map whose entry has an
// empty pattern, an empty scope, or a scope outside knownPolicyScopes.
// Without this validation a typo (`scope: filesytem`) would cause the
// gateway's strict-mode dual-check to silently skip the second
// Engine.Check entirely.
func validateToolScopeMap(pol *Policy) error {
	for i, m := range pol.ToolScopeMap {
		if strings.TrimSpace(m.Pattern) == "" {
			return fmt.Errorf("tool_scope_map[%d].pattern: must not be empty", i)
		}
		if strings.TrimSpace(m.Scope) == "" {
			return fmt.Errorf("tool_scope_map[%d].scope: must not be empty (pattern=%q)", i, m.Pattern)
		}
		if _, ok := knownPolicyScopes[m.Scope]; !ok {
			return fmt.Errorf("tool_scope_map[%d].scope: %q is not a known scope (allowed: shell, filesystem, network, browser, data, cost, mcp_tool); pattern=%q", i, m.Scope, m.Pattern)
		}
	}
	return nil
}

// MapToolScope returns the existing-scope rule that applies to the
// given namespaced MCP tool name (`<ns>:<tool>`), per the policy's
// tool_scope_map. Returns ("", false) if no entry matches. First
// match wins; operators control resolution order via the YAML list
// order.
//
// Used by the MCP Gateway in --policy-mode strict to fire a second
// Engine.Check against the mapped scope per tool call. Single-call
// hot path; safe to invoke under any lock state because it does not
// touch engine state.
func (p *Policy) MapToolScope(toolName string) (string, bool) {
	if p == nil || toolName == "" {
		return "", false
	}
	for _, m := range p.ToolScopeMap {
		if globMatch(m.Pattern, toolName) {
			return m.Scope, true
		}
	}
	return "", false
}

// validateRedactionPatterns checks that every notification redaction
// extra_pattern compiles as an RE2 regex. Failing fast here means the
// dispatcher does not have to recover from a bad pattern at first
// dispatch.
func validateRedactionPatterns(pol *Policy) error {
	for i, p := range pol.Notifications.Redaction.ExtraPatterns {
		if _, err := regexp.Compile(p); err != nil {
			return fmt.Errorf("notifications.redaction.extra_patterns[%d]: invalid regex %q: %w", i, p, err)
		}
	}
	return nil
}

// validateRuleDurationsAndCounts walks every RuleSet's rate_limit and every
// rule-level condition.time_window, requiring durations to parse cleanly
// and integer thresholds to be strictly positive. Both base rules and
// per-agent overrides are checked.
func validateRuleDurationsAndCounts(pol *Policy) error {
	check := func(loc string, rs RuleSet) error {
		if rs.RateLimit != nil {
			if rs.RateLimit.MaxRequests <= 0 {
				return fmt.Errorf("%s.rate_limit.max_requests: must be > 0, got %d", loc, rs.RateLimit.MaxRequests)
			}
			d, err := time.ParseDuration(rs.RateLimit.Window)
			if err != nil {
				return fmt.Errorf("%s.rate_limit.window: %w", loc, err)
			}
			if d <= 0 {
				return fmt.Errorf("%s.rate_limit.window: must be > 0, got %q", loc, rs.RateLimit.Window)
			}
		}
		// Walk every condition.time_window across allow/deny/require_approval.
		for kind, rules := range map[string][]Rule{
			"allow":            rs.Allow,
			"deny":             rs.Deny,
			"require_approval": rs.RequireApproval,
		} {
			for i, r := range rules {
				for j, c := range r.Conditions {
					if c.TimeWindow == "" {
						continue
					}
					d, err := time.ParseDuration(c.TimeWindow)
					if err != nil {
						return fmt.Errorf("%s.%s[%d].conditions[%d].time_window: %w", loc, kind, i, j, err)
					}
					if d <= 0 {
						return fmt.Errorf("%s.%s[%d].conditions[%d].time_window: must be > 0, got %q", loc, kind, i, j, c.TimeWindow)
					}
				}
			}
		}
		return nil
	}

	for i, rs := range pol.Rules {
		if err := check(fmt.Sprintf("rules[%d](%s)", i, rs.Scope), rs); err != nil {
			return err
		}
	}
	for agentID, cfg := range pol.Agents {
		for i, rs := range cfg.Override {
			if err := check(fmt.Sprintf("agents.%s.override[%d](%s)", agentID, i, rs.Scope), rs); err != nil {
				return err
			}
		}
	}
	return nil
}

// errorTimeWindowOnlyConditions returns an error for any rule whose
// conditions include a time_window without a require_prior. Such a rule
// is a runtime no-op; rejecting it at load avoids silent footguns.
func errorTimeWindowOnlyConditions(pol *Policy) error {
	check := func(loc string, rules []Rule) error {
		for i, r := range rules {
			for j, c := range r.Conditions {
				if c.RequirePrior == "" && c.TimeWindow != "" {
					id := r.Pattern
					if id == "" {
						id = r.Action
					}
					if id == "" {
						id = r.Domain
					}
					return fmt.Errorf("%s[%d](%q).conditions[%d]: time_window without require_prior is rejected; pair time_window with require_prior or remove it", loc, i, id, j)
				}
			}
		}
		return nil
	}
	for i, rs := range pol.Rules {
		base := fmt.Sprintf("rules[%d](%s)", i, rs.Scope)
		if err := check(base+".allow", rs.Allow); err != nil {
			return err
		}
		if err := check(base+".deny", rs.Deny); err != nil {
			return err
		}
		if err := check(base+".require_approval", rs.RequireApproval); err != nil {
			return err
		}
	}
	for agentID, cfg := range pol.Agents {
		for i, rs := range cfg.Override {
			base := fmt.Sprintf("agents.%s.override[%d](%s)", agentID, i, rs.Scope)
			if err := check(base+".allow", rs.Allow); err != nil {
				return err
			}
			if err := check(base+".deny", rs.Deny); err != nil {
				return err
			}
			if err := check(base+".require_approval", rs.RequireApproval); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateTunables bounds-checks proxy/notification config keys. Durations
// must parse with time.ParseDuration and be strictly positive when present;
// byte and row limits must be strictly positive when present; audit MaxLimit,
// if set, must be >= audit DefaultLimit (including the case where one is set
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

// sessionCostKey partitions the cost accumulator by (tenant, session) so two
// tenants that happen to reuse the same session_id never share a budget
// (v0.6 multi-tenancy). A struct key is collision-free regardless of what
// characters tenant/session IDs contain — unlike a concatenated string key.
type sessionCostKey struct {
	tenant  string
	session string
}

// Engine evaluates actions against a policy. The policy itself is owned
// by a PolicyProvider (file-backed, static, or a future database-backed
// impl), not by the Engine. Engine caches the latest *Policy for the local
// tenant via a Watch subscription so that Check() does not pay a provider
// lookup on every request.
//
// Caching strategy: the cached pointer is refreshed whenever the provider
// fires its watch callback (for FilePolicyProvider, on every successful
// reload; for StaticPolicyProvider, on every UpdatePolicy call). All
// reads of the cache use Engine.mu so a concurrent reload cannot tear a
// pointer swap.
type Engine struct {
	mu           sync.RWMutex
	provider     PolicyProvider
	policy       *Policy // cached snapshot for LocalTenantID; refreshed by watchStop
	watchStop    func()
	history      HistoryQuerier
	sessionCosts map[sessionCostKey]sessionCostEntry // (tenant, session_id) -> entry

	// lastPolicyLoadAtNs records the unix-nanosecond timestamp of the most
	// recent successful policy load (initial Get + each Watch callback fire).
	// Stored as int64 and accessed via sync/atomic so health probes can read
	// it without contending with Engine.mu on the hot path.
	lastPolicyLoadAtNs int64
}

// NewEngine creates a policy engine that reads policies through the given
// provider. The engine immediately calls provider.Get(LocalTenantID) to
// populate its cached policy and registers a Watch callback so subsequent
// changes are picked up automatically.
//
// A nil provider is rejected. A provider that returns ErrTenantNotFound
// for the local tenant on initial Get is also rejected — this catches
// configuration mistakes (an empty file provider, a database with no
// tenant row) at boot rather than at the first Check call. Operators who
// genuinely need a policy-less engine (e.g. tests that populate the
// provider after construction) should use NewStaticPolicyProvider with a
// non-nil placeholder *Policy and update it later.
func NewEngine(provider PolicyProvider) (*Engine, error) {
	if provider == nil {
		return nil, fmt.Errorf("policy: NewEngine requires a non-nil PolicyProvider")
	}
	pol, err := provider.Get(LocalTenantID)
	if err != nil {
		return nil, fmt.Errorf("policy: provider has no policy for tenant %q: %w", LocalTenantID, err)
	}
	e := &Engine{
		provider:     provider,
		policy:       pol,
		sessionCosts: make(map[sessionCostKey]sessionCostEntry),
	}
	// Stamp the load timestamp before Watch wires up so a probe that
	// races with NewEngine never sees the zero value when a policy is in
	// fact loaded. The watch callback re-stamps on every reload.
	e.noteLoad()
	stop, err := provider.Watch(LocalTenantID, e.onPolicyChange)
	if err != nil {
		return nil, fmt.Errorf("policy: provider Watch failed for tenant %q: %w", LocalTenantID, err)
	}
	e.watchStop = stop
	return e, nil
}

// NewEngineFromPolicy is a convenience constructor that wraps pol in a
// StaticPolicyProvider and hands the provider to NewEngine. Library
// embedders who manage policy lifecycle out-of-band, plus the engine's
// own test suite, use this to avoid the FilePolicyProvider boilerplate.
//
// The returned engine owns the StaticPolicyProvider — calling Engine.Close
// stops the watch subscription but does not close the provider; callers
// that need full teardown should construct the provider explicitly.
func NewEngineFromPolicy(pol *Policy) *Engine {
	prov := NewStaticPolicyProvider(pol)
	e, err := NewEngine(prov)
	if err != nil {
		// The only failure mode of NewEngine on a StaticPolicyProvider is
		// pol == nil. Surface a deterministic engine wrapping a sentinel
		// policy so callers (mostly tests) get a useful default-deny
		// engine rather than a nil pointer.
		prov.UpdatePolicy(&Policy{Version: "1", Name: "empty"})
		e2, _ := NewEngine(prov)
		return e2
	}
	return e
}

// onPolicyChange refreshes the engine's cached policy when the provider
// reports a change. Invoked from the provider's watcher goroutine; takes
// the write lock briefly to avoid a torn read in Check.
func (e *Engine) onPolicyChange(newPol *Policy) {
	e.mu.Lock()
	e.policy = newPol
	e.mu.Unlock()
	// Stamp the load timestamp outside the engine lock so a slow health
	// probe never serializes against Check. The value is monotonic-ish
	// (wall clock) — operators querying it get RFC 3339 timestamps for
	// human display, not for distributed-systems ordering.
	e.noteLoad()
}

// noteLoad stamps the timestamp of the most recent successful policy
// load. Atomic write so LastPolicyLoadAt() can read without taking
// Engine.mu — health probes must not block the hot path.
func (e *Engine) noteLoad() {
	atomic.StoreInt64(&e.lastPolicyLoadAtNs, time.Now().UnixNano())
}

// LastPolicyLoadAt returns the wall-clock time of the most recent
// successful policy load. Returns the zero time if no policy has been
// loaded yet (which should not occur at runtime: NewEngine refuses to
// construct without a successful initial Get and stamps the timestamp
// before returning).
func (e *Engine) LastPolicyLoadAt() time.Time {
	ns := atomic.LoadInt64(&e.lastPolicyLoadAtNs)
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

// Close releases the engine's Watch subscription. Safe to call multiple
// times (the underlying stop function uses sync.Once). Engines that
// outlive their server should call Close to avoid leaking the callback
// registration on the provider.
func (e *Engine) Close() error {
	if e.watchStop != nil {
		e.watchStop()
		e.watchStop = nil
	}
	return nil
}

// SetHistoryQuerier sets the history querier for conditional rule evaluation.
func (e *Engine) SetHistoryQuerier(h HistoryQuerier) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.history = h
}

// RecordCost adds the cost of a completed action to the local tenant's
// session accumulator. Called by the proxy after a check returns ALLOW for a
// cost-scoped request.
//
// Note: callers should prefer CheckAndReserve in Check() when possible, which
// updates the accumulator atomically with the Allow decision. RecordCost is
// retained for backfill or out-of-band accounting.
//
// Backward-compat: this single-tenant signature is preserved for embedders;
// it resolves to LocalTenantID. Tenant-aware out-of-band accounting uses
// recordCost directly (the v0.6 Store syncer will expose this when needed).
func (e *Engine) RecordCost(sessionID string, cost float64) {
	e.recordCost(LocalTenantID, sessionID, cost)
}

// recordCost is the tenant-aware accumulator increment shared by RecordCost
// (local) and any future tenant-scoped caller.
func (e *Engine) recordCost(tenantID, sessionID string, cost float64) {
	if sessionID == "" || cost <= 0 {
		return
	}
	key := sessionCostKey{tenant: tenantID, session: sessionID}
	e.mu.Lock()
	defer e.mu.Unlock()
	entry := e.sessionCosts[key]
	entry.cost += cost
	entry.lastUpdated = time.Now()
	e.sessionCosts[key] = entry
}

// RefundCost subtracts from the local tenant's session accumulator. Used if a
// reserved cost is rolled back (e.g. a downstream action failed after the
// policy allowed it). Preserved single-tenant signature → LocalTenantID.
func (e *Engine) RefundCost(sessionID string, cost float64) {
	if sessionID == "" || cost <= 0 {
		return
	}
	key := sessionCostKey{tenant: LocalTenantID, session: sessionID}
	e.mu.Lock()
	defer e.mu.Unlock()
	entry := e.sessionCosts[key]
	entry.cost -= cost
	if entry.cost < 0 {
		entry.cost = 0
	}
	entry.lastUpdated = time.Now()
	e.sessionCosts[key] = entry
}

// SessionCost returns the accumulated cost for a session under the local
// tenant (for testing). Preserved single-tenant signature → LocalTenantID.
func (e *Engine) SessionCost(sessionID string) float64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.sessionCosts[sessionCostKey{tenant: LocalTenantID, session: sessionID}].cost
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
	for key, entry := range e.sessionCosts {
		if entry.lastUpdated.Before(cutoff) {
			delete(e.sessionCosts, key)
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

// CostSnapshot is a point-in-time copy of one session's accumulated cost,
// used by the persistence syncer. (Tenant, Session) is the partition key.
type CostSnapshot struct {
	Tenant      string
	Session     string
	Cost        float64
	LastUpdated time.Time
}

// SnapshotCosts returns a copy of every session-cost entry. Read-locked and
// intended for the background persistence syncer — never the request path.
func (e *Engine) SnapshotCosts() []CostSnapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]CostSnapshot, 0, len(e.sessionCosts))
	for k, v := range e.sessionCosts {
		out = append(out, CostSnapshot{Tenant: k.tenant, Session: k.session, Cost: v.cost, LastUpdated: v.lastUpdated})
	}
	return out
}

// RestoreCosts loads session-cost entries from a prior snapshot (boot
// hydration). Intended to run once, before serving traffic.
func (e *Engine) RestoreCosts(snaps []CostSnapshot) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, s := range snaps {
		e.sessionCosts[sessionCostKey{tenant: s.Tenant, session: s.Session}] = sessionCostEntry{cost: s.Cost, lastUpdated: s.LastUpdated}
	}
}

// Policy returns the currently active policy for the local tenant
// (thread-safe). Returns nil only if the provider's most recent Get
// surfaced ErrTenantNotFound for the local tenant; this should not
// happen at runtime because NewEngine refuses to construct without a
// policy.
func (e *Engine) Policy() *Policy {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.policy
}

// PolicyForTenant returns the policy for tenantID (or the cached local
// policy when tenantID is "" or LocalTenantID). Forwards to the
// underlying provider for any other tenantID so multi-tenant providers
// can resolve tenants the engine has not subscribed to. Returns
// ErrTenantNotFound when the tenant is unknown.
//
// Used by /v1/health and the /v1/t/{tenant}/health endpoint to validate
// the requested tenant before composing the response. The hot path
// (Engine.Check) goes through the existing dispatch logic and remains
// unchanged.
func (e *Engine) PolicyForTenant(tenantID string) (*Policy, error) {
	if tenantID == "" || tenantID == LocalTenantID {
		e.mu.RLock()
		pol := e.policy
		e.mu.RUnlock()
		if pol == nil {
			return nil, ErrTenantNotFound
		}
		return pol, nil
	}
	if e.provider == nil {
		return nil, ErrTenantNotFound
	}
	return e.provider.Get(tenantID)
}

// ActionRequest represents an agent's intended action.
//
// SchemaVersion identifies the wire-format version. Clients may omit
// it (the proxy defaults missing values to "v1"); supplying any value
// other than "v1" is rejected with HTTP 400. The full schema is
// documented in pkg/proxy/schema/v1/schema.json.
type ActionRequest struct {
	SchemaVersion string            `json:"schema_version,omitempty"`
	Scope         string            `json:"scope"`
	Action        string            `json:"action,omitempty"`
	Command       string            `json:"command,omitempty"`
	Path          string            `json:"path,omitempty"`
	Domain        string            `json:"domain,omitempty"`
	URL           string            `json:"url,omitempty"`
	AgentID       string            `json:"agent_id,omitempty"`
	SessionID     string            `json:"session_id,omitempty"`
	EstCost       float64           `json:"est_cost,omitempty"`
	Meta          map[string]string `json:"meta,omitempty"`

	// ApprovalID, when set, instructs the central server's handleCheck
	// to look up the approval queue before running policy. If a matching
	// entry exists and is resolved, the server short-circuits with the
	// human's resolved decision rather than re-evaluating policy from
	// scratch. This is what makes the "approve once, model proceeds" UX
	// work: when a model retries a tool call after a human clicks
	// approve on the dashboard, the gateway propagates the original
	// approval_id (carried through MCP `_meta.dev.agentguard/approval_id`)
	// and the server honors the human's decision instead of producing a
	// fresh REQUIRE_APPROVAL entry.
	//
	// Empty / unset → server evaluates fresh (legacy behavior; back-
	// compat for SDK callers and any client that strips _meta).
	//
	// Wire-protocol note: the field is `omitempty` so existing v1
	// clients that never set it serialize byte-for-byte identically to
	// pre-A19b traffic. Engine.Check itself does NOT inspect this field —
	// the lookup short-circuit lives in pkg/proxy.handleCheck so the
	// approval queue (a server-side construct) is not dragged into the
	// pure policy package.
	ApprovalID string `json:"approval_id,omitempty"`
}

// Check evaluates an action request against the active policy for the
// given tenant. Order: deny rules -> require_approval rules -> allow
// rules -> default deny. Per-agent overrides are applied when AgentID
// matches a key in policy.Agents.
//
// tenantID selects which policy to evaluate against. The local tenant
// ("" and "local" are accepted) is always valid; an unknown tenant
// returns a synthetic DENY with Rule="deny:tenant:not_found".
//
// Bad-tenant is surfaced as a CheckResult Deny rather than an error
// because the existing handleCheck flow already routes Deny through the
// audit + notify + response path; introducing a separate error channel
// would force every caller to add bespoke fallback logic for a case the
// CheckResult schema already covers. Future providers that need to
// distinguish "tenant unknown" from "tenant denied" can do so via
// Rule="deny:tenant:not_found" (the canonical sentinel).
//
// For cost-scoped requests that are ALLOWed, the session accumulator is
// incremented atomically under the same write lock as the decision, so
// concurrent checks on the same session_id cannot collectively exceed the
// configured max_per_session limit (TOCTOU fix).
func (e *Engine) Check(req ActionRequest, tenantID string) CheckResult {
	if tenantID == "" {
		tenantID = LocalTenantID
	}

	// Resolve the policy to evaluate against. For a non-local tenant this comes
	// from the provider — a MultiTenantProvider returns THAT tenant's own
	// policy (served from its in-memory cache, so no DB on the hot path); the
	// FilePolicyProvider rejects every non-local tenant with ErrTenantNotFound.
	// The lookup happens BEFORE e.mu is taken so the engine lock never nests
	// under the provider lock.
	var tenantPol *Policy
	if tenantID != LocalTenantID {
		p, err := e.provider.Get(tenantID)
		if err != nil {
			if errors.Is(err, ErrTenantNotFound) {
				return CheckResult{
					Decision: Deny,
					Reason:   fmt.Sprintf("tenant %q has no policy", tenantID),
					Rule:     "deny:tenant:not_found",
				}
			}
			// A non-ErrTenantNotFound error is an infrastructure failure (e.g.
			// DB down); default-deny with a distinct sentinel so operators can
			// alert on it separately from a missing-tenant case.
			return CheckResult{
				Decision: Deny,
				Reason:   fmt.Sprintf("policy provider lookup failed for tenant %q: %v", tenantID, err),
				Rule:     "deny:tenant:provider_error",
			}
		}
		tenantPol = p
	}

	// Normalize request inputs (Unicode, URL-encoding, null bytes) before
	// matching. Callers should ideally do this at the proxy boundary, but we
	// do it here as a belt-and-suspenders defense.
	req = normalizeRequest(req)

	// Cost-scoped requests that may write to sessionCosts need the write lock
	// to make check-and-reserve atomic. For all other scopes a read lock
	// suffices. The lock also guards the e.policy snapshot read below and
	// e.history reads inside matchConditions.
	if req.Scope == "cost" {
		e.mu.Lock()
		defer e.mu.Unlock()
	} else {
		e.mu.RLock()
		defer e.mu.RUnlock()
	}

	// Evaluate against the tenant's policy: the provider-supplied policy for a
	// non-local tenant, otherwise the engine's cached local snapshot.
	pol := e.policy
	if tenantPol != nil {
		pol = tenantPol
	}
	if pol == nil {
		// Local cache empty — the provider lost its policy between construction
		// and now. Treat as default-deny rather than panicking.
		return CheckResult{
			Decision: Deny,
			Reason:   fmt.Sprintf("tenant %q has no policy", tenantID),
			Rule:     "deny:tenant:not_found",
		}
	}

	rules := resolveRules(pol, req.AgentID)

	for _, rs := range rules {
		if rs.Scope != req.Scope {
			continue
		}

		// Cost scope: evaluate limits instead of pattern rules
		if rs.Scope == "cost" && rs.Limits != nil {
			return e.checkCost(rs, req, tenantID)
		}

		// Data scope: gates form inputs, browser data exfiltration, and
		// any other "value-bearing" action where the operator wants to
		// apply PII / credential rules independently of the broader
		// browser/network scopes. No scope-specific custom logic here —
		// matching uses the standard Pattern (against req.Command, which
		// carries the redacted form value), Domain (against req.URL /
		// req.Domain), and Action (against req.Action — typically
		// "form_input"). Default-deny applies when no rule matches.
		//
		// TODO(v0.6, #data-pii): regex / classifier-based PII patterns
		// (SSN, credit-card numbers, AWS keys) baked into a built-in
		// rule library so operators don't have to spell them out.
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

// RateLimitConfig returns the rate limit config for a given scope under a
// tenant's policy, considering per-agent overrides. Returns nil if no rate
// limit is configured (or the tenant is unknown). Evaluated against the
// tenant's policy so a non-local tenant gets ITS OWN rate limits, not local's.
func (e *Engine) RateLimitConfig(scope, agentID, tenantID string) *RateLimitCfg {
	// PolicyForTenant snapshots the local policy under e.mu (or fetches the
	// tenant's from the provider). resolveRules then operates on that immutable
	// snapshot lock-free.
	pol, err := e.PolicyForTenant(tenantID)
	if err != nil || pol == nil {
		return nil
	}
	rules := resolveRules(pol, agentID)
	for _, rs := range rules {
		if rs.Scope == scope && rs.RateLimit != nil {
			return rs.RateLimit
		}
	}
	return nil
}

// resolveRules returns the effective rule list for a given agent.
//
// Combine semantics depend on AgentCfg.OverrideMode:
//
//   - "merge" (default): the effective RuleSet for an overridden scope is
//     base.Deny ∪ override.Deny, base.RequireApproval ∪
//     override.RequireApproval, and override.Allow alone (so the agent can
//     narrow the allow list without inheriting base allows it does not
//     want). The override's RateLimit and Limits, when set, replace the
//     base values; when unset, base wins. This preserves base safety
//     guarantees (e.g. `deny: rm -rf *`) under per-agent customisation.
//
//   - "replace": the override RuleSet fully supplants the base RuleSet
//     for that scope. Use only when the agent must not inherit anything
//     — typically a privileged agent with its own hand-vetted policy.
//
// Scopes present only in the override are appended to the result regardless
// of mode. Scopes present only in the base are passed through unchanged.
func resolveRules(pol *Policy, agentID string) []RuleSet {
	if agentID == "" || pol.Agents == nil {
		return pol.Rules
	}

	agentCfg, ok := pol.Agents[agentID]
	if !ok {
		return pol.Rules
	}

	// Build a map of overridden scopes
	overridden := make(map[string]RuleSet, len(agentCfg.Override))
	for _, rs := range agentCfg.Override {
		overridden[rs.Scope] = rs
	}

	mode := agentCfg.OverrideMode
	if mode == "" {
		mode = OverrideModeMerge
	}

	// Merge: combine overrides with base per the resolved mode.
	var merged []RuleSet
	seen := make(map[string]bool)

	for _, rs := range pol.Rules {
		if override, ok := overridden[rs.Scope]; ok {
			if mode == OverrideModeReplace {
				merged = append(merged, override)
			} else {
				merged = append(merged, mergeRuleSet(rs, override))
			}
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

// mergeRuleSet folds an override RuleSet onto a base RuleSet for the
// agent-merge case. New slices are allocated for Deny and RequireApproval
// so the caller cannot mutate the base policy by appending into the
// returned RuleSet's slice fields. Allow is taken verbatim from the
// override so per-agent allowlists can narrow without inheriting base
// allows the agent shouldn't have.
func mergeRuleSet(base, override RuleSet) RuleSet {
	out := RuleSet{
		Scope: override.Scope,
		// Allow is override-only by design — the merge default is
		// "agents may NARROW what's allowed but never WIDEN what's
		// denied"; widening allow would defeat the safety guarantee.
		Allow:           override.Allow,
		Deny:            mergeRules(base.Deny, override.Deny),
		RequireApproval: mergeRules(base.RequireApproval, override.RequireApproval),
		RateLimit:       override.RateLimit,
		Limits:          override.Limits,
	}
	if out.RateLimit == nil {
		out.RateLimit = base.RateLimit
	}
	if out.Limits == nil {
		out.Limits = base.Limits
	}
	return out
}

// mergeRules concatenates base and over into a fresh slice. The order is
// "base first, then override" so a base deny still fires even if an agent
// override appends a deny that would never match.
func mergeRules(base, over []Rule) []Rule {
	if len(base) == 0 {
		return over
	}
	if len(over) == 0 {
		return base
	}
	out := make([]Rule, 0, len(base)+len(over))
	out = append(out, base...)
	out = append(out, over...)
	return out
}

// checkCost evaluates cost limits for a request. MUST be called with e.mu
// held for write, because an Allow decision reserves the cost atomically
// against the session accumulator.
func (e *Engine) checkCost(rs RuleSet, req ActionRequest, tenantID string) CheckResult {
	if rs.Limits == nil {
		return CheckResult{Decision: Allow, Reason: "No cost limits configured"}
	}
	// Partition the accumulator by (tenant, session) so two tenants reusing
	// the same session_id keep independent budgets. tenantID is already
	// normalized to LocalTenantID by Check before this runs.
	costKey := sessionCostKey{tenant: tenantID, session: req.SessionID}

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

	// Session-level cost enforcement.
	//
	// We compare `cumulative + est_cost > max_per_session` regardless of
	// est_cost. When est_cost==0, that simplifies to "cumulative > max",
	// which correctly denies a session already over the cap while still
	// allowing exactly-at-cap. A guard like `req.EstCost > 0` here would
	// let an agent submit est_cost=0 forever after blowing past the cap.
	maxPerSession, err := parseDollar(rs.Limits.MaxPerSession)
	if err != nil {
		return CheckResult{
			Decision: Deny,
			Reason:   fmt.Sprintf("Invalid max_per_session in policy: %v", err),
			Rule:     "deny:cost:invalid_config",
		}
	}
	if req.SessionID != "" && maxPerSession > 0 {
		cumulative := e.sessionCosts[costKey].cost
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
		entry := e.sessionCosts[costKey]
		entry.cost += req.EstCost
		entry.lastUpdated = time.Now()
		e.sessionCosts[costKey] = entry
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
// Pattern semantics — STABLE CONTRACT (closes R3 #11 by documenting the
// asymmetry; see .audit/v05_decisions.md "Glob ** semantics for paths vs
// domains" for the choice):
//
//  1. Path patterns (contain `/`):
//     - Split on `/`. Each segment except `**` is matched with wildcardMatch.
//     - `**` matches zero or more whole `/`-delimited segments.
//     - Therefore `/etc/**` matches both `/etc/passwd` AND `/etc` itself
//     (the `**` consumes zero segments). Operators who want "at least
//     one segment under /etc" must spell it `/etc/*/**` or list `/etc`
//     explicitly in a separate rule.
//     - The security guarantee: `**/secret/**` does NOT match
//     `/notsecret/x`. `**` always lands on segment boundaries; it never
//     substring-matches.
//
//  2. Domain patterns (no `/`):
//     - Matched with wildcardMatch. `*` matches any chars including `.`.
//     - Therefore `*.foo.com` matches `api.foo.com` but does NOT match
//     `foo.com` (the `*` requires at least one character before `.foo.com`).
//     - To match `foo.com` itself, list it as a separate rule or use the
//     literal pattern `foo.com`.
//
//  3. Shell-command patterns (no `/`, no `**`):
//     - Same as domain: wildcardMatch. `*` is greedy across `/`, spaces,
//     and dots.
//
// The asymmetry between (1) and (2) is intentional and documented:
//   - Path `**` is segment-aware (designed for filesystem trees) and
//     matches zero or more segments.
//   - Domain `*` is character-aware (designed for hostname allowlists)
//     and requires at least one char.
//
// If you find this asymmetry confusing, prefer explicit literals:
//   - For "everything under /etc but not /etc itself": use both
//     `/etc/**` and a separate explicit deny on `/etc`.
//   - For "foo.com and any subdomain": list both `foo.com` and `*.foo.com`.
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
// LoadFromFile rejects time_window-only conditions (no require_prior), so
// this path is only reachable for in-process policies that bypass loading
// (tests, embedders constructing Policy literals). We keep the no-op pass-
// through to stay tolerant rather than fail-closed in those cases.
func (e *Engine) matchConditions(rule Rule, req ActionRequest) bool {
	if len(rule.Conditions) == 0 {
		return true
	}

	for _, cond := range rule.Conditions {
		if cond.RequirePrior == "" {
			// TimeWindow-only (or empty Condition): nothing to verify.
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
