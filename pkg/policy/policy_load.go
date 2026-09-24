package policy

import (
	"fmt"
	"os"
	"reflect"

	"gopkg.in/yaml.v3"
)

// LoadFromFileWithWarnings loads and validates a policy file like
// LoadFromFile, and also returns the non-fatal warnings it found (merged
// duplicate scope blocks, recursive path globs) instead of only logging
// them. `agentguard validate` prints them, and `--strict` fails on them.
func LoadFromFileWithWarnings(path string) (*Policy, []string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("reading policy file: %w", err)
	}
	return parsePolicyBytesWithWarnings(data)
}

// parsePolicyBytesWithWarnings is the single YAML → Policy path: file load,
// multi-tenant store load and Validate all go through it.
func parsePolicyBytesWithWarnings(data []byte) (*Policy, []string, error) {
	var pol Policy
	if err := yaml.Unmarshal(data, &pol); err != nil {
		return nil, nil, fmt.Errorf("parsing policy YAML: %w", err)
	}

	if pol.Version == "" {
		return nil, nil, fmt.Errorf("policy missing required 'version' field")
	}
	if pol.Name == "" {
		return nil, nil, fmt.Errorf("policy missing required 'name' field")
	}

	if err := validateFilesystemPaths(&pol); err != nil {
		return nil, nil, err
	}
	if err := validateRedactionPatterns(&pol); err != nil {
		return nil, nil, err
	}
	if err := validateToolScopeMap(&pol); err != nil {
		return nil, nil, err
	}

	// Validate proxy and notification tunables: parse durations, bound-check
	// integers. Fail at load so an operator who types "1hr" instead of "1h"
	// finds out before a session tries to expire.
	if err := validateTunables(&pol); err != nil {
		return nil, nil, err
	}

	// Validate every rule-level rate_limit and condition.time_window
	// duration at load time. Lazy parsing on the request path silently
	// fell through on bad input, so a typo like `window: "1minute"`
	// produced a no-op rule. window=0 (panic in the limiter) is also
	// rejected here.
	if err := validateRuleDurationsAndCounts(&pol); err != nil {
		return nil, nil, err
	}

	// Reject conditions with time_window but no require_prior. Such a
	// condition is inert at runtime; we hard-fail at load so a footgun
	// in production cannot hide behind a one-line typo.
	if err := errorTimeWindowOnlyConditions(&pol); err != nil {
		return nil, nil, err
	}

	// Several blocks for one scope are merged into one, so a deny in a later
	// block applies (Check stops at the first block that decides).
	var warnings []string
	merged, w, err := mergeDuplicateScopes(pol.Rules, "rules")
	if err != nil {
		return nil, nil, err
	}
	pol.Rules = merged
	warnings = append(warnings, w...)
	for agentID, cfg := range pol.Agents {
		merged, w, err := mergeDuplicateScopes(cfg.Override, fmt.Sprintf("agents.%s.override", agentID))
		if err != nil {
			return nil, nil, err
		}
		cfg.Override = merged
		pol.Agents[agentID] = cfg
		warnings = append(warnings, w...)
	}

	// Fold rule domains to lower case once, so case-insensitive domain
	// matching (normalizeRequest lower-cases the request side per Check)
	// works without a rule-side allocation on the hot path.
	normalizeRuleDomains(&pol)

	// Non-fatal lint: path patterns whose '*' recurses across '/'.
	warnings = append(warnings, lintPathPatterns(&pol)...)

	return &pol, warnings, nil
}

// mergeDuplicateScopes combines rule sets that share a scope into one, in
// file order: deny, require_approval and allow rules are concatenated, so
// deny-before-approval-before-allow precedence holds across the original
// blocks. A rate_limit or limits set in more than one block must be
// identical; otherwise the policy is rejected, since either choice would
// silently drop the other.
func mergeDuplicateScopes(sets []RuleSet, loc string) ([]RuleSet, []string, error) {
	if len(sets) < 2 {
		return sets, nil, nil
	}
	firstIndex := make(map[string]int, len(sets))
	out := make([]RuleSet, 0, len(sets))
	var warnings []string
	for i, rs := range sets {
		j, seen := firstIndex[rs.Scope]
		if !seen {
			firstIndex[rs.Scope] = len(out)
			out = append(out, rs)
			continue
		}
		dst := &out[j]
		warnings = append(warnings, fmt.Sprintf(
			"policy: scope %q appears in more than one block (%s[%d] is merged into the first %q block); "+
				"their deny, require_approval and allow rules now apply together", rs.Scope, loc, i, rs.Scope))
		dst.Deny = append(dst.Deny, rs.Deny...)
		dst.RequireApproval = append(dst.RequireApproval, rs.RequireApproval...)
		dst.Allow = append(dst.Allow, rs.Allow...)
		if rs.RateLimit != nil {
			if dst.RateLimit != nil && !reflect.DeepEqual(dst.RateLimit, rs.RateLimit) {
				return nil, nil, fmt.Errorf("%s[%d](%s).rate_limit: scope %q already has a different rate_limit in an earlier block; keep one", loc, i, rs.Scope, rs.Scope)
			}
			dst.RateLimit = rs.RateLimit
		}
		if rs.Limits != nil {
			if dst.Limits != nil && !reflect.DeepEqual(dst.Limits, rs.Limits) {
				return nil, nil, fmt.Errorf("%s[%d](%s).limits: scope %q already has different limits in an earlier block; keep one", loc, i, rs.Scope, rs.Scope)
			}
			dst.Limits = rs.Limits
		}
	}
	return out, warnings, nil
}
