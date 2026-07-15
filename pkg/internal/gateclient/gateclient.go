// Package gateclient is the shared /v1/check client substrate for the
// LLM API Proxy (pkg/llmproxy) and the MCP Gateway (pkg/mcpgw). Both
// gates speak the same wire contract — POST a policy.ActionRequest to
// the central server, decode the policy.CheckResult, translate
// transport failures per --fail-mode — so that contract lives here
// once. Each proxy keeps only its own scope-mapping and argument-
// projection logic.
//
// The package is internal: it is implementation substrate, not public
// API. The proxies re-export the pieces that are part of their stable
// contracts (Decision via type alias, the FailModeRule* constants).
package gateclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// DefaultGuardHTTPTimeout is the per-/v1/check-call timeout applied
// when the operator does not pass a custom http.Client. Five seconds
// matches the SDKs and docs/PROXY_ARCHITECTURE.md § 6.1.
const DefaultGuardHTTPTimeout = 5 * time.Second

// Decision is the verdict a gate returns to its proxy. pkg/llmproxy
// and pkg/mcpgw alias this type, so it is one shape across both
// binaries and the refusal/error-surfacing helpers on each side.
type Decision struct {
	Allow            bool
	RequiresApproval bool
	Reason           string
	Rule             string
	ApprovalID       string // set when REQUIRE_APPROVAL
	ApprovalURL      string
}

// FailModeRules carries the synthetic Rule strings a gate stamps on
// decisions it manufactures itself (fail-mode translations and
// malformed /v1/check responses). The values are per-binary stable
// contracts — dashboards alert on them — so each proxy supplies its
// own set.
type FailModeRules struct {
	Open        string // --fail-mode allow
	Closed      string // --fail-mode deny (default)
	ClosedAudit string // --fail-mode fail-closed-with-audit
	Invalid     string // /v1/check returned an unrecognised decision
}

// Caller is the wire-level /v1/check client. Zero-value fields are
// tolerated: an empty TenantID falls back to "local", a nil HTTPClient
// gets the default timeout.
type Caller struct {
	GuardURL   string
	APIKey     string
	TenantID   string
	UserAgent  string
	HTTPClient *http.Client
}

// CallV1Check POSTs ar to <GuardURL>/v1/t/<TenantID>/check and decodes
// the CheckResult into a Decision. Errors are returned for the caller
// to translate via FailModeDecision. SchemaVersion is stamped "v1"
// when the caller left it empty (the central server's request
// validator requires it).
func (c *Caller) CallV1Check(ctx context.Context, ar policy.ActionRequest, rules FailModeRules) (Decision, error) {
	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: DefaultGuardHTTPTimeout}
	}

	tenant := c.TenantID
	if tenant == "" {
		tenant = "local"
	}
	endpoint := strings.TrimRight(c.GuardURL, "/") + "/v1/t/" + url.PathEscape(tenant) + "/check"

	if ar.SchemaVersion == "" {
		ar.SchemaVersion = "v1"
	}
	body, err := json.Marshal(ar)
	if err != nil {
		return Decision{}, fmt.Errorf("marshal /v1/check body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return Decision{}, fmt.Errorf("build /v1/check request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return Decision{}, fmt.Errorf("/v1/check request: %w", err)
	}
	defer resp.Body.Close()

	// Cap the response body so a misbehaving server doesn't OOM the
	// proxy. /v1/check responses are O(few hundred bytes).
	const maxResp = 64 * 1024
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResp))
	if err != nil {
		return Decision{}, fmt.Errorf("read /v1/check body: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Decision{}, fmt.Errorf("/v1/check HTTP %d: %s", resp.StatusCode, truncateForError(string(raw)))
	}

	var cr policy.CheckResult
	if err := json.Unmarshal(raw, &cr); err != nil {
		return Decision{}, fmt.Errorf("decode /v1/check response: %w", err)
	}

	return DecisionFromCheckResult(cr, rules), nil
}

// DecisionFromCheckResult maps a policy.CheckResult onto the Decision
// shape. An unrecognised decision string is treated as a hard DENY
// stamped with rules.Invalid so dashboards can alert on it.
func DecisionFromCheckResult(cr policy.CheckResult, rules FailModeRules) Decision {
	d := Decision{
		Reason: cr.Reason,
		Rule:   cr.Rule,
	}
	switch cr.Decision {
	case policy.Allow:
		d.Allow = true
	case policy.RequireApproval:
		d.Allow = false
		d.RequiresApproval = true
		d.ApprovalID = cr.ApprovalID
		d.ApprovalURL = cr.ApprovalURL
	case policy.Deny:
		d.Allow = false
	default:
		d.Allow = false
		if d.Rule == "" {
			d.Rule = rules.Invalid
		}
		if d.Reason == "" {
			d.Reason = "unknown decision: " + string(cr.Decision)
		}
	}
	return d
}

// FailModeDecision returns the synthetic Decision dictated by
// --fail-mode when /v1/check is unreachable or returns malformed
// bytes.
func FailModeDecision(failMode string, err error, rules FailModeRules) Decision {
	switch strings.ToLower(failMode) {
	case "allow":
		return Decision{
			Allow:  true,
			Reason: "fail-mode allow: " + err.Error(),
			Rule:   rules.Open,
		}
	case "fail-closed-with-audit":
		return Decision{
			Allow:  false,
			Reason: "central server unreachable: " + err.Error(),
			Rule:   rules.ClosedAudit,
		}
	default: // "deny" or anything unrecognised
		return Decision{
			Allow:  false,
			Reason: "central server unreachable: " + err.Error(),
			Rule:   rules.Closed,
		}
	}
}

// FirstStringArg returns the first non-empty string value found in
// args under any of the supplied keys, or "" if none match.
func FirstStringArg(args map[string]interface{}, keys ...string) string {
	if len(args) == 0 {
		return ""
	}
	for _, k := range keys {
		if v, ok := args[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

// InferFilesystemAction maps a tool-name verb to the canonical
// filesystem-scope action ("read"/"write"/"delete"). Best-effort —
// rules that match by Path only are unaffected.
func InferFilesystemAction(toolName string) string {
	tl := strings.ToLower(toolName)
	switch {
	case strings.HasPrefix(tl, "read"), strings.HasPrefix(tl, "list"),
		strings.HasPrefix(tl, "get"), strings.HasPrefix(tl, "stat"),
		strings.HasPrefix(tl, "cat"), strings.HasPrefix(tl, "find"),
		strings.HasPrefix(tl, "glob"):
		return "read"
	case strings.HasPrefix(tl, "write"), strings.HasPrefix(tl, "edit"),
		strings.HasPrefix(tl, "create"), strings.HasPrefix(tl, "append"),
		strings.HasPrefix(tl, "save"), strings.HasPrefix(tl, "copy"),
		strings.HasPrefix(tl, "move"):
		return "write"
	case strings.HasPrefix(tl, "delete"), strings.HasPrefix(tl, "remove"),
		strings.HasPrefix(tl, "unlink"), strings.HasPrefix(tl, "rm"):
		return "delete"
	}
	return ""
}

// truncateForError caps long /v1/check error bodies so a verbose
// upstream response doesn't blow up logs.
func truncateForError(s string) string {
	const maxLen = 256
	s = strings.TrimSpace(s)
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
