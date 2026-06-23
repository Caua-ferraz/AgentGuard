package gateclient

// config.go owns the CLI/env configuration surface every gate binary
// shares: the flag set (guard-url, api-key, tenant-id, fail-mode,
// log-level, policy), the AGENTGUARD_API_KEY env fallback, and the
// validation of the shared invariants. Adding a shared gate flag means
// touching this file once instead of each binary's ParseConfig.

import (
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
)

// Default values for the shared gate flags. Both proxies document the
// same defaults in docs/PROXY_ARCHITECTURE.md § 6.
const (
	DefaultGuardURL = "http://127.0.0.1:8080"
	DefaultTenantID = "local"
	DefaultFailMode = "deny"
	DefaultLogLevel = "info"
)

// DefaultFailAuditLog is where fail-closed-with-audit denials are
// recorded locally when the central server is unreachable. Only ever
// created in that mode, and only when a check actually fails.
const DefaultFailAuditLog = "agentguard-fail-audit.jsonl"

// GateFlags holds the destination pointers of the CLI flags every gate
// binary shares. Register on a FlagSet via RegisterGateFlags; after
// fs.Parse, apply the env fallback + validation via Resolve.
type GateFlags struct {
	GuardURL     *string
	APIKey       *string
	TenantID     *string
	FailMode     *string
	LogLevel     *string
	PolicyPath   *string
	FailAuditLog *string
}

// RegisterGateFlags registers the shared gate flags on fs. policyHelp
// is binary-specific because the two proxies document different
// behaviour for a missing --policy (the LLM proxy falls back to the
// bundled scope map; the MCP gateway requires it in strict mode).
func RegisterGateFlags(fs *flag.FlagSet, policyHelp string) *GateFlags {
	return &GateFlags{
		GuardURL:   fs.String("guard-url", DefaultGuardURL, "Central AgentGuard server base URL"),
		APIKey:     fs.String("api-key", "", "Bearer token for /v1/check (defaults to $AGENTGUARD_API_KEY)"),
		TenantID:   fs.String("tenant-id", DefaultTenantID, "Tenant ID for the central server"),
		FailMode:   fs.String("fail-mode", DefaultFailMode, `Fail mode when /v1/check is unreachable: "deny" | "allow" | "fail-closed-with-audit"`),
		LogLevel:   fs.String("log-level", DefaultLogLevel, `Stderr verbosity: "info" | "debug"`),
		PolicyPath: fs.String("policy", "", policyHelp),
		FailAuditLog: fs.String("fail-audit-log", DefaultFailAuditLog,
			`Local JSONL file recording denials made while the central server is unreachable (used only with --fail-mode fail-closed-with-audit; empty disables)`),
	}
}

// Resolve applies the env fallback and validates the shared invariants.
// Call after fs.Parse. The flag-wins-over-env API-key contract matches
// the agentguard core CLI.
func (f *GateFlags) Resolve() error {
	*f.APIKey = ResolveAPIKey(*f.APIKey)
	return ValidateGateConfig(*f.GuardURL, *f.TenantID, *f.FailMode, *f.LogLevel)
}

// ResolveAPIKey returns the explicit flag value when set, otherwise the
// AGENTGUARD_API_KEY env var.
func ResolveAPIKey(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	return os.Getenv("AGENTGUARD_API_KEY")
}

// ValidateGateConfig enforces the invariants shared by every gate
// binary. Exposed separately from Resolve so config structs built
// directly in tests can validate without a FlagSet.
func ValidateGateConfig(guardURL, tenantID, failMode, logLevel string) error {
	if err := ValidateBaseURL("--guard-url", guardURL); err != nil {
		return err
	}
	if tenantID == "" {
		return errors.New("--tenant-id must not be empty")
	}
	switch failMode {
	case "deny", "allow", "fail-closed-with-audit":
	default:
		return fmt.Errorf("--fail-mode must be deny|allow|fail-closed-with-audit, got %q", failMode)
	}
	switch logLevel {
	case "info", "debug":
	default:
		return fmt.Errorf("--log-level must be info|debug, got %q", logLevel)
	}
	return nil
}

// ValidateBaseURL enforces that v has an http(s) scheme + host. Empty
// paths are accepted (concrete paths are joined at request time).
func ValidateBaseURL(name, v string) error {
	if v == "" {
		return fmt.Errorf("%s must not be empty", name)
	}
	parsed, err := url.Parse(v)
	if err != nil {
		return fmt.Errorf("%s %q is not a valid URL: %w", name, v, err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("%s %q is not a valid URL (missing scheme or host)", name, v)
	}
	switch parsed.Scheme {
	case "http", "https":
	default:
		return fmt.Errorf("%s %q must use http or https", name, v)
	}
	return nil
}
