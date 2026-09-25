package gateclient

// config.go owns the CLI/env configuration surface every gate binary
// shares: the flag set (guard-url, api-key, tenant-id, fail-mode,
// log-level, policy), the AGENTGUARD_API_KEY and AGENTGUARD_URL env
// fallbacks, the flags-only argument check, and the validation of the
// shared invariants. Adding a shared gate flag means
// touching this file once instead of each binary's ParseConfig.

import (
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
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

	fs *flag.FlagSet // to tell a --guard-url given on the command line from its default
}

// RegisterGateFlags registers the shared gate flags on fs. policyHelp
// is binary-specific because the two proxies document different
// behaviour for a missing --policy (the LLM proxy falls back to the
// bundled scope map; the MCP gateway requires it in strict mode).
func RegisterGateFlags(fs *flag.FlagSet, policyHelp string) *GateFlags {
	return &GateFlags{
		fs:         fs,
		GuardURL:   fs.String("guard-url", DefaultGuardURL, "Central AgentGuard server URL. Env: AGENTGUARD_URL"),
		APIKey:     fs.String("api-key", "", "Bearer token for /v1/check. Env: AGENTGUARD_API_KEY"),
		TenantID:   fs.String("tenant-id", DefaultTenantID, "Tenant ID for the central server"),
		FailMode:   fs.String("fail-mode", DefaultFailMode, "What to do when /v1/check can't be reached: deny, allow, or fail-closed-with-audit (deny, and record it in --fail-audit-log)"),
		LogLevel:   fs.String("log-level", DefaultLogLevel, "Stderr verbosity: info or debug"),
		PolicyPath: fs.String("policy", "", policyHelp),
		FailAuditLog: fs.String("fail-audit-log", DefaultFailAuditLog,
			"Local JSON Lines file for the denials made while the central server is unreachable. Used only with --fail-mode fail-closed-with-audit; empty disables it."),
	}
}

// Resolve applies the env fallbacks and validates the shared invariants.
// Call after fs.Parse.
func (f *GateFlags) Resolve() error {
	f.ApplyEnv()
	return ValidateGateConfig(*f.GuardURL, *f.TenantID, *f.FailMode, *f.LogLevel)
}

// ApplyEnv fills what the command line left unset from the environment:
// --api-key from AGENTGUARD_API_KEY and --guard-url from AGENTGUARD_URL
// (the variable the SDKs and the agentguard client commands read). A flag
// always wins over its variable, matching the agentguard core CLI. Call
// after fs.Parse.
func (f *GateFlags) ApplyEnv() {
	*f.APIKey = ResolveAPIKey(*f.APIKey)
	guardURLSet := false
	if f.fs != nil {
		f.fs.Visit(func(fl *flag.Flag) {
			if fl.Name == "guard-url" {
				guardURLSet = true
			}
		})
	}
	if env := os.Getenv("AGENTGUARD_URL"); env != "" && !guardURLSet {
		*f.GuardURL = env
	}
}

// RejectArgs returns an error for the first positional argument in args
// (fs.Args() after parsing). The gate binaries take flags only; a stray
// word used to be ignored silently, so `agentguard-llm-proxy version`
// started the proxy and an unquoted --upstream command lost its arguments.
// hint says what the argument might have been meant as; it may be empty.
func RejectArgs(args []string, hint string) error {
	if len(args) == 0 {
		return nil
	}
	arg := args[0]
	switch strings.ToLower(arg) {
	case "version":
		return fmt.Errorf("unexpected argument %q (did you mean --version?)", arg)
	case "help":
		return fmt.Errorf("unexpected argument %q (did you mean --help?)", arg)
	}
	if hint == "" {
		hint = "this command takes flags only"
	}
	return fmt.Errorf("unexpected argument %q (%s)", arg, hint)
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
