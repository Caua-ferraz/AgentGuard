package mcpgw

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"
)

// Config is the parsed CLI/env configuration for one gateway invocation.
//
// All fields are populated by ParseConfig (which honours both flags
// and env-var fallback). The bridge consumes this struct read-only;
// every value that influences a hot-path decision is plumbed through
// the bridge's hooks rather than re-read from the config at request
// time, so the bridge does not need to lock around config access.
type Config struct {
	// Upstreams is the ordered list of downstream MCP servers the
	// gateway brokers. Repeatable via --upstream. At least one entry
	// is required.
	Upstreams []UpstreamSpec

	// GuardURL is the central AgentGuard server's base URL (the host
	// of /v1/check). Default "http://127.0.0.1:8080".
	GuardURL string

	// APIKey is the bearer token sent to /v1/check. Falls back to the
	// AGENTGUARD_API_KEY env var when the flag is empty. May be empty
	// (the central server runs without auth in that case — a WARNING
	// is logged at startup).
	APIKey string

	// TenantID is the tenant header value. Default "local".
	TenantID string

	// FailMode controls behaviour when /v1/check is unreachable.
	// One of "deny", "allow", "fail-closed-with-audit". Default "deny".
	// Mirrors the SDK fail-mode contract documented in
	// docs/PROXY_ARCHITECTURE.md § 6.1.
	FailMode string

	// PolicyMode is "strict" (dual-check: mcp_tool + mapped scope) or
	// "fast" (single-check: mcp_tool only). Default "strict".
	// docs/MCP_GATEWAY.md § 4.4.3 — A18 wires the actual dual-check;
	// the bridge passes this value through to the policy hook.
	PolicyMode string

	// LogLevel controls stderr verbosity. "info" or "debug". Default
	// "info". A18/A19 may extend this set.
	LogLevel string

	// UpstreamTimeout caps how long the bridge waits for a response
	// from a single upstream Send. Default 30s.
	UpstreamTimeout time.Duration

	// ReconnectCap caps the upper bound on reconnect backoff between
	// upstream restart attempts. Default 60s.
	ReconnectCap time.Duration

	// SupportedProtocolVersions is the set of MCP protocol versions
	// the gateway will accept on `initialize`. Defaults to
	// DefaultSupportedProtocolVersions; populated by ParseConfig so
	// tests can pin a custom set.
	SupportedProtocolVersions []string

	// PolicyPath is the filesystem path to the same policy YAML the
	// central AgentGuard server loads. The gateway opens this file at
	// startup so it can resolve `tool_scope_map` locally for the
	// dual-check pattern (see docs/MCP_GATEWAY.md § 4.4 and gate.go).
	// Required when --policy-mode strict is in effect; tests may leave
	// it empty and supply a *policy.Policy directly via the gate's
	// constructor instead.
	PolicyPath string
}

// UpstreamSpec describes one downstream MCP subprocess.
//
// The Command field is the raw command string that the transport
// layer splits via a small shell-style tokenizer (see
// SplitCommandLine). For v0.5 only stdio is supported; the
// (currently unused) Transport field is reserved for v0.6 when
// Streamable-HTTP transport ships.
//
// TODO(v0.6, #mcp-streamable-http): add Transport == "http" with a
// URL field, paired with a different Upstream impl in transport.go.
type UpstreamSpec struct {
	Namespace string // e.g. "fs", "github"
	Command   string // raw command string, shell-tokenized at start time

	// Transport is reserved for future use. v0.5 always uses stdio.
	Transport string
}

// ParseConfig parses CLI args (without the leading binary name) and
// returns a Config. Errors are returned for the caller to surface;
// usage text is written to `errOut` when non-nil and the args contain
// `--help`.
//
// API-key resolution: the explicit --api-key flag wins over the
// AGENTGUARD_API_KEY env var (matching the agentguard core CLI).
func ParseConfig(args []string) (*Config, error) {
	return ParseConfigWithOutput(args, os.Stderr)
}

// ParseConfigWithOutput is ParseConfig with the usage-output stream
// pluggable for tests.
func ParseConfigWithOutput(args []string, errOut io.Writer) (*Config, error) {
	fs := flag.NewFlagSet("agentguard-mcp-gateway", flag.ContinueOnError)
	fs.SetOutput(errOut)

	var upstreams stringSliceFlag
	fs.Var(&upstreams, "upstream", `Downstream MCP server. Format: "<ns>:<cmd>" or "<cmd>" (ns defaults to first command word). Repeatable.`)
	guardURL := fs.String("guard-url", "http://127.0.0.1:8080", "Central AgentGuard server base URL")
	apiKey := fs.String("api-key", "", "Bearer token for /v1/check (defaults to $AGENTGUARD_API_KEY)")
	tenantID := fs.String("tenant-id", "local", "Tenant ID for the central server")
	failMode := fs.String("fail-mode", "deny", `Fail mode when /v1/check is unreachable: "deny" | "allow" | "fail-closed-with-audit"`)
	policyMode := fs.String("policy-mode", "strict", `Policy mode: "strict" (dual-check) or "fast" (single-check)`)
	logLevel := fs.String("log-level", "info", `Stderr verbosity: "info" | "debug"`)
	upstreamTimeout := fs.Duration("upstream-timeout", 30*time.Second, "Per-frame upstream-response timeout")
	reconnectCap := fs.Duration("reconnect-cap", 60*time.Second, "Upper bound on reconnect backoff")
	policyPath := fs.String("policy", "", "Path to the same policy YAML the central AgentGuard server loads (required for --policy-mode strict; used to resolve tool_scope_map locally)")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	if len(upstreams) == 0 {
		return nil, errors.New("at least one --upstream is required")
	}

	cfg := &Config{
		GuardURL:                  *guardURL,
		APIKey:                    *apiKey,
		TenantID:                  *tenantID,
		FailMode:                  *failMode,
		PolicyMode:                *policyMode,
		LogLevel:                  *logLevel,
		UpstreamTimeout:           *upstreamTimeout,
		ReconnectCap:              *reconnectCap,
		PolicyPath:                *policyPath,
		SupportedProtocolVersions: append([]string{}, DefaultSupportedProtocolVersions...),
	}

	// API-key fallback: env var if flag empty.
	if cfg.APIKey == "" {
		cfg.APIKey = os.Getenv("AGENTGUARD_API_KEY")
	}

	// Validate guard URL.
	if cfg.GuardURL == "" {
		return nil, errors.New("--guard-url must not be empty")
	}
	parsed, err := url.Parse(cfg.GuardURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("--guard-url %q is not a valid URL", cfg.GuardURL)
	}

	// Validate enums.
	switch cfg.FailMode {
	case "deny", "allow", "fail-closed-with-audit":
	default:
		return nil, fmt.Errorf("--fail-mode must be deny|allow|fail-closed-with-audit, got %q", cfg.FailMode)
	}
	switch cfg.PolicyMode {
	case "strict", "fast":
	default:
		return nil, fmt.Errorf("--policy-mode must be strict|fast, got %q", cfg.PolicyMode)
	}
	switch cfg.LogLevel {
	case "info", "debug":
	default:
		return nil, fmt.Errorf("--log-level must be info|debug, got %q", cfg.LogLevel)
	}

	// --policy is required in strict mode (the gate needs the
	// tool_scope_map). In fast mode the gateway never consults the
	// policy locally — the central server's mcp_tool decision is
	// authoritative — so the flag is optional.
	if cfg.PolicyMode == "strict" && cfg.PolicyPath == "" {
		return nil, errors.New("--policy is required when --policy-mode is strict (use the same YAML the central server loads)")
	}

	// Parse and validate upstreams.
	parsedSpecs, err := parseUpstreamSpecs(upstreams)
	if err != nil {
		return nil, err
	}
	cfg.Upstreams = parsedSpecs

	return cfg, nil
}

// parseUpstreamSpecs converts the raw --upstream string slice into
// UpstreamSpec values, deriving namespaces and rejecting duplicates.
//
// Format precedence:
//
//   - "<ns>:<cmd>" — namespace is the substring before the first `:`,
//     command is everything after. Whitespace is trimmed off both
//     sides of `<ns>` (so "fs : npx ..." works).
//   - "<cmd>" (no `:`) — namespace defaults to the first
//     whitespace-delimited token of cmd (the program name as the
//     operator typed it).
//
// We split on the FIRST `:` only — command lines with `:` later are
// preserved verbatim (e.g., a Windows path containing `C:\` would not
// trigger here because the first `:` would be after the namespace
// label, but we are explicit about it).
//
// Edge case: a command starting with a colon ("--upstream :foo") would
// be parsed as namespace="" + cmd="foo", which we reject as invalid
// (namespace is required to be non-empty).
func parseUpstreamSpecs(raw []string) ([]UpstreamSpec, error) {
	specs := make([]UpstreamSpec, 0, len(raw))
	seen := map[string]struct{}{}

	for i, entry := range raw {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			return nil, fmt.Errorf("--upstream #%d is empty", i)
		}

		var ns, cmd string
		if idx := strings.IndexByte(entry, ':'); idx >= 0 {
			ns = strings.TrimSpace(entry[:idx])
			cmd = strings.TrimSpace(entry[idx+1:])
			if ns == "" {
				return nil, fmt.Errorf("--upstream #%d has empty namespace before colon: %q", i, entry)
			}
			if cmd == "" {
				return nil, fmt.Errorf("--upstream #%d has empty command after colon: %q", i, entry)
			}
		} else {
			cmd = entry
			// Default namespace = first whitespace-delimited token.
			fields := strings.Fields(cmd)
			if len(fields) == 0 {
				return nil, fmt.Errorf("--upstream #%d has no command tokens: %q", i, entry)
			}
			ns = fields[0]
		}

		// Namespace must not contain colon (would break tools/call routing).
		if strings.ContainsAny(ns, ": \t") {
			return nil, fmt.Errorf("--upstream namespace %q must not contain colon or whitespace", ns)
		}

		if _, dup := seen[ns]; dup {
			return nil, fmt.Errorf("--upstream namespace %q declared more than once", ns)
		}
		seen[ns] = struct{}{}

		specs = append(specs, UpstreamSpec{
			Namespace: ns,
			Command:   cmd,
			Transport: "stdio",
		})
	}

	return specs, nil
}

// stringSliceFlag implements flag.Value for repeatable string flags.
type stringSliceFlag []string

func (s *stringSliceFlag) String() string {
	if s == nil {
		return ""
	}
	return strings.Join(*s, ",")
}

func (s *stringSliceFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// SplitCommandLine performs a small shell-style tokenization of `cmd`
// suitable for exec.Command. It supports double-quoted segments (with
// `\"` escaping) and ignores tabs/spaces between tokens. It does NOT
// support backtick substitution, $VAR expansion, redirection, pipes,
// or single-quoted strings — operators who need those should pre-shell
// the command (e.g., wrap in `sh -c "..."`).
//
// Returned slice is never empty unless input is empty.
func SplitCommandLine(cmd string) ([]string, error) {
	var out []string
	var cur strings.Builder
	inQuote := false
	escape := false

	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}

	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		if escape {
			cur.WriteByte(c)
			escape = false
			continue
		}
		if c == '\\' && inQuote {
			escape = true
			continue
		}
		if c == '"' {
			inQuote = !inQuote
			continue
		}
		if !inQuote && (c == ' ' || c == '\t') {
			flush()
			continue
		}
		cur.WriteByte(c)
	}
	if inQuote {
		return nil, fmt.Errorf("unterminated quote in command: %q", cmd)
	}
	if escape {
		return nil, fmt.Errorf("trailing backslash in command: %q", cmd)
	}
	flush()
	return out, nil
}
