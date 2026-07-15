// Package llmproxy implements the AgentGuard LLM API Proxy: an HTTP
// server that speaks OpenAI Chat Completions and Anthropic Messages
// wire formats, forwards requests to the real upstreams, and gates
// any tool calls the model emits through the central AgentGuard
// policy engine.
//
// Major pieces:
//
//   - server.go — HTTP server skeleton, non-streaming forwarding,
//     protocol types, integration hooks.
//   - streaming.go — streaming pause/resume/rewrite (SSE parsing for
//     both providers, byte-identity invariant on ALLOW, synthetic
//     refusal on DENY / REQUIRE_APPROVAL).
//   - scope_map.go — tool-call → policy-scope mapping (built-in
//     defaults + YAML override).
//   - gate.go — PolicyCheck hook wired against /v1/check, fail-mode
//     handling.
//   - refusal.go — synthetic-refusal payload construction.
//
// See docs/LLM_API_PROXY.md for the wire format design and
// docs/PROXY_ARCHITECTURE.md for cross-cutting decisions (audit
// transport tag, two-binary topology, fail-mode flag parity).
package llmproxy

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/Caua-ferraz/AgentGuard/pkg/internal/gateclient"
)

// Default flag values. Centralised here so tests can refer to them
// without re-running the flag parser.
const (
	// DefaultListen binds to loopback by design — non-loopback binds
	// without --proxy-api-key are refused at validation time.
	DefaultListen = "127.0.0.1:8081"

	// Defaults aligned with docs/LLM_API_PROXY.md § 2 CLI surface.
	// The gate-side values are the shared contract from
	// pkg/internal/gateclient (same for the MCP gateway).
	DefaultUpstreamOpenAI    = "https://api.openai.com"
	DefaultUpstreamAnthropic = "https://api.anthropic.com"
	DefaultGuardURL          = gateclient.DefaultGuardURL
	DefaultTenantID          = gateclient.DefaultTenantID
	DefaultFailMode          = gateclient.DefaultFailMode
	DefaultLogLevel          = gateclient.DefaultLogLevel

	// DefaultMaxBufferBytes (1 MiB) is the per-stream tool-call
	// accumulation cap. Mirrors the central server's MaxRequestBodySize
	// so /v1/check side-channel payloads always fit. The streaming
	// path enforces this; the configured value is stored here.
	DefaultMaxBufferBytes = 1024 * 1024 // 1 MiB

	// MaxConfigurableBufferBytes refuses pathological values up front.
	// 64 MiB is the upper bound — beyond that, gating an individual
	// tool call is no longer the right tool (operators should split
	// the workload).
	MaxConfigurableBufferBytes = 64 * 1024 * 1024 // 64 MiB

	// DefaultMaxConcurrentStreams caps simultaneously-active streaming
	// requests on the proxy. Each in-flight stream owns a per-request
	// accumulator + read buffer (up to ~2x --max-buffer-bytes), so a
	// global cap is the only thing keeping memory bounded under fan-out
	// load. 100 was picked as a default that balances normal SDK
	// concurrency (typically <10) against worst-case memory (100 × 1
	// MiB ≈ 200 MiB read+accumulator territory). Operators with heavy
	// fan-out should raise this and lower --max-buffer-bytes
	// proportionally; operators on tiny boxes should lower it.
	//
	// 0 disables the cap entirely.
	DefaultMaxConcurrentStreams = 100
)

// Config is the parsed CLI/env configuration for one proxy invocation.
// Populated by ParseConfig. The server reads it once at startup and
// treats it as immutable thereafter; hot-reload of flags is out of
// scope.
type Config struct {
	// Listen is the proxy's HTTP bind address. Default DefaultListen
	// (loopback). Non-loopback is rejected unless --proxy-api-key
	// is set (mirrors central server's localhost-only fallback).
	Listen string

	// UpstreamOpenAI is the base URL for OpenAI-shape requests
	// (/v1/chat/completions, /v1/completions, /v1/embeddings, /v1/models).
	UpstreamOpenAI string

	// UpstreamAnthropic is the base URL for Anthropic-shape requests
	// (/v1/messages).
	UpstreamAnthropic string

	// GuardURL is the central AgentGuard server's base URL — the
	// PolicyCheck hook calls <GuardURL>/v1/check.
	GuardURL string

	// APIKey is the bearer token sent on the /v1/check side channel.
	// Falls back to AGENTGUARD_API_KEY env var when the flag is empty.
	// Distinct from the user's upstream Authorization header (which
	// is forwarded verbatim, never read).
	APIKey string

	// ProxyAPIKey is the OPTIONAL bearer the proxy enforces on inbound
	// requests via the X-AgentGuard-Proxy-Auth header. Empty disables
	// proxy-level auth (safe on loopback). Sent in a separate header
	// from Authorization so the upstream's own bearer token can be
	// forwarded unambiguously.
	ProxyAPIKey string

	// TenantID is plumbed through to /v1/check and audit entries.
	TenantID string

	// FailMode mirrors the SDK / MCP gateway contract from
	// docs/PROXY_ARCHITECTURE.md § 6.1: "deny" | "allow" |
	// "fail-closed-with-audit". The gate honours this on /v1/check
	// failures.
	FailMode string

	// FailAuditLog is the local JSONL file the gate appends a deny
	// record to when /v1/check is unreachable in fail-closed-with-audit
	// mode (the central server can't write the audit entry itself).
	// Empty disables the local record. Unused in other fail modes.
	FailAuditLog string

	// MaxBufferBytes caps the per-stream tool-call accumulation
	// buffer (default 1 MiB). The streaming pipeline enforces it.
	MaxBufferBytes int

	// MaxConcurrentStreams caps simultaneously-active streaming
	// requests across the whole proxy. When the cap is reached, new
	// streaming requests are refused with 503 + Retry-After: 5 instead
	// of being processed (which would otherwise allocate another
	// per-stream accumulator + read buffer pair). 0 disables the cap.
	// Default: DefaultMaxConcurrentStreams.
	//
	// Without this cap the streaming memory ceiling is unbounded; the
	// per-stream cap (--max-buffer-bytes) only constrains a single
	// in-flight call.
	MaxConcurrentStreams int

	// LogLevel controls stderr verbosity. "info" or "debug".
	LogLevel string

	// PolicyPath points at the policy YAML the proxy reads to resolve
	// the LLM tool→scope mapping locally (operators run the same YAML
	// the central server loads — typically a shared file path).
	//
	// Optional: when unset, the gate falls back to the bundled
	// DefaultLLMToolScopeMap and skips hot-reload. main.go logs a
	// WARNING in that case because operator overrides won't apply.
	// Cross-host deployments must mount the file on a shared volume
	// (or replicate the YAML out-of-band) so the proxy and the
	// central server stay in lockstep.
	PolicyPath string
}

// ParseConfig parses CLI args (without the leading binary name) and
// returns a Config. Errors are returned for the caller to surface.
// API-key resolution: explicit --api-key wins over AGENTGUARD_API_KEY.
func ParseConfig(args []string) (*Config, error) {
	return ParseConfigWithOutput(args, os.Stderr)
}

// ParseConfigWithOutput is ParseConfig with the usage stream pluggable
// for tests. Mirrors mcpgw.ParseConfigWithOutput.
func ParseConfigWithOutput(args []string, errOut io.Writer) (*Config, error) {
	fs := flag.NewFlagSet("agentguard-llm-proxy", flag.ContinueOnError)
	fs.SetOutput(errOut)

	gate := gateclient.RegisterGateFlags(fs,
		"Path to policy YAML for tool→scope mapping; empty falls back to DefaultLLMToolScopeMap with no operator overrides")
	listen := fs.String("listen", DefaultListen, "Address to bind (host:port)")
	upstreamOpenAI := fs.String("upstream-openai", DefaultUpstreamOpenAI, "Base URL for OpenAI-shape requests")
	upstreamAnthropic := fs.String("upstream-anthropic", DefaultUpstreamAnthropic, "Base URL for Anthropic-shape requests")
	proxyAPIKey := fs.String("proxy-api-key", "", "Optional bearer the proxy itself enforces on inbound requests (X-AgentGuard-Proxy-Auth). Empty = no proxy auth.")
	maxBufferBytes := fs.Int("max-buffer-bytes", DefaultMaxBufferBytes, "Per-stream tool-call buffer cap in bytes")
	maxConcurrentStreams := fs.Int("max-concurrent-streams", DefaultMaxConcurrentStreams, "Global cap on simultaneous streaming requests; 0 disables the cap. Excess requests are refused with 503 + Retry-After: 5.")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	cfg := &Config{
		Listen:               *listen,
		UpstreamOpenAI:       *upstreamOpenAI,
		UpstreamAnthropic:    *upstreamAnthropic,
		GuardURL:             *gate.GuardURL,
		APIKey:               gateclient.ResolveAPIKey(*gate.APIKey),
		ProxyAPIKey:          *proxyAPIKey,
		TenantID:             *gate.TenantID,
		FailMode:             *gate.FailMode,
		FailAuditLog:         *gate.FailAuditLog,
		MaxBufferBytes:       *maxBufferBytes,
		MaxConcurrentStreams: *maxConcurrentStreams,
		LogLevel:             *gate.LogLevel,
		PolicyPath:           *gate.PolicyPath,
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Validate enforces invariants on a parsed Config. Exposed for tests
// that build a Config struct directly without going through the
// flag parser.
func (c *Config) Validate() error {
	if c.Listen == "" {
		return errors.New("--listen must not be empty")
	}
	host, port, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return fmt.Errorf("--listen %q is not a valid host:port: %w", c.Listen, err)
	}
	if port == "" {
		return fmt.Errorf("--listen %q is missing port", c.Listen)
	}

	if err := gateclient.ValidateBaseURL("--upstream-openai", c.UpstreamOpenAI); err != nil {
		return err
	}
	if err := gateclient.ValidateBaseURL("--upstream-anthropic", c.UpstreamAnthropic); err != nil {
		return err
	}
	if err := gateclient.ValidateGateConfig(c.GuardURL, c.TenantID, c.FailMode, c.LogLevel); err != nil {
		return err
	}

	if c.MaxBufferBytes <= 0 {
		return fmt.Errorf("--max-buffer-bytes must be > 0, got %d", c.MaxBufferBytes)
	}
	if c.MaxBufferBytes > MaxConfigurableBufferBytes {
		return fmt.Errorf("--max-buffer-bytes %d exceeds maximum %d", c.MaxBufferBytes, MaxConfigurableBufferBytes)
	}

	// Negative max-concurrent-streams is a typo; 0 disables the cap.
	if c.MaxConcurrentStreams < 0 {
		return fmt.Errorf("--max-concurrent-streams must be >= 0, got %d", c.MaxConcurrentStreams)
	}

	if c.TenantID == "" {
		return errors.New("--tenant-id must not be empty")
	}

	// Non-loopback bind without --proxy-api-key is refused per
	// docs/LLM_API_PROXY.md § 8.1: avoids accidental
	// internet-exposed proxies.
	if !isLoopbackHost(host) && c.ProxyAPIKey == "" {
		return fmt.Errorf("--listen %q binds non-loopback host %q without --proxy-api-key; refuse to start to avoid exposing an unauthenticated proxy", c.Listen, host)
	}

	return nil
}

// isLoopbackHost returns true for "", "localhost", "127.x.x.x", "::1",
// "[::1]". Used by Validate to detect loopback binds.
func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" || host == "localhost" {
		return true
	}
	// Strip brackets from IPv6 literal (net.SplitHostPort already
	// strips them, but be defensive in case Validate was invoked on
	// a hand-built Config).
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}
