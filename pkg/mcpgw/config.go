package mcpgw

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Caua-ferraz/AgentGuard/internal/clihelp"
	"github.com/Caua-ferraz/AgentGuard/pkg/internal/gateclient"
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
	// gateway brokers: every --upstream (stdio) first, then every
	// --upstream-http, each in flag order. At least one entry is
	// required.
	Upstreams []UpstreamSpec

	// UpstreamHeaders holds the extra HTTP headers (--upstream-header)
	// sent to each --upstream-http server, keyed by namespace, with
	// ${ENV_VAR} references already expanded. Values may carry bearer
	// tokens: never log them.
	//
	// The headers live here rather than on UpstreamSpec so UpstreamSpec
	// stays a comparable struct (adding a map field to it would break
	// any caller comparing specs with ==).
	UpstreamHeaders map[string]http.Header

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

	// FailAuditLog is the local JSONL file the gate appends a deny
	// record to when /v1/check is unreachable in fail-closed-with-audit
	// mode (the central server can't write the audit entry itself).
	// Empty disables the local record. Unused in other fail modes.
	FailAuditLog string

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

// Upstream transports. UpstreamSpec.Transport is one of these.
const (
	// TransportStdio runs Command as a subprocess and speaks
	// newline-delimited JSON-RPC over its stdin/stdout (--upstream).
	TransportStdio = "stdio"

	// TransportHTTP talks to a remote MCP server at URL over the MCP
	// Streamable HTTP transport (--upstream-http).
	TransportHTTP = "http"
)

// UpstreamSpec describes one downstream MCP server.
//
// For stdio upstreams the Command field is the raw command string
// that the transport layer splits via a small shell-style tokenizer
// (see SplitCommandLine). For HTTP upstreams URL is the server's MCP
// endpoint and Command is empty. An empty Transport means stdio.
type UpstreamSpec struct {
	Namespace string // e.g. "fs", "github"
	Command   string // raw command string, shell-tokenized at start time

	// Transport is TransportStdio or TransportHTTP.
	Transport string

	// URL is the MCP endpoint of an HTTP upstream, e.g.
	// "https://mcp.example.com/mcp". Empty for stdio.
	URL string
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

// gatewayFlagGroups is the layout of `agentguard-mcp-gateway -h`. Every
// flag must be in one group (TestParseConfig_HelpGroupsEveryFlag).
var gatewayFlagGroups = []clihelp.Group{
	{Title: "MCP servers to guard", Names: []string{"upstream", "upstream-http", "upstream-header", "upstream-timeout", "reconnect-cap"}},
	{Title: "AgentGuard server", Names: []string{"guard-url", "api-key", "tenant-id"}},
	{Title: "Policy", Names: []string{"policy", "policy-mode"}},
	{Title: "When the AgentGuard server is unreachable", Names: []string{"fail-mode", "fail-audit-log"}},
	{Title: "Logging", Names: []string{"log-level"}},
}

// ParseConfigWithOutput is ParseConfig with the usage-output stream
// pluggable for tests.
func ParseConfigWithOutput(args []string, errOut io.Writer) (*Config, error) {
	fs := flag.NewFlagSet("agentguard-mcp-gateway", flag.ContinueOnError)
	fs.SetOutput(errOut)
	fs.Usage = func() {
		fmt.Fprintf(errOut, `Usage: agentguard-mcp-gateway --upstream "<ns>:<cmd>" [flags]
       agentguard-mcp-gateway --upstream-http "<ns>:<url>" [flags]

agentguard-mcp-gateway is a stdio JSON-RPC bridge spawned by an MCP
client (Claude Desktop, Cursor, IDE plugins): it sits between the host
and one or more downstream MCP servers and gates every tools/call
through a central AgentGuard server's /v1/check endpoint. stdin/stdout
carry JSON-RPC frames; all logging goes to stderr.

Example (as the "command" in an MCP client configuration):
  agentguard-mcp-gateway \
      --upstream "fs:npx -y @modelcontextprotocol/server-filesystem /tmp" \
      --guard-url http://127.0.0.1:8080 \
      --policy /etc/agentguard/policy.yaml

Quote each --upstream command: an unquoted one is split into separate
arguments, and the gateway refuses to start.

Example (a remote server over Streamable HTTP, token from the environment):
  agentguard-mcp-gateway \
      --upstream-http "docs:https://mcp.example.com/mcp" \
      --upstream-header 'docs:Authorization=Bearer ${DOCS_TOKEN}' \
      --policy /etc/agentguard/policy.yaml

`)
		clihelp.WriteGroups(errOut, fs, gatewayFlagGroups, clihelp.Options{})
		fmt.Fprint(errOut, `
Other:
  --version  Print the version and exit (checked before any other flag)

Environment:
  AGENTGUARD_URL       Used when --guard-url is not set.
  AGENTGUARD_API_KEY   Used when --api-key is not set.
`)
	}

	var upstreams, httpUpstreams, upstreamHeaders stringSliceFlag
	fs.Var(&upstreams, "upstream", "MCP server to start and guard, as `\"<ns>:<cmd>\"` (or just the command; ns then defaults to its first word). Repeat for more servers.")
	fs.Var(&httpUpstreams, "upstream-http", "Remote MCP server to guard over Streamable HTTP, as `\"<ns>:<url>\"`. The URL must be https, or http to localhost. Repeat for more servers.")
	fs.Var(&upstreamHeaders, "upstream-header", "Extra HTTP header for an --upstream-http server, as `\"<ns>:<Name>=<Value>\"`. ${VAR} in the value is read from the environment, so tokens stay out of client config files. Repeat for more headers.")
	gate := gateclient.RegisterGateFlags(fs,
		"Path to the same policy YAML the central AgentGuard server loads (required for --policy-mode strict; used to resolve tool_scope_map locally)")
	policyMode := fs.String("policy-mode", "strict", "strict: check the tool, then the scope --policy maps it to (dual check). fast: check the tool only; --policy is then optional.")
	upstreamTimeout := fs.Duration("upstream-timeout", 30*time.Second, "How long to wait for an MCP server's reply to one message")
	reconnectCap := fs.Duration("reconnect-cap", 60*time.Second, "Longest wait between attempts to restart an MCP server that exited, or to reach an --upstream-http server again. The waits grow 1s, 2s, 5s, 30s, 60s, stopping at this.")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if err := gateclient.RejectArgs(fs.Args(), `put each --upstream command in quotes, e.g. --upstream "fs:npx -y @modelcontextprotocol/server-filesystem /tmp"`); err != nil {
		return nil, err
	}

	if len(upstreams) == 0 && len(httpUpstreams) == 0 {
		return nil, errors.New("at least one --upstream or --upstream-http is required")
	}

	// Env fallback + shared invariants (guard-url, tenant, fail-mode,
	// log-level) — one contract with the LLM proxy.
	if err := gate.Resolve(); err != nil {
		return nil, err
	}

	cfg := &Config{
		GuardURL:                  *gate.GuardURL,
		APIKey:                    *gate.APIKey,
		TenantID:                  *gate.TenantID,
		FailMode:                  *gate.FailMode,
		FailAuditLog:              *gate.FailAuditLog,
		PolicyMode:                *policyMode,
		LogLevel:                  *gate.LogLevel,
		UpstreamTimeout:           *upstreamTimeout,
		ReconnectCap:              *reconnectCap,
		PolicyPath:                *gate.PolicyPath,
		SupportedProtocolVersions: append([]string{}, DefaultSupportedProtocolVersions...),
	}

	switch cfg.PolicyMode {
	case "strict", "fast":
	default:
		return nil, fmt.Errorf("--policy-mode must be strict|fast, got %q", cfg.PolicyMode)
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
	httpSpecs, err := parseHTTPUpstreamSpecs(httpUpstreams)
	if err != nil {
		return nil, err
	}
	// One namespace space across both transports: tools/call routes on
	// the namespace alone.
	seen := map[string]struct{}{}
	for _, s := range parsedSpecs {
		seen[s.Namespace] = struct{}{}
	}
	for _, s := range httpSpecs {
		if _, dup := seen[s.Namespace]; dup {
			return nil, fmt.Errorf("namespace %q is used by both --upstream and --upstream-http; give each server its own namespace", s.Namespace)
		}
	}
	cfg.Upstreams = append(parsedSpecs, httpSpecs...)

	headers, err := parseUpstreamHeaders(upstreamHeaders, cfg.Upstreams, os.LookupEnv)
	if err != nil {
		return nil, err
	}
	cfg.UpstreamHeaders = headers

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
			Transport: TransportStdio,
		})
	}

	return specs, nil
}

// parseHTTPUpstreamSpecs converts the raw --upstream-http values
// ("<ns>:<url>") into UpstreamSpec values. Unlike --upstream, the
// namespace is required: a bare URL would otherwise yield "https" as
// its namespace.
func parseHTTPUpstreamSpecs(raw []string) ([]UpstreamSpec, error) {
	specs := make([]UpstreamSpec, 0, len(raw))
	seen := map[string]struct{}{}
	for _, entry := range raw {
		entry = strings.TrimSpace(entry)
		idx := strings.IndexByte(entry, ':')
		if idx < 0 || strings.HasPrefix(entry[idx+1:], "//") {
			return nil, fmt.Errorf("--upstream-http %q needs a namespace, as \"<ns>:<url>\" (e.g. \"docs:https://mcp.example.com/mcp\")", entry)
		}
		ns := strings.TrimSpace(entry[:idx])
		rawURL := strings.TrimSpace(entry[idx+1:])
		if ns == "" {
			return nil, fmt.Errorf("--upstream-http %q has an empty namespace before the colon", entry)
		}
		if strings.ContainsAny(ns, ": \t") {
			return nil, fmt.Errorf("--upstream-http namespace %q must not contain colon or whitespace", ns)
		}
		if _, dup := seen[ns]; dup {
			return nil, fmt.Errorf("--upstream-http namespace %q declared more than once", ns)
		}
		seen[ns] = struct{}{}
		if err := validateUpstreamURL(rawURL); err != nil {
			return nil, fmt.Errorf("--upstream-http %q: %w", ns, err)
		}
		specs = append(specs, UpstreamSpec{
			Namespace: ns,
			Transport: TransportHTTP,
			URL:       rawURL,
		})
	}
	return specs, nil
}

// validateUpstreamURL accepts https URLs, and plain http only to a
// loopback host: tool arguments, results and any --upstream-header
// token must not cross a network in clear text.
func validateUpstreamURL(raw string) error {
	if raw == "" {
		return errors.New("URL is empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("URL does not parse: %w", err)
	}
	if u.Host == "" {
		return fmt.Errorf("URL %q has no host; use the full MCP endpoint, e.g. https://mcp.example.com/mcp", raw)
	}
	if u.User != nil {
		// Credentials in the URL would end up in error messages and
		// logs. --upstream-header keeps them out of both.
		return errors.New("URL must not contain credentials; send them with --upstream-header instead")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("URL %q uses plain http to a non-local host; use https (http is allowed only for localhost, 127.0.0.1 and [::1])", raw)
	default:
		return fmt.Errorf("URL %q must start with https:// (or http:// for localhost)", raw)
	}
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.Equal(net.IPv4(127, 0, 0, 1)) || ip.Equal(net.IPv6loopback))
}

// managedHTTPHeaders are set by the gateway itself on every request to
// an HTTP upstream; an --upstream-header for one of them would corrupt
// the transport (or, for Host, be silently ignored by net/http).
var managedHTTPHeaders = map[string]struct{}{
	"Accept":               {},
	"Content-Type":         {},
	"Content-Length":       {},
	"Host":                 {},
	"Mcp-Session-Id":       {},
	"Mcp-Protocol-Version": {},
	"Last-Event-Id":        {},
}

// envRef matches one ${NAME} reference in an --upstream-header value.
var envRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// parseUpstreamHeaders converts the raw --upstream-header values
// ("<ns>:<Name>=<Value>") into per-namespace headers, expanding
// ${ENV_VAR} references through lookup. Error messages name the
// header and the variable, never the value: it may be a token.
func parseUpstreamHeaders(raw []string, specs []UpstreamSpec, lookup func(string) (string, bool)) (map[string]http.Header, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	transport := map[string]string{}
	for _, s := range specs {
		transport[s.Namespace] = s.Transport
	}
	out := map[string]http.Header{}
	for _, entry := range raw {
		idx := strings.IndexByte(entry, ':')
		if idx < 0 {
			return nil, errors.New(`--upstream-header must be "<ns>:<Name>=<Value>", e.g. "docs:Authorization=Bearer ${DOCS_TOKEN}"`)
		}
		ns := strings.TrimSpace(entry[:idx])
		rest := entry[idx+1:]
		switch t, ok := transport[ns]; {
		case !ok:
			return nil, fmt.Errorf("--upstream-header for namespace %q, but no --upstream-http declares it", ns)
		case t != TransportHTTP:
			return nil, fmt.Errorf("--upstream-header for namespace %q, but %q is a stdio --upstream; headers apply to --upstream-http servers only", ns, ns)
		}
		eq := strings.IndexByte(rest, '=')
		if eq < 0 {
			return nil, fmt.Errorf(`--upstream-header for %q must be "<ns>:<Name>=<Value>"`, ns)
		}
		name := strings.TrimSpace(rest[:eq])
		if !validHeaderName(name) {
			return nil, fmt.Errorf("--upstream-header for %q: %q is not a valid HTTP header name", ns, name)
		}
		canon := http.CanonicalHeaderKey(name)
		if _, managed := managedHTTPHeaders[canon]; managed {
			return nil, fmt.Errorf("--upstream-header for %q: the gateway sets %s itself; remove it", ns, canon)
		}
		value, err := expandEnvRefs(rest[eq+1:], lookup)
		if err != nil {
			return nil, fmt.Errorf("--upstream-header %s for %q: %w", canon, ns, err)
		}
		if strings.ContainsAny(value, "\r\n\x00") {
			return nil, fmt.Errorf("--upstream-header %s for %q: the value contains a line break or NUL byte", canon, ns)
		}
		if out[ns] == nil {
			out[ns] = http.Header{}
		}
		out[ns].Add(canon, value)
	}
	return out, nil
}

// expandEnvRefs replaces every ${NAME} in v with the variable's value.
// Only the braced form is expanded, so a literal "$" in a token is
// left alone. An unset variable is an error rather than an empty
// string: a header like "Bearer " would fail later, far from the cause.
func expandEnvRefs(v string, lookup func(string) (string, bool)) (string, error) {
	// Check the input, not the output: an expanded value may itself
	// legitimately contain "${".
	if strings.Contains(envRef.ReplaceAllString(v, ""), "${") {
		return "", errors.New("malformed ${...} reference; use ${NAME} with letters, digits and _")
	}
	var missing string
	out := envRef.ReplaceAllStringFunc(v, func(ref string) string {
		name := ref[2 : len(ref)-1]
		val, ok := lookup(name)
		if !ok && missing == "" {
			missing = name
		}
		return val
	})
	if missing != "" {
		return "", fmt.Errorf("environment variable %s is not set", missing)
	}
	return out, nil
}

// validHeaderName reports whether name is an RFC 9110 token.
func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
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
