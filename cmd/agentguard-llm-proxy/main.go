// Command agentguard-llm-proxy is the AgentGuard LLM API Proxy: an
// HTTP server that speaks the OpenAI Chat Completions and Anthropic
// Messages wire formats, forwards traffic to the real upstream, and
// gates any tool calls the model emits through the central
// AgentGuard policy engine.
//
// Usage:
//
//	agentguard-llm-proxy \
//	    --listen 127.0.0.1:8081 \
//	    --upstream-openai https://api.openai.com \
//	    --upstream-anthropic https://api.anthropic.com \
//	    --guard-url http://127.0.0.1:8080 \
//	    --api-key $AGENTGUARD_API_KEY \
//	    --proxy-api-key $PROXY_AUTH_TOKEN \
//	    --policy /etc/agentguard/policy.yaml \
//	    --tenant-id local \
//	    --fail-mode deny \
//	    --max-buffer-bytes 1048576 \
//	    --log-level info
//
// Set the agent's environment to point its OpenAI-compatible SDK at
// the proxy. Note the asymmetric `/v1` convention between providers:
//
//	OPENAI_BASE_URL=http://127.0.0.1:8081/v1
//	ANTHROPIC_BASE_URL=http://127.0.0.1:8081
//
// The OpenAI SDK appends paths under OPENAI_BASE_URL including the
// `/v1` segment that the proxy registers (POST /v1/chat/completions),
// so the env var must include `/v1`. The Anthropic SDK convention is
// the opposite — ANTHROPIC_BASE_URL is the *origin* and the SDK
// appends `/v1/messages` itself, so the env var must NOT include a
// `/v1` suffix.
//
// See docs/LLM_API_PROXY.md for the wire-format design and
// docs/PROXY_ARCHITECTURE.md for cross-cutting decisions.
//
// Phase 4C is split across four workers:
//
//   - A21: server skeleton + non-streaming forwarding + protocol types.
//   - A22: streaming pause/resume/rewrite + tool-call accumulators.
//   - A23: tool-call → policy-scope mapping (defaults + YAML override).
//   - A24 (this build): policy gate (HTTPPolicyClient against /v1/check),
//     rich provider-aware refusal builder, and the final main.go
//     wiring that binds all three hooks (PolicyCheck, ScopeMap,
//     BuildRefusal) to the server.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Caua-ferraz/AgentGuard/pkg/llmproxy"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// Versions injected at link time via -ldflags. Defaults are used
// for `go run ./cmd/agentguard-llm-proxy` and `go test`.
var (
	version = "0.5.0"
	commit  = "dev"
)

func main() {
	args := os.Args[1:]

	// `--version` short-circuit; checked before parsing other flags
	// so it works without any other config (mirrors mcp-gateway).
	for _, a := range args {
		if a == "--version" || a == "-version" {
			fmt.Printf("agentguard-llm-proxy %s (%s)\n", version, commit)
			return
		}
	}

	cfg, err := llmproxy.ParseConfig(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentguard-llm-proxy: %v\n", err)
		os.Exit(2)
	}

	// Plumb the build version into the package var so /healthz and
	// the upstream User-Agent advertise it.
	llmproxy.BuildVersion = version

	// Surface the no-API-key fallback explicitly. Mirrors central
	// server's WARN-on-no-api-key behaviour. The /v1/check side
	// channel still works without --api-key when the central server
	// itself runs without auth (single-host loopback dev mode), but
	// production deployments should set both.
	if cfg.APIKey == "" {
		fmt.Fprintln(os.Stderr, "agentguard-llm-proxy: WARNING --api-key not set; /v1/check calls will be unauthenticated")
	}
	if cfg.ProxyAPIKey == "" {
		fmt.Fprintf(os.Stderr, "agentguard-llm-proxy: WARNING --proxy-api-key not set; %s header will not be enforced\n", llmproxy.ProxyAuthHeader)
	}

	// Build the server skeleton (A21). The hooks below wire A22 (via
	// the server's built-in streaming runner) and A23/A24 (gate +
	// scope map + refusal).
	server, err := llmproxy.NewServer(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentguard-llm-proxy: %v\n", err)
		os.Exit(1)
	}

	// Load policy via the same provider abstraction the central server
	// uses. The proxy reads the same policy YAML the central server
	// loads — typically operators run them on the same host with a
	// shared file path; cross-host deployments mount the file from a
	// shared volume (or replicate it out-of-band) so the proxy and the
	// central server stay in lockstep.
	//
	// --policy is OPTIONAL: when absent, the gate falls back to the
	// bundled DefaultLLMToolScopeMap with no operator overrides. The
	// /v1/check endpoint still gates every detected tool_call (the
	// central server's scope rules are authoritative); only the local
	// scope-mapping table degrades.
	var (
		gate      *llmproxy.HTTPPolicyClient
		stopWatch func()
	)
	if cfg.PolicyPath != "" {
		provider, perr := policy.NewFilePolicyProvider(cfg.PolicyPath)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "agentguard-llm-proxy: policy load: %v\n", perr)
			os.Exit(1)
		}
		defer provider.Close()

		pol, perr := provider.Get(cfg.TenantID)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "agentguard-llm-proxy: policy get for tenant %q: %v\n", cfg.TenantID, perr)
			os.Exit(1)
		}

		gate = llmproxy.NewHTTPPolicyClient(cfg, pol)

		// Hot-reload: when the operator edits the YAML, the gate's
		// cached snapshot is replaced atomically so subsequent /v1/check
		// calls see the new tool_scope_map without restarting the
		// proxy. Mirrors agentguard-mcp-gateway's pattern.
		stop, werr := provider.Watch(cfg.TenantID, gate.SetPolicy)
		if werr != nil {
			fmt.Fprintf(os.Stderr, "agentguard-llm-proxy: policy watch: %v\n", werr)
			os.Exit(1)
		}
		stopWatch = stop
	} else {
		fmt.Fprintln(os.Stderr, "agentguard-llm-proxy: WARNING --policy not set; tool→scope mapping will use bundled defaults only (no operator overrides)")
		gate = llmproxy.NewHTTPPolicyClient(cfg, nil)
	}
	if stopWatch != nil {
		defer stopWatch()
	}

	// Bind the three hooks. The server is otherwise immutable post-
	// construction so this must happen before Run.
	server.PolicyCheck = gate.Check
	server.ScopeMap = gate.MapScope
	server.BuildRefusal = llmproxy.BuildRefusalRich

	// Tool-call-level audit + SSE flow through the central server's
	// /v1/check path: the gate stamps meta["transport"] = "llm_api_proxy"
	// on every check; Phase 4B A19's transport-tag plumbing in
	// pkg/proxy + pkg/audit lands the entry on disk and on the SSE bus
	// with the right chip. So no additional audit emission lives in
	// the proxy itself — single source of truth.

	// Signal handling for graceful shutdown. The server cancels
	// in-flight upstream calls when ctx is done.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintln(os.Stderr, "agentguard-llm-proxy: signal received, shutting down")
		cancel()
	}()

	fmt.Fprintf(os.Stderr, "agentguard-llm-proxy %s listening on %s (upstream-openai=%s upstream-anthropic=%s guard=%s)\n",
		version, cfg.Listen, cfg.UpstreamOpenAI, cfg.UpstreamAnthropic, cfg.GuardURL)

	if err := server.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "agentguard-llm-proxy: %v\n", err)
		os.Exit(1)
	}
}
