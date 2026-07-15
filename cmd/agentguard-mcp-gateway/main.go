// Command agentguard-mcp-gateway is the AgentGuard MCP Gateway: a
// stdio JSON-RPC bridge that sits between an MCP host (Claude
// Desktop, Cursor, IDE plugins) and one or more downstream MCP
// servers, gating every tools/call through the AgentGuard policy
// engine.
//
// Usage:
//
//	agentguard-mcp-gateway \
//	    --upstream "fs:npx -y @modelcontextprotocol/server-filesystem /tmp" \
//	    --upstream "github:npx -y @modelcontextprotocol/server-github" \
//	    --guard-url http://127.0.0.1:8080 \
//	    --api-key $AGENTGUARD_API_KEY \
//	    --tenant-id local \
//	    --fail-mode deny \
//	    --policy-mode strict \
//	    --log-level info
//
// stdin/stdout are reserved for newline-delimited JSON-RPC. All
// logging goes to stderr — the MCP spec explicitly permits this.
//
// The host (Claude Desktop, Cursor, etc.) spawns this binary as a
// subprocess via its `command` configuration; the gateway in turn
// spawns the downstream MCP servers listed in --upstream.
//
// See docs/MCP_GATEWAY.md for the wire-format design and
// docs/PROXY_ARCHITECTURE.md for cross-cutting decisions.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Caua-ferraz/AgentGuard/pkg/mcpgw"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// Versions are injected at link time via -ldflags. Defaults are used
// for `go run ./cmd/agentguard-mcp-gateway` and `go test`.
var (
	version = "0.9.0"
	commit  = "dev"
)

func main() {
	args := os.Args[1:]

	// `--version` short-circuit; checked before parsing other flags so
	// it works without --upstream.
	for _, a := range args {
		if a == "--version" || a == "-version" {
			fmt.Printf("agentguard-mcp-gateway %s (%s)\n", version, commit)
			return
		}
	}

	cfg, err := mcpgw.ParseConfig(args)
	if err != nil {
		// flag.ContinueOnError already wrote usage on parse errors;
		// for our own validation errors we add a one-line summary.
		if !errors.Is(err, errFlagAlreadyHandled) {
			fmt.Fprintf(os.Stderr, "agentguard-mcp-gateway: %v\n", err)
		}
		os.Exit(2)
	}

	// Plumb the build version into the package var so the bridge
	// advertises it on initialize.
	mcpgw.GatewayBuildVersion = version

	// Signal handling for graceful shutdown. The bridge cancels
	// in-flight upstream subprocesses when ctx is done.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintln(os.Stderr, "agentguard-mcp-gateway: signal received, shutting down")
		cancel()
	}()

	// Wire the bridge's PolicyCheck hook against the central server's
	// /v1/check via mcpgw.HTTPPolicyClient (A18). The gate also reads
	// the local policy file (the same YAML the central server loads)
	// for the dual-check tool_scope_map.
	//
	// In --policy-mode fast --policy may be empty; the gate then
	// skips the second Engine.Check and the central server's mcp_tool
	// decision is authoritative.
	bridge := mcpgw.NewBridge(cfg, os.Stderr, version)

	var stopWatch func()
	if cfg.PolicyPath != "" {
		provider, err := policy.NewFilePolicyProvider(cfg.PolicyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "agentguard-mcp-gateway: policy load: %v\n", err)
			os.Exit(1)
		}
		defer provider.Close()

		pol, err := provider.Get(cfg.TenantID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "agentguard-mcp-gateway: policy get for tenant %q: %v\n", cfg.TenantID, err)
			os.Exit(1)
		}

		gate := mcpgw.NewHTTPPolicyClient(cfg, pol)
		bridge.PolicyCheck = gate.Check

		// Hot-reload: when the operator edits the YAML, the gate's
		// cached snapshot is replaced atomically so subsequent
		// dual-check resolutions see the new tool_scope_map without
		// restarting the gateway.
		stop, err := provider.Watch(cfg.TenantID, func(newPol *policy.Policy) {
			gate.SetPolicy(newPol)
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "agentguard-mcp-gateway: policy watch: %v\n", err)
			os.Exit(1)
		}
		stopWatch = stop
	} else {
		// Fast-mode without --policy: the gate has no local policy to
		// resolve tool_scope_map against, but cfg.PolicyMode == "fast"
		// means the gateway never asks. The gate still calls
		// /v1/check for the mcp_tool scope.
		gate := mcpgw.NewHTTPPolicyClient(cfg, nil)
		bridge.PolicyCheck = gate.Check
	}
	if stopWatch != nil {
		defer stopWatch()
	}

	// Tool-call-level audit + SSE for MCP traffic flow through the
	// central server's /v1/check path: the gate stamps
	// meta["transport"] = "mcp_gateway" on every check, A19's
	// transport-tag plumbing in pkg/proxy + pkg/audit lands the entry
	// on disk and on the SSE bus with the right chip. So the bridge's
	// per-tool-call AuditEmit / SSEEmit hooks (defined in
	// pkg/mcpgw/bridge.go) intentionally stay nil — wiring them here
	// would double-audit every check.
	//
	// Gateway-LEVEL events (upstream subprocess crash, malformed
	// JSON-RPC frame from host, gateway startup failure) are a
	// separate operator-monitoring concern. They ship to stderr logs
	// today; an /v1/operator/event endpoint to surface them in the
	// dashboard is future work. See pkg/mcpgw/audit.go for the full
	// rationale and TODO(v0.7, #mcp-gateway-events).

	if err := bridge.Run(ctx, os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "agentguard-mcp-gateway: %v\n", err)
		os.Exit(1)
	}
}

// errFlagAlreadyHandled is a sentinel for flag-parse errors that the
// flag package has already written usage text for. Currently unused
// (flag.ContinueOnError returns its own errors that we just print);
// kept so future error-path refinements can plug in here.
var errFlagAlreadyHandled = errors.New("flag-parse error already reported")
