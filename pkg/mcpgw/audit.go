// Package mcpgw — gateway-level audit + SSE wiring stubs.
//
// This file is the documented-but-deferred home of the gateway-level
// audit and SSE wiring. v0.5 ships the bridge's `AuditEmit` and
// `SSEEmit` hooks (see bridge.go) but leaves them nil-by-default.
//
// Why deferred: the v0.5 value proposition for the MCP Gateway is
// wire-level enforcement of tool calls. Every `tools/call` already
// produces a tool-call-level audit entry + SSE event via the central
// server's `/v1/check` flow (the gate stamps `meta["transport"] =
// "mcp_gateway"`, A19's transport tag plumbs it to disk and the SSE
// bus). That covers the operator-visible behaviour the dashboard
// needs.
//
// The remaining gap — gateway-level events that AREN'T tool calls
// (upstream subprocess crashed, malformed JSON-RPC frame from host,
// gateway startup failure) — is a SEPARATE operator-monitoring
// concern. Implementing it cleanly needs a new central-server
// endpoint (see options below) and that's a v0.6 surface-area
// decision, not a v0.5 ship-blocker.
//
// Three options were considered for v0.5:
//
//	(a) New endpoint /v1/audit/append on the central server that
//	    accepts a pre-built audit.Entry. Auth-gated. Bumps API
//	    surface area; needs a separate rate-limit posture; arguably
//	    a "write port" the dashboard token shouldn't carry.
//
//	(b) Gateway POSTs a synthetic /v1/check with scope:
//	    "mcp_gateway:event" and meta.event_type set. Reuses
//	    existing audit infrastructure. Adds a synthetic policy
//	    decision (always ALLOW) that's noisy in /metrics —
//	    operator alerting on agentguard_denied_total would silently
//	    sample over real denies + gateway events.
//
//	(c) Defer to v0.6.
//
// Decision: (c). Rationale captured in
// .audit/v05_decisions.md ("MCP gateway-level audit emission").
//
// What v0.5 ships in this file: nothing functional. Defining the
// types here would imply a stable API the v0.6 endpoint must conform
// to; better to design endpoint + wiring together when we know what
// shape operators need (e.g. is "upstream crashed" a deny-class
// alerting signal or a separate gauge?).
//
// What an operator sees today for gateway-level health:
//   - The central server's /v1/health returns warnings populated by
//     the existing traffic / policy-load probes (see Phase 2 A10).
//   - The gateway's stderr log carries upstream-crash / fail-mode
//     decisions; operators with a log aggregator can alert on those.
//   - /v1/audit + the dashboard show every tool-call-level event,
//     including synthetic deny:gateway:fail_closed entries when the
//     gate falls back due to /v1/check unreachable.
//
// TODO(v0.6, #mcp-gateway-events): operator-grade gateway-level
// audit endpoint. Owner: orchestrator-decided; current best guess
// is a small `/v1/operator/event` endpoint scoped to
// `notify`-class events (degraded upstream, frame error,
// startup failure) with its own retention + auth posture
// distinct from the policy-decision audit log.
package mcpgw
