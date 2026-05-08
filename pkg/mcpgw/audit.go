// Package mcpgw — gateway-level audit + SSE wiring stubs.
//
// This file is the documented-but-deferred home of gateway-level audit
// and SSE wiring. The bridge's `AuditEmit` and `SSEEmit` hooks (see
// bridge.go) are nil by default.
//
// Why: every `tools/call` already produces a tool-call-level audit
// entry + SSE event via the central server's `/v1/check` flow (the
// gate stamps `meta["transport"] = "mcp_gateway"` and the transport-
// tag plumbing in pkg/audit lands it on disk and on the SSE bus). That
// covers the operator-visible behaviour the dashboard needs.
//
// The remaining gap — gateway-level events that AREN'T tool calls
// (upstream subprocess crashed, malformed JSON-RPC frame from host,
// gateway startup failure) — is a separate operator-monitoring concern
// that needs a new central-server endpoint (see options below). Defining
// types here would imply a stable API the future endpoint must conform
// to; better to design endpoint + wiring together when the desired
// operator UX is clearer.
//
// What an operator sees today for gateway-level health:
//   - The central server's /v1/health returns warnings populated by
//     traffic / policy-load probes.
//   - The gateway's stderr log carries upstream-crash / fail-mode
//     decisions; operators with a log aggregator can alert on those.
//   - /v1/audit + the dashboard show every tool-call-level event,
//     including synthetic deny:gateway:fail_closed entries when the
//     gate falls back due to /v1/check unreachable.
//
// TODO(v0.6, #mcp-gateway-events): operator-grade gateway-level audit
// endpoint. Current best guess is a small `/v1/operator/event` endpoint
// scoped to notify-class events (degraded upstream, frame error,
// startup failure) with its own retention + auth posture distinct from
// the policy-decision audit log.
package mcpgw
