// Package mcpgw implements the AgentGuard MCP Gateway: a stdio JSON-RPC
// bridge that sits between an MCP host (Claude Desktop, Cursor, IDE
// plugins) and one or more downstream MCP servers, gating every
// tools/call through the AgentGuard policy engine.
//
// This file owns the wire-format types: JSON-RPC 2.0 envelopes, the
// MCP-specific request/result shapes for the methods the gateway
// dispatches (initialize, tools/list, tools/call, ping, notifications),
// and the protocol-version negotiation helper.
//
// The types are intentionally minimal — only the fields the gateway
// actually inspects are typed. Everything else is preserved as
// json.RawMessage so the gateway can forward upstream payloads
// (descriptions, input schemas, content blocks) verbatim without
// shape-coupling to every downstream MCP server's quirks.
package mcpgw

import (
	"encoding/json"
	"fmt"
)

// JSONRPCVersion is the only JSON-RPC version the gateway speaks.
// Every Request/Response/Notification must carry this exact string.
const JSONRPCVersion = "2.0"

// MCP method names the gateway routes. Anything not in this set is
// returned as method-not-found except notifications, which are
// broadcast to all upstreams (best-effort, fire-and-forget).
const (
	MethodInitialize        = "initialize"
	MethodToolsList         = "tools/list"
	MethodToolsCall         = "tools/call"
	MethodPing              = "ping"
	MethodLoggingSetLevel   = "logging/setLevel"
	NotificationInitialized = "notifications/initialized"
	NotificationCancelled   = "notifications/cancelled"
)

// JSON-RPC 2.0 reserved error codes (per the spec).
const (
	ErrCodeParseError     = -32700
	ErrCodeInvalidRequest = -32600
	ErrCodeMethodNotFound = -32601
	ErrCodeInvalidParams  = -32602
	ErrCodeInternalError  = -32603
)

// AgentGuard server-defined error codes. JSON-RPC 2.0 reserves
// -32000..-32099 for server-defined errors. Per docs/MCP_GATEWAY.md
// § 11, denial and approval-required are surfaced as tool execution
// errors (`isError: true`) at the application layer, not as JSON-RPC
// protocol errors. These codes still exist for transport-level
// failures (upstream unavailable) and as a typed alternative the
// bridge can fall back to when a tool call cannot even reach the
// upstream.
const (
	// ErrCodeUpstreamUnavail is returned when the namespace's upstream
	// is degraded (subprocess crashed, awaiting reconnect).
	ErrCodeUpstreamUnavail = -32002

	// ErrCodePolicyDeny / ErrCodePolicyApproval are reserved for the
	// JSON-RPC error path. The bridge prefers the tool-error path
	// (isError: true content block) for the actual deny/approval
	// responses; these codes exist so error.data is well-typed when
	// the bridge does need to surface a deny at the JSON-RPC layer
	// (e.g., a malformed tools/call that policy refuses before any
	// upstream sees it).
	ErrCodePolicyDeny     = -32000
	ErrCodePolicyApproval = -32001
)

// RequestID is the JSON-RPC id field. Per the spec it MAY be a string,
// integer, or null. We carry it as an opaque interface{} so we can
// echo back exactly what the client sent without coercing types.
//
// Note: notifications (no `id` field at all) are represented by the
// Notification struct, not by Request{ID: nil}.
type RequestID = interface{}

// Request is a JSON-RPC 2.0 request envelope.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      RequestID       `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Response is a JSON-RPC 2.0 response envelope. Exactly one of
// Result or Error must be set; both are optional in JSON encoding so
// callers control which path is taken.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      RequestID       `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// Error is the error object inside a JSON-RPC response.
type Error struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// Notification is a JSON-RPC 2.0 notification (no id, no response
// expected). The MCP spec uses notifications for `initialized`,
// `cancelled`, log emissions, list-changed signals, etc.
type Notification struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// NewResponseResult builds a successful response with the given result
// payload pre-marshalled into json.RawMessage. Callers that want to
// pass a typed Go struct should use NewResponseFrom.
func NewResponseResult(id RequestID, result json.RawMessage) *Response {
	return &Response{JSONRPC: JSONRPCVersion, ID: id, Result: result}
}

// NewResponseFrom marshals the given Go value as the response result.
// Returns an error response if marshalling fails (which would indicate
// a programmer bug — every result we emit is composed of stdlib types
// and json.RawMessage forwarded from upstreams, so json.Marshal cannot
// fail in practice).
func NewResponseFrom(id RequestID, result interface{}) *Response {
	raw, err := json.Marshal(result)
	if err != nil {
		return NewResponseError(id, ErrCodeInternalError,
			fmt.Sprintf("internal: failed to marshal result: %v", err), nil)
	}
	return &Response{JSONRPC: JSONRPCVersion, ID: id, Result: raw}
}

// NewResponseError builds an error response.
func NewResponseError(id RequestID, code int, message string, data json.RawMessage) *Response {
	return &Response{
		JSONRPC: JSONRPCVersion,
		ID:      id,
		Error: &Error{
			Code:    code,
			Message: message,
			Data:    data,
		},
	}
}

// -- MCP-specific shapes for the methods the gateway dispatches --

// InitializeParams is the params object on `initialize`.
type InitializeParams struct {
	ProtocolVersion string                 `json:"protocolVersion"`
	Capabilities    map[string]interface{} `json:"capabilities,omitempty"`
	ClientInfo      ClientInfo             `json:"clientInfo"`
}

// ClientInfo identifies the MCP host (Claude Desktop, Cursor, etc.).
type ClientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// InitializeResult is the result object on `initialize`.
type InitializeResult struct {
	ProtocolVersion string                 `json:"protocolVersion"`
	Capabilities    map[string]interface{} `json:"capabilities"`
	ServerInfo      ServerInfo             `json:"serverInfo"`
}

// ServerInfo identifies the gateway (or, when received from an
// upstream, that upstream). The gateway's own ServerInfo.Name is
// always "agentguard-mcp-gateway" — we do not impersonate downstreams.
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ToolDescriptor is one entry in `tools/list` result.tools. Fields
// outside Name/Description/InputSchema are passed through verbatim
// inside Extra so we don't shape-couple to downstream MCP server
// quirks (e.g., experimental schema annotations).
type ToolDescriptor struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	InputSchema map[string]interface{} `json:"inputSchema,omitempty"`

	// Annotations / outputSchema / future fields are preserved so the
	// gateway forwards the descriptor verbatim. We marshal/unmarshal
	// through a custom helper to keep this clean — see toolDescriptorFromRaw.
	Extra map[string]json.RawMessage `json:"-"`
}

// MarshalJSON re-merges Extra into the wire output. We can't use the
// default struct encoding because Extra needs to be inlined.
func (t ToolDescriptor) MarshalJSON() ([]byte, error) {
	out := map[string]json.RawMessage{}
	for k, v := range t.Extra {
		out[k] = v
	}
	nameJSON, err := json.Marshal(t.Name)
	if err != nil {
		return nil, err
	}
	out["name"] = nameJSON
	if t.Description != "" {
		descJSON, err := json.Marshal(t.Description)
		if err != nil {
			return nil, err
		}
		out["description"] = descJSON
	}
	if t.InputSchema != nil {
		schemaJSON, err := json.Marshal(t.InputSchema)
		if err != nil {
			return nil, err
		}
		out["inputSchema"] = schemaJSON
	}
	return json.Marshal(out)
}

// UnmarshalJSON inverts MarshalJSON. Stashes unknown keys in Extra so
// they round-trip when we re-emit the descriptor with a prefixed Name.
func (t *ToolDescriptor) UnmarshalJSON(data []byte) error {
	raw := map[string]json.RawMessage{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	t.Extra = map[string]json.RawMessage{}
	for k, v := range raw {
		switch k {
		case "name":
			if err := json.Unmarshal(v, &t.Name); err != nil {
				return fmt.Errorf("tool descriptor: name: %w", err)
			}
		case "description":
			if err := json.Unmarshal(v, &t.Description); err != nil {
				return fmt.Errorf("tool descriptor: description: %w", err)
			}
		case "inputSchema":
			if err := json.Unmarshal(v, &t.InputSchema); err != nil {
				return fmt.Errorf("tool descriptor: inputSchema: %w", err)
			}
		default:
			t.Extra[k] = v
		}
	}
	return nil
}

// ToolsListResult is the `result` of a tools/list response.
type ToolsListResult struct {
	Tools      []ToolDescriptor       `json:"tools"`
	NextCursor string                 `json:"nextCursor,omitempty"`
	Meta       map[string]interface{} `json:"_meta,omitempty"`
}

// ToolsCallParams is the params object on `tools/call`.
type ToolsCallParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
	Meta      map[string]interface{} `json:"_meta,omitempty"`
}

// ToolsCallResult is the result object on `tools/call`. Per the MCP
// spec, tool execution errors are reported with isError=true and a
// content block describing the failure (NOT a JSON-RPC error). The
// gateway uses this shape for policy denials and approval-required
// responses.
type ToolsCallResult struct {
	Content []ContentBlock `json:"content"`
	IsError bool           `json:"isError,omitempty"`
}

// ContentBlock is one entry in tools/call result.content. The MCP
// spec defines text/image/resource block types; the gateway only
// constructs text blocks itself (for policy refusals) but forwards
// arbitrary upstream blocks verbatim via Extra.
type ContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`

	// Extra carries image/resource fields, annotations, etc., so a
	// content block from an upstream round-trips losslessly.
	Extra map[string]json.RawMessage `json:"-"`
}

// MarshalJSON / UnmarshalJSON keep Extra inlined on the wire.
func (c ContentBlock) MarshalJSON() ([]byte, error) {
	out := map[string]json.RawMessage{}
	for k, v := range c.Extra {
		out[k] = v
	}
	typeJSON, err := json.Marshal(c.Type)
	if err != nil {
		return nil, err
	}
	out["type"] = typeJSON
	if c.Text != "" {
		textJSON, err := json.Marshal(c.Text)
		if err != nil {
			return nil, err
		}
		out["text"] = textJSON
	}
	return json.Marshal(out)
}

// UnmarshalJSON inverts MarshalJSON.
func (c *ContentBlock) UnmarshalJSON(data []byte) error {
	raw := map[string]json.RawMessage{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	c.Extra = map[string]json.RawMessage{}
	for k, v := range raw {
		switch k {
		case "type":
			if err := json.Unmarshal(v, &c.Type); err != nil {
				return fmt.Errorf("content block: type: %w", err)
			}
		case "text":
			if err := json.Unmarshal(v, &c.Text); err != nil {
				return fmt.Errorf("content block: text: %w", err)
			}
		default:
			c.Extra[k] = v
		}
	}
	return nil
}

// -- Protocol negotiation --

// DefaultSupportedProtocolVersions is the set of MCP protocol versions
// the gateway advertises. Order matters: index 0 is the gateway's
// preferred (newest) version. NegotiateProtocolVersion picks the
// highest version in this set that is ≤ the client's requested
// version, falling through to the gateway's preferred version when
// the client requested something newer than we know about.
//
// Sourced from docs/MCP_GATEWAY.md § 3.1.
var DefaultSupportedProtocolVersions = []string{
	"2025-11-25", // current spec, default
	"2025-03-26", // streamable HTTP era
	"2024-11-05", // legacy stdio (still common in the field)
}

// NegotiateProtocolVersion returns the protocolVersion to advertise to
// the client, given what the client requested and what the gateway
// supports.
//
// Strategy (matches docs/MCP_GATEWAY.md § 3.2):
//
//   - If `clientRequested` is in `supported`, echo it back exactly.
//   - If `clientRequested` is newer than every entry in `supported`
//     (i.e., the client knows a version the gateway has never heard
//     of), return the gateway's highest supported version. The MCP
//     lifecycle spec lets the client decide whether that's acceptable.
//   - If `clientRequested` is older than every entry in `supported`
//     (i.e., the client predates the gateway's lowest known version),
//     return the empty string — the caller MUST treat that as
//     "negotiation failed" and respond with -32602.
//   - If `clientRequested` is between two entries in `supported`
//     (e.g., gateway knows 2024-11-05 and 2025-11-25; client asks for
//     2025-03-26 but gateway doesn't list it), return the highest
//     supported version that is ≤ clientRequested.
//
// Versions are compared as opaque date strings ordered lexically.
// The MCP spec guarantees YYYY-MM-DD format which sorts correctly.
//
// `supported` is treated read-only; pass DefaultSupportedProtocolVersions
// for the production set or a custom slice for tests.
func NegotiateProtocolVersion(clientRequested string, supported []string) string {
	if len(supported) == 0 {
		return ""
	}

	// Find the gateway's highest and lowest known versions.
	highest := supported[0]
	lowest := supported[0]
	for _, v := range supported {
		if v > highest {
			highest = v
		}
		if v < lowest {
			lowest = v
		}
	}

	// Empty client request — fall back to highest.
	if clientRequested == "" {
		return highest
	}

	// Exact match? Echo back.
	for _, v := range supported {
		if v == clientRequested {
			return clientRequested
		}
	}

	// Client is newer than anything we know — advertise our best.
	if clientRequested > highest {
		return highest
	}

	// Client is older than anything we know — negotiation fails.
	if clientRequested < lowest {
		return ""
	}

	// Client is between two of our supported versions. Find the
	// highest entry in `supported` that is ≤ clientRequested. (Since
	// MCP versions are released yearly-ish in YYYY-MM-DD form, this
	// happens when a client speaks a version we don't list but is
	// "close enough" to one we do.)
	chosen := lowest
	for _, v := range supported {
		if v <= clientRequested && v > chosen {
			chosen = v
		}
	}
	return chosen
}

// MergeCapabilities returns the union of upstream capabilities for
// advertisement to the client during initialize. Rules (per
// docs/MCP_GATEWAY.md § 3.3):
//
//   - `tools` is always advertised; listChanged: false (the gateway
//     does not subscribe to upstream tools/list_changed yet).
//   - `logging` is always advertised; gateway forwards
//     logging/setLevel to every upstream.
//   - `completions` is not advertised.
//
// `resources` and `prompts` capabilities are intentionally masked OUT —
// even when an upstream advertises them, the gateway does NOT expose
// them to the client because resources/* and prompts/* method routing
// is not yet implemented (see TODO(v0.6, #mcp-resources)). Advertising
// them today would mislead the client into showing resources that every
// read would reject with MethodNotFound (see Bridge.handleNotImplemented).
//
// TODO(v0.6, #mcp-list-changed): forward upstream
// notifications/tools/list_changed and flip our advertised tools
// capability to listChanged: true.
func MergeCapabilities(upstreamCaps []map[string]interface{}) map[string]interface{} {
	merged := map[string]interface{}{
		"tools":   map[string]interface{}{"listChanged": false},
		"logging": map[string]interface{}{},
	}

	// Intentionally do NOT propagate `resources` or `prompts` from
	// upstreams. See doc-comment above. The upstreamCaps parameter is
	// retained as a no-op to keep the signature stable for when the
	// masking is removed.
	_ = upstreamCaps

	return merged
}
