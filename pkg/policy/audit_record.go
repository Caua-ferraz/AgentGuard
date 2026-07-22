package policy

// AuditRecord is the POST body for the central server's /v1/audit ingest
// endpoint (pkg/proxy handleAuditRecord). It carries a pre-decided fail-closed
// verdict for the server to append to the audit trail VERBATIM, without running
// the policy engine.
//
// Why it exists: a transport proxy (e.g. the LLM API Proxy) sometimes
// manufactures its own fail-closed refusal — the canonical case is a streaming
// tool call whose assembled arguments are malformed JSON at completion, which
// the proxy refuses with rule "deny:llm_api_proxy:malformed_tool_call". The
// audit trail must reflect the DENY the client actually received, not the ALLOW
// a fidelity-blind /v1/check would have logged after evaluating the (garbage)
// projected request. This record closes that fidelity gap while keeping the
// central audit log the single source of truth (the proxy still does not write
// audit entries locally).
//
// The endpoint records DENY only: the server hardcodes Decision=DENY and never
// trusts a caller-supplied allow, so this path can never be used to inject an
// ALLOW into the trail. Rule/Reason are caller-supplied so the recorded verdict
// carries the exact rule string the client saw.
//
// Additive wire type (v1.0 freeze): new type + new endpoint; nothing on the
// existing /v1/check request or response path changes.
type AuditRecord struct {
	// SchemaVersion identifies the wire-format version. The server defaults an
	// empty value to "v1" and rejects any other value, mirroring ActionRequest.
	SchemaVersion string `json:"schema_version,omitempty"`

	// Request is the action the refusal was for, shaped exactly like a normal
	// gate's ActionRequest (scope, command, meta carrying the transport tag,
	// ...), so the recorded entry sits in the audit trail indistinguishable
	// from a real gate entry.
	Request ActionRequest `json:"request"`

	// Reason and Rule are the verdict strings the client received. Rule is
	// required (the server rejects an empty rule so no unattributable entry is
	// written); Reason is optional.
	Reason string `json:"reason,omitempty"`
	Rule   string `json:"rule,omitempty"`
}
