package gateclient

// Transport-level contract for RecordForcedAudit — the F1 audit-verdict
// fidelity path, previously at 0% coverage in this package.
//
// Its behaviour IS exercised end-to-end through pkg/llmproxy's gate wrapper,
// but the HTTP contract itself was untested: where it POSTs, what it sends,
// how it reports failure. That matters because this is the call that keeps a
// firewall from going dark. When the LLM proxy manufactures its own
// fail-closed refusal (a malformed tool-call completion), the client is denied
// locally and the central server never sees a /v1/check for it. Without this
// record the audit trail shows nothing — a block happened and was never
// written down, which for a compliance-facing product is worse than a noisy
// failure.
//
// Assertions are on the contract (endpoint, method, tenant routing, auth,
// payload fields, error signalling), not on byte-exact JSON, so the record
// shape stays free to gain fields.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// captured records what the fake central server received.
type captured struct {
	mu     sync.Mutex
	method string
	path   string
	auth   string
	ctype  string
	body   []byte
	hits   int
}

func (c *captured) snapshot() captured {
	c.mu.Lock()
	defer c.mu.Unlock()
	return captured{method: c.method, path: c.path, auth: c.auth, ctype: c.ctype, body: c.body, hits: c.hits}
}

// auditServer stands up a fake central server that records the request and
// answers with the given status.
func auditServer(t *testing.T, status int) (*httptest.Server, *captured) {
	t.Helper()
	got := &captured{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got.mu.Lock()
		got.method, got.path = r.Method, r.URL.Path
		got.auth = r.Header.Get("Authorization")
		got.ctype = r.Header.Get("Content-Type")
		got.body = body
		got.hits++
		got.mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	return srv, got
}

// TestRecordForcedAudit_PostsVerdictToTenantAuditEndpoint pins the contract:
// the DENY the client actually saw reaches the central audit trail, routed to
// the caller's tenant.
func TestRecordForcedAudit_PostsVerdictToTenantAuditEndpoint(t *testing.T) {
	srv, got := auditServer(t, http.StatusOK)
	c := &Caller{GuardURL: srv.URL, TenantID: "acme", APIKey: "secret-token"}

	req := policy.ActionRequest{Scope: "mcp_tool", Command: "bash", AgentID: "agent-1"}
	err := c.RecordForcedAudit(context.Background(), req,
		"tool call arguments are malformed; refused", "deny:llm_api_proxy:malformed_tool_call")
	if err != nil {
		t.Fatalf("RecordForcedAudit: %v", err)
	}

	g := got.snapshot()
	if g.hits != 1 {
		t.Fatalf("central server saw %d requests, want exactly 1", g.hits)
	}
	if g.method != http.MethodPost {
		t.Errorf("method = %s, want POST", g.method)
	}
	// Tenant routing is the invariant-#3 half: a forced audit record must land
	// on the CALLER's tenant, never a default or another tenant's trail.
	if !strings.Contains(g.path, "/acme/") {
		t.Errorf("path = %q, want the record routed to the caller's tenant", g.path)
	}
	if !strings.HasSuffix(g.path, "/audit") {
		t.Errorf("path = %q, want the /audit ingest endpoint (not /check — this record must "+
			"bypass policy evaluation and be written verbatim)", g.path)
	}
	if g.auth != "Bearer secret-token" {
		t.Errorf("Authorization = %q, want the configured API key forwarded", g.auth)
	}

	// The payload must carry the verdict the CLIENT saw, not a re-evaluated one.
	var rec policy.AuditRecord
	if err := json.Unmarshal(g.body, &rec); err != nil {
		t.Fatalf("body is not a decodable AuditRecord: %v (%q)", err, g.body)
	}
	if rec.Rule != "deny:llm_api_proxy:malformed_tool_call" {
		t.Errorf("rule = %q, want the client-visible rule preserved verbatim", rec.Rule)
	}
	if rec.Reason == "" {
		t.Error("reason is empty; the audit trail would not say why the request was refused")
	}
	if rec.Request.Command != "bash" {
		t.Errorf("request.command = %q, want the original action preserved", rec.Request.Command)
	}
	if rec.SchemaVersion == "" {
		t.Error("schema_version is empty; the server's request validator requires it")
	}
}

// TestRecordForcedAudit_DefaultsToLocalTenant: an unset TenantID must route to
// "local" rather than producing a malformed URL.
func TestRecordForcedAudit_DefaultsToLocalTenant(t *testing.T) {
	srv, got := auditServer(t, http.StatusOK)
	c := &Caller{GuardURL: srv.URL} // no TenantID

	if err := c.RecordForcedAudit(context.Background(), policy.ActionRequest{Scope: "mcp_tool"},
		"reason", "deny:test:rule"); err != nil {
		t.Fatalf("RecordForcedAudit: %v", err)
	}
	if g := got.snapshot(); !strings.Contains(g.path, "/local/") {
		t.Errorf("path = %q, want an unset tenant to route to local", g.path)
	}
}

// TestRecordForcedAudit_NonSuccessIsReported: the caller logs this error, so a
// server that rejects the record must not look like success. Silent success on
// a 5xx is how an audit gap goes unnoticed.
func TestRecordForcedAudit_NonSuccessIsReported(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusInternalServerError} {
		srv, _ := auditServer(t, status)
		c := &Caller{GuardURL: srv.URL, TenantID: "local"}

		err := c.RecordForcedAudit(context.Background(), policy.ActionRequest{Scope: "mcp_tool"},
			"reason", "deny:test:rule")
		if err == nil {
			t.Errorf("HTTP %d was reported as success; a rejected audit record must surface "+
				"so the operator learns the trail has a hole", status)
		}
	}
}

// TestRecordForcedAudit_UnreachableServerIsReported: the refusal has already
// been sent to the client, so this must return an error for the caller to log
// rather than panic or block indefinitely.
func TestRecordForcedAudit_UnreachableServerIsReported(t *testing.T) {
	// Bind then immediately close, so the port is almost certainly refusing.
	srv, _ := auditServer(t, http.StatusOK)
	url := srv.URL
	srv.Close()

	c := &Caller{GuardURL: url, TenantID: "local"}
	if err := c.RecordForcedAudit(context.Background(), policy.ActionRequest{Scope: "mcp_tool"},
		"reason", "deny:test:rule"); err == nil {
		t.Error("an unreachable central server must be reported, not swallowed")
	}
}
