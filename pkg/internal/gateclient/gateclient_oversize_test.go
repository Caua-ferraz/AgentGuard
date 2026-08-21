package gateclient

// Regression tests for audit B25: a `/v1/check` response larger than the read
// cap must be REJECTED as oversized, never silently truncated.
//
// The bug: the body was read through a plain io.LimitReader(body, maxResp),
// which returns a clean EOF exactly at the cap. A verdict at or past that size
// was cut mid-JSON, json.Unmarshal failed, and the caller could not tell that
// error apart from a transport failure — so it applied its configured fail-mode
// default in place of a verdict the central server had actually issued. With
// --fail-mode allow that silently converts a real DENY into an ALLOW.
//
// The fix reads maxResp+1 and treats the extra byte as proof of overflow.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// maxRespBytes mirrors the unexported cap inside CallV1Check. If that constant
// ever changes, these tests must be updated with it — which is the point.
const maxRespBytes = 64 * 1024

// checkServer serves a fixed body from the /v1/t/{tenant}/check endpoint.
func checkServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestCallV1Check_OversizedResponseIsRejectedNotTruncated is the core B25
// assertion. A valid-JSON DENY padded past the cap must produce an error that
// names the overflow — not a decode error, and above all not a silent verdict
// swap.
func TestCallV1Check_OversizedResponseIsRejected(t *testing.T) {
	// Valid JSON whose `reason` alone pushes the document past the cap. This is
	// the dangerous shape: perfectly well-formed, genuinely issued by the
	// server, and only the transport cap makes it unusable.
	huge := `{"schema_version":"v1","decision":"DENY","reason":"` +
		strings.Repeat("x", maxRespBytes) + `","matched_rule":"deny:test:real_verdict"}`
	if len(huge) <= maxRespBytes {
		t.Fatalf("test fixture is not oversized: %d bytes", len(huge))
	}

	srv := checkServer(t, huge)
	c := &Caller{GuardURL: srv.URL, TenantID: "local"}

	_, err := c.CallV1Check(context.Background(), policy.ActionRequest{Scope: "shell", Command: "ls"}, testRules)
	if err == nil {
		t.Fatal("oversized /v1/check response must be an error, not a silently truncated verdict")
	}
	// The error must be distinguishable from a transport failure so a caller
	// can alert on "the server answered but we could not use it".
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("error = %v; want it to name the size overflow so it is not mistaken for a network error", err)
	}
	if strings.Contains(err.Error(), "decode") {
		t.Errorf("error = %v; an oversized body must not surface as a decode failure (that is exactly the B25 confusion)", err)
	}
}

// TestCallV1Check_AtCapBoundary pins the boundary: a body of exactly maxResp
// bytes is still valid and must decode. Off-by-one here would reject legitimate
// large-but-legal verdicts, trading one silent failure for another.
func TestCallV1Check_AtCapBoundary(t *testing.T) {
	prefix := `{"schema_version":"v1","decision":"DENY","reason":"`
	suffix := `","matched_rule":"deny:test:real_verdict"}`
	pad := maxRespBytes - len(prefix) - len(suffix)
	if pad < 1 {
		t.Fatal("cap too small to build the boundary fixture")
	}
	body := prefix + strings.Repeat("x", pad) + suffix
	if len(body) != maxRespBytes {
		t.Fatalf("fixture is %d bytes, want exactly %d", len(body), maxRespBytes)
	}

	srv := checkServer(t, body)
	c := &Caller{GuardURL: srv.URL, TenantID: "local"}

	d, err := c.CallV1Check(context.Background(), policy.ActionRequest{Scope: "shell", Command: "ls"}, testRules)
	if err != nil {
		t.Fatalf("a body of exactly the cap must still decode, got %v", err)
	}
	if d.Allow {
		t.Errorf("decision = allow, want the server's DENY to survive at the boundary")
	}
}

// TestCallV1Check_NormalResponseUnaffected is the no-regression guard: the
// overwhelming majority of verdicts are a few hundred bytes and must be
// untouched by the cap logic.
func TestCallV1Check_NormalResponseUnaffected(t *testing.T) {
	srv := checkServer(t, `{"schema_version":"v1","decision":"ALLOW","reason":"ok","matched_rule":"allow:test:rule"}`)
	c := &Caller{GuardURL: srv.URL, TenantID: "local"}

	d, err := c.CallV1Check(context.Background(), policy.ActionRequest{Scope: "shell", Command: "ls"}, testRules)
	if err != nil {
		t.Fatalf("CallV1Check: %v", err)
	}
	if !d.Allow {
		t.Errorf("decision = deny, want the server's ALLOW")
	}
	if d.Rule != "allow:test:rule" {
		t.Errorf("rule = %q, want the server's matched_rule to survive", d.Rule)
	}
}
