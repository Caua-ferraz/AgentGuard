package proxy

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
)

// slowAuditLogger is an audit.Logger whose Log() blocks for a fixed delay,
// simulating a slow synchronous audit backend (e.g. an unbuffered file or DB
// write). It lets the timing test prove that the audit cost is reflected in
// X-AgentGuard-Total-Ms / the request-duration SLO metric.
type slowAuditLogger struct {
	delay   time.Duration
	mu      sync.Mutex
	entries []audit.Entry
}

func (s *slowAuditLogger) Log(e audit.Entry) error {
	time.Sleep(s.delay)
	s.mu.Lock()
	s.entries = append(s.entries, e)
	s.mu.Unlock()
	return nil
}

func (s *slowAuditLogger) Query(audit.QueryFilter) ([]audit.Entry, error) { return nil, nil }
func (s *slowAuditLogger) Close() error                                   { return nil }

func parseMsHeader(t *testing.T, h http.Header, name string) float64 {
	t.Helper()
	raw := h.Get(name)
	if raw == "" {
		t.Fatalf("missing %s header", name)
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		t.Fatalf("%s = %q is not a float: %v", name, raw, err)
	}
	return v
}

// TestHandleCheck_TimingHeaders_TotalIncludesAudit pins the contract documented
// in docs/API.md and docs/OBSERVABILITY.md: X-AgentGuard-Total-Ms (and the
// agentguard_request_duration_ms SLO histogram, which is fed the same value) is
// the END-TO-END /v1/check processing time, including the audit write.
//
// Regression guard: a previous version computed Total from a timestamp captured
// BEFORE the audit write, so a slow audit backend was silently dropped from the
// reported latency (Total ≈ policy, well under Audit). With a deliberately slow
// audit logger, Total must now be >= Audit.
func TestHandleCheck_TimingHeaders_TotalIncludesAudit(t *testing.T) {
	const auditDelay = 25 * time.Millisecond
	slow := &slowAuditLogger{delay: auditDelay}
	srv := newTestServer(t, func(c *Config) { c.Logger = slow })

	body := `{"scope":"shell","command":"ls -la"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/check", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.handleCheck(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	policyMs := parseMsHeader(t, w.Header(), "X-AgentGuard-Policy-Ms")
	auditMs := parseMsHeader(t, w.Header(), "X-AgentGuard-Audit-Ms")
	totalMs := parseMsHeader(t, w.Header(), "X-AgentGuard-Total-Ms")
	t.Logf("Policy-Ms=%.3f Audit-Ms=%.3f Total-Ms=%.3f (audit slept %v)", policyMs, auditMs, totalMs, auditDelay)

	const wantAuditFloor = 20.0 // ms; the 25ms sleep, minus slack for timer coarseness.
	if auditMs < wantAuditFloor {
		t.Errorf("Audit-Ms = %.3f, want >= %.1f (the audit logger slept %v)", auditMs, wantAuditFloor, auditDelay)
	}
	// The core regression guard: Total must include the audit write.
	if totalMs < auditMs {
		t.Errorf("Total-Ms = %.3f must be >= Audit-Ms = %.3f — Total must include the audit write", totalMs, auditMs)
	}
	// Total is the whole; Policy is a component of it.
	if totalMs < policyMs {
		t.Errorf("Total-Ms = %.3f must be >= Policy-Ms = %.3f", totalMs, policyMs)
	}
	// And the policy decision itself must exclude the audit write (otherwise the
	// decomposition is meaningless): policy work is far faster than the 25ms sleep.
	if policyMs >= wantAuditFloor {
		t.Errorf("Policy-Ms = %.3f unexpectedly >= %.1f; Policy must exclude the audit write", policyMs, wantAuditFloor)
	}
}

// TestHandleCheck_TimingHeaders_FastAuditDecomposition checks the common
// (fast, buffered) case: all three timing headers are present, non-negative,
// and Total is at least the sum of its policy and audit components minus
// rounding — i.e. Total never *understates* the work it decomposes.
func TestHandleCheck_TimingHeaders_FastAuditDecomposition(t *testing.T) {
	srv := newTestServer(t) // default FileLogger: fast synchronous append

	body := `{"scope":"shell","command":"ls -la"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/check", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.handleCheck(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	policyMs := parseMsHeader(t, w.Header(), "X-AgentGuard-Policy-Ms")
	auditMs := parseMsHeader(t, w.Header(), "X-AgentGuard-Audit-Ms")
	totalMs := parseMsHeader(t, w.Header(), "X-AgentGuard-Total-Ms")

	for name, v := range map[string]float64{"Policy-Ms": policyMs, "Audit-Ms": auditMs, "Total-Ms": totalMs} {
		if v < 0 {
			t.Errorf("%s = %.3f, want >= 0", name, v)
		}
	}
	// Total must cover both named components (allow 1ms slack for 3-decimal
	// rounding and the clock read between phases).
	if totalMs+1.0 < policyMs+auditMs {
		t.Errorf("Total-Ms = %.3f understates Policy-Ms(%.3f) + Audit-Ms(%.3f)", totalMs, policyMs, auditMs)
	}
}
