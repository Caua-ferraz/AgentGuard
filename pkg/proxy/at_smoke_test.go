package proxy

// AT-added end-to-end smoke test.
//
// Although pkg/proxy/integration_test.go already covers individual aspects
// (CORS, SSE, multi-agent, audit query), the AT spec specifically asks for a
// single bundled smoke test that exercises the canonical happy path:
//
//   1. Boot a Server through httptest (real listener, real handler chain).
//   2. POST /v1/check with an ALLOW-shaped request.
//   3. POST /v1/check with a DENY-shaped request.
//   4. GET /health -> 200 + version field.
//   5. GET /metrics -> contains agentguard_checks_total advanced by >=2.
//   6. GET /v1/audit?limit=10 -> contains both decisions.
//   7. Tear down within a deadline (httptest.Close + Logger.Close).
//
// This is the test that fails if a future refactor breaks any one of those
// guarantees in isolation.

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/metrics"
	"github.com/Caua-ferraz/AgentGuard/pkg/notify"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// TestATSmoke_FullServerHappyPath is the AT-tier smoke test described in
// the v0.5 Phase 1 brief.
func TestATSmoke_FullServerHappyPath(t *testing.T) {
	// Capture metrics baseline first so the assertion below is robust to
	// other tests in the same `go test` run.
	checksBefore := atomic.LoadUint64(&metrics.ChecksTotal)

	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")

	logger, err := audit.NewFileLogger(auditPath)
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })

	pol := &policy.Policy{
		Version: "1",
		Name:    "at-smoke",
		Rules: []policy.RuleSet{
			{
				Scope: "shell",
				Allow: []policy.Rule{{Pattern: "ls *"}},
				Deny:  []policy.Rule{{Pattern: "rm -rf *", Message: "destructive"}},
			},
		},
	}

	disp := notify.NewDispatcher(policy.NotificationCfg{})
	t.Cleanup(disp.Close)

	srv := newIntegrationServer(t, func(c *Config) {
		c.Engine = policy.NewEngine(pol)
		c.Logger = logger
		c.Notifier = disp
		c.APIKey = "at-smoke-key"
	})

	// 1. ALLOW request.
	r := srv.postJSON("/v1/check", map[string]any{
		"scope":    "shell",
		"command":  "ls -la /tmp",
		"agent_id": "at-bot",
	}, nil)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("ALLOW check status: got %d, want 200", r.StatusCode)
	}
	var allowResp policy.CheckResult
	if err := json.NewDecoder(r.Body).Decode(&allowResp); err != nil {
		t.Fatalf("decode ALLOW: %v", err)
	}
	r.Body.Close()
	if allowResp.Decision != policy.Allow {
		t.Errorf("ALLOW request decided %s, want ALLOW (reason=%s)", allowResp.Decision, allowResp.Reason)
	}

	// 2. DENY request.
	r = srv.postJSON("/v1/check", map[string]any{
		"scope":    "shell",
		"command":  "rm -rf /var",
		"agent_id": "at-bot",
	}, nil)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("DENY check status: got %d, want 200", r.StatusCode)
	}
	var denyResp policy.CheckResult
	if err := json.NewDecoder(r.Body).Decode(&denyResp); err != nil {
		t.Fatalf("decode DENY: %v", err)
	}
	r.Body.Close()
	if denyResp.Decision != policy.Deny {
		t.Errorf("DENY request decided %s, want DENY (reason=%s)", denyResp.Decision, denyResp.Reason)
	}

	// 3. /health.
	r = srv.getWith("/health", nil)
	if r.StatusCode != http.StatusOK {
		t.Errorf("/health status: got %d, want 200", r.StatusCode)
	}
	var hb map[string]string
	if err := json.NewDecoder(r.Body).Decode(&hb); err != nil {
		t.Errorf("decode /health: %v", err)
	}
	r.Body.Close()
	if hb["status"] != "ok" {
		t.Errorf("/health.status = %q, want ok", hb["status"])
	}
	if hb["version"] == "" {
		t.Error("/health.version missing")
	}

	// 4. /metrics — counter must have advanced by at least 2.
	r = srv.getWith("/metrics", nil)
	body := readBody(t, r)
	if !strings.Contains(body, "agentguard_checks_total") {
		t.Errorf("/metrics missing agentguard_checks_total; got first 200 chars:\n%s",
			body[:min(len(body), 200)])
	}
	checksAfter := atomic.LoadUint64(&metrics.ChecksTotal)
	if got := checksAfter - checksBefore; got < 2 {
		t.Errorf("ChecksTotal delta = %d, want >= 2", got)
	}

	// 5. /v1/audit?limit=10 — both entries should be present.
	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer at-smoke-key")
	r = srv.getWith("/v1/audit?agent_id=at-bot&limit=10", hdr)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("/v1/audit status: got %d, want 200; body=%s", r.StatusCode, readBody(t, r))
	}
	var entries []audit.Entry
	if err := json.NewDecoder(r.Body).Decode(&entries); err != nil {
		t.Fatalf("decode audit: %v", err)
	}
	r.Body.Close()
	if len(entries) < 2 {
		t.Fatalf("audit returned %d entries, want >= 2", len(entries))
	}
	var seenAllow, seenDeny bool
	for _, e := range entries {
		switch e.Result.Decision {
		case policy.Allow:
			seenAllow = true
		case policy.Deny:
			seenDeny = true
		}
	}
	if !seenAllow {
		t.Error("audit log missing ALLOW entry")
	}
	if !seenDeny {
		t.Error("audit log missing DENY entry")
	}

	// 6. Teardown deadline — closing the httptest.Server and logger should
	//    return well under a second. We don't goroutine-leak-check here
	//    (the project doesn't pull goleak as a dep), but we do ensure
	//    Close calls return promptly.
	doneCh := make(chan struct{})
	go func() {
		srv.ts.Close()
		_ = logger.Close()
		disp.Close()
		close(doneCh)
	}()
	select {
	case <-doneCh:
	case <-time.After(2 * time.Second):
		t.Fatal("teardown blocked > 2s — possible goroutine leak")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
