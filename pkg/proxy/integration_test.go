package proxy

// Full-project integration tests — spin up the real Server against a real
// HTTP listener (not httptest.ResponseRecorder), exercise auth, CORS,
// SSE, CSRF, approval round-trips, audit query, and multi-agent overrides
// end-to-end. Runs under -race to catch any residual data races that
// per-handler unit tests miss.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/notify"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// integrationServer wires a real Server into an httptest.Server so we can
// hit it with net/http clients (cookies, gzip, follow redirects, etc.).
type integrationServer struct {
	t         *testing.T
	srv       *Server
	ts        *httptest.Server
	client    *http.Client
	cookiesMu sync.Mutex
	cookies   map[string]*http.Cookie
}

func newIntegrationServer(t *testing.T, cfgMutators ...func(*Config)) *integrationServer {
	t.Helper()

	dir := t.TempDir()
	logger, err := audit.NewFileLogger(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatalf("audit logger: %v", err)
	}
	t.Cleanup(func() { logger.Close() })

	pol := &policy.Policy{
		Version: "1",
		Name:    "integration",
		Rules: []policy.RuleSet{
			{
				Scope: "shell",
				Allow: []policy.Rule{{Pattern: "ls *"}, {Pattern: "echo *"}},
				Deny:  []policy.Rule{{Pattern: "rm -rf *", Message: "blocked"}},
				RequireApproval: []policy.Rule{{Pattern: "sudo *"}},
			},
			{
				Scope: "network",
				Allow: []policy.Rule{{Domain: "api.openai.com"}, {Domain: "*.wikipedia.org"}},
				Deny:  []policy.Rule{{Domain: "*.evil.com", Message: "blocked"}},
			},
			{
				Scope: "cost",
				Limits: &policy.CostLimits{
					MaxPerAction:  "$5.00",
					MaxPerSession: "$10.00",
				},
			},
		},
		Agents: map[string]policy.AgentCfg{
			"researcher": {
				Override: []policy.RuleSet{
					{
						Scope: "network",
						Allow: []policy.Rule{{Domain: "scholar.google.com"}},
					},
				},
			},
		},
	}

	cfg := Config{
		Port:             0,
		Engine:           policy.NewEngine(pol),
		Logger:           logger,
		DashboardEnabled: true,
		Notifier:         notify.NewDispatcher(policy.NotificationCfg{}),
		APIKey:           "integration-secret",
		BaseURL:          "http://127.0.0.1:0",
		Version:          "integration",
	}
	for _, m := range cfgMutators {
		m(&cfg)
	}

	srv := NewServer(cfg)

	// httptest.Server uses the http.Handler we pass and runs a real listener.
	// We rebuild the same handler chain NewServer constructed.
	ts := httptest.NewServer(srv.http.Handler)
	t.Cleanup(ts.Close)

	// No Jar — we track cookies manually on integrationServer so we don't
	// have to implement net/url-based public-suffix cookie scoping for
	// 127.0.0.1 test hosts. Each request attaches accumulated cookies via
	// jarCookies(); each response gets absorbed via absorbCookies().
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &integrationServer{
		t:       t,
		srv:     srv,
		ts:      ts,
		client:  client,
		cookies: make(map[string]*http.Cookie),
	}
}

// --- small helpers ---

// postJSON POSTs a JSON-encoded body with the given headers. Captures
// response cookies into the jar if one is provided.
func (s *integrationServer) postJSON(path string, body any, hdr http.Header) *http.Response {
	s.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			s.t.Fatalf("encode: %v", err)
		}
	}
	req, err := http.NewRequest(http.MethodPost, s.ts.URL+path, &buf)
	if err != nil {
		s.t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	// Attach any cookies we've accumulated.
	for _, c := range s.jarCookies() {
		req.AddCookie(c)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		s.t.Fatalf("POST %s: %v", path, err)
	}
	s.absorbCookies(resp)
	return resp
}

func (s *integrationServer) getWith(path string, hdr http.Header) *http.Response {
	s.t.Helper()
	req, err := http.NewRequest(http.MethodGet, s.ts.URL+path, nil)
	if err != nil {
		s.t.Fatalf("new request: %v", err)
	}
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	for _, c := range s.jarCookies() {
		req.AddCookie(c)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		s.t.Fatalf("GET %s: %v", path, err)
	}
	s.absorbCookies(resp)
	return resp
}

// Simple embedded cookie storage tied to the integrationServer (no jar).
func (s *integrationServer) jarCookies() []*http.Cookie {
	s.cookiesMu.Lock()
	defer s.cookiesMu.Unlock()
	out := make([]*http.Cookie, 0, len(s.cookies))
	for _, c := range s.cookies {
		out = append(out, c)
	}
	return out
}

func (s *integrationServer) absorbCookies(resp *http.Response) {
	s.cookiesMu.Lock()
	defer s.cookiesMu.Unlock()
	for _, c := range resp.Cookies() {
		if c.MaxAge < 0 {
			delete(s.cookies, c.Name)
			continue
		}
		if s.cookies == nil {
			s.cookies = make(map[string]*http.Cookie)
		}
		s.cookies[c.Name] = c
	}
}

// Add cookie storage to integrationServer (appended via an extension struct
// isn't natural in Go; re-define with embedded fields).

// ---------------------------------------------------------------------------
// Test: end-to-end login + CSRF approve/deny flow
// ---------------------------------------------------------------------------

func TestIntegration_LoginThenApprove(t *testing.T) {
	s := newIntegrationServer(t)

	// 1. Unauthenticated /dashboard → login page.
	r := s.getWith("/dashboard", nil)
	body := readBody(t, r)
	if r.StatusCode != 200 {
		t.Fatalf("dashboard GET: %d", r.StatusCode)
	}
	if !strings.Contains(body, "Sign in") {
		t.Fatal("unauthenticated dashboard must serve login page")
	}
	if strings.Contains(body, "integration-secret") {
		t.Fatal("login page must not leak the API key")
	}

	// 2. /auth/login with wrong key → 401.
	r = s.postJSON("/auth/login", map[string]string{"api_key": "nope"}, nil)
	if r.StatusCode != 401 {
		t.Fatalf("wrong-key login should 401, got %d", r.StatusCode)
	}
	readBody(t, r)

	// 3. /auth/login with right key → sets session + csrf cookies, returns csrf token.
	r = s.postJSON("/auth/login", map[string]string{"api_key": "integration-secret"}, nil)
	if r.StatusCode != 200 {
		t.Fatalf("login: %d: %s", r.StatusCode, readBody(t, r))
	}
	var loginResp loginResponse
	if err := json.NewDecoder(r.Body).Decode(&loginResp); err != nil {
		t.Fatalf("decode login: %v", err)
	}
	r.Body.Close()
	if loginResp.CSRFToken == "" {
		t.Fatal("login response missing csrf_token")
	}

	// 4. /dashboard now serves the real dashboard.
	r = s.getWith("/dashboard", nil)
	body = readBody(t, r)
	if !strings.Contains(body, "Action Feed") {
		t.Fatal("authenticated dashboard should show Action Feed")
	}

	// 5. Enqueue a pending action via /v1/check (public endpoint).
	r = s.postJSON("/v1/check", map[string]any{
		"scope":    "shell",
		"command":  "sudo reboot",
		"agent_id": "bot",
	}, nil)
	var checkResp policy.CheckResult
	if err := json.NewDecoder(r.Body).Decode(&checkResp); err != nil {
		t.Fatalf("decode check: %v", err)
	}
	r.Body.Close()
	if checkResp.Decision != policy.RequireApproval {
		t.Fatalf("expected REQUIRE_APPROVAL, got %s", checkResp.Decision)
	}

	// 6. Approve without CSRF header → 403.
	r = s.postJSON("/v1/approve/"+checkResp.ApprovalID, nil, nil)
	if r.StatusCode != 403 {
		t.Fatalf("approve without CSRF must 403, got %d", r.StatusCode)
	}
	readBody(t, r)

	// 7. Approve with CSRF header → 200.
	hdr := http.Header{}
	hdr.Set(CSRFHeaderName, loginResp.CSRFToken)
	r = s.postJSON("/v1/approve/"+checkResp.ApprovalID, nil, hdr)
	if r.StatusCode != 200 {
		t.Fatalf("approve with CSRF: %d: %s", r.StatusCode, readBody(t, r))
	}
	readBody(t, r)

	// 8. /v1/status with session cookie (no CSRF — GET) → resolved.
	r = s.getWith("/v1/status/"+checkResp.ApprovalID, nil)
	var statusResp map[string]string
	if err := json.NewDecoder(r.Body).Decode(&statusResp); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	r.Body.Close()
	if statusResp["status"] != "resolved" || statusResp["decision"] != "ALLOW" {
		t.Errorf("expected resolved+ALLOW, got %v", statusResp)
	}

	// 9. /auth/logout clears cookies.
	r = s.postJSON("/auth/logout", nil, nil)
	if r.StatusCode != http.StatusNoContent {
		t.Errorf("logout: %d", r.StatusCode)
	}
	readBody(t, r)
	// After logout the session is gone — next dashboard GET must serve login
	// again. Clear our local cookie jar too so the request reflects a fresh
	// browser.
	s.cookiesMu.Lock()
	s.cookies = nil
	s.cookiesMu.Unlock()
	r = s.getWith("/dashboard", nil)
	body = readBody(t, r)
	if !strings.Contains(body, "Sign in") {
		t.Error("after logout, /dashboard must serve login page")
	}
}

// ---------------------------------------------------------------------------
// Test: Bearer token path still works on every gated endpoint
// ---------------------------------------------------------------------------

func TestIntegration_BearerAuthStillWorks(t *testing.T) {
	s := newIntegrationServer(t)

	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer integration-secret")

	// Enqueue.
	r := s.postJSON("/v1/check", map[string]any{
		"scope":    "shell",
		"command":  "sudo halt",
		"agent_id": "bot",
	}, nil)
	var checkResp policy.CheckResult
	json.NewDecoder(r.Body).Decode(&checkResp)
	r.Body.Close()

	// Approve with Bearer (no session, no CSRF).
	r = s.postJSON("/v1/approve/"+checkResp.ApprovalID, nil, hdr)
	if r.StatusCode != 200 {
		t.Fatalf("bearer approve: %d: %s", r.StatusCode, readBody(t, r))
	}
	readBody(t, r)

	// /v1/audit with Bearer.
	r = s.getWith("/v1/audit?agent_id=bot", hdr)
	if r.StatusCode != 200 {
		t.Fatalf("bearer audit: %d: %s", r.StatusCode, readBody(t, r))
	}
	readBody(t, r)

	// /v1/status with Bearer.
	r = s.getWith("/v1/status/"+checkResp.ApprovalID, hdr)
	if r.StatusCode != 200 {
		t.Errorf("bearer status: %d", r.StatusCode)
	}
	readBody(t, r)

	// No Bearer and no session → 401 on audit.
	r = s.getWith("/v1/audit", nil)
	if r.StatusCode != 401 {
		t.Errorf("unauthenticated audit should 401, got %d", r.StatusCode)
	}
	readBody(t, r)
}

// ---------------------------------------------------------------------------
// Test: permissive-localhost CORS default (backward compat)
// ---------------------------------------------------------------------------

func TestIntegration_CORS_PermissiveLocalhostDefault(t *testing.T) {
	s := newIntegrationServer(t, func(c *Config) { c.AllowedOrigin = "" })

	// localhost origin: should be reflected.
	hdr := http.Header{}
	hdr.Set("Origin", "http://localhost:3000")
	r := s.getWith("/health", hdr)
	if got := r.Header.Get("Access-Control-Allow-Origin"); got != "http://localhost:3000" {
		t.Errorf("permissive-localhost should reflect localhost, got %q", got)
	}
	readBody(t, r)

	// External origin: must NOT be reflected.
	hdr.Set("Origin", "https://evil.com")
	r = s.getWith("/health", hdr)
	if got := r.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("permissive-localhost must reject evil.com, got ACAO=%q", got)
	}
	readBody(t, r)
}

// ---------------------------------------------------------------------------
// Test: strict CORS when --allowed-origin is set
// ---------------------------------------------------------------------------

func TestIntegration_CORS_StrictMode(t *testing.T) {
	s := newIntegrationServer(t, func(c *Config) { c.AllowedOrigin = "https://app.example" })

	hdr := http.Header{}
	hdr.Set("Origin", "https://app.example")
	r := s.getWith("/health", hdr)
	if r.Header.Get("Access-Control-Allow-Origin") != "https://app.example" {
		t.Error("strict mode must reflect exact origin")
	}
	readBody(t, r)

	// Same host different scheme must not match.
	hdr.Set("Origin", "http://app.example")
	r = s.getWith("/health", hdr)
	if r.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Error("strict mode must reject http when only https is allowed")
	}
	readBody(t, r)

	// Even localhost is rejected in strict mode.
	hdr.Set("Origin", "http://localhost:3000")
	r = s.getWith("/health", hdr)
	if r.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Error("strict mode must reject localhost when not configured")
	}
	readBody(t, r)
}

// ---------------------------------------------------------------------------
// Test: SSE stream delivers check + resolved events
// ---------------------------------------------------------------------------

func TestIntegration_SSE_StreamsEvents(t *testing.T) {
	s := newIntegrationServer(t)

	// Log in first since /api/stream is gated.
	s.postJSON("/auth/login", map[string]string{"api_key": "integration-secret"}, nil).Body.Close()

	// Open SSE with a goroutine that reads the first event and signals.
	// SSE is a long-poll, so we use a dedicated client with no Timeout and
	// rely on context cancellation to stop the read when the test ends.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	sseClient := &http.Client{} // no Timeout — SSE is long-lived
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, s.ts.URL+"/api/stream", nil)
	for _, c := range s.jarCookies() {
		req.AddCookie(c)
	}
	sseResp, err := sseClient.Do(req)
	if err != nil {
		t.Fatalf("stream open: %v", err)
	}
	defer sseResp.Body.Close()
	if sseResp.StatusCode != 200 {
		t.Fatalf("stream status: %d", sseResp.StatusCode)
	}

	gotEvent := make(chan string, 1)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := sseResp.Body.Read(buf)
			if n > 0 {
				gotEvent <- string(buf[:n])
				return
			}
			if err != nil {
				return
			}
		}
	}()

	// Trigger a check to produce an SSE event.
	time.Sleep(50 * time.Millisecond) // let the subscriber register
	s.postJSON("/v1/check", map[string]any{"scope": "shell", "command": "ls -la"}, nil).Body.Close()

	select {
	case data := <-gotEvent:
		if !strings.Contains(data, "data: ") {
			t.Errorf("expected SSE frame, got %q", data)
		}
		if !strings.Contains(data, "ALLOW") {
			t.Errorf("expected ALLOW decision in SSE payload, got %q", data)
		}
	case <-ctx.Done():
		t.Fatal("no SSE event received within timeout")
	}
}

// ---------------------------------------------------------------------------
// Test: end-to-end cost-scope session tracking
// ---------------------------------------------------------------------------

func TestIntegration_CostScope_SessionEnforced(t *testing.T) {
	s := newIntegrationServer(t)

	decide := func(est float64) string {
		r := s.postJSON("/v1/check", map[string]any{
			"scope":      "cost",
			"session_id": "sess-int",
			"est_cost":   est,
		}, nil)
		var out policy.CheckResult
		json.NewDecoder(r.Body).Decode(&out)
		r.Body.Close()
		return string(out.Decision)
	}

	// $4 + $4 + $3 > $10 → third should deny.
	if d := decide(4.0); d != "ALLOW" {
		t.Fatalf("1st check expected ALLOW, got %s", d)
	}
	if d := decide(4.0); d != "ALLOW" {
		t.Fatalf("2nd check expected ALLOW, got %s", d)
	}
	if d := decide(3.0); d != "DENY" {
		t.Fatalf("3rd check expected DENY, got %s", d)
	}
}

// ---------------------------------------------------------------------------
// Test: multi-agent override over HTTP
// ---------------------------------------------------------------------------

func TestIntegration_MultiAgent_Overrides(t *testing.T) {
	s := newIntegrationServer(t)

	decide := func(agent, domain string) string {
		r := s.postJSON("/v1/check", map[string]any{
			"scope":    "network",
			"domain":   domain,
			"agent_id": agent,
		}, nil)
		var out policy.CheckResult
		json.NewDecoder(r.Body).Decode(&out)
		r.Body.Close()
		return string(out.Decision)
	}

	// researcher override: scholar.google.com allowed, openai NOT in override.
	if d := decide("researcher", "scholar.google.com"); d != "ALLOW" {
		t.Errorf("researcher/scholar should ALLOW, got %s", d)
	}
	if d := decide("researcher", "api.openai.com"); d != "DENY" {
		t.Errorf("researcher/openai should DENY (overridden), got %s", d)
	}

	// Default agent falls back to base rules.
	if d := decide("", "api.openai.com"); d != "ALLOW" {
		t.Errorf("default/openai should ALLOW, got %s", d)
	}
	if d := decide("", "scholar.google.com"); d != "DENY" {
		t.Errorf("default/scholar should DENY, got %s", d)
	}
}

// ---------------------------------------------------------------------------
// Test: concurrent /v1/check barrage against a real listener
// ---------------------------------------------------------------------------

func TestIntegration_ConcurrentChecks(t *testing.T) {
	s := newIntegrationServer(t)

	const workers = 24
	const per = 25

	var wg sync.WaitGroup
	errs := make(chan error, workers*per)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(wid int) {
			defer wg.Done()
			for i := 0; i < per; i++ {
				body := map[string]any{"scope": "shell", "command": fmt.Sprintf("ls -la worker-%d-i-%d", wid, i)}
				resp := s.postJSON("/v1/check", body, nil)
				if resp.StatusCode != 200 {
					errs <- fmt.Errorf("worker %d iter %d: HTTP %d", wid, i, resp.StatusCode)
				}
				resp.Body.Close()
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

// ---------------------------------------------------------------------------
// Test: dashboard JS never references the old api-key meta tag
// ---------------------------------------------------------------------------

func TestIntegration_DashboardHTMLNeverLeaksKey(t *testing.T) {
	s := newIntegrationServer(t, func(c *Config) { c.APIKey = "super-secret-key-should-never-appear" })

	// Authenticated.
	s.postJSON("/auth/login", map[string]string{"api_key": "super-secret-key-should-never-appear"}, nil).Body.Close()

	r := s.getWith("/dashboard", nil)
	body := readBody(t, r)

	if strings.Contains(body, "super-secret-key-should-never-appear") {
		t.Fatal("authenticated dashboard HTML leaks the API key")
	}
	if strings.Contains(body, "agentguard-api-key") {
		t.Fatal("dashboard references the old api-key meta tag")
	}
}

// ---------------------------------------------------------------------------
// Test: 401 and 403 are both returned as expected
// ---------------------------------------------------------------------------

func TestIntegration_401vs403(t *testing.T) {
	s := newIntegrationServer(t)

	// No auth at all → 401 on gated endpoints.
	r := s.postJSON("/v1/approve/ap_nonexistent", nil, nil)
	if r.StatusCode != 401 {
		t.Errorf("no auth should give 401, got %d", r.StatusCode)
	}
	readBody(t, r)

	// Valid session, missing CSRF → 403.
	s.postJSON("/auth/login", map[string]string{"api_key": "integration-secret"}, nil).Body.Close()
	r = s.postJSON("/v1/approve/ap_nonexistent", nil, nil)
	if r.StatusCode != 403 {
		t.Errorf("session without CSRF should give 403, got %d", r.StatusCode)
	}
	readBody(t, r)
}

// ---------------------------------------------------------------------------
// Test: MaxRequestBodySize enforced
// ---------------------------------------------------------------------------

func TestIntegration_OversizedBodyRejected(t *testing.T) {
	s := newIntegrationServer(t)

	body := strings.Repeat("x", MaxRequestBodySize+1)
	req, _ := http.NewRequest(http.MethodPost, s.ts.URL+"/v1/check", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Errorf("oversized body should give 400, got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Test: health + metrics are unauthenticated
// ---------------------------------------------------------------------------

func TestIntegration_HealthAndMetrics_Open(t *testing.T) {
	s := newIntegrationServer(t)

	r := s.getWith("/health", nil)
	if r.StatusCode != 200 {
		t.Errorf("health: %d", r.StatusCode)
	}
	readBody(t, r)

	r = s.getWith("/metrics", nil)
	if r.StatusCode != 200 {
		t.Errorf("metrics: %d", r.StatusCode)
	}
	body := readBody(t, r)
	if !strings.Contains(body, "agentguard_checks_total") {
		t.Error("metrics response should contain agentguard_checks_total")
	}
}

// ---------------------------------------------------------------------------
// Test: audit query returns entries created by prior checks
// ---------------------------------------------------------------------------

func TestIntegration_AuditQueryRoundTrip(t *testing.T) {
	s := newIntegrationServer(t)

	// Seed audit.
	for i := 0; i < 5; i++ {
		s.postJSON("/v1/check", map[string]any{
			"scope":    "shell",
			"command":  fmt.Sprintf("ls -la %d", i),
			"agent_id": "audit-bot",
		}, nil).Body.Close()
	}

	// Query with Bearer.
	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer integration-secret")
	r := s.getWith("/v1/audit?agent_id=audit-bot", hdr)
	var entries []audit.Entry
	if err := json.NewDecoder(r.Body).Decode(&entries); err != nil {
		t.Fatalf("decode: %v", err)
	}
	r.Body.Close()
	if len(entries) != 5 {
		t.Errorf("expected 5 audit entries, got %d", len(entries))
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// readBody consumes + closes resp.Body and returns the string.
func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}

