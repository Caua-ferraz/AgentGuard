package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// --- SessionStore ---

func TestSessionStore_CreateValidate(t *testing.T) {
	s := NewSessionStore()
	sess, err := s.Create()
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(sess.Token) != 64 { // 32 bytes hex
		t.Errorf("expected 64-char hex token, got %d chars: %q", len(sess.Token), sess.Token)
	}
	if !s.Validate(sess.Token) {
		t.Error("freshly created session must validate")
	}
	if s.Validate("") {
		t.Error("empty token must never validate")
	}
	if s.Validate("not-a-real-token") {
		t.Error("unknown token must not validate")
	}
}

// TestSessionStore_CustomTTL verifies that NewSessionStoreWithTTL honors
// the caller-supplied lifetime and that a non-positive value falls back to
// the package default. Protects the proxy.session.ttl wiring path.
func TestSessionStore_CustomTTL(t *testing.T) {
	short := 250 * time.Millisecond
	s := NewSessionStoreWithTTL(short)
	sess, err := s.Create()
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	deadline := time.Now().Add(short + 50*time.Millisecond)
	if sess.ExpiresAt.After(deadline) {
		t.Errorf("ExpiresAt %v past expected %v", sess.ExpiresAt, deadline)
	}
	// Non-positive TTL => package default.
	s2 := NewSessionStoreWithTTL(0)
	sess2, _ := s2.Create()
	if got := time.Until(sess2.ExpiresAt); got < SessionTTL-time.Second {
		t.Errorf("zero TTL should fall back to SessionTTL (%v); got remaining %v", SessionTTL, got)
	}
}

func TestSessionStore_Destroy(t *testing.T) {
	s := NewSessionStore()
	sess, _ := s.Create()
	s.Destroy(sess.Token)
	if s.Validate(sess.Token) {
		t.Error("destroyed session must no longer validate")
	}
}

func TestSessionStore_Expires(t *testing.T) {
	s := NewSessionStore()
	// Fabricate an expired session directly.
	s.mu.Lock()
	s.sessions["expired"] = Session{Token: "expired", ExpiresAt: time.Now().Add(-time.Minute)}
	s.mu.Unlock()
	if s.Validate("expired") {
		t.Error("expired session must not validate")
	}
	// Expired entries are lazily evicted on Validate.
	if s.Count() != 0 {
		t.Errorf("expired session should be evicted; count=%d", s.Count())
	}
}

// TestSessionStore_RejectsNewWhenFull verifies the v0.4.1 behavior: when
// every slot holds a live session, Create returns ErrSessionStoreFull and
// the caller (handleLogin) is expected to surface 503. Earlier versions
// silently evicted the oldest live session here, which kicked a real
// operator out of an active session.
func TestSessionStore_RejectsNewWhenFull(t *testing.T) {
	s := NewSessionStore()

	// Fill with live sessions (ExpiresAt well in the future).
	s.mu.Lock()
	for i := 0; i < MaxSessions; i++ {
		tok := hexToken(i)
		s.sessions[tok] = Session{
			Token:     tok,
			ExpiresAt: time.Now().Add(time.Hour),
		}
	}
	s.mu.Unlock()

	_, err := s.Create()
	if err == nil {
		t.Fatal("Create on a full store must return an error, not silently evict")
	}
	if !errors.Is(err, ErrSessionStoreFull) {
		t.Errorf("want ErrSessionStoreFull, got %v", err)
	}

	// No live session was harmed: every one of the MaxSessions tokens is
	// still valid.
	for i := 0; i < MaxSessions; i++ {
		if !s.Validate(hexToken(i)) {
			t.Errorf("session %d was evicted; reject-new must leave existing sessions alone", i)
			break
		}
	}
}

// TestSessionStore_SweepsExpiredBeforeRejecting: a store "full" of expired
// entries must not block new logins. Create sweeps expired sessions before
// checking capacity.
func TestSessionStore_SweepsExpiredBeforeRejecting(t *testing.T) {
	s := NewSessionStore()

	// Fill with already-expired sessions.
	s.mu.Lock()
	for i := 0; i < MaxSessions; i++ {
		tok := hexToken(i)
		s.sessions[tok] = Session{
			Token:     tok,
			ExpiresAt: time.Now().Add(-time.Second),
		}
	}
	s.mu.Unlock()

	sess, err := s.Create()
	if err != nil {
		t.Fatalf("Create must succeed after expired sweep, got %v", err)
	}
	if !s.Validate(sess.Token) {
		t.Error("newly-created session must validate")
	}
	// After the sweep, only the new live session should remain.
	if got := s.Count(); got != 1 {
		t.Errorf("expected 1 session after sweep+create, got %d", got)
	}
}

// hexToken builds a deterministic unique 64-char hex string for the given
// integer. Uses the integer as a big-endian seed across the first 16 hex
// chars, with a constant fill for the remaining 48 so every i in [0, 2^64)
// yields a unique token.
func hexToken(i int) string {
	const hex = "0123456789abcdef"
	b := make([]byte, 64)
	// Encode i into the first 16 hex chars (64 bits).
	v := uint64(i)
	for k := 15; k >= 0; k-- {
		b[k] = hex[v&0xF]
		v >>= 4
	}
	// Fill the tail with a constant pattern.
	for k := 16; k < 64; k++ {
		b[k] = hex[k%16]
	}
	return string(b)
}

// TestSessionStore_ConcurrentCreate stresses the reject-new path under
// concurrent creators. With the race detector this asserts no data race.
// Workers×per deliberately exceeds MaxSessions, so some Creates are
// expected to return ErrSessionStoreFull once the store fills up — that is
// the new contract, not a test failure.
func TestSessionStore_ConcurrentCreate(t *testing.T) {
	s := NewSessionStore()

	const workers = 32
	const per = 50 // 32*50 = 1600 > MaxSessions=1024

	var wg sync.WaitGroup
	var full atomic.Uint64
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < per; j++ {
				sess, err := s.Create()
				if err != nil {
					if errors.Is(err, ErrSessionStoreFull) {
						full.Add(1)
						continue
					}
					t.Errorf("unexpected Create error: %v", err)
					return
				}
				if !s.Validate(sess.Token) {
					t.Errorf("just-created session failed to validate")
					return
				}
			}
		}()
	}
	wg.Wait()

	if got := s.Count(); got > MaxSessions {
		t.Errorf("session count must never exceed MaxSessions=%d, got %d", MaxSessions, got)
	}
	if full.Load() == 0 {
		// Not an error per se, but the test is designed to exercise the
		// rejection path — if nothing was rejected, either MaxSessions was
		// raised or the workload was shrunk. Flag it so future edits do not
		// silently stop exercising the new behavior.
		t.Errorf("expected at least one ErrSessionStoreFull rejection across %d creates", workers*per)
	}
}

// --- /auth/login and /auth/logout ---

func TestHandleLogin_Success(t *testing.T) {
	srv := newTestServer(t)

	body := `{"api_key":"test-secret"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.handleLogin(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Must set both the session cookie (HttpOnly) and CSRF cookie (JS-readable).
	cookies := w.Result().Cookies()
	var sess, csrf *http.Cookie
	for _, c := range cookies {
		switch c.Name {
		case SessionCookieName:
			sess = c
		case CSRFCookieName:
			csrf = c
		}
	}
	if sess == nil || csrf == nil {
		t.Fatalf("expected both %s and %s cookies, got %+v", SessionCookieName, CSRFCookieName, cookies)
	}
	if !sess.HttpOnly {
		t.Error("session cookie must be HttpOnly so JS can't read it")
	}
	if csrf.HttpOnly {
		t.Error("CSRF cookie MUST be JS-readable (not HttpOnly)")
	}
	if sess.SameSite != http.SameSiteStrictMode {
		t.Error("session cookie must be SameSite=Strict")
	}
	if sess.Value != csrf.Value {
		t.Error("double-submit: session and csrf cookies must share the same token")
	}

	var resp loginResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	if resp.CSRFToken != sess.Value {
		t.Error("login response CSRF token must match cookie token")
	}

	// Session store should now have it.
	if !srv.sessions.Validate(sess.Value) {
		t.Error("session store should contain the new token")
	}
}

func TestHandleLogin_TLSTerminatedUpstreamSetsSecure(t *testing.T) {
	// With TLSTerminatedUpstream=true, cookies must be issued with Secure=true
	// even though the inbound request has r.TLS==nil (plaintext hop from the
	// TLS-terminating reverse proxy).
	srv := newTestServer(t, func(c *Config) { c.TLSTerminatedUpstream = true })

	body := `{"api_key":"test-secret"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if req.TLS != nil {
		t.Fatal("httptest plaintext request should have nil TLS")
	}
	w := httptest.NewRecorder()
	srv.handleLogin(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	for _, c := range w.Result().Cookies() {
		if c.Name != SessionCookieName && c.Name != CSRFCookieName {
			continue
		}
		if !c.Secure {
			t.Errorf("cookie %q must have Secure=true when TLSTerminatedUpstream=true", c.Name)
		}
	}
}

func TestHandleLogin_DefaultNoTLSNoSecure(t *testing.T) {
	// Default (TLSTerminatedUpstream=false) preserves v0.4.0 behavior: cookies
	// are emitted without Secure when the request arrives over plaintext.
	srv := newTestServer(t) // default: TLSTerminatedUpstream=false

	body := `{"api_key":"test-secret"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handleLogin(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	for _, c := range w.Result().Cookies() {
		if c.Name != SessionCookieName && c.Name != CSRFCookieName {
			continue
		}
		if c.Secure {
			t.Errorf("cookie %q should not have Secure=true on plaintext request with default config", c.Name)
		}
	}
}

// TestHandleLogin_503OnSessionStoreFull: when the session store is full of
// live sessions, /auth/login must respond 503 with a numeric Retry-After
// header rather than a generic 500 ("session creation failed").
func TestHandleLogin_503OnSessionStoreFull(t *testing.T) {
	srv := newTestServer(t)

	// Pre-fill the store with live fabricated sessions.
	srv.sessions.mu.Lock()
	for i := 0; i < MaxSessions; i++ {
		tok := hexToken(i)
		srv.sessions.sessions[tok] = Session{
			Token:     tok,
			ExpiresAt: time.Now().Add(time.Hour),
		}
	}
	srv.sessions.mu.Unlock()

	body := `{"api_key":"test-secret"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handleLogin(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%q", w.Code, w.Body.String())
	}
	ra := w.Header().Get("Retry-After")
	if ra == "" {
		t.Error("Retry-After header must be set on 503")
	}
	if ra != fmt.Sprint(SessionStoreFullRetryAfterSeconds) {
		t.Errorf("Retry-After = %q, want %q", ra, fmt.Sprint(SessionStoreFullRetryAfterSeconds))
	}
}

func TestHandleLogin_WrongKey(t *testing.T) {
	srv := newTestServer(t)
	body := `{"api_key":"wrong"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(body))
	w := httptest.NewRecorder()

	srv.handleLogin(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for wrong key, got %d", w.Code)
	}
}

func TestHandleLogin_NoAPIKeyConfigured_Disabled(t *testing.T) {
	srv := newTestServer(t, func(c *Config) { c.APIKey = "" })

	body := `{"api_key":"anything"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleLogin(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("login should be disabled when no API key configured, got %d", w.Code)
	}
}

func TestHandleLogin_MalformedBody(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader("not json"))
	w := httptest.NewRecorder()
	srv.handleLogin(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleLogin_MethodNotAllowed(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	w := httptest.NewRecorder()
	srv.handleLogin(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleLogout(t *testing.T) {
	srv := newTestServer(t)
	sess, _ := srv.sessions.Create()

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sess.Token})
	w := httptest.NewRecorder()
	srv.handleLogout(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", w.Code)
	}
	if srv.sessions.Validate(sess.Token) {
		t.Error("logout should destroy the session")
	}
	// Cookies should be cleared (MaxAge=-1).
	for _, c := range w.Result().Cookies() {
		if (c.Name == SessionCookieName || c.Name == CSRFCookieName) && c.MaxAge != -1 {
			t.Errorf("cookie %s not cleared: MaxAge=%d", c.Name, c.MaxAge)
		}
	}
}

// --- requireAuthOrSession middleware paths ---

func TestRequireAuthOrSession_SessionWithCSRF_Pass(t *testing.T) {
	store := NewSessionStore()
	sess, _ := store.Create()

	called := false
	h := requireAuthOrSession("secret", store, true, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sess.Token})
	req.Header.Set(CSRFHeaderName, sess.Token)
	w := httptest.NewRecorder()
	h(w, req)

	if !called {
		t.Error("valid session + CSRF should be authorized")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestRequireAuthOrSession_SessionMissingCSRF_Rejected(t *testing.T) {
	store := NewSessionStore()
	sess, _ := store.Create()

	h := requireAuthOrSession("secret", store, true, func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler must not be called without CSRF header")
	})

	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sess.Token})
	// No CSRF header.
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 on missing CSRF, got %d", w.Code)
	}
}

func TestRequireAuthOrSession_SessionWrongCSRF_Rejected(t *testing.T) {
	store := NewSessionStore()
	sess, _ := store.Create()

	h := requireAuthOrSession("secret", store, true, func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler must not be called with wrong CSRF")
	})

	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sess.Token})
	req.Header.Set(CSRFHeaderName, "wrong-token")
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 on CSRF mismatch, got %d", w.Code)
	}
}

func TestRequireAuthOrSession_GETNoCSRFNeeded(t *testing.T) {
	store := NewSessionStore()
	sess, _ := store.Create()

	called := false
	h := requireAuthOrSession("secret", store, false, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sess.Token})
	w := httptest.NewRecorder()
	h(w, req)

	if !called {
		t.Error("GET endpoints with valid session should not need CSRF")
	}
}

// --- Full flow: login → protected GET with cookie ---

func TestFullLoginFlow(t *testing.T) {
	srv := newTestServer(t)

	// 1. Login.
	login := httptest.NewRequest(http.MethodPost, "/auth/login",
		strings.NewReader(`{"api_key":"test-secret"}`))
	lw := httptest.NewRecorder()
	srv.handleLogin(lw, login)
	if lw.Code != http.StatusOK {
		t.Fatalf("login failed: %d: %s", lw.Code, lw.Body.String())
	}

	var sessionCookie *http.Cookie
	for _, c := range lw.Result().Cookies() {
		if c.Name == SessionCookieName {
			sessionCookie = c
		}
	}
	if sessionCookie == nil {
		t.Fatal("no session cookie")
	}

	// 2. GET /api/pending through the middleware with the cookie.
	handler := requireAuthOrSession(srv.cfg.APIKey, srv.sessions, false, srv.handlePendingList)
	req := httptest.NewRequest(http.MethodGet, "/api/pending", nil)
	req.AddCookie(sessionCookie)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with session cookie, got %d: %s", w.Code, w.Body.String())
	}

	// 3. POST approve — needs CSRF header.
	pending := mustAdd(t, srv.approval,
		policy.ActionRequest{Scope: "shell", Command: "sudo"},
		policy.CheckResult{Decision: policy.RequireApproval},
	)
	approveHandler := requireAuthOrSession(srv.cfg.APIKey, srv.sessions, true, srv.handleApprove)

	approveReq := httptest.NewRequest(http.MethodPost, "/v1/approve/"+pending.ID, nil)
	approveReq.AddCookie(sessionCookie)
	approveReq.Header.Set(CSRFHeaderName, sessionCookie.Value)
	aw := httptest.NewRecorder()
	approveHandler(aw, approveReq)

	if aw.Code != http.StatusOK {
		t.Errorf("approve with CSRF header expected 200, got %d", aw.Code)
	}
}

// TestDashboardDoesNotLeakAPIKey: critical regression. The previously
// acknowledged leak (meta tag with server API key) must be gone.
func TestDashboardDoesNotLeakAPIKey(t *testing.T) {
	for _, apiKey := range []string{"", "test-secret", "another-very-secret-key-xyz"} {
		srv := newTestServer(t, func(c *Config) { c.APIKey = apiKey })

		req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
		w := httptest.NewRecorder()
		srv.handleDashboard(w, req)

		body := w.Body.String()
		if apiKey != "" && strings.Contains(body, apiKey) {
			t.Errorf("dashboard HTML contains API key %q", apiKey)
		}
		if strings.Contains(body, "agentguard-api-key") {
			t.Errorf("dashboard HTML references the old api-key meta tag (key=%q)", apiKey)
		}
	}
}
