package proxy

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Session cookie and CSRF header names used by the dashboard.
//
// Double-submit cookie pattern:
//   - ag_session is HttpOnly: used by the server to validate the session.
//   - ag_csrf is JS-readable: the dashboard reads it via document.cookie and
//     echoes its value in X-CSRF-Token. Both cookies carry the SAME token, so
//     the server compares the header against the session token. An attacker
//     on another origin cannot read either cookie (same-origin policy), so
//     cannot forge the X-CSRF-Token header.
const (
	SessionCookieName = "ag_session"
	CSRFCookieName    = "ag_csrf"
	CSRFHeaderName    = "X-CSRF-Token"
	SessionTTL        = 1 * time.Hour
	MaxSessions       = 1024 // cap memory; oldest evicted when exceeded
)

// Session represents an authenticated dashboard session. The token value is
// stored in an HTTP-only cookie AND returned in the login response body so the
// browser JS can send it back as an X-CSRF-Token header on state-changing
// requests (double-submit cookie pattern).
type Session struct {
	Token     string
	ExpiresAt time.Time
}

// SessionStore holds active dashboard sessions in memory.
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]Session
}

// NewSessionStore creates an empty in-memory session store.
func NewSessionStore() *SessionStore {
	return &SessionStore{sessions: make(map[string]Session)}
}

// Create issues a new session token with the configured TTL.
func (s *SessionStore) Create() (Session, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return Session{}, fmt.Errorf("session token rand: %w", err)
	}
	token := hex.EncodeToString(b[:])
	sess := Session{Token: token, ExpiresAt: time.Now().Add(SessionTTL)}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Cap memory: if at limit, evict the oldest entry. Simple O(n) scan is
	// fine because MaxSessions is small and evictions are rare.
	if len(s.sessions) >= MaxSessions {
		var oldestToken string
		var oldestExpiry time.Time
		for tok, existing := range s.sessions {
			if oldestToken == "" || existing.ExpiresAt.Before(oldestExpiry) {
				oldestToken = tok
				oldestExpiry = existing.ExpiresAt
			}
		}
		delete(s.sessions, oldestToken)
	}

	s.sessions[token] = sess
	return sess, nil
}

// Validate returns true iff the provided token exists and is not expired.
// Expired tokens are lazily removed.
func (s *SessionStore) Validate(token string) bool {
	if token == "" {
		return false
	}
	s.mu.RLock()
	sess, ok := s.sessions[token]
	s.mu.RUnlock()
	if !ok {
		return false
	}
	if time.Now().After(sess.ExpiresAt) {
		s.mu.Lock()
		delete(s.sessions, token)
		s.mu.Unlock()
		return false
	}
	return true
}

// Count returns the number of active sessions (for testing).
func (s *SessionStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}

// Destroy removes a session token.
func (s *SessionStore) Destroy(token string) {
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
}

// loginRequest is the POST body for /auth/login.
type loginRequest struct {
	APIKey string `json:"api_key"`
}

// loginResponse is returned from a successful /auth/login.
type loginResponse struct {
	CSRFToken string `json:"csrf_token"`
	ExpiresAt string `json:"expires_at"`
}

// handleLogin validates the submitted API key and issues a session cookie.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.cfg.APIKey == "" {
		http.Error(w, "login disabled: server has no API key configured", http.StatusServiceUnavailable)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if subtle.ConstantTimeCompare([]byte(req.APIKey), []byte(s.cfg.APIKey)) != 1 {
		http.Error(w, "invalid api key", http.StatusUnauthorized)
		return
	}

	sess, err := s.sessions.Create()
	if err != nil {
		http.Error(w, "session creation failed", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    sess.Token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   r.TLS != nil || s.cfg.TLSTerminatedUpstream,
		Expires:  sess.ExpiresAt,
	})
	// JS-readable companion cookie so the dashboard can attach X-CSRF-Token.
	http.SetCookie(w, &http.Cookie{
		Name:     CSRFCookieName,
		Value:    sess.Token,
		Path:     "/",
		HttpOnly: false,
		SameSite: http.SameSiteStrictMode,
		Secure:   r.TLS != nil || s.cfg.TLSTerminatedUpstream,
		Expires:  sess.ExpiresAt,
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(loginResponse{
		CSRFToken: sess.Token,
		ExpiresAt: sess.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

// handleLogout destroys the current session.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if c, err := r.Cookie(SessionCookieName); err == nil {
		s.sessions.Destroy(c.Value)
	}
	for _, name := range []string{SessionCookieName, CSRFCookieName} {
		http.SetCookie(w, &http.Cookie{
			Name:    name,
			Value:   "",
			Path:    "/",
			Expires: time.Unix(0, 0),
			MaxAge:  -1,
		})
	}
	w.WriteHeader(http.StatusNoContent)
}

// sessionToken pulls the session cookie value, or "" if missing.
func sessionToken(r *http.Request) string {
	c, err := r.Cookie(SessionCookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

// bearerToken extracts the Bearer credential from the Authorization header.
func bearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(auth, "Bearer ")
}

// requireAuthOrSession protects an endpoint. A caller is allowed if EITHER:
//  1. They present a valid Bearer token matching the configured API key, OR
//  2. They have a valid session cookie. If requireCSRF is true (state-changing
//     requests), they must ALSO present a matching X-CSRF-Token header whose
//     value equals the session cookie value (double-submit cookie).
//
// When apiKey is empty the endpoint is unauthenticated (matching the
// historical behavior of --api-key unset).
func requireAuthOrSession(apiKey string, store *SessionStore, requireCSRF bool, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if apiKey == "" {
			next(w, r)
			return
		}

		// 1) Bearer token path.
		if tok := bearerToken(r); tok != "" {
			if subtle.ConstantTimeCompare([]byte(tok), []byte(apiKey)) == 1 {
				next(w, r)
				return
			}
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// 2) Session cookie path.
		tok := sessionToken(r)
		if !store.Validate(tok) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if requireCSRF {
			csrf := r.Header.Get(CSRFHeaderName)
			if subtle.ConstantTimeCompare([]byte(csrf), []byte(tok)) != 1 {
				http.Error(w, "CSRF token mismatch", http.StatusForbidden)
				return
			}
		}
		next(w, r)
	}
}
