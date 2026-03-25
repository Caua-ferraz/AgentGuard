package proxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/yourname/agentguard/pkg/audit"
	"github.com/yourname/agentguard/pkg/policy"
)

// Config holds the server configuration.
type Config struct {
	Port             int
	Engine           *policy.Engine
	Logger           audit.Logger
	DashboardEnabled bool
	// APIKey protects the approve/deny endpoints. If empty, a warning is
	// logged and the endpoints are open (suitable for localhost-only deployments).
	APIKey string
	// AllowedOrigin is returned in Access-Control-Allow-Origin. Defaults to
	// localhost only. Set to a specific origin or leave empty for localhost.
	AllowedOrigin string
}

// Server is the AgentGuard HTTP proxy.
type Server struct {
	cfg      Config
	http     *http.Server
	approval *ApprovalQueue
}

// ApprovalQueue manages pending approval requests.
type ApprovalQueue struct {
	mu       sync.RWMutex
	pending  map[string]*PendingAction
	watchers []chan PendingAction
}

// PendingAction is an action waiting for human approval.
type PendingAction struct {
	ID        string               `json:"id"`
	Request   policy.ActionRequest `json:"request"`
	Result    policy.CheckResult   `json:"result"`
	CreatedAt time.Time            `json:"created_at"`
	Resolved  bool                 `json:"resolved"`
	Decision  string               `json:"decision,omitempty"`
	response  chan policy.Decision
}

// NewServer creates a new proxy server.
func NewServer(cfg Config) *Server {
	if cfg.APIKey == "" {
		log.Println("WARNING: no --api-key set; approve/deny endpoints are unauthenticated")
	}

	s := &Server{
		cfg: cfg,
		approval: &ApprovalQueue{
			pending: make(map[string]*PendingAction),
		},
	}

	mux := http.NewServeMux()

	// Core API
	mux.HandleFunc("/v1/check", s.handleCheck)
	mux.HandleFunc("/v1/approve/", requireAuth(cfg.APIKey, s.handleApprove))
	mux.HandleFunc("/v1/deny/", requireAuth(cfg.APIKey, s.handleDeny))
	mux.HandleFunc("/v1/status/", s.handleStatus)

	// Audit API
	mux.HandleFunc("/v1/audit", s.handleAuditQuery)

	// Health
	mux.HandleFunc("/health", s.handleHealth)

	// Dashboard
	if cfg.DashboardEnabled {
		mux.HandleFunc("/dashboard", s.handleDashboard)
		mux.HandleFunc("/api/pending", s.handlePendingList)
		mux.HandleFunc("/api/stream", s.handleEventStream)
	}

	s.http = &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Port),
		Handler: withCORS(cfg.AllowedOrigin)(withLogging(mux)),
	}

	return s
}

// Start begins listening for requests.
func (s *Server) Start() error {
	return s.http.ListenAndServe()
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s.http.Shutdown(ctx)
}

// handleCheck is the main policy enforcement endpoint.
func (s *Server) handleCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req policy.ActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}

	start := time.Now()
	result := s.cfg.Engine.Check(req)
	duration := time.Since(start)

	// Log to audit trail
	entry := audit.Entry{
		Timestamp:  time.Now().UTC(),
		AgentID:    req.AgentID,
		Request:    req,
		Result:     result,
		DurationMs: duration.Milliseconds(),
	}
	if err := s.cfg.Logger.Log(entry); err != nil {
		log.Printf("Audit log error: %v", err)
	}

	// If approval required, queue it
	if result.Decision == policy.RequireApproval {
		pending := s.approval.Add(req, result)
		result.ApprovalID = pending.ID
		result.ApprovalURL = fmt.Sprintf("http://localhost:%d/v1/approve/%s", s.cfg.Port, pending.ID)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// handleApprove approves a pending action.
func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Path[len("/v1/approve/"):]
	if err := s.approval.Resolve(id, policy.Allow); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "approved", "id": id})
}

// handleDeny denies a pending action.
func (s *Server) handleDeny(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Path[len("/v1/deny/"):]
	if err := s.approval.Resolve(id, policy.Deny); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "denied", "id": id})
}

// handleAuditQuery returns filtered audit log entries.
func (s *Server) handleAuditQuery(w http.ResponseWriter, r *http.Request) {
	filter := audit.QueryFilter{
		AgentID:   r.URL.Query().Get("agent_id"),
		SessionID: r.URL.Query().Get("session_id"),
		Decision:  r.URL.Query().Get("decision"),
		Scope:     r.URL.Query().Get("scope"),
		Limit:     100,
	}

	entries, err := s.cfg.Logger.Query(filter)
	if err != nil {
		http.Error(w, fmt.Sprintf("Query error: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries)
}

// handleHealth returns server health status.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// handleDashboard serves the web dashboard.
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, dashboardHTML)
}

// handlePendingList returns pending approval actions.
func (s *Server) handlePendingList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.approval.List())
}

// handleEventStream is a Server-Sent Events endpoint for live updates.
func (s *Server) handleEventStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := s.approval.Subscribe()
	defer s.approval.Unsubscribe(ch)

	for {
		select {
		case action := <-ch:
			data, _ := json.Marshal(action)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

// ApprovalQueue methods

func (q *ApprovalQueue) Add(req policy.ActionRequest, result policy.CheckResult) *PendingAction {
	q.mu.Lock()
	defer q.mu.Unlock()

	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Extremely unlikely; fall back to time-based id rather than panic
		log.Printf("crypto/rand failed, falling back: %v", err)
		b[0] = byte(time.Now().UnixNano())
	}
	id := "ap_" + hex.EncodeToString(b[:])
	pa := &PendingAction{
		ID:        id,
		Request:   req,
		Result:    result,
		CreatedAt: time.Now().UTC(),
		response:  make(chan policy.Decision, 1),
	}
	q.pending[id] = pa

	// Notify watchers
	for _, ch := range q.watchers {
		select {
		case ch <- *pa:
		default:
		}
	}

	return pa
}

func (q *ApprovalQueue) Resolve(id string, decision policy.Decision) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	pa, ok := q.pending[id]
	if !ok {
		return fmt.Errorf("pending action %s not found", id)
	}

	pa.Resolved = true
	pa.Decision = string(decision)
	pa.response <- decision
	return nil
}

func (q *ApprovalQueue) List() []*PendingAction {
	q.mu.RLock()
	defer q.mu.RUnlock()

	var list []*PendingAction
	for _, pa := range q.pending {
		if !pa.Resolved {
			list = append(list, pa)
		}
	}
	return list
}

func (q *ApprovalQueue) Subscribe() chan PendingAction {
	q.mu.Lock()
	defer q.mu.Unlock()
	ch := make(chan PendingAction, 16)
	q.watchers = append(q.watchers, ch)
	return ch
}

func (q *ApprovalQueue) Unsubscribe(ch chan PendingAction) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for i, w := range q.watchers {
		if w == ch {
			q.watchers = append(q.watchers[:i], q.watchers[i+1:]...)
			break
		}
	}
	close(ch)
}

// handleStatus returns the current state of a pending approval request.
// Polled by SDKs implementing wait_for_approval.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/v1/status/"):]
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}

	s.approval.mu.RLock()
	pa, ok := s.approval.pending[id]
	s.approval.mu.RUnlock()

	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if pa.Resolved {
		json.NewEncoder(w).Encode(map[string]string{
			"id":       id,
			"decision": pa.Decision,
			"status":   "resolved",
		})
	} else {
		json.NewEncoder(w).Encode(map[string]string{
			"id":     id,
			"status": "pending",
		})
	}
}

// Middleware

// requireAuth wraps a handler with API key authentication.
// If apiKey is empty the handler is invoked directly (localhost default).
func requireAuth(apiKey string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if apiKey == "" {
			next(w, r)
			return
		}
		auth := r.Header.Get("Authorization")
		if auth != "Bearer "+apiKey {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// withCORS adds CORS headers. Only reflects the Origin back if it is a
// localhost origin (or matches the configured AllowedOrigin). The old
// wildcard "*" is intentionally removed to prevent cross-origin abuse.
func withCORS(allowedOrigin string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" {
				allow := false
				if allowedOrigin != "" {
					allow = origin == allowedOrigin
				} else {
					allow = strings.HasPrefix(origin, "http://localhost:") ||
						strings.HasPrefix(origin, "http://127.0.0.1:")
				}
				if allow {
					w.Header().Set("Access-Control-Allow-Origin", origin)
				}
			}
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %v", r.Method, r.URL.Path, time.Since(start))
	})
}

// Embedded dashboard HTML (minimal — a real version would be in web/)
var dashboardHTML = `<!DOCTYPE html>
<html>
<head>
  <title>AgentGuard Dashboard</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'SF Mono', 'Fira Code', monospace; background: #0a0a0a; color: #e0e0e0; }
    .header { padding: 24px 32px; border-bottom: 1px solid #222; display: flex; align-items: center; gap: 16px; }
    .header h1 { font-size: 18px; color: #fff; }
    .header .badge { background: #1a3a1a; color: #4ade80; padding: 4px 12px; border-radius: 100px; font-size: 12px; }
    .content { display: grid; grid-template-columns: 1fr 380px; height: calc(100vh - 73px); }
    .feed { padding: 24px; overflow-y: auto; }
    .sidebar { border-left: 1px solid #222; padding: 24px; }
    .entry { padding: 12px 16px; border-radius: 8px; margin-bottom: 8px; border: 1px solid #222; }
    .entry.allow { border-left: 3px solid #4ade80; }
    .entry.deny { border-left: 3px solid #f87171; }
    .entry.approval { border-left: 3px solid #fbbf24; }
    .entry .meta { font-size: 11px; color: #666; margin-top: 4px; }
    .entry .action { font-size: 13px; }
    h2 { font-size: 14px; margin-bottom: 16px; color: #888; text-transform: uppercase; letter-spacing: 1px; }
    .stat { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #1a1a1a; }
    .stat .value { color: #fff; font-weight: bold; }
    .empty { color: #444; text-align: center; padding: 48px; }
  </style>
</head>
<body>
  <div class="header">
    <h1>AgentGuard</h1>
    <span class="badge">● LIVE</span>
  </div>
  <div class="content">
    <div class="feed" id="feed">
      <h2>Action Feed</h2>
      <div class="empty">Waiting for agent actions...</div>
    </div>
    <div class="sidebar">
      <h2>Pending Approvals</h2>
      <div id="pending" class="empty">None</div>
    </div>
  </div>
  <script>
    const feed = document.getElementById('feed');
    const es = new EventSource('/api/stream');
    es.onmessage = (e) => {
      const data = JSON.parse(e.data);
      const el = document.createElement('div');
      el.className = 'entry approval';

      const actionEl = document.createElement('div');
      actionEl.className = 'action';
      actionEl.textContent = data.request.scope + ': ' +
        (data.request.command || data.request.path || data.request.domain || 'unknown');

      const metaEl = document.createElement('div');
      metaEl.className = 'meta';
      metaEl.textContent = 'Agent: ' + (data.request.agent_id || 'unknown') + ' \u2022 Awaiting approval';

      el.appendChild(actionEl);
      el.appendChild(metaEl);
      feed.querySelector('.empty')?.remove();
      feed.appendChild(el);
    };
  </script>
</body>
</html>`
