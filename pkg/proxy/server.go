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

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/notify"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
	"github.com/Caua-ferraz/AgentGuard/pkg/ratelimit"
)

// Config holds the server configuration.
type Config struct {
	Port             int
	Engine           *policy.Engine
	Logger           audit.Logger
	DashboardEnabled bool
	Notifier         *notify.Dispatcher
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
	limiter  *ratelimit.Limiter
}

// ApprovalQueue manages pending approval requests.
type ApprovalQueue struct {
	mu       sync.RWMutex
	pending  map[string]*PendingAction
	watchers []chan AuditEvent
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

// AuditEvent is sent over SSE to dashboard clients for any check result.
type AuditEvent struct {
	Type      string               `json:"type"` // "check", "approval", "resolved"
	Timestamp time.Time            `json:"timestamp"`
	Request   policy.ActionRequest `json:"request"`
	Result    policy.CheckResult   `json:"result"`
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
		limiter: ratelimit.New(),
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
		mux.HandleFunc("/api/stats", s.handleStats)
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
	if err := s.http.Shutdown(ctx); err != nil {
		log.Printf("Shutdown error: %v", err)
	}
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

	// Rate limiting check (before policy evaluation)
	if rlCfg := s.cfg.Engine.RateLimitConfig(req.Scope, req.AgentID); rlCfg != nil {
		window, err := ratelimit.ParseWindow(rlCfg.Window)
		if err == nil {
			key := fmt.Sprintf("%s:%s", req.Scope, req.AgentID)
			if err := s.limiter.Allow(key, rlCfg.MaxRequests, window); err != nil {
				result := policy.CheckResult{
					Decision: policy.Deny,
					Reason:   err.Error(),
					Rule:     "deny:ratelimit:" + req.Scope,
				}
				s.logAndRespond(w, req, result, start)
				return
			}
		}
	}

	result := s.cfg.Engine.Check(req)

	// If approval required, queue it
	if result.Decision == policy.RequireApproval {
		pending := s.approval.Add(req, result)
		result.ApprovalID = pending.ID
		result.ApprovalURL = fmt.Sprintf("http://localhost:%d/v1/approve/%s", s.cfg.Port, pending.ID)

		// Send notification
		if s.cfg.Notifier != nil {
			s.cfg.Notifier.Send(notify.Event{
				Type:        "approval_required",
				Timestamp:   time.Now().UTC(),
				Request:     req,
				Result:      result,
				ApprovalURL: result.ApprovalURL,
			})
		}
	}

	// Notify on deny
	if result.Decision == policy.Deny && s.cfg.Notifier != nil {
		s.cfg.Notifier.Send(notify.Event{
			Type:      "denied",
			Timestamp: time.Now().UTC(),
			Request:   req,
			Result:    result,
		})
	}

	s.logAndRespond(w, req, result, start)
}

func (s *Server) logAndRespond(w http.ResponseWriter, req policy.ActionRequest, result policy.CheckResult, start time.Time) {
	duration := time.Since(start)

	entry := audit.Entry{
		Timestamp:  time.Now().UTC(),
		AgentID:    req.AgentID,
		SessionID:  req.SessionID,
		Request:    req,
		Result:     result,
		DurationMs: duration.Milliseconds(),
	}
	if err := s.cfg.Logger.Log(entry); err != nil {
		log.Printf("Audit log error: %v", err)
	}

	// Push to SSE watchers
	s.approval.Broadcast(AuditEvent{
		Type:      "check",
		Timestamp: entry.Timestamp,
		Request:   req,
		Result:    result,
	})

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		log.Printf("Response encode error: %v", err)
	}
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
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "approved", "id": id})
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
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "denied", "id": id})
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
	_ = json.NewEncoder(w).Encode(entries)
}

// handleHealth returns server health status.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": "0.2.0"})
}

// handleStats returns aggregate statistics for the dashboard.
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	entries, err := s.cfg.Logger.Query(audit.QueryFilter{Limit: 10000})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	total := len(entries)
	allowed := 0
	denied := 0
	approvals := 0
	for _, e := range entries {
		switch e.Result.Decision {
		case policy.Allow:
			allowed++
		case policy.Deny:
			denied++
		case policy.RequireApproval:
			approvals++
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]int{
		"total":     total,
		"allowed":   allowed,
		"denied":    denied,
		"approvals": approvals,
	})
}

// handleDashboard serves the web dashboard.
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, dashboardHTML)
}

// handlePendingList returns pending approval actions.
func (s *Server) handlePendingList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.approval.List())
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
		case event := <-ch:
			data, _ := json.Marshal(event)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

// handleStatus returns the current state of a pending approval request.
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
		_ = json.NewEncoder(w).Encode(map[string]string{
			"id":       id,
			"decision": pa.Decision,
			"status":   "resolved",
		})
	} else {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"id":     id,
			"status": "pending",
		})
	}
}

// ApprovalQueue methods

func (q *ApprovalQueue) Add(req policy.ActionRequest, result policy.CheckResult) *PendingAction {
	q.mu.Lock()
	defer q.mu.Unlock()

	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
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

	// Broadcast resolution to SSE clients
	q.broadcast(AuditEvent{
		Type:      "resolved",
		Timestamp: time.Now().UTC(),
		Request:   pa.Request,
		Result:    policy.CheckResult{Decision: decision, Reason: "manually " + strings.ToLower(string(decision))},
	})

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

func (q *ApprovalQueue) Subscribe() chan AuditEvent {
	q.mu.Lock()
	defer q.mu.Unlock()
	ch := make(chan AuditEvent, 64)
	q.watchers = append(q.watchers, ch)
	return ch
}

func (q *ApprovalQueue) Unsubscribe(ch chan AuditEvent) {
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

// Broadcast sends an event to all SSE subscribers (public, acquires lock).
func (q *ApprovalQueue) Broadcast(event AuditEvent) {
	q.mu.RLock()
	defer q.mu.RUnlock()
	q.broadcastLocked(event)
}

// broadcast sends without acquiring the lock (caller must hold it).
func (q *ApprovalQueue) broadcast(event AuditEvent) {
	q.broadcastLocked(event)
}

func (q *ApprovalQueue) broadcastLocked(event AuditEvent) {
	for _, ch := range q.watchers {
		select {
		case ch <- event:
		default:
			// Drop if consumer is slow
		}
	}
}

// Middleware

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

// Embedded dashboard HTML
var dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>AgentGuard Dashboard</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, 'SF Mono', 'Fira Code', monospace; background: #0a0a0a; color: #e0e0e0; }
    .header { padding: 20px 32px; border-bottom: 1px solid #222; display: flex; align-items: center; gap: 16px; }
    .header h1 { font-size: 18px; color: #fff; }
    .header .badge { background: #1a3a1a; color: #4ade80; padding: 4px 12px; border-radius: 100px; font-size: 12px; }
    .stats { display: flex; gap: 16px; padding: 20px 32px; border-bottom: 1px solid #222; }
    .stat-card { background: #111; border: 1px solid #222; border-radius: 8px; padding: 16px 20px; flex: 1; }
    .stat-card .label { font-size: 11px; color: #666; text-transform: uppercase; letter-spacing: 1px; }
    .stat-card .value { font-size: 28px; font-weight: bold; color: #fff; margin-top: 4px; }
    .stat-card.allowed .value { color: #4ade80; }
    .stat-card.denied .value { color: #f87171; }
    .stat-card.pending .value { color: #fbbf24; }
    .content { display: grid; grid-template-columns: 1fr 400px; height: calc(100vh - 170px); }
    .feed { padding: 20px; overflow-y: auto; }
    .sidebar { border-left: 1px solid #222; padding: 20px; overflow-y: auto; }
    .entry { padding: 12px 16px; border-radius: 8px; margin-bottom: 8px; border: 1px solid #222; transition: background 0.2s; }
    .entry:hover { background: #111; }
    .entry.ALLOW { border-left: 3px solid #4ade80; }
    .entry.DENY { border-left: 3px solid #f87171; }
    .entry.REQUIRE_APPROVAL { border-left: 3px solid #fbbf24; }
    .entry .decision { font-size: 11px; font-weight: bold; letter-spacing: 0.5px; }
    .entry .decision.ALLOW { color: #4ade80; }
    .entry .decision.DENY { color: #f87171; }
    .entry .decision.REQUIRE_APPROVAL { color: #fbbf24; }
    .entry .action { font-size: 13px; margin-top: 4px; }
    .entry .meta { font-size: 11px; color: #666; margin-top: 4px; }
    h2 { font-size: 13px; margin-bottom: 16px; color: #888; text-transform: uppercase; letter-spacing: 1px; }
    .pending-item { background: #1a1500; border: 1px solid #332800; border-radius: 8px; padding: 14px; margin-bottom: 10px; }
    .pending-item .info { font-size: 13px; margin-bottom: 8px; }
    .pending-item .scope-badge { background: #222; color: #fbbf24; padding: 2px 8px; border-radius: 4px; font-size: 11px; }
    .pending-item .actions { display: flex; gap: 8px; margin-top: 10px; }
    .btn { padding: 6px 16px; border-radius: 6px; border: none; cursor: pointer; font-size: 12px; font-weight: 600; }
    .btn-approve { background: #166534; color: #4ade80; }
    .btn-approve:hover { background: #15803d; }
    .btn-deny { background: #7f1d1d; color: #f87171; }
    .btn-deny:hover { background: #991b1b; }
    .empty { color: #444; text-align: center; padding: 48px; }
  </style>
</head>
<body>
  <div class="header">
    <h1>AgentGuard</h1>
    <span class="badge" id="status-badge">&#x25cf; LIVE</span>
  </div>
  <div class="stats">
    <div class="stat-card"><div class="label">Total Checks</div><div class="value" id="stat-total">0</div></div>
    <div class="stat-card allowed"><div class="label">Allowed</div><div class="value" id="stat-allowed">0</div></div>
    <div class="stat-card denied"><div class="label">Denied</div><div class="value" id="stat-denied">0</div></div>
    <div class="stat-card pending"><div class="label">Pending Approval</div><div class="value" id="stat-approvals">0</div></div>
  </div>
  <div class="content">
    <div class="feed">
      <h2>Action Feed</h2>
      <div id="feed"><div class="empty">Waiting for agent actions...</div></div>
    </div>
    <div class="sidebar">
      <h2>Pending Approvals</h2>
      <div id="pending"><div class="empty">None</div></div>
    </div>
  </div>
  <script>
    const feed = document.getElementById('feed');
    const pendingEl = document.getElementById('pending');

    // Load stats
    function refreshStats() {
      fetch('/api/stats').then(r => r.json()).then(s => {
        document.getElementById('stat-total').textContent = s.total;
        document.getElementById('stat-allowed').textContent = s.allowed;
        document.getElementById('stat-denied').textContent = s.denied;
        document.getElementById('stat-approvals').textContent = s.approvals;
      }).catch(() => {});
    }
    refreshStats();
    setInterval(refreshStats, 5000);

    // Load pending
    function refreshPending() {
      fetch('/api/pending').then(r => r.json()).then(items => {
        if (!items || items.length === 0) {
          pendingEl.innerHTML = '<div class="empty">None</div>';
          return;
        }
        pendingEl.innerHTML = '';
        items.forEach(item => {
          const action = item.request.command || item.request.path || item.request.domain || 'unknown';
          const div = document.createElement('div');
          div.className = 'pending-item';
          div.innerHTML =
            '<div class="info"><span class="scope-badge">' + item.request.scope + '</span> ' + action + '</div>' +
            '<div style="font-size:11px;color:#888">Agent: ' + (item.request.agent_id || 'unknown') +
            ' &bull; ' + new Date(item.created_at).toLocaleTimeString() + '</div>' +
            '<div class="actions">' +
            '<button class="btn btn-approve" onclick="resolve(\'' + item.id + '\', \'approve\')">Approve</button>' +
            '<button class="btn btn-deny" onclick="resolve(\'' + item.id + '\', \'deny\')">Deny</button>' +
            '</div>';
          pendingEl.appendChild(div);
        });
      }).catch(() => {});
    }
    refreshPending();

    // Approve / Deny from dashboard
    function resolve(id, action) {
      fetch('/v1/' + action + '/' + id, { method: 'POST' })
        .then(() => { refreshPending(); refreshStats(); })
        .catch(e => console.error(e));
    }

    // SSE live feed
    const es = new EventSource('/api/stream');
    es.onmessage = (e) => {
      const data = JSON.parse(e.data);
      const decision = data.result ? data.result.decision : data.type;
      const action = (data.request.command || data.request.path || data.request.domain || 'unknown');

      const el = document.createElement('div');
      el.className = 'entry ' + decision;
      el.innerHTML =
        '<div class="decision ' + decision + '">' + decision + '</div>' +
        '<div class="action">' + data.request.scope + ': ' + action + '</div>' +
        '<div class="meta">Agent: ' + (data.request.agent_id || 'unknown') +
        ' &bull; ' + new Date(data.timestamp).toLocaleTimeString() +
        (data.result && data.result.reason ? ' &bull; ' + data.result.reason : '') + '</div>';

      feed.querySelector('.empty')?.remove();
      feed.prepend(el);

      // Keep feed at 200 entries max
      while (feed.children.length > 200) feed.removeChild(feed.lastChild);

      refreshStats();
      if (decision === 'REQUIRE_APPROVAL' || data.type === 'resolved') refreshPending();
    };
    es.onerror = () => {
      document.getElementById('status-badge').textContent = '&#x25cf; DISCONNECTED';
      document.getElementById('status-badge').style.color = '#f87171';
      document.getElementById('status-badge').style.background = '#3a1a1a';
    };
  </script>
</body>
</html>`
