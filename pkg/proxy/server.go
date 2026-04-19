package proxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/metrics"
	"github.com/Caua-ferraz/AgentGuard/pkg/notify"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
	"github.com/Caua-ferraz/AgentGuard/pkg/ratelimit"
)

const (
	// DefaultAuditQueryLimit is the entry count returned when the client does
	// not supply ?limit=.
	DefaultAuditQueryLimit = 100
	// MaxAuditQueryLimit is the hard ceiling on ?limit=. Clients asking for
	// more receive this many entries (silently clamped); the ceiling exists
	// so a client cannot request an unbounded scan of the audit file.
	MaxAuditQueryLimit = 1000
	// SSEChannelBufferSize is the buffer size for Server-Sent Events channels.
	SSEChannelBufferSize = 64
	// ApprovalIDPrefix is the prefix for generated approval IDs.
	ApprovalIDPrefix = "ap_"
	// ShutdownTimeout is the graceful shutdown deadline.
	ShutdownTimeout = 10 * time.Second
	// MaxRequestBodySize is the maximum allowed size of incoming request bodies (1 MB).
	MaxRequestBodySize = 1 << 20
	// MaxPendingApprovals is the maximum number of entries (pending + resolved) kept
	// in the approval queue. When at capacity, the oldest resolved entry is
	// evicted first (LRU); if every slot holds an unresolved entry, new
	// approvals are rejected with 503 rather than silently dropped.
	MaxPendingApprovals = 10000
	// ApprovalQueueFullRetryAfterSeconds is the Retry-After value returned
	// when the approval queue is full and no resolved entries are available
	// to evict. Operators tune MaxPendingApprovals or drain pending items;
	// clients should back off roughly this long before retrying.
	ApprovalQueueFullRetryAfterSeconds = 30
)

// ErrApprovalQueueFull is returned by ApprovalQueue.Add when the queue is at
// capacity and every entry is still unresolved. The HTTP handler maps this
// to 503 + Retry-After so the caller knows to back off rather than treating
// it as a generic 500.
var ErrApprovalQueueFull = errors.New("approval queue full: no resolved entries to evict")

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
	// BaseURL is the externally-reachable URL of this server, used to
	// construct approval URLs. Defaults to http://localhost:<Port>.
	BaseURL string
	// Version is the application version string shown in /health.
	Version string
	// TLSTerminatedUpstream tells the server that session cookies should be
	// issued with Secure set regardless of whether the incoming request has
	// r.TLS populated. Set this when AgentGuard runs behind a reverse proxy
	// that terminates TLS and does not forward X-Forwarded-Proto. Default
	// false preserves v0.4.0 behavior (cookie Secure keyed to r.TLS only).
	TLSTerminatedUpstream bool

	// SessionCostTTL bounds how long an idle session_id entry lingers in the
	// cost accumulator map. A periodic goroutine evicts entries whose last
	// write was more than TTL ago. Zero disables the sweep (v0.4.0 behavior:
	// entries accumulate for the process lifetime).
	SessionCostTTL time.Duration
	// SessionCostSweepInterval controls how often the sweeper runs. If zero
	// and SessionCostTTL > 0, it defaults to SessionCostTTL/4 with a floor
	// of 1 minute.
	SessionCostSweepInterval time.Duration

	// SessionTTL overrides the dashboard session cookie lifetime. Zero or
	// negative falls back to SessionTTL (the package-level default). Wired
	// from policy's proxy.session.ttl.
	SessionTTL time.Duration
	// MaxRequestBodyBytes overrides the POST /v1/check body cap. Zero or
	// negative falls back to MaxRequestBodySize. Wired from policy's
	// proxy.request.max_body_bytes.
	MaxRequestBodyBytes int64
	// AuditDefaultLimit overrides the default ?limit= on /v1/audit. Zero or
	// negative falls back to DefaultAuditQueryLimit. Wired from policy's
	// proxy.audit.default_limit.
	AuditDefaultLimit int
	// AuditMaxLimit overrides the hard ceiling on ?limit= for /v1/audit.
	// Zero or negative falls back to MaxAuditQueryLimit. Wired from
	// policy's proxy.audit.max_limit.
	AuditMaxLimit int
}

// Server is the AgentGuard HTTP proxy.
type Server struct {
	cfg      Config
	http     *http.Server
	approval *ApprovalQueue
	limiter  *ratelimit.Limiter
	sessions *SessionStore
	// sweeperDone signals the session-cost sweeper goroutine to stop.
	// Nil when the sweeper is not running. Closed exactly once via sweeperStop.
	sweeperDone chan struct{}
	sweeperStop sync.Once
	// Resolved tunables. Set once in NewServer from Config or package
	// defaults so the hot paths (handleCheck, handleAuditQuery) do not
	// re-evaluate fallbacks on every request.
	maxRequestBodyBytes int64
	auditDefaultLimit   int
	auditMaxLimit       int
}

// ApprovalQueue manages pending approval requests.
//
// maxSize caps the total number of entries (resolved + unresolved) so a
// spike of approval-required traffic with no operator around cannot exhaust
// memory. It is exposed as a field rather than a package const so tests can
// shrink it without faking 10 000 entries; production code always uses
// MaxPendingApprovals via NewServer.
type ApprovalQueue struct {
	mu       sync.RWMutex
	pending  map[string]*PendingAction
	watchers []chan AuditEvent
	maxSize  int
}

// PendingAction is an action waiting for human approval.
type PendingAction struct {
	ID        string               `json:"id"`
	Request   policy.ActionRequest `json:"request"`
	Result    policy.CheckResult   `json:"result"`
	CreatedAt time.Time            `json:"created_at"`
	Resolved  bool                 `json:"resolved"`
	Decision  string               `json:"decision,omitempty"`
}

// AuditEvent is sent over SSE to dashboard clients for any check result.
type AuditEvent struct {
	Type      string               `json:"type"` // "check", "approval", "resolved"
	Timestamp time.Time            `json:"timestamp"`
	Request   policy.ActionRequest `json:"request"`
	Result    policy.CheckResult   `json:"result"`
}

// auditHistoryAdapter bridges audit.Logger to policy.HistoryQuerier,
// avoiding a circular import between the audit and policy packages.
type auditHistoryAdapter struct {
	logger audit.Logger
}

func (a *auditHistoryAdapter) RecentActions(agentID string, scope string, since time.Time) ([]policy.HistoryEntry, error) {
	entries, err := a.logger.Query(audit.QueryFilter{
		AgentID: agentID,
		Scope:   scope,
		Since:   &since,
	})
	if err != nil {
		return nil, err
	}
	var result []policy.HistoryEntry
	for _, e := range entries {
		result = append(result, policy.HistoryEntry{
			Action:   e.Request.Action,
			Command:  e.Request.Command,
			Decision: policy.Decision(e.Result.Decision),
			EstCost:  e.Request.EstCost,
		})
	}
	return result, nil
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
			maxSize: MaxPendingApprovals,
		},
		limiter:             ratelimit.New(),
		sessions:            NewSessionStoreWithTTL(cfg.SessionTTL),
		maxRequestBodyBytes: resolveInt64(cfg.MaxRequestBodyBytes, MaxRequestBodySize),
		auditDefaultLimit:   resolveInt(cfg.AuditDefaultLimit, DefaultAuditQueryLimit),
		auditMaxLimit:       resolveInt(cfg.AuditMaxLimit, MaxAuditQueryLimit),
	}

	// Wire up history querier for conditional rule evaluation
	cfg.Engine.SetHistoryQuerier(&auditHistoryAdapter{logger: cfg.Logger})

	// Seed in-memory counters from the existing audit log so stats survive
	// restarts. A large audit file rescanned from scratch on every boot can
	// stall startup and delay /metrics accuracy, so when the Logger is a
	// FileLogger we persist a byte-offset checkpoint and resume from there.
	// Other Logger implementations (e.g. SQLiteLogger) fall back to a full
	// Query() — their scan cost is their own concern.
	type pathReporter interface{ Path() string }
	replayStart := time.Now()
	var replayed uint64
	if pr, ok := cfg.Logger.(pathReporter); ok && pr.Path() != "" {
		path := pr.Path()
		cp, cpErr := audit.ReadCheckpoint(path)
		if cpErr != nil {
			log.Printf("WARN: audit checkpoint read failed (%v); replaying full log", cpErr)
		}
		newOffset, err := audit.ReplayFrom(path, cp, func(e audit.Entry) {
			metrics.IncDecision(string(e.Result.Decision))
			replayed++
		})
		if err != nil {
			log.Printf("WARN: audit replay failed (%v); counters may be under-seeded", err)
		} else if newOffset > 0 {
			// Best-effort: a failed checkpoint write just means the next
			// boot re-scans. No need to surface the error at startup.
			_ = audit.WriteCheckpoint(path, audit.Checkpoint{
				Offset:    newOffset,
				AuditSize: newOffset,
			})
		}
	} else if existing, err := cfg.Logger.Query(audit.QueryFilter{}); err == nil {
		for _, e := range existing {
			metrics.IncDecision(string(e.Result.Decision))
			replayed++
		}
	}
	metrics.AddAuditReplayEntries(replayed)
	metrics.SetAuditReplayDuration(time.Since(replayStart))

	mux := http.NewServeMux()

	// Core API
	// /v1/check is intentionally open: it is the policy query endpoint called
	// by many agents, and the answer is not sensitive by itself. If you need
	// to gate it, run with --api-key and put /v1/check behind a reverse proxy.
	mux.HandleFunc("/v1/check", s.handleCheck)

	// State-changing endpoints: Bearer OR (session + CSRF).
	mux.HandleFunc("/v1/approve/", requireAuthOrSession(cfg.APIKey, s.sessions, true, s.handleApprove))
	mux.HandleFunc("/v1/deny/", requireAuthOrSession(cfg.APIKey, s.sessions, true, s.handleDeny))

	// Read endpoints that expose audit/status data: Bearer OR session (no CSRF needed for GET).
	mux.HandleFunc("/v1/status/", requireAuthOrSession(cfg.APIKey, s.sessions, false, s.handleStatus))
	mux.HandleFunc("/v1/audit", requireAuthOrSession(cfg.APIKey, s.sessions, false, s.handleAuditQuery))

	// Auth endpoints for dashboard login/logout.
	mux.HandleFunc("/auth/login", s.handleLogin)
	mux.HandleFunc("/auth/logout", s.handleLogout)

	// Health + Metrics (unauthenticated — commonly scraped by monitoring).
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/metrics", s.handleMetrics)

	// Dashboard — /dashboard itself returns login page when unauthenticated;
	// API subpaths are gated.
	if cfg.DashboardEnabled {
		mux.HandleFunc("/dashboard", s.handleDashboard)
		mux.HandleFunc("/api/pending", requireAuthOrSession(cfg.APIKey, s.sessions, false, s.handlePendingList))
		mux.HandleFunc("/api/stream", requireAuthOrSession(cfg.APIKey, s.sessions, false, s.handleEventStream))
		mux.HandleFunc("/api/stats", requireAuthOrSession(cfg.APIKey, s.sessions, false, s.handleStats))
	}

	addr := fmt.Sprintf(":%d", cfg.Port)
	if cfg.APIKey == "" {
		// Without an API key, bind to localhost only to prevent network-adjacent
		// attackers from approving/denying actions.
		addr = fmt.Sprintf("127.0.0.1:%d", cfg.Port)
		log.Printf("INFO: binding to %s (localhost only) — set --api-key to listen on all interfaces", addr)
	}

	s.http = &http.Server{
		Addr:              addr,
		Handler:           withCORS(cfg.AllowedOrigin)(withLogging(mux)),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Start the session-cost sweeper if TTL is configured.
	if cfg.SessionCostTTL > 0 {
		interval := cfg.SessionCostSweepInterval
		if interval <= 0 {
			interval = cfg.SessionCostTTL / 4
			if interval < time.Minute {
				interval = time.Minute
			}
		}
		s.sweeperDone = make(chan struct{})
		go s.runSessionCostSweeper(interval, cfg.SessionCostTTL)
	}

	return s
}

// runSessionCostSweeper periodically calls Engine.SweepSessionCosts until
// sweeperDone is closed. Evictions are logged at INFO when non-zero so
// operators can see the background work without grepping metrics.
func (s *Server) runSessionCostSweeper(interval, ttl time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-s.sweeperDone:
			return
		case <-t.C:
			if n := s.cfg.Engine.SweepSessionCosts(ttl); n > 0 {
				log.Printf("INFO: session-cost sweeper evicted %d entries (ttl=%s)", n, ttl)
			}
		}
	}
}

// Start begins listening for requests.
func (s *Server) Start() error {
	return s.http.ListenAndServe()
}

// Shutdown gracefully stops the server. Safe to call multiple times.
func (s *Server) Shutdown() {
	if s.sweeperDone != nil {
		s.sweeperStop.Do(func() { close(s.sweeperDone) })
	}
	ctx, cancel := context.WithTimeout(context.Background(), ShutdownTimeout)
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

	limit := s.maxRequestBodyBytes
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	var req policy.ActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Distinguish "body too large" from other parse errors so that the
		// enforcement of MaxRequestBodySize is observable. http.MaxBytesError
		// is the canonical error returned by MaxBytesReader when the limit
		// is hit (stdlib, Go 1.19+).
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			metrics.IncRequestRejected(metrics.RejectedBodyTooLarge)
			log.Printf("WARN: request body exceeds limit: remote=%s content_length=%d limit=%d",
				r.RemoteAddr, r.ContentLength, limit)
			http.Error(w, fmt.Sprintf("Request body too large (limit %d bytes)", limit), http.StatusRequestEntityTooLarge)
			return
		}
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
				metrics.IncRateLimited()
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

	evalStart := time.Now()
	result := s.cfg.Engine.Check(req)
	evalMs := float64(time.Since(evalStart).Microseconds()) / 1000.0
	metrics.PolicyEvalDuration.Observe(evalMs)

	// If approval required, queue it
	if result.Decision == policy.RequireApproval {
		pending, err := s.approval.Add(req, result)
		if err != nil {
			if errors.Is(err, ErrApprovalQueueFull) {
				// Tell the client this is a transient capacity problem, not
				// a permanent failure. Retry-After is advisory; tune via
				// ApprovalQueueFullRetryAfterSeconds or grow
				// MaxPendingApprovals if operators report repeated 503s.
				log.Printf("approval queue full: %d unresolved entries", s.approval.PendingCount())
				w.Header().Set("Retry-After", strconv.Itoa(ApprovalQueueFullRetryAfterSeconds))
				http.Error(w, "approval queue full; retry later", http.StatusServiceUnavailable)
				return
			}
			log.Printf("approval queue error: %v", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		result.ApprovalID = pending.ID
		result.ApprovalURL = fmt.Sprintf("%s/v1/approve/%s", s.cfg.BaseURL, pending.ID)

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

	// Cost reservation is atomic inside Engine.Check for cost-scoped allows,
	// so no post-hoc RecordCost call is needed (that would double-count).

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
	auditStart := time.Now()
	if err := s.cfg.Logger.Log(entry); err != nil {
		log.Printf("Audit log error: %v", err)
	}
	auditMs := float64(time.Since(auditStart).Microseconds()) / 1000.0
	metrics.AuditWriteDuration.Observe(auditMs)

	totalMs := float64(duration.Microseconds()) / 1000.0
	metrics.RequestDuration.Observe(totalMs)
	metrics.IncDecision(string(result.Decision))

	// Expose per-phase timing as response headers for easy curl inspection.
	w.Header().Set("X-AgentGuard-Policy-Ms", fmt.Sprintf("%.3f", totalMs-auditMs))
	w.Header().Set("X-AgentGuard-Audit-Ms", fmt.Sprintf("%.3f", auditMs))
	w.Header().Set("X-AgentGuard-Total-Ms", fmt.Sprintf("%.3f", totalMs))

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
//
// Query-string contract (stable as of v0.4.1):
//   - ?limit=N — integer in [1, MaxAuditQueryLimit]. Values above the ceiling
//     are clamped silently. Missing/empty uses DefaultAuditQueryLimit.
//     Non-integers or values < 1 return 400.
//   - ?offset=N — integer ≥ 0. Defaults to 0. Non-integers or negatives
//     return 400.
//
// Prior to v0.4.1 the handler ignored ?limit= and always passed 100.
func (s *Server) handleAuditQuery(w http.ResponseWriter, r *http.Request) {
	limit, err := parseBoundedInt(r.URL.Query().Get("limit"), s.auditDefaultLimit, 1, s.auditMaxLimit)
	if err != nil {
		http.Error(w, "invalid limit: "+err.Error(), http.StatusBadRequest)
		return
	}
	offset, err := parseBoundedInt(r.URL.Query().Get("offset"), 0, 0, -1)
	if err != nil {
		http.Error(w, "invalid offset: "+err.Error(), http.StatusBadRequest)
		return
	}

	filter := audit.QueryFilter{
		AgentID:   r.URL.Query().Get("agent_id"),
		SessionID: r.URL.Query().Get("session_id"),
		Decision:  r.URL.Query().Get("decision"),
		Scope:     r.URL.Query().Get("scope"),
		Limit:     limit,
		Offset:    offset,
	}

	entries, err := s.cfg.Logger.Query(filter)
	if err != nil {
		http.Error(w, fmt.Sprintf("Query error: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(entries)
}

// parseBoundedInt parses an optional query-string integer.
//
//   - An empty raw value returns defaultVal, no error.
//   - A non-integer returns an error (handler should map to 400).
//   - min is the inclusive lower bound. Values below min return an error.
//   - max is the inclusive upper bound. Values above max are clamped to max
//     (silently), not rejected. Pass max=-1 for no upper bound.
//
// The asymmetry — reject below, clamp above — matches how operators expect
// these knobs to behave: a negative limit is a bug, a huge limit is usually
// "give me all of them" and we want a safe ceiling rather than a 400.
// resolveInt returns override when strictly positive, otherwise fallback.
// Used to flatten policy-driven tunables into effective runtime values at
// server construction so request-path code does not branch per call.
func resolveInt(override, fallback int) int {
	if override > 0 {
		return override
	}
	return fallback
}

func resolveInt64(override, fallback int64) int64 {
	if override > 0 {
		return override
	}
	return fallback
}

func parseBoundedInt(raw string, defaultVal, minVal, maxVal int) (int, error) {
	if raw == "" {
		return defaultVal, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("not an integer: %q", raw)
	}
	if n < minVal {
		return 0, fmt.Errorf("value %d below minimum %d", n, minVal)
	}
	if maxVal >= 0 && n > maxVal {
		return maxVal, nil
	}
	return n, nil
}

// handleHealth returns server health status.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": s.cfg.Version})
}

// handleMetrics serves Prometheus-compatible metrics in text format.
// Scrape with: curl http://localhost:8080/metrics
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	// PendingCount counts under RLock without allocating a slice — matters
	// because this endpoint is scraped on a schedule.
	metrics.SetPendingApprovals(s.approval.PendingCount())
	// Refresh the rate-limit bucket gauge from the limiter; BucketCount()
	// takes the limiter lock for a single len() read.
	metrics.SetRateLimitBuckets(s.limiter.BucketCount())
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	metrics.WritePrometheus(w)
}

// handleStats returns aggregate statistics for the dashboard.
// Reads from in-memory atomic counters (O(1)) rather than scanning the audit
// file, so it stays accurate regardless of how large the log grows.
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]uint64{
		"total":     atomic.LoadUint64(&metrics.ChecksTotal),
		"allowed":   atomic.LoadUint64(&metrics.AllowedTotal),
		"denied":    atomic.LoadUint64(&metrics.DeniedTotal),
		"approvals": atomic.LoadUint64(&metrics.ApprovalTotal),
	})
}

// handleDashboard serves the web dashboard.
//
// Authentication model:
//   - When --api-key is empty, the dashboard is freely accessible (historical
//     localhost-only mode).
//   - When --api-key is set, the user must first POST their key to /auth/login
//     which issues an HTTP-only session cookie. Without a valid session, we
//     serve a login form; never the actual dashboard.
//
// The API key is NEVER embedded in the HTML response.
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")

	if s.cfg.APIKey != "" && !s.sessions.Validate(sessionToken(r)) {
		fmt.Fprint(w, loginHTML)
		return
	}
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
	w.Header().Set("X-Accel-Buffering", "no") // disable nginx proxy buffering

	// Flush headers immediately so clients (browser EventSource, test code,
	// reverse proxies) see 200 OK and the content-type before any event
	// arrives. Without this, a slow-traffic channel leaves the client
	// blocked on the response-headers read until the first event, which
	// also means EventSource.onopen never fires until activity starts.
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

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

// Add registers a new pending approval. If the queue is at capacity the
// oldest resolved entry is evicted first (LRU on CreatedAt; resolution does
// not rewind it, so the eviction target is the entry that has been around
// the longest). If every slot is still unresolved, Add returns
// ErrApprovalQueueFull and the caller is expected to surface 503 +
// Retry-After — silently dropping the request would leave the agent
// waiting forever on an ID that does not exist.
func (q *ApprovalQueue) Add(req policy.ActionRequest, result policy.CheckResult) (*PendingAction, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	cap := q.maxSize
	if cap <= 0 {
		cap = MaxPendingApprovals
	}
	if len(q.pending) >= cap {
		if !q.evictOldestResolvedLocked() {
			metrics.IncApprovalEvicted(metrics.ApprovalEvictedQueueFull)
			return nil, ErrApprovalQueueFull
		}
		metrics.IncApprovalEvicted(metrics.ApprovalEvictedLRUResolved)
	}

	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, fmt.Errorf("crypto/rand failed — cannot generate secure approval IDs: %w", err)
	}
	id := ApprovalIDPrefix + hex.EncodeToString(b[:])
	pa := &PendingAction{
		ID:        id,
		Request:   req,
		Result:    result,
		CreatedAt: time.Now().UTC(),
	}
	q.pending[id] = pa

	return pa, nil
}

// evictOldestResolvedLocked drops exactly one entry: the resolved entry with
// the earliest CreatedAt. Returns true when something was evicted, false
// when every entry is still unresolved. The linear scan is O(n), but n is
// capped at maxSize and eviction only fires when Add hits the cap — not on
// the hot path of normal traffic.
//
// Must be called with q.mu held.
func (q *ApprovalQueue) evictOldestResolvedLocked() bool {
	var oldestID string
	var oldestCreated time.Time
	for id, pa := range q.pending {
		if !pa.Resolved {
			continue
		}
		if oldestID == "" || pa.CreatedAt.Before(oldestCreated) {
			oldestID = id
			oldestCreated = pa.CreatedAt
		}
	}
	if oldestID == "" {
		return false
	}
	delete(q.pending, oldestID)
	return true
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

// PendingCount returns the number of unresolved pending actions without
// allocating. Intended for metrics/health endpoints that just need the count.
func (q *ApprovalQueue) PendingCount() int {
	q.mu.RLock()
	defer q.mu.RUnlock()
	n := 0
	for _, pa := range q.pending {
		if !pa.Resolved {
			n++
		}
	}
	return n
}

func (q *ApprovalQueue) Subscribe() chan AuditEvent {
	q.mu.Lock()
	defer q.mu.Unlock()
	ch := make(chan AuditEvent, SSEChannelBufferSize)
	q.watchers = append(q.watchers, ch)
	metrics.IncSSESubscribers()
	return ch
}

func (q *ApprovalQueue) Unsubscribe(ch chan AuditEvent) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for i, w := range q.watchers {
		if w == ch {
			q.watchers = append(q.watchers[:i], q.watchers[i+1:]...)
			metrics.DecSSESubscribers()
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
			// Drop if consumer is slow. The metric lets ops see which
			// deployments have backed-up SSE subscribers — a persistent
			// non-zero rate usually means a dashboard tab left open on
			// battery-throttled hardware.
			metrics.IncSSEEventDropped(metrics.SSEDroppedSlowConsumer)
		}
	}
}

// Middleware

// withCORS handles Origin reflection with two modes:
//
//  1. Strict (allowedOrigin != ""): reflect an Origin header ONLY when it
//     EXACTLY matches the configured AllowedOrigin. Use this in production
//     deployments where a specific frontend needs to talk to AgentGuard.
//
//  2. Permissive-localhost (allowedOrigin == ""): accept any
//     http://localhost:* or http://127.0.0.1:* origin. This is the historical
//     default and is retained for backward compatibility with local dev
//     frontends that predate --allowed-origin. It is safe because:
//     - the API key is NEVER embedded in the dashboard HTML;
//     - session cookies are SameSite=Strict (cross-origin requests don't
//       carry them);
//     - state-changing endpoints require a CSRF token that attackers on
//       other origins cannot read (double-submit cookie pattern).
//
// `Vary: Origin` is always set to prevent cached responses from leaking
// cross-origin.
func withCORS(allowedOrigin string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			w.Header().Add("Vary", "Origin")

			allow := false
			if origin != "" {
				if allowedOrigin != "" {
					// Strict mode: exact match only.
					allow = origin == allowedOrigin
				} else {
					// Permissive-localhost: match http://localhost:<port> or
					// http://127.0.0.1:<port>. We require the `:` so origins
					// like "http://localhost.evil.com" cannot slip through.
					allow = strings.HasPrefix(origin, "http://localhost:") ||
						strings.HasPrefix(origin, "http://127.0.0.1:") ||
						origin == "http://localhost" ||
						origin == "http://127.0.0.1"
				}
			}

			if allow {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, "+CSRFHeaderName)
			}
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
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
    <span class="badge" id="status-badge">● LIVE</span>
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
    const MAX_FEED_ENTRIES = 200;
    // CSRF token is sourced from a server-rendered cookie named ag_csrf on page
    // load. We no longer embed the API key in HTML.
    function getCsrf() {
      return (document.cookie.split('; ').find(c => c.startsWith('ag_csrf=')) || '').split('=')[1] || '';
    }

    // Escape HTML to prevent XSS when inserting user-controlled data.
    function esc(s) {
      const d = document.createElement('div');
      d.textContent = s;
      return d.innerHTML;
    }

    // Shared entry renderer used by both history load and live SSE.
    // entry shape: { request, result, timestamp } — works for both audit entries and SSE events.
    function renderEntry(entry) {
      const result = entry.result || {};
      const decision = result.decision || 'UNKNOWN';
      const req = entry.request || {};
      const action = req.command || req.path || req.domain || 'unknown';
      const el = document.createElement('div');
      el.className = 'entry ' + esc(decision);

      const decDiv = document.createElement('div');
      decDiv.className = 'decision ' + esc(decision);
      decDiv.textContent = decision;
      el.appendChild(decDiv);

      const actDiv = document.createElement('div');
      actDiv.className = 'action';
      actDiv.textContent = (req.scope || '') + ': ' + action;
      el.appendChild(actDiv);

      const metaDiv = document.createElement('div');
      metaDiv.className = 'meta';
      metaDiv.textContent = 'Agent: ' + (req.agent_id || 'unknown') +
        ' \u2022 ' + new Date(entry.timestamp).toLocaleTimeString() +
        (result.reason ? ' \u2022 ' + result.reason : '');
      el.appendChild(metaDiv);

      return el;
    }

    // Wrapper that adds credentials + redirects to login on 401/403.
    // 401: no/invalid session. 403: session ok but CSRF header mismatch —
    // usually means the session expired between reads and a state-changing
    // request; force the user through the login flow again.
    function agFetch(path, opts) {
      opts = opts || {};
      opts.credentials = 'same-origin';
      return fetch(path, opts).then(r => {
        if (r.status === 401 || r.status === 403) {
          location.href = '/dashboard';
          throw new Error('reauth');
        }
        return r;
      });
    }

    // Load stats
    function refreshStats() {
      agFetch('/api/stats').then(r => r.json()).then(s => {
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
      agFetch('/api/pending').then(r => r.json()).then(items => {
        if (!items || items.length === 0) {
          pendingEl.innerHTML = '<div class="empty">None</div>';
          return;
        }
        pendingEl.innerHTML = '';
        items.forEach(item => {
          const action = item.request.command || item.request.path || item.request.domain || 'unknown';
          const div = document.createElement('div');
          div.className = 'pending-item';

          const info = document.createElement('div');
          info.className = 'info';
          const badge = document.createElement('span');
          badge.className = 'scope-badge';
          badge.textContent = item.request.scope;
          info.appendChild(badge);
          info.appendChild(document.createTextNode(' ' + action));
          div.appendChild(info);

          const meta = document.createElement('div');
          meta.style.cssText = 'font-size:11px;color:#888';
          meta.textContent = 'Agent: ' + (item.request.agent_id || 'unknown') +
            ' \u2022 ' + new Date(item.created_at).toLocaleTimeString();
          div.appendChild(meta);

          const actions = document.createElement('div');
          actions.className = 'actions';
          const btnApprove = document.createElement('button');
          btnApprove.className = 'btn btn-approve';
          btnApprove.textContent = 'Approve';
          btnApprove.addEventListener('click', function() { resolve(item.id, 'approve'); });
          actions.appendChild(btnApprove);
          const btnDeny = document.createElement('button');
          btnDeny.className = 'btn btn-deny';
          btnDeny.textContent = 'Deny';
          btnDeny.addEventListener('click', function() { resolve(item.id, 'deny'); });
          actions.appendChild(btnDeny);
          div.appendChild(actions);

          pendingEl.appendChild(div);
        });
      }).catch(() => {});
    }
    refreshPending();

    // Approve / Deny from dashboard — sends session cookie + CSRF header.
    function resolve(id, action) {
      const csrf = getCsrf();
      const opts = { method: 'POST', headers: {} };
      if (csrf) opts.headers['X-CSRF-Token'] = csrf;
      agFetch('/v1/' + action + '/' + id, opts)
        .then(r => { if (!r.ok) throw new Error('HTTP ' + r.status); refreshPending(); refreshStats(); })
        .catch(e => {
          const errDiv = document.createElement('div');
          errDiv.style.cssText = 'background:#3a1a1a;color:#f87171;padding:8px 12px;border-radius:6px;margin:8px 0;font-size:13px';
          errDiv.textContent = action + ' failed: ' + e.message;
          pendingEl.prepend(errDiv);
          setTimeout(() => errDiv.remove(), 5000);
        });
    }

    // Load historical entries on page open so the feed isn't blank.
    // Fetches the last MAX_FEED_ENTRIES audit entries (newest-first after reversing).
    function loadHistory() {
      agFetch('/v1/audit?limit=' + MAX_FEED_ENTRIES)
        .then(r => r.json())
        .then(entries => {
          if (!entries || entries.length === 0) return;
          feed.querySelector('.empty')?.remove();
          // Audit entries come oldest-first; reverse so newest is at the top.
          entries.slice().reverse().forEach(entry => {
            feed.appendChild(renderEntry(entry));
          });
        })
        .catch(() => {});
    }
    loadHistory();

    // SSE live feed — prepends new events above the history.
    const es = new EventSource('/api/stream');
    es.onmessage = (e) => {
      const data = JSON.parse(e.data);
      feed.querySelector('.empty')?.remove();
      feed.prepend(renderEntry(data));

      // Keep feed at MAX_FEED_ENTRIES entries
      while (feed.children.length > MAX_FEED_ENTRIES) feed.removeChild(feed.lastChild);

      refreshStats();
      const decision = (data.result || {}).decision;
      if (decision === 'REQUIRE_APPROVAL' || data.type === 'resolved') refreshPending();
    };
    es.onopen = () => {
      const badge = document.getElementById('status-badge');
      badge.textContent = '● LIVE';
      badge.style.color = '#4ade80';
      badge.style.background = '#1a3a1a';
    };
    es.onerror = () => {
      const badge = document.getElementById('status-badge');
      if (es.readyState === 2) {
        badge.textContent = '● DISCONNECTED';
        badge.style.color = '#f87171';
        badge.style.background = '#3a1a1a';
      } else {
        badge.textContent = '● RECONNECTING...';
        badge.style.color = '#fbbf24';
        badge.style.background = '#1a1500';
      }
    };
  </script>
</body>
</html>`

// loginHTML is served from /dashboard when no valid session cookie exists
// (and APIKey is configured). It collects the API key via a POST to
// /auth/login; on success the server sets an HTTP-only session cookie and
// a JS-readable CSRF cookie, and the page redirects back to /dashboard.
var loginHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>AgentGuard — Sign in</title>
  <style>
    body { font-family: -apple-system, 'SF Mono', 'Fira Code', monospace; background: #0a0a0a; color: #e0e0e0; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
    .box { background: #111; border: 1px solid #222; border-radius: 10px; padding: 28px 32px; width: 360px; }
    h1 { font-size: 18px; margin: 0 0 4px; color: #fff; }
    p { font-size: 12px; color: #888; margin: 0 0 18px; }
    label { display: block; font-size: 11px; color: #888; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 6px; }
    input[type=password] { width: 100%; padding: 10px 12px; background: #000; border: 1px solid #333; border-radius: 6px; color: #fff; font-family: inherit; font-size: 14px; box-sizing: border-box; }
    button { margin-top: 14px; width: 100%; padding: 10px; border: none; border-radius: 6px; background: #166534; color: #4ade80; font-weight: 600; cursor: pointer; }
    button:hover { background: #15803d; }
    .err { color: #f87171; font-size: 12px; margin-top: 10px; min-height: 14px; }
  </style>
</head>
<body>
  <form class="box" id="f" autocomplete="off">
    <h1>AgentGuard</h1>
    <p>Sign in with the server API key.</p>
    <label for="k">API key</label>
    <input id="k" type="password" autocomplete="off" required>
    <button type="submit">Sign in</button>
    <div class="err" id="e"></div>
  </form>
  <script>
    const f = document.getElementById('f');
    const e = document.getElementById('e');
    f.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      e.textContent = '';
      const key = document.getElementById('k').value;
      try {
        const r = await fetch('/auth/login', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ api_key: key }),
        });
        if (!r.ok) {
          e.textContent = r.status === 401 ? 'Invalid API key' : ('Error: HTTP ' + r.status);
          return;
        }
        location.href = '/dashboard';
      } catch (err) {
        e.textContent = 'Network error: ' + err.message;
      }
    });
  </script>
</body>
</html>`
