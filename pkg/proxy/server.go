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
	"runtime/debug"
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
	// SchemaVersionV1 is the wire-protocol version emitted on every
	// /v1/check response and accepted on every /v1/check request. Clients
	// may omit the field on requests (defaults to v1); any other value is
	// rejected with HTTP 400. The full schema lives in
	// pkg/proxy/schema/v1/schema.json and is documented in
	// docs/WIRE_PROTOCOL.md.
	SchemaVersionV1 = "v1"
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
	// false keys cookie Secure to r.TLS only.
	TLSTerminatedUpstream bool

	// SessionCostTTL bounds how long an idle session_id entry lingers in the
	// cost accumulator map. A periodic goroutine evicts entries whose last
	// write was more than TTL ago. Zero disables the sweep — entries
	// accumulate for the process lifetime.
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

	// startedAt records process start time for the /v1/health
	// uptime_seconds field. Set once in NewServer; never mutated.
	startedAt time.Time
	// lastRequestAtNs is the unix-nanosecond timestamp of the most recent
	// HTTP request observed by withLogging. Atomic so /v1/health probes
	// (and any future health-derived gauges) read it without taking a
	// lock. Zero means "no traffic since boot".
	lastRequestAtNs int64
}

// noteRequest stamps the timestamp of the most recent HTTP request.
// Called from withLogging on every request, including health probes
// themselves. The wall-clock skew between the probe call and the stamp
// is sub-millisecond and irrelevant for the 5-minute staleness warning.
func (s *Server) noteRequest() {
	atomic.StoreInt64(&s.lastRequestAtNs, time.Now().UnixNano())
}

// LastRequestAt returns the wall-clock time of the most recent HTTP
// request, or the zero time if no request has been observed yet.
func (s *Server) LastRequestAt() time.Time {
	ns := atomic.LoadInt64(&s.lastRequestAtNs)
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
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
	watchers []sseWatcher
	maxSize  int
}

// sseWatcher is one SSE subscriber plus the tenant whose events it receives.
// A tenant-aware /v1/t/{tenant}/api/stream subscriber sees only that tenant's
// events; the legacy /api/stream subscriber resolves to LocalTenantID, so in a
// single-tenant deployment it behaves exactly as before. (There is no
// all-tenants firehose yet — that is a future explicit operator opt-in.)
type sseWatcher struct {
	ch     chan AuditEvent
	tenant string // normalized (non-empty); "" is coerced to LocalTenantID
}

// NewApprovalQueue creates an empty approval queue with the given capacity
// (maxSize <= 0 falls back to MaxPendingApprovals). Exposed so the persistence
// syncer and embedders can construct/reference a queue independently of a full
// Server; NewServer uses it internally too.
func NewApprovalQueue(maxSize int) *ApprovalQueue {
	if maxSize <= 0 {
		maxSize = MaxPendingApprovals
	}
	return &ApprovalQueue{pending: make(map[string]*PendingAction), maxSize: maxSize}
}

// PendingAction is an action waiting for human approval.
type PendingAction struct {
	ID string `json:"id"`
	// TenantID is the tenant that produced this approval. Lookup/Resolve/List
	// scope on it so one tenant can neither observe nor resolve another
	// tenant's pending actions. Empty ("local") is omitted on the wire so
	// single-tenant dashboard payloads stay byte-identical.
	TenantID  string               `json:"tenant_id,omitempty"`
	Request   policy.ActionRequest `json:"request"`
	Result    policy.CheckResult   `json:"result"`
	CreatedAt time.Time            `json:"created_at"`
	Resolved  bool                 `json:"resolved"`
	Decision  string               `json:"decision,omitempty"`
	// ResolvedAt is set when Resolve flips Resolved=true. It drives the durable
	// store's resolved-approval GC (PurgeResolvedApprovals). Zero while pending;
	// omitempty keeps single-tenant /api/pending payloads byte-stable.
	ResolvedAt time.Time `json:"resolved_at,omitempty"`
}

// AuditEvent is sent over SSE to dashboard clients for any check result.
//
// Transport identifies the integration path that produced the event
// ("sdk", "mcp_gateway", "llm_api_proxy"). Defaults to "sdk" on the wire
// when unset so dashboard JS does not need a fallback. Older SSE
// consumers see the field as an extra (ignored) JSON key.
//
// Tenant carries the owning tenant so broadcast can route the event only to
// subscribers of that tenant. Omitted on the wire for the default "local"
// tenant to keep single-tenant SSE payloads byte-identical.
type AuditEvent struct {
	Type      string               `json:"type"` // "check", "approval", "resolved"
	Timestamp time.Time            `json:"timestamp"`
	Tenant    string               `json:"tenant,omitempty"`
	Transport string               `json:"transport,omitempty"`
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
		cfg:                 cfg,
		approval:            NewApprovalQueue(MaxPendingApprovals),
		limiter:             ratelimit.New(),
		sessions:            NewSessionStoreWithTTL(cfg.SessionTTL),
		maxRequestBodyBytes: resolveInt64(cfg.MaxRequestBodyBytes, MaxRequestBodySize),
		auditDefaultLimit:   resolveInt(cfg.AuditDefaultLimit, DefaultAuditQueryLimit),
		auditMaxLimit:       resolveInt(cfg.AuditMaxLimit, MaxAuditQueryLimit),
		startedAt:           time.Now(),
	}

	// Wire up history querier for conditional rule evaluation
	cfg.Engine.SetHistoryQuerier(&auditHistoryAdapter{logger: cfg.Logger})

	// Seed in-memory counters from the existing audit log so stats survive
	// restarts. A large audit file rescanned from scratch on every boot can
	// stall startup and delay /metrics accuracy, so when the Logger is a
	// FileLogger we persist a byte-offset checkpoint and resume from there.
	// Other Logger implementations (e.g. the store-backed logger) fall back
	// to a full Query() — their scan cost is their own concern.
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

	// -----------------------------------------------------------------
	// Tenant-aware mirrors of every operational route.
	//
	// Layout: /v1/t/{tenant}/<suffix>. The withTenant middleware extracts
	// {tenant}, validates it via Engine.PolicyForTenant (404 on
	// ErrTenantNotFound), stamps it on the request context, then delegates
	// to the same handler the legacy /v1/<suffix> route uses. The default
	// FilePolicyProvider only recognises the "local" tenant; a future
	// database-backed PolicyProvider can resolve arbitrary tenant IDs.
	//
	// Auth posture mirrors the legacy routes exactly: /v1/t/{tenant}/check
	// is open (the policy query endpoint), every other tenant-aware route
	// requires Bearer OR session, and the state-changing approve/deny
	// routes additionally require CSRF when authenticated via session.
	//
	// Method-prefixed wildcard syntax is Go 1.22+; the Dockerfile pins
	// golang:1.22-alpine so this is safe.
	mux.HandleFunc("POST /v1/t/{tenant}/check", s.withTenant(s.handleCheck))
	mux.HandleFunc("POST /v1/t/{tenant}/approve/{id}",
		s.withTenant(requireAuthOrSession(cfg.APIKey, s.sessions, true, s.handleApprove)))
	mux.HandleFunc("POST /v1/t/{tenant}/deny/{id}",
		s.withTenant(requireAuthOrSession(cfg.APIKey, s.sessions, true, s.handleDeny)))
	mux.HandleFunc("GET /v1/t/{tenant}/status/{id}",
		s.withTenant(requireAuthOrSession(cfg.APIKey, s.sessions, false, s.handleStatus)))
	mux.HandleFunc("GET /v1/t/{tenant}/audit",
		s.withTenant(requireAuthOrSession(cfg.APIKey, s.sessions, false, s.handleAuditQuery)))

	// Auth endpoints for dashboard login/logout.
	mux.HandleFunc("/auth/login", s.handleLogin)
	mux.HandleFunc("/auth/logout", s.handleLogout)

	// Health + Metrics (unauthenticated — commonly scraped by monitoring).
	mux.HandleFunc("/health", s.handleHealth)
	// /v1/health is the operator-grade health endpoint (richer payload,
	// includes last-request and last-policy-load timestamps + warnings).
	// Anchored on the "local" tenant; the tenant-aware route below uses
	// the same handler with {tenant} extracted by withTenant.
	mux.HandleFunc("GET /v1/health", s.handleHealthV1Local)
	// Tenant-aware variant. Currently only "local" resolves; any other
	// tenant returns 404 until a multi-tenant PolicyProvider is wired.
	mux.HandleFunc("GET /v1/t/{tenant}/health", s.handleHealthV1Tenant)
	mux.HandleFunc("/metrics", s.handleMetrics)

	// Dashboard — /dashboard itself returns login page when unauthenticated;
	// API subpaths are gated.
	if cfg.DashboardEnabled {
		mux.HandleFunc("/dashboard", s.handleDashboard)
		mux.HandleFunc("/api/pending", requireAuthOrSession(cfg.APIKey, s.sessions, false, s.handlePendingList))
		mux.HandleFunc("/api/stream", requireAuthOrSession(cfg.APIKey, s.sessions, false, s.handleEventStream))
		mux.HandleFunc("/api/stats", requireAuthOrSession(cfg.APIKey, s.sessions, false, s.handleStats))

		// Tenant-aware mirrors of the dashboard data endpoints. The
		// dashboard HTML itself is intentionally NOT remapped to a
		// tenant-aware URL — there is one operator UI per AgentGuard
		// instance. SDK / CLI consumers that need per-tenant lists hit
		// these JSON endpoints.
		mux.HandleFunc("GET /v1/t/{tenant}/api/pending",
			s.withTenant(requireAuthOrSession(cfg.APIKey, s.sessions, false, s.handlePendingList)))
		mux.HandleFunc("GET /v1/t/{tenant}/api/stream",
			s.withTenant(requireAuthOrSession(cfg.APIKey, s.sessions, false, s.handleEventStream)))
		mux.HandleFunc("GET /v1/t/{tenant}/api/stats",
			s.withTenant(requireAuthOrSession(cfg.APIKey, s.sessions, false, s.handleStats)))
	}

	addr := fmt.Sprintf(":%d", cfg.Port)
	if cfg.APIKey == "" {
		// Without an API key, bind to localhost only to prevent network-adjacent
		// attackers from approving/denying actions.
		addr = fmt.Sprintf("127.0.0.1:%d", cfg.Port)
		log.Printf("INFO: binding to %s (localhost only) — set --api-key to listen on all interfaces", addr)
	}

	s.http = &http.Server{
		Addr: addr,
		// Middleware order (outermost first): recoverPanic catches handler
		// panics so a single bad request never tears the server down;
		// withCORS runs next so a panicking handler still returns a CORS
		// header pair via the recovered 500; withTraffic stamps
		// lastRequestAtNs (used by /v1/health); withLogging is innermost
		// so the recovered duration includes the panic path.
		Handler:           recoverPanic(withCORS(cfg.AllowedOrigin)(s.withTraffic(withLogging(mux)))),
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
		// goRecover guarantees a panic inside SweepSessionCosts (or any
		// future code reachable from the sweeper) logs and dies in
		// isolation rather than tearing the whole process down.
		goRecover("session-cost-sweeper", func() {
			s.runSessionCostSweeper(interval, cfg.SessionCostTTL)
		})
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

// Handler returns the fully wired http.Handler (recoverPanic → withCORS →
// withTraffic → withLogging → mux). Exposed for embedders and integration
// tests that want to drive the server through httptest.NewServer rather
// than binding a real port. Stable contract — callers should NOT inspect
// or wrap individual middleware.
func (s *Server) Handler() http.Handler {
	return s.http.Handler
}

// ApprovalQueue returns the server's in-memory approval queue. Exposed so the
// persistence syncer can snapshot/restore it; callers must not mutate queue
// internals directly (use the queue's own methods).
func (s *Server) ApprovalQueue() *ApprovalQueue { return s.approval }

// Limiter returns the server's in-memory rate limiter, exposed for the
// persistence syncer's snapshot/restore. Not for request-path use.
func (s *Server) Limiter() *ratelimit.Limiter { return s.limiter }

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

	// Wire-protocol version negotiation. Empty defaults to "v1" so older
	// clients continue to interoperate; any other value is rejected with
	// 400 so a future "v2" client never silently misinterprets a v1 server.
	// See pkg/proxy/schema/v1/schema.json and docs/WIRE_PROTOCOL.md.
	if req.SchemaVersion == "" {
		req.SchemaVersion = SchemaVersionV1
	} else if req.SchemaVersion != SchemaVersionV1 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":    "unsupported schema_version; expected " + SchemaVersionV1,
			"received": req.SchemaVersion,
		})
		return
	}

	start := time.Now()

	// Tenant the action is evaluated against. For tenant-aware
	// /v1/t/{tenant}/check this was validated + stamped by withTenant; for
	// legacy /v1/check it defaults to LocalTenantID. Hoisted once so the
	// approval-id, rate-limit-deny, and final response paths all stamp the
	// same tenant on the audit entry.
	tenantID := TenantIDFromContext(r.Context())

	// Approval-id round-trip: if the caller (typically the MCP gateway
	// retrying after a human approve/deny on the dashboard) set
	// ApprovalID, consult the approval queue before running policy.
	// This is what closes the "approve once, model proceeds" UX —
	// without this, the model's retry produces a fresh REQUIRE_APPROVAL
	// cycle even though a human already decided.
	//
	// Resolved entries short-circuit to the human's decision (ALLOW or
	// DENY). Still-pending entries return REQUIRE_APPROVAL referencing
	// the SAME id so the client can keep polling rather than spawning
	// duplicate queue entries. Unknown ids fall through to normal
	// policy evaluation: an attacker who guesses an approval_id gains
	// nothing (policy still runs fresh), and an honest caller with a
	// stale id gets correct enforcement rather than a 4xx surprise.
	//
	// We deliberately bypass the rate limiter for the resolved-approval
	// path: the human already paid the latency cost of the original
	// REQUIRE_APPROVAL evaluation, and the retry's bucket consumption
	// would be charged twice for one logical action.
	if req.ApprovalID != "" {
		if pa, ok := s.approval.Lookup(req.ApprovalID, tenantID); ok {
			// Bind the cached decision to the original request shape.
			// Without this guard, /v1/check (intentionally unauthenticated)
			// becomes a credential-bearer endpoint whose credential — the
			// approval_id — is broadcast through audit logs, SSE feeds,
			// webhook payloads, and the refusal text echoed back to the
			// model. Anyone (or any buggy agent) who learns an approved
			// id could submit ANY action with that id and short-circuit
			// to ALLOW. Compare on operationally-meaningful fields only;
			// SessionID/EstCost/Meta legitimately drift across retries
			// (see matchesOriginalRequest for the full rationale).
			//
			// On mismatch, fall through to normal Engine.Check rather
			// than returning a 4xx — the latter would let an attacker
			// distinguish "id valid but action wrong" from "id unknown",
			// turning the endpoint into an oracle. Closes audit B1
			// (R-Sec H1 + R-Stub C3, two reviewers, same finding).
			if !matchesOriginalRequest(req, pa.Request) {
				metrics.IncApprovalReplayMismatch()
				log.Printf("approval_id %q replayed against mismatched action: agent=%q vs %q, scope=%q vs %q, command=%q vs %q, path=%q vs %q, domain=%q vs %q, url=%q vs %q, action=%q vs %q (falling through to fresh policy evaluation)",
					req.ApprovalID,
					req.AgentID, pa.Request.AgentID,
					req.Scope, pa.Request.Scope,
					req.Command, pa.Request.Command,
					req.Path, pa.Request.Path,
					req.Domain, pa.Request.Domain,
					req.URL, pa.Request.URL,
					req.Action, pa.Request.Action,
				)
				// Intentional fall-through: do NOT short-circuit, do NOT
				// 4xx. Normal Engine.Check runs below.
			} else {
				result := s.resolvedApprovalToResult(req, pa)
				s.logAndRespond(w, req, result, start, tenantID)
				return
			}
		}
		// Unknown approval_id — fall through to normal evaluation.
	}

	// Rate limiting check (before policy evaluation)
	if rlCfg := s.cfg.Engine.RateLimitConfig(req.Scope, req.AgentID, tenantID); rlCfg != nil {
		window, err := ratelimit.ParseWindow(rlCfg.Window)
		if err == nil {
			// Normalize an empty agent_id so two distinct callers that both
			// omit the field do not implicitly share the key "scope::tenant"
			// with any legitimate agent whose id is the literal empty string.
			// All anonymous callers still share a single bucket per scope
			// by design — partitioning by remote IP would require plumbing
			// and opens a DoS vector via IP floods against MaxBuckets.
			agentID := req.AgentID
			if agentID == "" {
				agentID = "anonymous"
			}
			// Key format is "scope:tenant:agent_id" — tenant is the MIDDLE
			// field on purpose. ratelimit.scopeFromKey reads the first field
			// for the eviction metric label, so keeping scope first leaves the
			// (bounded-cardinality) label correct without a parser change, and
			// the bucket is still partitioned per tenant so one tenant cannot
			// consume another's rate budget.
			key := fmt.Sprintf("%s:%s:%s", req.Scope, tenantID, agentID)
			if err := s.limiter.Allow(key, rlCfg.MaxRequests, window); err != nil {
				metrics.IncRateLimited()
				result := policy.CheckResult{
					Decision: policy.Deny,
					Reason:   err.Error(),
					Rule:     "deny:ratelimit:" + req.Scope,
				}
				s.logAndRespond(w, req, result, start, tenantID)
				return
			}
		}
	}

	evalStart := time.Now()
	// Tenant resolution: tenantID was hoisted above from the request context
	// (legacy /v1/check → LocalTenantID; tenant-aware route validated by
	// withTenant). The approval queue / rate limiter are still single-tenant;
	// that sharding is the next step — see pkg/proxy/tenant.go.
	result := s.cfg.Engine.Check(req, tenantID)
	evalMs := float64(time.Since(evalStart).Microseconds()) / 1000.0
	metrics.ObservePolicyEvalDuration(evalMs)

	// If approval required, queue it
	if result.Decision == policy.RequireApproval {
		pending, err := s.approval.Add(req, result, tenantID)
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

	s.logAndRespond(w, req, result, start, tenantID)
}

func (s *Server) logAndRespond(w http.ResponseWriter, req policy.ActionRequest, result policy.CheckResult, start time.Time, tenantID string) {
	duration := time.Since(start)

	// Stamp the wire-format version on the outgoing response so clients
	// can verify they're talking to a compatible server. This is the
	// single chokepoint for /v1/check responses, including synthetic
	// rate-limit denies — every path lands here before encoding.
	if result.SchemaVersion == "" {
		result.SchemaVersion = SchemaVersionV1
	}

	// Determine the transport for this check. The MCP Gateway and
	// (future) LLM API Proxy stamp meta["transport"] on every
	// /v1/check call. SDK callers (Python/TS) don't currently emit
	// the field; they implicitly identify as "sdk". Future SDK
	// versions may set it explicitly; the server-side default
	// (audit.TransportSDK) ensures back-compat either way.
	transport := transportFromRequest(req)

	entry := audit.Entry{
		Timestamp:  time.Now().UTC(),
		AgentID:    req.AgentID,
		SessionID:  req.SessionID,
		Request:    req,
		Result:     result,
		DurationMs: duration.Milliseconds(),
		Transport:  transport,
	}
	// Stamp the tenant the action was evaluated against. The default "local"
	// tenant is stored as "" (omitempty) so single-tenant audit output stays
	// byte-identical to pre-v0.6 files; audit.Entry.EffectiveTenant() resolves
	// "" → "local" on read. Non-local tenants are written verbatim.
	if tenantID != "" && tenantID != policy.LocalTenantID {
		entry.TenantID = tenantID
	}
	// policyMs is the policy-decision cost (request decode → here, i.e. the
	// Engine.Check path). It is also what the audit entry records as DurationMs.
	policyMs := float64(duration.Microseconds()) / 1000.0

	auditStart := time.Now()
	if err := s.cfg.Logger.Log(entry); err != nil {
		log.Printf("Audit log error: %v", err)
	}
	auditMs := float64(time.Since(auditStart).Microseconds()) / 1000.0
	metrics.ObserveAuditWriteDuration(auditMs)

	// Push to SSE watchers. The transport is stamped on the event so
	// dashboard JS can render the chip without re-deriving from meta.
	s.approval.Broadcast(AuditEvent{
		Type:      "check",
		Timestamp: entry.Timestamp,
		Tenant:    entry.TenantID, // "" for local (already normalized by the stamp above)
		Transport: transport,
		Request:   req,
		Result:    result,
	})

	// Total is measured AFTER the policy decision, the audit write, and the
	// notify/SSE enqueue, so it is the true end-to-end server processing time —
	// the only work left is serializing the response body below. Measuring it
	// here (not from the pre-audit `duration`) keeps the
	// agentguard_request_duration_ms SLO histogram and the X-AgentGuard-Total-Ms
	// header honest: a slow synchronous audit backend now shows up in Total
	// instead of being silently dropped. Headers must be set before the first
	// body write below.
	totalMs := float64(time.Since(start).Microseconds()) / 1000.0
	metrics.ObserveRequestDuration(totalMs)
	metrics.IncDecision(string(result.Decision))

	// Expose per-phase timing as response headers for easy curl inspection.
	w.Header().Set("X-AgentGuard-Policy-Ms", fmt.Sprintf("%.3f", policyMs))
	w.Header().Set("X-AgentGuard-Audit-Ms", fmt.Sprintf("%.3f", auditMs))
	w.Header().Set("X-AgentGuard-Total-Ms", fmt.Sprintf("%.3f", totalMs))

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		log.Printf("Response encode error: %v", err)
	}
}

// matchesOriginalRequest returns true iff the retry request's
// operationally-meaningful fields equal those of the originally-
// approved PendingAction. Guards against approval-id replay across
// mismatched actions.
//
// Compared fields (mismatch on any one → fall through to fresh policy
// evaluation rather than returning the cached decision):
//
//	AgentID  — the human approved an action FOR this agent; another
//	           agent re-using the id is unambiguously a different
//	           authorisation request.
//	Scope    — same logical reason: a shell approval is not a network
//	           approval.
//	Command  — covers the shell scope (and any free-form Pattern-based
//	           rule scope) where the policy decision turns on the exact
//	           command string.
//	Path     — filesystem scope identity.
//	Domain   — network scope identity (host-only rules).
//	URL      — network scope identity (full-URL rules; some operators
//	           gate on URL rather than Domain to authorise a specific
//	           endpoint).
//	Action   — covers Action+Paths style filesystem rules and any
//	           future scope that authorises by named action.
//
// NOT compared (legitimately drift across retries):
//
//	SessionID — agents may reconnect/retry from a fresh session id
//	            without invalidating an in-flight approval.
//	EstCost   — cost-scoped retries inherently recompute cost (a token
//	            estimate, an exchange-rate refresh, a refunded
//	            reservation). Binding here would cause every cost
//	            retry to fall through and ask for re-approval.
//	Meta      — carries transport tags ("transport", "arg_*", trace
//	            ids) that are diagnostic, not authorising. Binding on
//	            Meta would couple the security check to telemetry
//	            evolution. The transport tag itself is preserved on
//	            the audit entry via logAndRespond regardless.
//
// SchemaVersion is also not compared: it's a wire-protocol version
// negotiation field, validated independently before this point in
// handleCheck. ApprovalID is the lookup key by definition.
func matchesOriginalRequest(retry policy.ActionRequest, original policy.ActionRequest) bool {
	return retry.AgentID == original.AgentID &&
		retry.Scope == original.Scope &&
		retry.Command == original.Command &&
		retry.Path == original.Path &&
		retry.Domain == original.Domain &&
		retry.URL == original.URL &&
		retry.Action == original.Action
}

// resolvedApprovalToResult converts a PendingAction (resolved or not)
// into a CheckResult suitable for the /v1/check response on a retry
// that carries an approval_id.
//
// Resolution → decision mapping:
//
//	resolved=false                → REQUIRE_APPROVAL with the SAME id
//	                                (rule="require_approval:pending"),
//	                                reusing the existing approval URL
//	                                so a polling client keeps waiting.
//	resolved=true, decision=ALLOW → ALLOW (rule="allow:approved").
//	resolved=true, decision=DENY  → DENY (rule="deny:approved").
//	resolved=true, decision=other → defensive DENY
//	                                (rule="deny:approved:invalid_resolution").
//
// The defensive branch only triggers if a future code path stamps a
// non-canonical decision string on Resolve; today Resolve only writes
// "ALLOW" or "DENY" (see ApprovalQueue.Resolve).
//
// Note that the original PendingAction.Request's transport is *not*
// re-applied here — the caller (handleCheck) hands logAndRespond the
// retry request as-is, and the retry request's own meta["transport"]
// is what gets stamped on the audit entry. In practice the gateway
// re-stamps "mcp_gateway" on every retry, so the audit log shows the
// same transport for both the original REQUIRE_APPROVAL entry and the
// resolved-approved entry. SDK callers that propagate approval_id
// without setting transport will land in the default "sdk" bucket on
// both legs, which is also consistent.
func (s *Server) resolvedApprovalToResult(req policy.ActionRequest, pa *PendingAction) policy.CheckResult {
	if !pa.Resolved {
		return policy.CheckResult{
			Decision:    policy.RequireApproval,
			Rule:        "require_approval:pending",
			Reason:      fmt.Sprintf("approval %s still pending human review", pa.ID),
			ApprovalID:  pa.ID,
			ApprovalURL: fmt.Sprintf("%s/v1/approve/%s", s.cfg.BaseURL, pa.ID),
		}
	}

	switch policy.Decision(pa.Decision) {
	case policy.Allow:
		return policy.CheckResult{
			Decision:   policy.Allow,
			Rule:       "allow:approved",
			Reason:     fmt.Sprintf("approval %s resolved ALLOW by human", pa.ID),
			ApprovalID: pa.ID,
		}
	case policy.Deny:
		return policy.CheckResult{
			Decision:   policy.Deny,
			Rule:       "deny:approved",
			Reason:     fmt.Sprintf("approval %s resolved DENY by human", pa.ID),
			ApprovalID: pa.ID,
		}
	default:
		// Should be unreachable: ApprovalQueue.Resolve only writes
		// canonical decisions. Treat any deviation as a hard DENY so an
		// accidental future bug can never silently allow.
		return policy.CheckResult{
			Decision:   policy.Deny,
			Rule:       "deny:approved:invalid_resolution",
			Reason:     fmt.Sprintf("approval %s has unexpected resolution %q", pa.ID, pa.Decision),
			ApprovalID: pa.ID,
		}
	}
}

// transportFromRequest extracts the integration-path tag the SDK or
// gateway stamped on meta["transport"]. Empty / unset / non-string
// values default to audit.TransportSDK so SDK callers (which don't
// currently emit the field) are categorised correctly without code
// changes on their side.
func transportFromRequest(req policy.ActionRequest) string {
	if req.Meta == nil {
		return audit.TransportSDK
	}
	if t, ok := req.Meta["transport"]; ok && t != "" {
		return t
	}
	return audit.TransportSDK
}

// approvalIDFromRequest extracts the approval ID from either URL family:
//
//	/v1/approve/{id}            (legacy)
//	/v1/deny/{id}               (legacy)
//	/v1/status/{id}             (legacy)
//	/v1/t/{tenant}/approve/{id} (tenant-aware; A7)
//	/v1/t/{tenant}/deny/{id}
//	/v1/t/{tenant}/status/{id}
//
// On the tenant-aware family the Go 1.22+ mux populates r.PathValue("id")
// for free; on the legacy family we strip the known prefix. Returns the
// empty string when the path does not contain an ID, so handlers can
// surface a 400 / 404 uniformly.
func approvalIDFromRequest(r *http.Request, legacyPrefix string) string {
	if id := r.PathValue("id"); id != "" {
		return id
	}
	if strings.HasPrefix(r.URL.Path, legacyPrefix) {
		return r.URL.Path[len(legacyPrefix):]
	}
	return ""
}

// handleApprove approves a pending action.
func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := approvalIDFromRequest(r, "/v1/approve/")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	if err := s.approval.Resolve(id, policy.Allow, TenantIDFromContext(r.Context())); err != nil {
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

	id := approvalIDFromRequest(r, "/v1/deny/")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	if err := s.approval.Resolve(id, policy.Deny, TenantIDFromContext(r.Context())); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "denied", "id": id})
}

// handleAuditQuery returns filtered audit log entries.
//
// Query-string contract:
//   - ?limit=N — integer in [1, MaxAuditQueryLimit]. Values above the ceiling
//     are clamped silently. Missing/empty uses DefaultAuditQueryLimit.
//     Non-integers or values < 1 return 400.
//   - ?offset=N — integer ≥ 0. Defaults to 0. Non-integers or negatives
//     return 400.
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

	// Scope the query to the request's tenant. Legacy /v1/audit has no tenant
	// in the path → TenantIDFromContext returns LocalTenantID, so it returns
	// only "local" entries (identical to legacy behavior in a single-tenant
	// deployment, where every entry is "local"). The tenant-aware
	// /v1/t/{tenant}/audit route was stamped by withTenant and is now scoped to
	// that tenant — closing the cross-tenant audit-read leak (plan § 3.3).
	filter := audit.QueryFilter{
		TenantID:  TenantIDFromContext(r.Context()),
		AgentID:   r.URL.Query().Get("agent_id"),
		SessionID: r.URL.Query().Get("session_id"),
		Decision:  r.URL.Query().Get("decision"),
		Scope:     r.URL.Query().Get("scope"),
		Transport: r.URL.Query().Get("transport"),
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

// healthResponse is the JSON shape returned by /v1/health and
// /v1/t/{tenant}/health. Timestamp fields use *string so
// `last_request_at: null` becomes `omitempty` on the wire when no
// traffic has arrived yet, while still populating when set.
type healthResponse struct {
	Status           string   `json:"status"`
	Version          string   `json:"version"`
	Tenant           string   `json:"tenant"`
	LastRequestAt    *string  `json:"last_request_at,omitempty"`
	LastPolicyLoadAt *string  `json:"last_policy_load_at,omitempty"`
	UptimeSeconds    int64    `json:"uptime_seconds"`
	Warnings         []string `json:"warnings"`
}

// healthStaleTrafficWindow is the threshold above which /v1/health adds
// "no traffic in 5m+" to the warnings array. Tuned for typical polling
// cadence (Prometheus + dashboard SSE keep traffic constant in healthy
// deployments). var, not const, so tests can override.
var healthStaleTrafficWindow = 5 * time.Minute

// healthStalePolicyWindow is the threshold above which /v1/health adds
// "policy not reloaded in 24h+" to the warnings array. Hot-reload is
// not required for a healthy system; this is meant to surface
// configurations that were intended to be regenerated by a CI job that
// silently stopped firing. var, not const, so tests can override.
var healthStalePolicyWindow = 24 * time.Hour

// handleHealthV1Local serves /v1/health (legacy single-tenant path).
// Always resolves the "local" tenant.
func (s *Server) handleHealthV1Local(w http.ResponseWriter, r *http.Request) {
	s.handleHealthV1(w, r, policy.LocalTenantID)
}

// handleHealthV1Tenant serves /v1/t/{tenant}/health. Extracts the tenant
// from the URL path (Go 1.22+ wildcard) and resolves it via the
// engine's policy provider. With FilePolicyProvider only "local" is
// configured; any other value yields 404 via policy.ErrTenantNotFound.
func (s *Server) handleHealthV1Tenant(w http.ResponseWriter, r *http.Request) {
	tenant := r.PathValue("tenant")
	s.handleHealthV1(w, r, tenant)
}

// handleHealthV1 is the shared implementation for both /v1/health and
// /v1/t/{tenant}/health. Returns 404 with a structured error body when
// the tenant is unknown; otherwise 200 with the full healthResponse.
//
// Status semantics: "ok" or "degraded". Degraded means the process is
// serving but a durability signal is unhealthy (audit entries parked in
// the buffered overflow backlog). The HTTP code stays 200 either way so
// liveness probes don't flap on degradation; orchestrators that want to
// act on it read the status field. The metrics-derived signals are
// process-wide, not per-tenant.
func (s *Server) handleHealthV1(w http.ResponseWriter, r *http.Request, tenant string) {
	w.Header().Set("Content-Type", "application/json")

	// Resolve the tenant via the engine's provider so multi-tenant
	// providers (which the engine has not subscribed to) still surface
	// 404s correctly. We do not use the resolved *Policy here — the
	// engine's last-load timestamp is currently a function of the local
	// tenant only. A per-tenant timestamp map is future work.
	if _, err := s.cfg.Engine.PolicyForTenant(tenant); err != nil {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "tenant not found"})
		return
	}

	now := time.Now()
	resp := healthResponse{
		Status:        "ok",
		Version:       s.cfg.Version,
		Tenant:        tenant,
		UptimeSeconds: int64(now.Sub(s.startedAt).Seconds()),
		Warnings:      []string{},
	}

	// last_request_at: omitted when never set (process just booted, no
	// request yet). RFC 3339 with millisecond precision so probe output
	// is comparable across machines without nanosecond noise.
	if t := s.LastRequestAt(); !t.IsZero() {
		v := t.UTC().Format("2006-01-02T15:04:05.000Z07:00")
		resp.LastRequestAt = &v
		if now.Sub(t) > healthStaleTrafficWindow {
			resp.Warnings = append(resp.Warnings, "no traffic in 5m+")
		}
	}

	// last_policy_load_at: same shape. NewEngine stamps this on initial
	// Get success, so it should never be zero in practice; treat zero
	// as "unknown" defensively.
	if t := s.cfg.Engine.LastPolicyLoadAt(); !t.IsZero() {
		v := t.UTC().Format("2006-01-02T15:04:05.000Z07:00")
		resp.LastPolicyLoadAt = &v
		if now.Sub(t) > healthStalePolicyWindow {
			resp.Warnings = append(resp.Warnings, "policy not reloaded in 24h+")
		}
	}

	// Metrics-derived signals (process-wide). Corrupt audit lines and
	// dropped notifications are warnings — the data is already degraded
	// or best-effort by design. An audit overflow backlog flips status
	// to degraded: entries are durable on disk but not yet queryable,
	// and a growing backlog means audit writes can't keep up.
	if n := metrics.AuditCorruptLinesTotal(); n > 0 {
		resp.Warnings = append(resp.Warnings, fmt.Sprintf("audit: %d corrupt line(s) skipped during queries", n))
	}
	dropped := metrics.AuditBufferedDroppedToOverflowTotal()
	drained := metrics.AuditBufferedDrainedFromOverflowTotal()
	if dropped > drained {
		resp.Status = "degraded"
		resp.Warnings = append(resp.Warnings, fmt.Sprintf("audit: %d entry(ies) in buffered overflow backlog", dropped-drained))
	}
	var notifyDrops uint64
	for _, v := range metrics.NotifyDroppedSnapshot() {
		notifyDrops += v
	}
	if notifyDrops > 0 {
		resp.Warnings = append(resp.Warnings, fmt.Sprintf("notify: %d notification(s) dropped (queue_full)", notifyDrops))
	}

	_ = json.NewEncoder(w).Encode(resp)
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
		"total":     metrics.ChecksTotal(),
		"allowed":   metrics.AllowedTotal(),
		"denied":    metrics.DeniedTotal(),
		"approvals": metrics.ApprovalTotal(),
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
	_ = json.NewEncoder(w).Encode(s.approval.List(TenantIDFromContext(r.Context())))
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

	ch := s.approval.Subscribe(TenantIDFromContext(r.Context()))
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
	id := approvalIDFromRequest(r, "/v1/status/")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}

	s.approval.mu.RLock()
	pa, ok := s.approval.pending[id]
	s.approval.mu.RUnlock()

	// Scope to the request's tenant: an id owned by another tenant is reported
	// as "not found" so status cannot be used as a cross-tenant existence
	// oracle (mirrors Lookup/Resolve).
	if !ok || !tenantsMatch(pa.TenantID, TenantIDFromContext(r.Context())) {
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

// Lookup returns a snapshot of the pending entry for the given ID. The
// bool result is false when the ID is unknown (e.g. expired/evicted,
// typo, or wrong tenant). Read-only — uses RLock.
//
// The returned *PendingAction is a defensive copy: callers cannot
// mutate queue state through it. The handleCheck approval-id round-
// trip uses this on the hot path of every retry, so the read-lock
// keeps it cheap relative to the existing /v1/check evaluation cost.
func (q *ApprovalQueue) Lookup(id, tenantID string) (*PendingAction, bool) {
	q.mu.RLock()
	defer q.mu.RUnlock()
	pa, ok := q.pending[id]
	if !ok || !tenantsMatch(pa.TenantID, tenantID) {
		// Unknown id OR an id owned by another tenant. Both return false so
		// the caller falls through to fresh policy evaluation — a tenant that
		// guesses another tenant's approval_id learns nothing and gains no
		// short-circuit (no cross-tenant oracle).
		return nil, false
	}
	cp := *pa
	return &cp, true
}

// Add registers a new pending approval. If the queue is at capacity the
// oldest resolved entry is evicted first (LRU on CreatedAt; resolution does
// not rewind it, so the eviction target is the entry that has been around
// the longest). If every slot is still unresolved, Add returns
// ErrApprovalQueueFull and the caller is expected to surface 503 +
// Retry-After — silently dropping the request would leave the agent
// waiting forever on an ID that does not exist.
func (q *ApprovalQueue) Add(req policy.ActionRequest, result policy.CheckResult, tenantID string) (*PendingAction, error) {
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
	// Store the local tenant as "" so single-tenant /api/pending payloads stay
	// byte-identical; tenantsMatch normalizes "" ↔ "local" on every read.
	if tenantID != policy.LocalTenantID {
		pa.TenantID = tenantID
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

func (q *ApprovalQueue) Resolve(id string, decision policy.Decision, tenantID string) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	pa, ok := q.pending[id]
	if !ok || !tenantsMatch(pa.TenantID, tenantID) {
		// A mismatched tenant is reported as "not found" (not 403) so a tenant
		// cannot probe for the existence of another tenant's approval IDs.
		return fmt.Errorf("pending action %s not found", id)
	}

	pa.Resolved = true
	pa.Decision = string(decision)
	pa.ResolvedAt = time.Now().UTC()

	// Broadcast resolution to SSE clients of this tenant. Carry the original
	// transport so dashboard JS keeps the same chip on the "resolved" event as
	// on the original "check" event, and the tenant so it routes correctly.
	q.broadcast(AuditEvent{
		Type:      "resolved",
		Timestamp: time.Now().UTC(),
		Tenant:    pa.TenantID,
		Transport: transportFromRequest(pa.Request),
		Request:   pa.Request,
		Result:    policy.CheckResult{Decision: decision, Reason: "manually " + strings.ToLower(string(decision))},
	})

	return nil
}

// List returns the unresolved pending actions owned by tenantID. The legacy
// /api/pending route resolves to LocalTenantID, so single-tenant deployments
// behave exactly as before.
func (q *ApprovalQueue) List(tenantID string) []*PendingAction {
	q.mu.RLock()
	defer q.mu.RUnlock()

	var list []*PendingAction
	for _, pa := range q.pending {
		if !pa.Resolved && tenantsMatch(pa.TenantID, tenantID) {
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

// Snapshot returns a defensive copy of every entry (pending and resolved) for
// write-behind persistence. Read-locked; intended for the background syncer,
// never the request path. Callers must not mutate the queue through the copies.
func (q *ApprovalQueue) Snapshot() []*PendingAction {
	q.mu.RLock()
	defer q.mu.RUnlock()
	out := make([]*PendingAction, 0, len(q.pending))
	for _, pa := range q.pending {
		cp := *pa
		out = append(out, &cp)
	}
	return out
}

// Restore loads approvals from persistence (boot hydration). It respects
// maxSize — entries beyond the cap are dropped — and skips any whose ID is
// already present. Intended to run once, before serving traffic.
func (q *ApprovalQueue) Restore(actions []*PendingAction) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, pa := range actions {
		if q.maxSize > 0 && len(q.pending) >= q.maxSize {
			break
		}
		if _, exists := q.pending[pa.ID]; exists {
			continue
		}
		cp := *pa
		q.pending[pa.ID] = &cp
	}
}

// remoteApplyChunk bounds how many remote approval records ApplyRemote merges
// under a single q.mu write-lock acquisition. The hot-path Lookup takes
// q.mu.RLock; holding the write lock for a whole O(n) re-hydrate pass would
// stall every concurrent Lookup (CLAUDE.md §1). We acquire, merge ≤K, release,
// repeat — mirroring ratelimit.applyChunk and policy.costApplyChunk (K=128).
const remoteApplyChunk = 128

// ApplyRemote merges remote approval records (loaded from the shared durable
// store by the background reconcile goroutine) into the local queue. It is the
// write half of multi-node approval cross-node visibility (v1.0) and runs ONLY
// on that background goroutine — NEVER on the /v1/check hot path, so it adds no
// request-path latency. The hot-path Lookup stays a pure in-memory RLock read
// and is unchanged.
//
// Each element is a remote view of one entry, tenant-normalized exactly as the
// queue stores it (the local tenant as ""), so the effective merge key is
// (tenant, ID) and a remote row for tenant X can only ever touch entry (X, ID)
// — no cross-tenant surfacing (CLAUDE.md §3).
//
// Locking: at most remoteApplyChunk (K=128) records are merged per write-lock
// hold, so a concurrent Lookup blocks for O(K) map ops, not O(n).
//
// Per-key merge rules (fail-closed — the security crux). For each remote record
// r the CURRENT local entry l is re-read UNDER the write lock (never from a
// stale snapshot), so a concurrent local Resolve remains authoritative:
//
//   - l absent:                     INSERT r (respecting maxSize, like Restore).
//   - l pending, r resolved:        adopt r (copy Decision+ResolvedAt+Result) — the visibility goal.
//   - l resolved, r pending:        KEEP l — never resurrect a resolved action.
//   - both resolved, diff decision: DENY wins, regardless of ResolvedAt (a deny is never overwritten by a remote allow).
//   - both resolved, same decision: KEEP l — ResolvedAt is a tiebreak only; state is identical.
//   - both pending:                 KEEP l — nothing to surface yet.
//
// A record whose ID is absent from `remote` is never passed here, so an
// unflushed local-only pending survives untouched (the no-clobber guarantee).
func (q *ApprovalQueue) ApplyRemote(remote []*PendingAction) {
	for i := 0; i < len(remote); i += remoteApplyChunk {
		end := i + remoteApplyChunk
		if end > len(remote) {
			end = len(remote)
		}
		q.mu.Lock()
		for _, r := range remote[i:end] {
			if r == nil {
				continue
			}
			l, ok := q.pending[r.ID]
			if !ok {
				// exists remote, not local => INSERT, honoring the cap exactly as
				// Restore does (drop when full — never evict a live entry here).
				if q.maxSize > 0 && len(q.pending) >= q.maxSize {
					continue
				}
				cp := *r
				q.pending[r.ID] = &cp
				continue
			}
			// A local entry sharing r's raw ID but owned by a DIFFERENT tenant
			// must never be rewritten by r (CLAUDE.md §3). The store PKs approvals
			// on (tenant_id, id), so two tenants can legitimately share a raw ID;
			// the local map is keyed by ID alone, so guard here. Mismatch => leave
			// the local entry alone (r is dropped rather than surfaced cross-tenant).
			if !tenantsMatch(l.TenantID, r.TenantID) {
				continue
			}
			mergeRemoteLocked(l, r)
		}
		q.mu.Unlock()
	}
}

// mergeRemoteLocked applies the per-key merge rules for one remote record r
// whose tenant already matches the live local entry l. Caller holds q.mu.Lock.
// It mutates l in place; it never resurrects a resolved action and never lets a
// remote allow overwrite a local deny (fail-closed).
func mergeRemoteLocked(l, r *PendingAction) {
	switch {
	case !l.Resolved && r.Resolved:
		// local pending, remote resolved => adopt the remote resolution.
		l.Resolved = true
		l.Decision = r.Decision
		l.ResolvedAt = r.ResolvedAt
		l.Result = r.Result
	case l.Resolved && r.Resolved && l.Decision != r.Decision:
		// Conflicting resolutions => DENY wins, regardless of ResolvedAt. Canonical
		// decisions are only ALLOW/DENY, so a differing pair is exactly one of
		// each; adopt the remote ONLY when it is the deny (local already-deny, or a
		// non-canonical remote, is kept — never downgraded to a remote allow).
		if l.Decision != string(policy.Deny) && r.Decision == string(policy.Deny) {
			l.Resolved = true
			l.Decision = r.Decision
			l.ResolvedAt = r.ResolvedAt
			l.Result = r.Result
		}
	default:
		// l resolved & r pending           => keep l (never resurrect).
		// both resolved, same decision       => keep l (identical state).
		// both pending                        => keep l (nothing to surface).
	}
}

// Subscribe registers an SSE watcher that receives only events for tenantID.
// The legacy /api/stream route subscribes as LocalTenantID.
func (q *ApprovalQueue) Subscribe(tenantID string) chan AuditEvent {
	q.mu.Lock()
	defer q.mu.Unlock()
	ch := make(chan AuditEvent, SSEChannelBufferSize)
	q.watchers = append(q.watchers, sseWatcher{ch: ch, tenant: effectiveTenant(tenantID)})
	metrics.IncSSESubscribers()
	return ch
}

func (q *ApprovalQueue) Unsubscribe(ch chan AuditEvent) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for i, w := range q.watchers {
		if w.ch == ch {
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
	for _, w := range q.watchers {
		// Route the event only to subscribers of its tenant. The event stores
		// the local tenant as "" (wire byte-identity); the watcher tenant is
		// already normalized, so compare under the same normalization.
		if !tenantsMatch(event.Tenant, w.tenant) {
			continue
		}
		select {
		case w.ch <- event:
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
//     carry them);
//     - state-changing endpoints require a CSRF token that attackers on
//     other origins cannot read (double-submit cookie pattern).
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

// withTraffic stamps Server.lastRequestAtNs on every request before the
// downstream handler runs. The stamp happens before the handler so a
// long-running /v1/check still surfaces as recent traffic at the moment
// it arrived, and a panic in the handler is still observed as activity.
// Method receiver (rather than free function like withLogging) so the
// closure can read the *Server identity for the atomic.
func (s *Server) withTraffic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.noteRequest()
		next.ServeHTTP(w, r)
	})
}

// recoverPanic is the outermost HTTP middleware. It catches any panic
// raised by a downstream handler, logs the stack trace, and returns a
// generic 500 to the client. Without it, a panic inside Engine.Check or a
// notifier callback would tear down the request goroutine but leave the
// connection in an indeterminate state.
func recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("PANIC %s %s: %v\n%s", r.Method, r.URL.Path, rec, debug.Stack())
				// Best-effort 500. If the handler already wrote headers,
				// http stdlib swallows the WriteHeader and we just log.
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"error":"internal server error"}`))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// goRecover runs fn in a fresh goroutine wrapped with a recover that logs
// the panic stack and a caller-supplied label. Used for AgentGuard's own
// background workers — the session-cost sweeper, dispatcher workers, and
// any future periodic goroutine — so a panic in one of them does not take
// the whole process down.
func goRecover(label string, fn func()) {
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("PANIC goroutine %s: %v\n%s", label, rec, debug.Stack())
			}
		}()
		fn()
	}()
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
    .transport-chip { display: inline-block; padding: 2px 6px; border-radius: 4px; font-size: 11px; font-family: 'SF Mono', monospace; color: white; margin-right: 8px; vertical-align: baseline; }
    .transport-chip.sdk { background: #6c757d; }
    .transport-chip.mcp_gateway { background: #0ea5e9; }
    .transport-chip.llm_api_proxy { background: #a855f7; }
    .transport-chip.unknown { background: #94a3b8; }
    .transport-legend { font-size: 11px; color: #666; display: flex; gap: 8px; align-items: center; }
    .transport-legend .transport-chip { font-size: 10px; padding: 1px 6px; }
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
    <span class="transport-legend" title="Integration path that produced each entry">
      Transport:
      <span class="transport-chip sdk">sdk</span>
      <span class="transport-chip mcp_gateway">mcp_gateway</span>
      <span class="transport-chip llm_api_proxy">llm_api_proxy</span>
    </span>
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
    // Whitelist of known transport tags. Any other value renders with
    // a neutral 'unknown' chip class so an unexpected gateway can't
    // inject CSS class names through the SSE / audit-query path.
    const KNOWN_TRANSPORTS = ['sdk', 'mcp_gateway', 'llm_api_proxy'];
    function transportClass(t) {
      return KNOWN_TRANSPORTS.indexOf(t) >= 0 ? t : 'unknown';
    }

    function renderEntry(entry) {
      const result = entry.result || {};
      const decision = result.decision || 'UNKNOWN';
      const req = entry.request || {};
      const action = req.command || req.path || req.domain || 'unknown';
      // Transport may sit at the top level (SSE event + newer audit
      // entries) or be absent on older audit entries; default 'sdk'.
      const transport = entry.transport || 'sdk';
      const el = document.createElement('div');
      el.className = 'entry ' + esc(decision);

      const headerRow = document.createElement('div');
      headerRow.style.cssText = 'display:flex;align-items:center;gap:8px;';

      const chip = document.createElement('span');
      chip.className = 'transport-chip ' + transportClass(transport);
      chip.textContent = transport;
      chip.title = 'Transport: ' + transport;
      headerRow.appendChild(chip);

      const decDiv = document.createElement('div');
      decDiv.className = 'decision ' + esc(decision);
      decDiv.textContent = decision;
      headerRow.appendChild(decDiv);
      el.appendChild(headerRow);

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
