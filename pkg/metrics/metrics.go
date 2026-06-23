// Package metrics provides a lightweight in-process metrics registry with
// Prometheus text-format output. It requires zero external dependencies.
//
// State lives in a Registry. The package-level functions delegate to
// Default, which is what the binaries use; tests that need isolation
// construct their own Registry (or call Reset) instead of doing
// before/after delta arithmetic against process-global counters.
//
// Instrumented points on the hot path:
//   - agentguard_checks_total            — counter, by decision label
//   - agentguard_request_duration_ms     — histogram, end-to-end /v1/check
//   - agentguard_policy_eval_duration_ms — histogram, Engine.Check only
//   - agentguard_audit_write_duration_ms — histogram, Logger.Log only
//   - agentguard_pending_approvals       — gauge, current queue depth
package metrics

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/deprecation"
)

// -- Label constants -----------------------------------------------------------

// Well-known reason labels for IncRequestRejected. Other reasons are allowed
// but callers must keep the cardinality bounded.
const (
	RejectedBodyTooLarge = "body_too_large"
)

// Well-known reason labels for IncNotifyDropped. Kept bounded so the
// Prometheus series cardinality stays predictable.
const (
	NotifyDroppedQueueFull = "queue_full"
)

// Well-known reason labels for IncApprovalEvicted. When the approval queue
// is at capacity, either an old resolved entry is dropped to make room
// (lru_resolved) or the request is refused with 503 because nothing was
// resolved (queue_full). Both paths increment this counter so operators
// can distinguish "we need a bigger queue" from "we need more approvers".
const (
	ApprovalEvictedLRUResolved = "lru_resolved"
	ApprovalEvictedQueueFull   = "queue_full"
)

// Migration status values for SetMigrationStatus.
const (
	MigrationStatusRan     = "ran"
	MigrationStatusSkipped = "skipped"
	MigrationStatusFailed  = "failed"
)

// SSEDroppedSlowConsumer labels a broadcast that was discarded because
// the per-subscriber channel was full (the subscriber isn't draining
// fast enough). This is the fail-fast drop in broadcastLocked's
// default case.
const (
	SSEDroppedSlowConsumer = "slow_consumer"
)

// notifyDroppedKey is the composite label key (notifier + reason) for
// agentguard_notify_events_dropped_total. Using a struct as the map key
// keeps the two-dimensional label space cheap without allocating strings.
type notifyDroppedKey struct {
	Notifier string
	Reason   string
}

// migrationStatusKey labels the migration-status gauge. The tuple is
// bounded because each Migration has a single From/To pair and status is
// drawn from {ran, skipped, failed}.
type migrationStatusKey struct {
	From, To, Status string
}

// -- Registry ------------------------------------------------------------------

// Registry holds every metric series for one logical process. The
// binaries use the package-level Default; tests construct their own via
// NewRegistry for isolation.
//
// Deprecation-usage counters are the one exception: they live in
// pkg/deprecation's process-global state and are only read at exposition
// time, so they are shared across registries and unaffected by Reset.
type Registry struct {
	// 64-bit atomically-accessed fields first so they stay 8-byte
	// aligned on 32-bit platforms (sync/atomic requirement).
	checksTotal                  uint64
	allowedTotal                 uint64
	deniedTotal                  uint64
	approvalTotal                uint64 // REQUIRE_APPROVAL decisions
	rateLimitedTotal             uint64 // rate-limit denies
	approvalReplayMismatchTotal  uint64
	auditCorruptLinesTotal       uint64
	auditReplayEntriesTotal      uint64
	auditRotationsTotal          uint64
	auditBufferedDroppedTotal    uint64
	auditBufferedDrainedTotal    uint64
	notifySpooledTotal           uint64
	notifyDespooledTotal         uint64
	llmProxyStreamsRejectedTotal uint64
	auditReplayDurationNanos     int64
	auditBufferedQueueDepth      int64
	llmProxyStreamsActive        int64
	notifyQueueDepth             int64
	sseSubscribers               int64
	rateLimitBuckets             int64
	pendingApprovals             int64

	// Labeled counters/gauges. Per-series mutexes keep the contention
	// profile of the old package-global layout.
	requestRejectedMu    sync.Mutex
	requestRejectedCount map[string]uint64

	approvalEvictedMu    sync.Mutex
	approvalEvictedCount map[string]uint64

	rateLimitEvictedMu    sync.Mutex
	rateLimitEvictedCount map[string]uint64

	sseDroppedMu    sync.Mutex
	sseDroppedCount map[string]uint64

	llmProxyBufferOverflowMu    sync.Mutex
	llmProxyBufferOverflowCount map[string]uint64

	llmProxyNonStreamingOverflowMu    sync.Mutex
	llmProxyNonStreamingOverflowCount map[string]uint64

	llmProxyProtocolViolationMu    sync.Mutex
	llmProxyProtocolViolationCount map[string]uint64

	migrationStatusMu sync.Mutex
	migrationStatus   map[migrationStatusKey]int64

	notifyDroppedMu    sync.Mutex
	notifyDroppedCount map[notifyDroppedKey]uint64

	notifyDispatchMu   sync.Mutex
	notifyDispatchHist map[string]*Histogram

	requestDuration    *Histogram
	policyEvalDuration *Histogram
	auditWriteDuration *Histogram
}

// NewRegistry returns an empty Registry with all series initialised.
func NewRegistry() *Registry {
	return &Registry{
		requestRejectedCount:              map[string]uint64{},
		approvalEvictedCount:              map[string]uint64{},
		rateLimitEvictedCount:             map[string]uint64{},
		sseDroppedCount:                   map[string]uint64{},
		llmProxyBufferOverflowCount:       map[string]uint64{},
		llmProxyNonStreamingOverflowCount: map[string]uint64{},
		llmProxyProtocolViolationCount:    map[string]uint64{},
		migrationStatus:                   map[migrationStatusKey]int64{},
		notifyDroppedCount:                map[notifyDroppedKey]uint64{},
		notifyDispatchHist:                map[string]*Histogram{},
		requestDuration:                   newHistogram(durationBuckets),
		policyEvalDuration:                newHistogram(durationBuckets),
		auditWriteDuration:                newHistogram(durationBuckets),
	}
}

// Default is the process-wide registry the package-level functions
// delegate to. Swap or Reset it only in tests.
var Default = NewRegistry()

// Reset zeroes every series in the registry. Test helper — production
// code never resets metrics. Deprecation counters live in
// pkg/deprecation and are not touched.
func (r *Registry) Reset() {
	atomic.StoreUint64(&r.checksTotal, 0)
	atomic.StoreUint64(&r.allowedTotal, 0)
	atomic.StoreUint64(&r.deniedTotal, 0)
	atomic.StoreUint64(&r.approvalTotal, 0)
	atomic.StoreUint64(&r.rateLimitedTotal, 0)
	atomic.StoreUint64(&r.approvalReplayMismatchTotal, 0)
	atomic.StoreUint64(&r.auditCorruptLinesTotal, 0)
	atomic.StoreUint64(&r.auditReplayEntriesTotal, 0)
	atomic.StoreUint64(&r.auditRotationsTotal, 0)
	atomic.StoreUint64(&r.auditBufferedDroppedTotal, 0)
	atomic.StoreUint64(&r.auditBufferedDrainedTotal, 0)
	atomic.StoreUint64(&r.notifySpooledTotal, 0)
	atomic.StoreUint64(&r.notifyDespooledTotal, 0)
	atomic.StoreUint64(&r.llmProxyStreamsRejectedTotal, 0)
	atomic.StoreInt64(&r.auditReplayDurationNanos, 0)
	atomic.StoreInt64(&r.auditBufferedQueueDepth, 0)
	atomic.StoreInt64(&r.llmProxyStreamsActive, 0)
	atomic.StoreInt64(&r.notifyQueueDepth, 0)
	atomic.StoreInt64(&r.sseSubscribers, 0)
	atomic.StoreInt64(&r.rateLimitBuckets, 0)
	atomic.StoreInt64(&r.pendingApprovals, 0)

	r.requestRejectedMu.Lock()
	r.requestRejectedCount = map[string]uint64{}
	r.requestRejectedMu.Unlock()
	r.approvalEvictedMu.Lock()
	r.approvalEvictedCount = map[string]uint64{}
	r.approvalEvictedMu.Unlock()
	r.rateLimitEvictedMu.Lock()
	r.rateLimitEvictedCount = map[string]uint64{}
	r.rateLimitEvictedMu.Unlock()
	r.sseDroppedMu.Lock()
	r.sseDroppedCount = map[string]uint64{}
	r.sseDroppedMu.Unlock()
	r.llmProxyBufferOverflowMu.Lock()
	r.llmProxyBufferOverflowCount = map[string]uint64{}
	r.llmProxyBufferOverflowMu.Unlock()
	r.llmProxyNonStreamingOverflowMu.Lock()
	r.llmProxyNonStreamingOverflowCount = map[string]uint64{}
	r.llmProxyNonStreamingOverflowMu.Unlock()
	r.llmProxyProtocolViolationMu.Lock()
	r.llmProxyProtocolViolationCount = map[string]uint64{}
	r.llmProxyProtocolViolationMu.Unlock()
	r.migrationStatusMu.Lock()
	r.migrationStatus = map[migrationStatusKey]int64{}
	r.migrationStatusMu.Unlock()
	r.notifyDroppedMu.Lock()
	r.notifyDroppedCount = map[notifyDroppedKey]uint64{}
	r.notifyDroppedMu.Unlock()
	r.notifyDispatchMu.Lock()
	r.notifyDispatchHist = map[string]*Histogram{}
	r.notifyDispatchMu.Unlock()

	r.requestDuration.reset()
	r.policyEvalDuration.reset()
	r.auditWriteDuration.reset()
}

// Reset zeroes the Default registry. Test helper.
func Reset() { Default.Reset() }

// -- Decision counters -----------------------------------------------------------

// IncDecision increments the appropriate decision counter.
func (r *Registry) IncDecision(decision string) {
	atomic.AddUint64(&r.checksTotal, 1)
	switch decision {
	case "ALLOW":
		atomic.AddUint64(&r.allowedTotal, 1)
	case "DENY":
		atomic.AddUint64(&r.deniedTotal, 1)
	case "REQUIRE_APPROVAL":
		atomic.AddUint64(&r.approvalTotal, 1)
	}
}

// IncRateLimited increments the rate-limit-specific counter.
//
// It used to also bump the checks/denied totals, which double-counted
// rate-limited requests because logAndRespond unconditionally calls
// IncDecision("DENY") for the synthetic rate-limit DENY result. As of v0.5
// the unified logAndRespond path owns those totals for every decision
// (including the synthetic rate-limit DENY); IncRateLimited only touches
// the rate-limit-specific series.
//
// Closes R3 #21 (audit finding "rate-limited requests double-count
// ChecksTotal and DeniedTotal").
func (r *Registry) IncRateLimited() { atomic.AddUint64(&r.rateLimitedTotal, 1) }

// IncApprovalReplayMismatch increments
// agentguard_approval_replay_mismatch_total. Called from
// pkg/proxy.handleCheck when the approval-id round-trip lookup hits an
// entry but the retry request's shape differs from the original.
//
// The counter tracks /v1/check requests that carried an approval_id whose
// corresponding PendingAction.Request did not match the retry's
// operationally-meaningful fields (agent_id / scope / command / path /
// domain / url / action). Mismatches are NOT short-circuited to the cached
// decision — the request falls through to normal Engine.Check evaluation.
// This metric is the security signal: legitimate retries match shape and
// never increment it; a non-zero rate means either a buggy gateway is
// reusing ids across distinct actions or an attacker who learned an
// approved id is replaying it against unrelated commands.
//
// See V05 audit B1 (R-Sec H1, R-Stub C3) for the underlying gating-
// bypass finding the validator closes.
func (r *Registry) IncApprovalReplayMismatch() {
	atomic.AddUint64(&r.approvalReplayMismatchTotal, 1)
}

// Read accessors for the decision counters. These replaced the exported
// raw uint64 vars (pre-v0.6.1 callers did metrics.X()).
func (r *Registry) ChecksTotal() uint64   { return atomic.LoadUint64(&r.checksTotal) }
func (r *Registry) AllowedTotal() uint64  { return atomic.LoadUint64(&r.allowedTotal) }
func (r *Registry) DeniedTotal() uint64   { return atomic.LoadUint64(&r.deniedTotal) }
func (r *Registry) ApprovalTotal() uint64 { return atomic.LoadUint64(&r.approvalTotal) }
func (r *Registry) RateLimitedTotal() uint64 {
	return atomic.LoadUint64(&r.rateLimitedTotal)
}
func (r *Registry) ApprovalReplayMismatchTotal() uint64 {
	return atomic.LoadUint64(&r.approvalReplayMismatchTotal)
}

// -- Labeled counters ------------------------------------------------------------

// IncRequestRejected increments agentguard_request_rejected_total{reason=...}.
// Keyed by a short, bounded-cardinality reason string.
func (r *Registry) IncRequestRejected(reason string) {
	if reason == "" {
		reason = "unknown"
	}
	r.requestRejectedMu.Lock()
	r.requestRejectedCount[reason]++
	r.requestRejectedMu.Unlock()
}

// RequestRejectedSnapshot returns a copy of the current counts (for tests).
func (r *Registry) RequestRejectedSnapshot() map[string]uint64 {
	r.requestRejectedMu.Lock()
	defer r.requestRejectedMu.Unlock()
	return copyStringMap(r.requestRejectedCount)
}

// IncApprovalEvicted increments agentguard_approvals_evicted_total{reason=...}.
// Cardinality is bounded to the ApprovalEvicted* constants above.
func (r *Registry) IncApprovalEvicted(reason string) {
	if reason == "" {
		reason = "unknown"
	}
	r.approvalEvictedMu.Lock()
	r.approvalEvictedCount[reason]++
	r.approvalEvictedMu.Unlock()
}

// ApprovalEvictedFor returns the count for a specific reason (for tests).
func (r *Registry) ApprovalEvictedFor(reason string) uint64 {
	r.approvalEvictedMu.Lock()
	defer r.approvalEvictedMu.Unlock()
	return r.approvalEvictedCount[reason]
}

// IncRateLimitBucketEvicted increments
// agentguard_ratelimit_bucket_evictions_total{scope=...}. Cardinality is
// bounded by the set of policy scopes (typically < 20 across a deployment).
func (r *Registry) IncRateLimitBucketEvicted(scope string) {
	if scope == "" {
		scope = "unknown"
	}
	r.rateLimitEvictedMu.Lock()
	r.rateLimitEvictedCount[scope]++
	r.rateLimitEvictedMu.Unlock()
}

// RateLimitBucketEvictedFor returns the eviction count for a scope (for tests).
func (r *Registry) RateLimitBucketEvictedFor(scope string) uint64 {
	r.rateLimitEvictedMu.Lock()
	defer r.rateLimitEvictedMu.Unlock()
	return r.rateLimitEvictedCount[scope]
}

// IncSSEEventDropped bumps the labeled counter for an SSE broadcast drop.
// Reasons are a bounded string set; slow_consumer is the only reason the
// current broadcast path produces.
func (r *Registry) IncSSEEventDropped(reason string) {
	if reason == "" {
		reason = "unknown"
	}
	r.sseDroppedMu.Lock()
	r.sseDroppedCount[reason]++
	r.sseDroppedMu.Unlock()
}

// SSEEventDroppedFor returns the count for a specific reason (for tests).
func (r *Registry) SSEEventDroppedFor(reason string) uint64 {
	r.sseDroppedMu.Lock()
	defer r.sseDroppedMu.Unlock()
	return r.sseDroppedCount[reason]
}

// IncNotifyDropped increments the labeled counter for a notification drop.
// notifier should be a bounded-cardinality notifier type
// ("webhook"/"slack"/"console"/"log"); reason should be a stable NotifyDropped*
// constant. Callers MUST NOT pass agent- or user-supplied strings here — that
// would explode Prometheus cardinality.
func (r *Registry) IncNotifyDropped(notifier, reason string) {
	if notifier == "" {
		notifier = "unknown"
	}
	if reason == "" {
		reason = "unknown"
	}
	r.notifyDroppedMu.Lock()
	r.notifyDroppedCount[notifyDroppedKey{Notifier: notifier, Reason: reason}]++
	r.notifyDroppedMu.Unlock()
}

// NotifyDroppedSnapshot returns a copy of the current counts (for tests).
func (r *Registry) NotifyDroppedSnapshot() map[notifyDroppedKey]uint64 {
	r.notifyDroppedMu.Lock()
	defer r.notifyDroppedMu.Unlock()
	out := make(map[notifyDroppedKey]uint64, len(r.notifyDroppedCount))
	for k, v := range r.notifyDroppedCount {
		out[k] = v
	}
	return out
}

// NotifyDroppedFor returns the count for a specific (notifier, reason) pair
// (for tests).
func (r *Registry) NotifyDroppedFor(notifier, reason string) uint64 {
	r.notifyDroppedMu.Lock()
	defer r.notifyDroppedMu.Unlock()
	return r.notifyDroppedCount[notifyDroppedKey{Notifier: notifier, Reason: reason}]
}

// -- LLM-proxy series ------------------------------------------------------------

// IncLLMProxyBufferOverflow increments
// agentguard_llmproxy_buffer_overflow_total{provider=...}. Provider
// MUST be "openai" or "anthropic" — the LLM proxy enforces that
// upstream so cardinality stays bounded. The proxy buffers streaming
// tool_call deltas up to --max-buffer-bytes; if accumulated arguments
// exceed that cap before finish_reason arrives, the call is denied as
// a synthetic refusal (operators want this visible). See
// pkg/llmproxy/streaming.go for the call sites.
func (r *Registry) IncLLMProxyBufferOverflow(provider string) {
	if provider == "" {
		provider = "unknown"
	}
	r.llmProxyBufferOverflowMu.Lock()
	r.llmProxyBufferOverflowCount[provider]++
	r.llmProxyBufferOverflowMu.Unlock()
}

// LLMProxyBufferOverflowFor returns the current count (for tests).
func (r *Registry) LLMProxyBufferOverflowFor(provider string) uint64 {
	r.llmProxyBufferOverflowMu.Lock()
	defer r.llmProxyBufferOverflowMu.Unlock()
	return r.llmProxyBufferOverflowCount[provider]
}

// IncLLMProxyNonStreamingOverflow increments
// agentguard_llmproxy_non_streaming_overflow_total{provider=...}.
// Distinct from the streaming overflow counter so dashboards can break
// out the two failure modes (the streaming counter measures runaway
// tool_call argument accumulation; this one measures upstream response
// bodies that are simply too large to safely inspect for tool_calls).
// F9 (B2) wires the non-streaming forwarders.
func (r *Registry) IncLLMProxyNonStreamingOverflow(provider string) {
	if provider == "" {
		provider = "unknown"
	}
	r.llmProxyNonStreamingOverflowMu.Lock()
	r.llmProxyNonStreamingOverflowCount[provider]++
	r.llmProxyNonStreamingOverflowMu.Unlock()
}

// LLMProxyNonStreamingOverflowFor returns the current count (for tests).
func (r *Registry) LLMProxyNonStreamingOverflowFor(provider string) uint64 {
	r.llmProxyNonStreamingOverflowMu.Lock()
	defer r.llmProxyNonStreamingOverflowMu.Unlock()
	return r.llmProxyNonStreamingOverflowCount[provider]
}

// IncLLMProxyProtocolViolation increments
// agentguard_llmproxy_protocol_violation_total{provider=...}. Security
// audit finding H1: a structurally unsafe stream (e.g. a second
// Anthropic tool_use content block opened before the first closed) is
// refused fail-closed rather than partially gated. A non-zero rate here
// means the proxy refused a stream whose block ordering could otherwise
// have smuggled an ungated tool call past the gate. See
// pkg/llmproxy/streaming.go.
func (r *Registry) IncLLMProxyProtocolViolation(provider string) {
	if provider == "" {
		provider = "unknown"
	}
	r.llmProxyProtocolViolationMu.Lock()
	r.llmProxyProtocolViolationCount[provider]++
	r.llmProxyProtocolViolationMu.Unlock()
}

// LLMProxyProtocolViolationFor returns the current count (for tests).
func (r *Registry) LLMProxyProtocolViolationFor(provider string) uint64 {
	r.llmProxyProtocolViolationMu.Lock()
	defer r.llmProxyProtocolViolationMu.Unlock()
	return r.llmProxyProtocolViolationCount[provider]
}

// SetLLMProxyStreamsActive updates the active-streams gauge. Called
// from the llmproxy server on every stream entry/exit (which atomically
// also updates the underlying server-side counter — this metric
// mirrors that counter). 0 is a valid value (no streams in flight).
// The gauge is sampled by the llmproxy server, not the central server,
// so it lives in its own process — but it ships through the same
// metrics surface so a single Prometheus scrape config covers both
// binaries when the llmproxy mounts /metrics. Closes R-Sec H3.
func (r *Registry) SetLLMProxyStreamsActive(n int64) {
	atomic.StoreInt64(&r.llmProxyStreamsActive, n)
}

// IncLLMProxyStreamsRejected bumps
// agentguard_llmproxy_streams_rejected_total. Called once per
// streaming request that was refused with 503 because the global
// cap was already at MaxConcurrentStreams.
func (r *Registry) IncLLMProxyStreamsRejected() {
	atomic.AddUint64(&r.llmProxyStreamsRejectedTotal, 1)
}

// LLMProxyStreamsActive returns the current active-streams gauge value
// (for tests).
func (r *Registry) LLMProxyStreamsActive() int64 {
	return atomic.LoadInt64(&r.llmProxyStreamsActive)
}

// LLMProxyStreamsRejectedTotal returns the rejected-streams counter
// (for tests).
func (r *Registry) LLMProxyStreamsRejectedTotal() uint64 {
	return atomic.LoadUint64(&r.llmProxyStreamsRejectedTotal)
}

// -- Audit series ----------------------------------------------------------------

// IncAuditCorruptLine bumps agentguard_audit_corrupt_lines_total: audit
// log lines that failed JSON parse during Query() and were skipped. Rare
// in practice — the usual cause is a crash between the write syscall and
// the newline flush, or disk corruption. Kept visible via /metrics so
// operators can spot silent audit-file degradation instead of
// discovering it when a query returns fewer entries than expected.
func (r *Registry) IncAuditCorruptLine() { atomic.AddUint64(&r.auditCorruptLinesTotal, 1) }

// AuditCorruptLinesTotal returns the corrupt-line counter (for tests).
func (r *Registry) AuditCorruptLinesTotal() uint64 {
	return atomic.LoadUint64(&r.auditCorruptLinesTotal)
}

// SetAuditReplayDuration records the duration of the startup audit replay.
// Expressed in seconds in the Prometheus output; nanoseconds are stored
// atomically under the hood so the setter is a single instruction.
// Gauge, not histogram: replay is a one-shot startup event.
func (r *Registry) SetAuditReplayDuration(d time.Duration) {
	atomic.StoreInt64(&r.auditReplayDurationNanos, int64(d))
}

// AddAuditReplayEntries records entries processed during replay. Cumulative
// across multiple replays in pathological re-entrance, but in the normal
// single-replay-per-process case just equals that one replay's count.
func (r *Registry) AddAuditReplayEntries(n uint64) {
	atomic.AddUint64(&r.auditReplayEntriesTotal, n)
}

// IncAuditRotation increments agentguard_audit_rotations_total. Called from
// the FileLogger rotation success path after the new live file is open.
func (r *Registry) IncAuditRotation() { atomic.AddUint64(&r.auditRotationsTotal, 1) }

// AuditReplayEntriesTotal returns the replay-entries counter (for tests).
func (r *Registry) AuditReplayEntriesTotal() uint64 {
	return atomic.LoadUint64(&r.auditReplayEntriesTotal)
}

// AuditRotationsTotal returns the rotation counter (for tests).
func (r *Registry) AuditRotationsTotal() uint64 {
	return atomic.LoadUint64(&r.auditRotationsTotal)
}

// IncAuditBufferedDroppedToOverflow counts an audit entry spilled to the
// BufferedAsyncLogger's overflow file (queue saturated, shutdown race,
// or underlying-logger failure). The entry is durable on disk, not lost;
// a sustained non-zero rate means the queue/worker sizing can't keep up.
func (r *Registry) IncAuditBufferedDroppedToOverflow() {
	atomic.AddUint64(&r.auditBufferedDroppedTotal, 1)
}

// AddAuditBufferedDrainedFromOverflow counts entries the recovery
// goroutine pushed back from the overflow file into the queue.
func (r *Registry) AddAuditBufferedDrainedFromOverflow(n uint64) {
	atomic.AddUint64(&r.auditBufferedDrainedTotal, n)
}

// SetAuditBufferedQueueDepth updates the buffered-audit queue gauge.
// Maintained by the BufferedAsyncLogger on enqueue/dequeue.
func (r *Registry) SetAuditBufferedQueueDepth(n int64) {
	atomic.StoreInt64(&r.auditBufferedQueueDepth, n)
}

// AuditBufferedDroppedToOverflowTotal returns the spill counter (for tests).
func (r *Registry) AuditBufferedDroppedToOverflowTotal() uint64 {
	return atomic.LoadUint64(&r.auditBufferedDroppedTotal)
}

// AuditBufferedDrainedFromOverflowTotal returns the drain counter (for tests).
func (r *Registry) AuditBufferedDrainedFromOverflowTotal() uint64 {
	return atomic.LoadUint64(&r.auditBufferedDrainedTotal)
}

// SetMigrationStatus updates the migration-status gauge for a given
// (from, to, status) triple. Value is 1 for the current outcome and 0
// for the others — Prometheus can then do `max by (from,to) (...)`.
// Callers typically record one ran/skipped/failed value per migration
// per startup.
func (r *Registry) SetMigrationStatus(from, to, status string, value int64) {
	if from == "" {
		from = "unknown"
	}
	if to == "" {
		to = "unknown"
	}
	if status == "" {
		status = "unknown"
	}
	r.migrationStatusMu.Lock()
	r.migrationStatus[migrationStatusKey{From: from, To: to, Status: status}] = value
	r.migrationStatusMu.Unlock()
}

// MigrationStatusFor returns the gauge value for a (from, to, status) triple
// (for tests).
func (r *Registry) MigrationStatusFor(from, to, status string) int64 {
	r.migrationStatusMu.Lock()
	defer r.migrationStatusMu.Unlock()
	return r.migrationStatus[migrationStatusKey{From: from, To: to, Status: status}]
}

// -- Notify series ---------------------------------------------------------------

// SetNotifyQueueDepth updates the notify dispatch queue depth gauge.
// Set from the dispatcher on each Send attempt; a scrape-time read
// would race with enqueue without additional locking.
func (r *Registry) SetNotifyQueueDepth(n int) {
	atomic.StoreInt64(&r.notifyQueueDepth, int64(n))
}

// IncNotifySpooled counts a notification event written to the on-disk
// spool because the dispatch queue was full (durable, will be retried
// by the recovery loop — NOT a drop).
func (r *Registry) IncNotifySpooled() { atomic.AddUint64(&r.notifySpooledTotal, 1) }

// AddNotifyDespooled counts spooled events re-enqueued for dispatch.
func (r *Registry) AddNotifyDespooled(n uint64) {
	atomic.AddUint64(&r.notifyDespooledTotal, n)
}

// NotifySpooledTotal returns the spooled counter (for tests).
func (r *Registry) NotifySpooledTotal() uint64 {
	return atomic.LoadUint64(&r.notifySpooledTotal)
}

// NotifyDespooledTotal returns the despooled counter (for tests).
func (r *Registry) NotifyDespooledTotal() uint64 {
	return atomic.LoadUint64(&r.notifyDespooledTotal)
}

// ObserveNotifyDispatch records a dispatch latency in seconds for the named
// notifier type. A missing histogram is created lazily; cardinality is
// bounded to the notifierType() domain in pkg/notify
// (webhook|slack|console|log|unknown).
func (r *Registry) ObserveNotifyDispatch(notifier string, seconds float64) {
	if notifier == "" {
		notifier = "unknown"
	}
	r.notifyDispatchMu.Lock()
	h, ok := r.notifyDispatchHist[notifier]
	if !ok {
		h = newHistogram(notifySecondsBuckets)
		r.notifyDispatchHist[notifier] = h
	}
	r.notifyDispatchMu.Unlock()
	h.Observe(seconds)
}

// notifyDispatchSnapshot returns a shallow map copy so the emitter can walk
// without holding notifyDispatchMu across I/O.
func (r *Registry) notifyDispatchSnapshot() map[string]*Histogram {
	r.notifyDispatchMu.Lock()
	defer r.notifyDispatchMu.Unlock()
	out := make(map[string]*Histogram, len(r.notifyDispatchHist))
	for k, v := range r.notifyDispatchHist {
		out[k] = v
	}
	return out
}

// -- SSE / queue gauges ------------------------------------------------------------

// IncSSESubscribers is called on Subscribe. Matching dec runs on
// Unsubscribe so the gauge stays accurate even if a client drops without
// the server side noticing (Unsubscribe is always called from the SSE
// handler's defer). Maintained via inc/dec rather than a scrape-time
// read so the /metrics handler doesn't have to take the ApprovalQueue
// lock.
func (r *Registry) IncSSESubscribers() { atomic.AddInt64(&r.sseSubscribers, 1) }

// DecSSESubscribers is the counterpart to IncSSESubscribers.
func (r *Registry) DecSSESubscribers() { atomic.AddInt64(&r.sseSubscribers, -1) }

// SetRateLimitBuckets updates the rate-limit bucket gauge. Called from the
// /metrics handler with Limiter.BucketCount() so operators can see bucket
// growth without exporting the limiter internals.
func (r *Registry) SetRateLimitBuckets(n int) {
	atomic.StoreInt64(&r.rateLimitBuckets, int64(n))
}

// SetPendingApprovals sets the current queue depth gauge.
func (r *Registry) SetPendingApprovals(n int) {
	atomic.StoreInt64(&r.pendingApprovals, int64(n))
}

// -- Hot-path duration histograms ---------------------------------------------------

// ObserveRequestDuration records one end-to-end /v1/check latency in ms.
func (r *Registry) ObserveRequestDuration(ms float64) { r.requestDuration.Observe(ms) }

// ObservePolicyEvalDuration records one Engine.Check latency in ms.
func (r *Registry) ObservePolicyEvalDuration(ms float64) { r.policyEvalDuration.Observe(ms) }

// ObserveAuditWriteDuration records one Logger.Log latency in ms.
func (r *Registry) ObserveAuditWriteDuration(ms float64) { r.auditWriteDuration.Observe(ms) }

// -- Histogram -------------------------------------------------------------------

// durationBuckets are shared upper-bounds in milliseconds. The tail (2500,
// 5000, 10000) covers events that are rare on the hot path but visible in
// practice: a slow audit-file fsync, a policy reload contending with
// Engine.Check, a rate-limit lock under heavy fan-out. Without these
// buckets, anything over 1 s all lands in +Inf and p99 loses resolution.
//
// These boundaries are treated as a stable contract: re-bucketing
// invalidates historical Prometheus data (see CHANGELOG v0.4.1). Only
// append new boundaries at the tail; do not edit or reorder existing ones.
var durationBuckets = []float64{
	0.25, 0.5, 1, 2, 5, 10, 25, 50, 100, 250, 500, 1000,
	2500, 5000, 10000,
}

// notifySecondsBuckets mirror typical notifier costs: sub-10ms for
// console/log, tens-to-hundreds-of-ms for webhook/slack, with a tail
// capturing the 10 s default HTTP timeout.
var notifySecondsBuckets = []float64{
	0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10,
}

// Histogram tracks a distribution using cumulative bucket counts.
// Each bucket counts observations with value ≤ the bucket bound, which is the
// Prometheus histogram convention.
type Histogram struct {
	mu      sync.Mutex
	buckets []float64
	counts  []uint64 // len = len(buckets) + 1 (+Inf)
	sum     float64
	total   uint64
}

func newHistogram(buckets []float64) *Histogram {
	return &Histogram{
		buckets: buckets,
		counts:  make([]uint64, len(buckets)+1),
	}
}

// Observe records one observation in milliseconds.
func (h *Histogram) Observe(ms float64) {
	h.mu.Lock()
	h.sum += ms
	h.total++
	for i, b := range h.buckets {
		if ms <= b {
			h.counts[i]++
		}
	}
	h.counts[len(h.buckets)]++ // +Inf is always incremented
	h.mu.Unlock()
}

// Snapshot returns a copy of internal state under the lock.
func (h *Histogram) Snapshot() (buckets []float64, counts []uint64, sum float64, total uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	b := make([]float64, len(h.buckets))
	copy(b, h.buckets)
	c := make([]uint64, len(h.counts))
	copy(c, h.counts)
	return b, c, h.sum, h.total
}

// reset zeroes the histogram in place (Registry.Reset test helper).
func (h *Histogram) reset() {
	h.mu.Lock()
	for i := range h.counts {
		h.counts[i] = 0
	}
	h.sum = 0
	h.total = 0
	h.mu.Unlock()
}

// -- Prometheus text output --------------------------------------------------

// WritePrometheus writes all metrics to w in the Prometheus text exposition
// format (https://prometheus.io/docs/instrumenting/exposition_formats/).
func (r *Registry) WritePrometheus(w io.Writer) {
	writeCounter(w, "agentguard_checks_total",
		"Total number of /v1/check requests processed.",
		atomic.LoadUint64(&r.checksTotal))
	writeCounter(w, "agentguard_allowed_total",
		"Number of requests with decision ALLOW.",
		atomic.LoadUint64(&r.allowedTotal))
	writeCounter(w, "agentguard_denied_total",
		"Number of requests with decision DENY (including rate-limit denies).",
		atomic.LoadUint64(&r.deniedTotal))
	writeCounter(w, "agentguard_approval_required_total",
		"Number of requests with decision REQUIRE_APPROVAL.",
		atomic.LoadUint64(&r.approvalTotal))
	writeCounter(w, "agentguard_rate_limited_total",
		"Number of requests denied by the rate limiter.",
		atomic.LoadUint64(&r.rateLimitedTotal))
	writeCounter(w, "agentguard_approval_replay_mismatch_total",
		"approval_id round-trips whose retry request shape did not match the original PendingAction.Request and therefore fell through to fresh policy evaluation. Non-zero values indicate either a buggy gateway or an attempted replay attack — see audit B1.",
		atomic.LoadUint64(&r.approvalReplayMismatchTotal))

	writeGauge(w, "agentguard_pending_approvals",
		"Current number of actions waiting for human approval.",
		float64(atomic.LoadInt64(&r.pendingApprovals)))

	writeHistogram(w, "agentguard_request_duration_ms",
		"End-to-end latency of /v1/check in milliseconds.",
		r.requestDuration)
	writeHistogram(w, "agentguard_policy_eval_duration_ms",
		"Time spent in Engine.Check (policy rule evaluation) in milliseconds.",
		r.policyEvalDuration)
	writeHistogram(w, "agentguard_audit_write_duration_ms",
		"Time spent in Logger.Log (audit file write) in milliseconds.",
		r.auditWriteDuration)

	writeGauge(w, "agentguard_ratelimit_buckets",
		"Current number of active rate-limit token buckets tracked in memory.",
		float64(atomic.LoadInt64(&r.rateLimitBuckets)))

	writeGauge(w, "agentguard_sse_subscribers",
		"Current number of connected Server-Sent Events subscribers on /api/stream.",
		float64(atomic.LoadInt64(&r.sseSubscribers)))

	writeGauge(w, "agentguard_notify_queue_depth",
		"Current length of the shared notify dispatch queue (sampled at last enqueue).",
		float64(atomic.LoadInt64(&r.notifyQueueDepth)))
	writeCounter(w, "agentguard_notify_spooled_to_disk_total",
		"Notification events written to the on-disk spool because the dispatch queue was full (retried by the recovery loop, not dropped).",
		atomic.LoadUint64(&r.notifySpooledTotal))
	writeCounter(w, "agentguard_notify_despooled_total",
		"Spooled notification events re-enqueued for dispatch.",
		atomic.LoadUint64(&r.notifyDespooledTotal))
	r.writeNotifyDispatchDuration(w)

	writeCounter(w, "agentguard_audit_replay_entries_total",
		"Audit log entries re-read at startup to seed in-memory counters.",
		atomic.LoadUint64(&r.auditReplayEntriesTotal))
	writeCounter(w, "agentguard_audit_rotations_total",
		"Audit file rotations triggered by the live-file size threshold.",
		atomic.LoadUint64(&r.auditRotationsTotal))
	writeCounter(w, "agentguard_audit_corrupt_lines_total",
		"Audit log lines that failed JSON parse during Query() and were skipped.",
		atomic.LoadUint64(&r.auditCorruptLinesTotal))
	// Replay duration is stored as nanoseconds; emit as seconds to match the
	// Prometheus base-unit convention.
	writeGauge(w, "agentguard_audit_replay_duration_seconds",
		"Wall-clock duration of the most recent startup audit replay.",
		time.Duration(atomic.LoadInt64(&r.auditReplayDurationNanos)).Seconds())

	writeCounter(w, "agentguard_audit_buffered_dropped_to_overflow_total",
		"Audit entries spilled to the buffered logger's overflow file (queue saturated or underlying write failed); durable on disk, not lost.",
		atomic.LoadUint64(&r.auditBufferedDroppedTotal))
	writeCounter(w, "agentguard_audit_buffered_drained_from_overflow_total",
		"Audit entries the recovery goroutine pushed back from the overflow file into the queue.",
		atomic.LoadUint64(&r.auditBufferedDrainedTotal))
	writeGauge(w, "agentguard_audit_buffered_queue_depth",
		"Approximate number of audit entries waiting in the buffered logger's in-memory queue.",
		float64(atomic.LoadInt64(&r.auditBufferedQueueDepth)))

	writeGauge(w, "agentguard_llmproxy_streams_active",
		"Current number of in-flight streaming LLM proxy requests (server-process gauge; bounded by --max-concurrent-streams).",
		float64(atomic.LoadInt64(&r.llmProxyStreamsActive)))
	writeCounter(w, "agentguard_llmproxy_streams_rejected_total",
		"LLM proxy streaming requests refused with 503 because the --max-concurrent-streams cap was reached.",
		atomic.LoadUint64(&r.llmProxyStreamsRejectedTotal))

	writeLabeledCounter(w, "agentguard_request_rejected_total",
		"Requests rejected before policy evaluation, by reason (e.g. body_too_large).",
		"reason", snapshotStringMap(&r.requestRejectedMu, r.requestRejectedCount))
	r.writeNotifyDropped(w)
	writeLabeledCounter(w, "agentguard_approvals_evicted_total",
		"Approval queue entries removed under capacity pressure, by reason (lru_resolved|queue_full).",
		"reason", snapshotStringMap(&r.approvalEvictedMu, r.approvalEvictedCount))
	writeLabeledCounter(w, "agentguard_ratelimit_bucket_evictions_total",
		"Rate-limit token buckets evicted under capacity pressure (MaxBuckets), labeled by policy scope.",
		"scope", snapshotStringMap(&r.rateLimitEvictedMu, r.rateLimitEvictedCount))
	writeLabeledCounter(w, "agentguard_sse_events_dropped_total",
		"Server-Sent Events dropped before reaching the subscriber, labeled by reason (slow_consumer).",
		"reason", snapshotStringMap(&r.sseDroppedMu, r.sseDroppedCount))
	r.writeMigrationStatus(w)
	writeLabeledCounter(w, "agentguard_llmproxy_buffer_overflow_total",
		"LLM-proxy streaming tool_call accumulations that exceeded --max-buffer-bytes and were converted to synthetic refusals, by provider.",
		"provider", snapshotStringMap(&r.llmProxyBufferOverflowMu, r.llmProxyBufferOverflowCount))
	writeLabeledCounter(w, "agentguard_llmproxy_non_streaming_overflow_total",
		"LLM-proxy non-streaming upstream responses that exceeded --max-buffer-bytes and were converted to synthetic refusals, by provider.",
		"provider", snapshotStringMap(&r.llmProxyNonStreamingOverflowMu, r.llmProxyNonStreamingOverflowCount))
	writeLabeledCounter(w, "agentguard_llmproxy_protocol_violation_total",
		"LLM-proxy streams refused fail-closed because the upstream's content-block ordering was structurally unsafe to gate (e.g. an interleaved second tool_use), by provider.",
		"provider", snapshotStringMap(&r.llmProxyProtocolViolationMu, r.llmProxyProtocolViolationCount))
	writeDeprecations(w)
}

// writeMigrationStatus emits agentguard_audit_migration_status{from,to,status}.
// Always emits HELP/TYPE so the series is visible before the first
// migration is observed.
func (r *Registry) writeMigrationStatus(w io.Writer) {
	const name = "agentguard_audit_migration_status"
	const help = "Audit-schema migration outcome gauge, labeled by from/to versions and status (ran|skipped|failed)."
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name)

	r.migrationStatusMu.Lock()
	snap := make(map[migrationStatusKey]int64, len(r.migrationStatus))
	for k, v := range r.migrationStatus {
		snap[k] = v
	}
	r.migrationStatusMu.Unlock()
	if len(snap) == 0 {
		return
	}
	keys := make([]migrationStatusKey, 0, len(snap))
	for k := range snap {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].From != keys[j].From {
			return keys[i].From < keys[j].From
		}
		if keys[i].To != keys[j].To {
			return keys[i].To < keys[j].To
		}
		return keys[i].Status < keys[j].Status
	})
	for _, k := range keys {
		fmt.Fprintf(w, "%s{from=\"%s\",to=\"%s\",status=\"%s\"} %d\n",
			name, escapeLabel(k.From), escapeLabel(k.To), escapeLabel(k.Status), snap[k])
	}
}

// writeNotifyDispatchDuration emits the labeled histogram
// agentguard_notify_dispatch_duration_seconds{notifier=...}. Always emits
// HELP/TYPE so the scraper sees the metric even when no dispatch has
// happened yet.
func (r *Registry) writeNotifyDispatchDuration(w io.Writer) {
	const name = "agentguard_notify_dispatch_duration_seconds"
	const help = "Wall-clock time spent in Notifier.Notify() per notifier type, in seconds."
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s histogram\n", name, help, name)

	snap := r.notifyDispatchSnapshot()
	if len(snap) == 0 {
		return
	}
	keys := make([]string, 0, len(snap))
	for k := range snap {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, notifier := range keys {
		h := snap[notifier]
		buckets, counts, sum, total := h.Snapshot()
		lv := escapeLabel(notifier)
		for i, b := range buckets {
			fmt.Fprintf(w, "%s_bucket{notifier=\"%s\",le=\"%g\"} %d\n",
				name, lv, b, counts[i])
		}
		fmt.Fprintf(w, "%s_bucket{notifier=\"%s\",le=\"+Inf\"} %d\n",
			name, lv, counts[len(buckets)])
		fmt.Fprintf(w, "%s_sum{notifier=\"%s\"} %g\n", name, lv, sum)
		fmt.Fprintf(w, "%s_count{notifier=\"%s\"} %d\n", name, lv, total)
	}
}

// writeNotifyDropped emits agentguard_notify_events_dropped_total with the
// two-dimensional (notifier, reason) label. Always emits HELP/TYPE so a
// Prometheus scraper sees the metric even when no drops have happened.
func (r *Registry) writeNotifyDropped(w io.Writer) {
	const name = "agentguard_notify_events_dropped_total"
	const help = "Notifier events dropped before delivery, by notifier type and reason (e.g. queue_full)."
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", name, help, name)
	snap := r.NotifyDroppedSnapshot()
	if len(snap) == 0 {
		return
	}
	// Deterministic exposition order: sort by (notifier, reason).
	keys := make([]notifyDroppedKey, 0, len(snap))
	for k := range snap {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Notifier != keys[j].Notifier {
			return keys[i].Notifier < keys[j].Notifier
		}
		return keys[i].Reason < keys[j].Reason
	})
	for _, k := range keys {
		fmt.Fprintf(w, "%s{notifier=\"%s\",reason=\"%s\"} %d\n",
			name, escapeLabel(k.Notifier), escapeLabel(k.Reason), snap[k])
	}
}

// writeDeprecations emits a labeled counter for every deprecated feature that
// has been used at least once in this process. Cardinality is bounded by the
// "feature" column in docs/DEPRECATIONS.md. Deprecation usage is tracked in
// pkg/deprecation's process-global state, so this series is shared across
// registries.
func writeDeprecations(w io.Writer) {
	writeLabeledCounter(w, "agentguard_deprecations_used_total",
		"Times a deprecated feature was used, labeled by stable feature key (see docs/DEPRECATIONS.md).",
		"feature", deprecation.Snapshot())
}

// writeLabeledCounter emits one single-label counter series: HELP/TYPE
// always (so scrapers see the metric before the first increment), then
// one line per label value in sorted order. Every single-label counter
// in this package shares this emitter.
func writeLabeledCounter(w io.Writer, name, help, label string, snap map[string]uint64) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", name, help, name)
	if len(snap) == 0 {
		return
	}
	keys := make([]string, 0, len(snap))
	for k := range snap {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(w, "%s{%s=\"%s\"} %d\n", name, label, escapeLabel(k), snap[k])
	}
}

// snapshotStringMap copies a string-keyed counter map under its mutex so
// the emitter can walk it without holding the lock across I/O.
func snapshotStringMap(mu *sync.Mutex, m map[string]uint64) map[string]uint64 {
	mu.Lock()
	defer mu.Unlock()
	return copyStringMap(m)
}

func copyStringMap(m map[string]uint64) map[string]uint64 {
	out := make(map[string]uint64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// escapeLabel escapes a Prometheus label value per the text exposition spec:
// backslash, double-quote, and newline are the only special characters.
func escapeLabel(s string) string {
	if !strings.ContainsAny(s, "\\\"\n") {
		return s
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return r.Replace(s)
}

func writeCounter(w io.Writer, name, help string, value uint64) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, help, name, name, value)
}

func writeGauge(w io.Writer, name, help string, value float64) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n%s %g\n", name, help, name, name, value)
}

func writeHistogram(w io.Writer, name, help string, h *Histogram) {
	buckets, counts, sum, total := h.Snapshot()
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s histogram\n", name, help, name)
	for i, b := range buckets {
		fmt.Fprintf(w, "%s_bucket{le=\"%g\"} %d\n", name, b, counts[i])
	}
	fmt.Fprintf(w, "%s_bucket{le=\"+Inf\"} %d\n", name, counts[len(buckets)])
	fmt.Fprintf(w, "%s_sum %g\n", name, sum)
	fmt.Fprintf(w, "%s_count %d\n", name, total)
}
