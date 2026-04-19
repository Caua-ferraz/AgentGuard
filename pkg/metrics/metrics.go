// Package metrics provides a lightweight in-process metrics registry with
// Prometheus text-format output. It requires zero external dependencies.
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

// -- Counters ----------------------------------------------------------------

var (
	ChecksTotal      uint64 // all /v1/check requests
	AllowedTotal     uint64
	DeniedTotal      uint64
	ApprovalTotal    uint64 // REQUIRE_APPROVAL decisions
	RateLimitedTotal uint64 // rate-limit denies

	// Labeled counter for requests rejected before policy evaluation.
	// Keyed by a short, bounded-cardinality reason string.
	requestRejectedMu    sync.Mutex
	requestRejectedCount = map[string]uint64{}
)

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

var (
	approvalEvictedMu    sync.Mutex
	approvalEvictedCount = map[string]uint64{}
)

// Rate-limit bucket eviction is labeled by scope (a bounded-cardinality
// value from the policy — e.g. "shell", "network", "filesystem"). A key of
// the form "scope:agent_id" is split by the caller before incrementing.
var (
	rateLimitEvictedMu    sync.Mutex
	rateLimitEvictedCount = map[string]uint64{}
)

// IncRateLimitBucketEvicted increments
// agentguard_ratelimit_bucket_evictions_total{scope=...}. Cardinality is
// bounded by the set of policy scopes (typically < 20 across a deployment).
func IncRateLimitBucketEvicted(scope string) {
	if scope == "" {
		scope = "unknown"
	}
	rateLimitEvictedMu.Lock()
	rateLimitEvictedCount[scope]++
	rateLimitEvictedMu.Unlock()
}

// RateLimitBucketEvictedFor returns the eviction count for a scope (for tests).
func RateLimitBucketEvictedFor(scope string) uint64 {
	rateLimitEvictedMu.Lock()
	defer rateLimitEvictedMu.Unlock()
	return rateLimitEvictedCount[scope]
}

// AuditCorruptLinesTotal counts audit log lines that failed JSON parse
// during Query() and were skipped. Rare in practice — the usual cause is
// a crash between the write syscall and the newline flush, or disk
// corruption. Kept visible via /metrics so operators can spot silent
// audit-file degradation instead of discovering it when a query returns
// fewer entries than expected.
var AuditCorruptLinesTotal uint64

// IncAuditCorruptLine bumps agentguard_audit_corrupt_lines_total.
func IncAuditCorruptLine() {
	atomic.AddUint64(&AuditCorruptLinesTotal, 1)
}

// Audit replay + rotation counters. Replay happens once at startup (seeding
// in-memory decision counters from the audit log); rotations happen inline
// on FileLogger.Log when the size threshold is crossed.
var (
	AuditReplayEntriesTotal uint64
	AuditRotationsTotal     uint64

	// auditReplayDurationSeconds is the duration (in seconds) of the most
	// recent replay. Gauge, not histogram: replay is a one-shot startup
	// event; a histogram would accumulate at most one observation per
	// process lifetime and offer no additional detail.
	auditReplayDurationSeconds int64 // stored as nanoseconds via atomic.Int64
)

// SetAuditReplayDuration records the duration of the startup audit replay.
// Expressed in seconds in the Prometheus output; nanoseconds are stored
// atomically under the hood so the setter is a single instruction.
func SetAuditReplayDuration(d time.Duration) {
	atomic.StoreInt64(&auditReplayDurationSeconds, int64(d))
}

// AddAuditReplayEntries records entries processed during replay. Cumulative
// across multiple replays in pathological re-entrance, but in the normal
// single-replay-per-process case just equals that one replay's count.
func AddAuditReplayEntries(n uint64) {
	atomic.AddUint64(&AuditReplayEntriesTotal, n)
}

// IncAuditRotation increments agentguard_audit_rotations_total. Called from
// the FileLogger rotation success path after the new live file is open.
func IncAuditRotation() {
	atomic.AddUint64(&AuditRotationsTotal, 1)
}

// Migration status: a gauge describing what happened to each registered
// audit-schema migration at startup. The label tuple (from, to, status) is
// bounded because each Migration has a single From/To pair and status is
// drawn from {ran, skipped, failed}. Value is 1 for the current outcome
// and 0 for the others — Prometheus can then do `max by (from,to) (...)`.
type migrationStatusKey struct {
	From, To, Status string
}

const (
	MigrationStatusRan     = "ran"
	MigrationStatusSkipped = "skipped"
	MigrationStatusFailed  = "failed"
)

var (
	migrationStatusMu sync.Mutex
	migrationStatus   = map[migrationStatusKey]int64{}
)

// SetMigrationStatus updates the migration-status gauge for a given
// (from, to, status) triple. Callers typically record one ran/skipped/
// failed value per migration per startup.
func SetMigrationStatus(from, to, status string, value int64) {
	if from == "" {
		from = "unknown"
	}
	if to == "" {
		to = "unknown"
	}
	if status == "" {
		status = "unknown"
	}
	migrationStatusMu.Lock()
	migrationStatus[migrationStatusKey{From: from, To: to, Status: status}] = value
	migrationStatusMu.Unlock()
}

// MigrationStatusFor returns the gauge value for a (from, to, status) triple
// (for tests).
func MigrationStatusFor(from, to, status string) int64 {
	migrationStatusMu.Lock()
	defer migrationStatusMu.Unlock()
	return migrationStatus[migrationStatusKey{From: from, To: to, Status: status}]
}

// Notify dispatch metrics:
//
//   agentguard_notify_queue_depth (gauge) — current length of the shared
//       dispatch channel. Set from the dispatcher on each Send attempt; a
//       scrape-time read would race with enqueue without additional locking.
//   agentguard_notify_dispatch_duration_seconds{notifier} (histogram) —
//       wall-clock time spent in Notifier.Notify() per notifier type. Label
//       cardinality is bounded by notifierType() (webhook|slack|console|log|unknown).
//
// The histogram is stored as a lazy map of (notifier type → *Histogram).
// Seconds buckets mirror typical notifier costs: sub-10ms for console/log,
// tens-to-hundreds-of-ms for webhook/slack, with a tail capturing the 10 s
// default HTTP timeout.
var notifyQueueDepth int64

var notifySecondsBuckets = []float64{
	0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10,
}

var (
	notifyDispatchMu   sync.Mutex
	notifyDispatchHist = map[string]*Histogram{}
)

// SetNotifyQueueDepth updates the notify dispatch queue depth gauge.
func SetNotifyQueueDepth(n int) {
	atomic.StoreInt64(&notifyQueueDepth, int64(n))
}

// ObserveNotifyDispatch records a dispatch latency in seconds for the named
// notifier type. A missing histogram is created lazily; cardinality is
// bounded to the notifierType() domain in pkg/notify.
func ObserveNotifyDispatch(notifier string, seconds float64) {
	if notifier == "" {
		notifier = "unknown"
	}
	notifyDispatchMu.Lock()
	h, ok := notifyDispatchHist[notifier]
	if !ok {
		h = newHistogram(notifySecondsBuckets)
		notifyDispatchHist[notifier] = h
	}
	notifyDispatchMu.Unlock()
	h.Observe(seconds)
}

// notifyDispatchSnapshot returns a shallow map copy so the emitter can walk
// without holding notifyDispatchMu across I/O.
func notifyDispatchSnapshot() map[string]*Histogram {
	notifyDispatchMu.Lock()
	defer notifyDispatchMu.Unlock()
	out := make(map[string]*Histogram, len(notifyDispatchHist))
	for k, v := range notifyDispatchHist {
		out[k] = v
	}
	return out
}

// SSE subscribers + dropped-events counter. The gauge is maintained via
// increment/decrement on Subscribe/Unsubscribe rather than via a
// scrape-time read so the /metrics handler doesn't have to take the
// ApprovalQueue lock. Dropped events are labeled by a bounded reason
// string; slow_consumer is the only reason the current broadcast path
// produces.
var sseSubscribers int64

const (
	// SSEDroppedSlowConsumer labels a broadcast that was discarded because
	// the per-subscriber channel was full (the subscriber isn't draining
	// fast enough). This is the fail-fast drop in broadcastLocked's
	// default case.
	SSEDroppedSlowConsumer = "slow_consumer"
)

var (
	sseDroppedMu    sync.Mutex
	sseDroppedCount = map[string]uint64{}
)

// IncSSESubscribers is called on Subscribe. Matching dec runs on
// Unsubscribe so the gauge stays accurate even if a client drops without
// the server side noticing (Unsubscribe is always called from the SSE
// handler's defer).
func IncSSESubscribers() {
	atomic.AddInt64(&sseSubscribers, 1)
}

// DecSSESubscribers is the counterpart to IncSSESubscribers.
func DecSSESubscribers() {
	atomic.AddInt64(&sseSubscribers, -1)
}

// IncSSEEventDropped bumps the labeled counter for an SSE broadcast drop.
func IncSSEEventDropped(reason string) {
	if reason == "" {
		reason = "unknown"
	}
	sseDroppedMu.Lock()
	sseDroppedCount[reason]++
	sseDroppedMu.Unlock()
}

// SSEEventDroppedFor returns the count for a specific reason (for tests).
func SSEEventDroppedFor(reason string) uint64 {
	sseDroppedMu.Lock()
	defer sseDroppedMu.Unlock()
	return sseDroppedCount[reason]
}

// rateLimitBuckets is the current tracked-bucket gauge. Refreshed at each
// /metrics scrape by the handler calling SetRateLimitBuckets.
var rateLimitBuckets int64

// SetRateLimitBuckets updates the rate-limit bucket gauge. Called from the
// /metrics handler with Limiter.BucketCount() so operators can see bucket
// growth without exporting the limiter internals.
func SetRateLimitBuckets(n int) {
	atomic.StoreInt64(&rateLimitBuckets, int64(n))
}

// IncApprovalEvicted increments agentguard_approvals_evicted_total{reason=...}.
// Cardinality is bounded to the ApprovalEvicted* constants above.
func IncApprovalEvicted(reason string) {
	if reason == "" {
		reason = "unknown"
	}
	approvalEvictedMu.Lock()
	approvalEvictedCount[reason]++
	approvalEvictedMu.Unlock()
}

// ApprovalEvictedFor returns the count for a specific reason (for tests).
func ApprovalEvictedFor(reason string) uint64 {
	approvalEvictedMu.Lock()
	defer approvalEvictedMu.Unlock()
	return approvalEvictedCount[reason]
}

// notifyDroppedKey is the composite label key (notifier + reason) for
// agentguard_notify_events_dropped_total. Using a struct as the map key
// keeps the two-dimensional label space cheap without allocating strings.
type notifyDroppedKey struct {
	Notifier string
	Reason   string
}

var (
	notifyDroppedMu    sync.Mutex
	notifyDroppedCount = map[notifyDroppedKey]uint64{}
)

// IncNotifyDropped increments the labeled counter for a notification drop.
// notifier should be a bounded-cardinality notifier type
// ("webhook"/"slack"/"console"/"log"); reason should be a stable NotifyDropped*
// constant. Callers MUST NOT pass agent- or user-supplied strings here — that
// would explode Prometheus cardinality.
func IncNotifyDropped(notifier, reason string) {
	if notifier == "" {
		notifier = "unknown"
	}
	if reason == "" {
		reason = "unknown"
	}
	notifyDroppedMu.Lock()
	notifyDroppedCount[notifyDroppedKey{Notifier: notifier, Reason: reason}]++
	notifyDroppedMu.Unlock()
}

// NotifyDroppedSnapshot returns a copy of the current counts (for tests).
func NotifyDroppedSnapshot() map[notifyDroppedKey]uint64 {
	notifyDroppedMu.Lock()
	defer notifyDroppedMu.Unlock()
	out := make(map[notifyDroppedKey]uint64, len(notifyDroppedCount))
	for k, v := range notifyDroppedCount {
		out[k] = v
	}
	return out
}

// NotifyDroppedFor returns the count for a specific (notifier, reason) pair
// (for tests).
func NotifyDroppedFor(notifier, reason string) uint64 {
	notifyDroppedMu.Lock()
	defer notifyDroppedMu.Unlock()
	return notifyDroppedCount[notifyDroppedKey{Notifier: notifier, Reason: reason}]
}

// IncRequestRejected increments agentguard_request_rejected_total{reason=...}.
func IncRequestRejected(reason string) {
	if reason == "" {
		reason = "unknown"
	}
	requestRejectedMu.Lock()
	requestRejectedCount[reason]++
	requestRejectedMu.Unlock()
}

// RequestRejectedSnapshot returns a copy of the current counts (for tests).
func RequestRejectedSnapshot() map[string]uint64 {
	requestRejectedMu.Lock()
	defer requestRejectedMu.Unlock()
	out := make(map[string]uint64, len(requestRejectedCount))
	for k, v := range requestRejectedCount {
		out[k] = v
	}
	return out
}

// IncDecision increments the appropriate decision counter.
func IncDecision(decision string) {
	atomic.AddUint64(&ChecksTotal, 1)
	switch decision {
	case "ALLOW":
		atomic.AddUint64(&AllowedTotal, 1)
	case "DENY":
		atomic.AddUint64(&DeniedTotal, 1)
	case "REQUIRE_APPROVAL":
		atomic.AddUint64(&ApprovalTotal, 1)
	}
}

// IncRateLimited increments the rate-limit deny counter.
func IncRateLimited() {
	atomic.AddUint64(&ChecksTotal, 1)
	atomic.AddUint64(&DeniedTotal, 1)
	atomic.AddUint64(&RateLimitedTotal, 1)
}

// -- Gauge -------------------------------------------------------------------

var pendingApprovals int64

// SetPendingApprovals sets the current queue depth gauge.
func SetPendingApprovals(n int) {
	atomic.StoreInt64(&pendingApprovals, int64(n))
}

// -- Histograms --------------------------------------------------------------

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

// Package-level histograms.
var (
	RequestDuration    = newHistogram(durationBuckets)
	PolicyEvalDuration = newHistogram(durationBuckets)
	AuditWriteDuration = newHistogram(durationBuckets)
)

// -- Prometheus text output --------------------------------------------------

// WritePrometheus writes all metrics to w in the Prometheus text exposition
// format (https://prometheus.io/docs/instrumenting/exposition_formats/).
func WritePrometheus(w io.Writer) {
	writeCounter(w, "agentguard_checks_total",
		"Total number of /v1/check requests processed.",
		atomic.LoadUint64(&ChecksTotal))
	writeCounter(w, "agentguard_allowed_total",
		"Number of requests with decision ALLOW.",
		atomic.LoadUint64(&AllowedTotal))
	writeCounter(w, "agentguard_denied_total",
		"Number of requests with decision DENY (including rate-limit denies).",
		atomic.LoadUint64(&DeniedTotal))
	writeCounter(w, "agentguard_approval_required_total",
		"Number of requests with decision REQUIRE_APPROVAL.",
		atomic.LoadUint64(&ApprovalTotal))
	writeCounter(w, "agentguard_rate_limited_total",
		"Number of requests denied by the rate limiter.",
		atomic.LoadUint64(&RateLimitedTotal))

	writeGauge(w, "agentguard_pending_approvals",
		"Current number of actions waiting for human approval.",
		float64(atomic.LoadInt64(&pendingApprovals)))

	writeHistogram(w, "agentguard_request_duration_ms",
		"End-to-end latency of /v1/check in milliseconds.",
		RequestDuration)
	writeHistogram(w, "agentguard_policy_eval_duration_ms",
		"Time spent in Engine.Check (policy rule evaluation) in milliseconds.",
		PolicyEvalDuration)
	writeHistogram(w, "agentguard_audit_write_duration_ms",
		"Time spent in Logger.Log (audit file write) in milliseconds.",
		AuditWriteDuration)

	writeGauge(w, "agentguard_ratelimit_buckets",
		"Current number of active rate-limit token buckets tracked in memory.",
		float64(atomic.LoadInt64(&rateLimitBuckets)))

	writeGauge(w, "agentguard_sse_subscribers",
		"Current number of connected Server-Sent Events subscribers on /api/stream.",
		float64(atomic.LoadInt64(&sseSubscribers)))

	writeGauge(w, "agentguard_notify_queue_depth",
		"Current length of the shared notify dispatch queue (sampled at last enqueue).",
		float64(atomic.LoadInt64(&notifyQueueDepth)))
	writeNotifyDispatchDuration(w)

	writeCounter(w, "agentguard_audit_replay_entries_total",
		"Audit log entries re-read at startup to seed in-memory counters.",
		atomic.LoadUint64(&AuditReplayEntriesTotal))
	writeCounter(w, "agentguard_audit_rotations_total",
		"Audit file rotations triggered by the live-file size threshold.",
		atomic.LoadUint64(&AuditRotationsTotal))
	writeCounter(w, "agentguard_audit_corrupt_lines_total",
		"Audit log lines that failed JSON parse during Query() and were skipped.",
		atomic.LoadUint64(&AuditCorruptLinesTotal))
	// Replay duration is stored as nanoseconds; emit as seconds to match the
	// Prometheus base-unit convention.
	writeGauge(w, "agentguard_audit_replay_duration_seconds",
		"Wall-clock duration of the most recent startup audit replay.",
		time.Duration(atomic.LoadInt64(&auditReplayDurationSeconds)).Seconds())

	writeRequestRejected(w)
	writeNotifyDropped(w)
	writeApprovalEvicted(w)
	writeRateLimitBucketEvicted(w)
	writeSSEDropped(w)
	writeMigrationStatus(w)
	writeDeprecations(w)
}

// writeMigrationStatus emits agentguard_audit_migration_status{from,to,status}.
// The triple is bounded by the registered migrations' From/To pairs times
// the fixed status set {ran, skipped, failed}. Always emits HELP/TYPE so
// the series is visible before the first migration is observed.
func writeMigrationStatus(w io.Writer) {
	const name = "agentguard_audit_migration_status"
	const help = "Audit-schema migration outcome gauge, labeled by from/to versions and status (ran|skipped|failed)."
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name)

	migrationStatusMu.Lock()
	snap := make(map[migrationStatusKey]int64, len(migrationStatus))
	for k, v := range migrationStatus {
		snap[k] = v
	}
	migrationStatusMu.Unlock()
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
func writeNotifyDispatchDuration(w io.Writer) {
	const name = "agentguard_notify_dispatch_duration_seconds"
	const help = "Wall-clock time spent in Notifier.Notify() per notifier type, in seconds."
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s histogram\n", name, help, name)

	snap := notifyDispatchSnapshot()
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

// writeSSEDropped emits agentguard_sse_events_dropped_total{reason=...}.
// Always emits HELP/TYPE so the scraper sees the series before the first
// drop.
func writeSSEDropped(w io.Writer) {
	const name = "agentguard_sse_events_dropped_total"
	const help = "Server-Sent Events dropped before reaching the subscriber, labeled by reason (slow_consumer)."
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", name, help, name)
	sseDroppedMu.Lock()
	snap := make(map[string]uint64, len(sseDroppedCount))
	for k, v := range sseDroppedCount {
		snap[k] = v
	}
	sseDroppedMu.Unlock()
	if len(snap) == 0 {
		return
	}
	keys := make([]string, 0, len(snap))
	for k := range snap {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(w, "%s{reason=\"%s\"} %d\n", name, escapeLabel(k), snap[k])
	}
}

// writeRateLimitBucketEvicted emits the scope-labeled eviction counter.
// Always emits HELP/TYPE so a scrape sees the series definition before any
// eviction has occurred.
func writeRateLimitBucketEvicted(w io.Writer) {
	const name = "agentguard_ratelimit_bucket_evictions_total"
	const help = "Rate-limit token buckets evicted under capacity pressure (MaxBuckets), labeled by policy scope."
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", name, help, name)
	rateLimitEvictedMu.Lock()
	snap := make(map[string]uint64, len(rateLimitEvictedCount))
	for k, v := range rateLimitEvictedCount {
		snap[k] = v
	}
	rateLimitEvictedMu.Unlock()
	if len(snap) == 0 {
		return
	}
	keys := make([]string, 0, len(snap))
	for k := range snap {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(w, "%s{scope=\"%s\"} %d\n", name, escapeLabel(k), snap[k])
	}
}

// writeApprovalEvicted emits agentguard_approvals_evicted_total{reason=...}.
// Always emits HELP/TYPE so scrapers see the metric even before the first
// eviction.
func writeApprovalEvicted(w io.Writer) {
	const name = "agentguard_approvals_evicted_total"
	const help = "Approval queue entries removed under capacity pressure, by reason (lru_resolved|queue_full)."
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", name, help, name)
	approvalEvictedMu.Lock()
	snap := make(map[string]uint64, len(approvalEvictedCount))
	for k, v := range approvalEvictedCount {
		snap[k] = v
	}
	approvalEvictedMu.Unlock()
	if len(snap) == 0 {
		return
	}
	keys := make([]string, 0, len(snap))
	for k := range snap {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(w, "%s{reason=\"%s\"} %d\n", name, escapeLabel(k), snap[k])
	}
}

// writeNotifyDropped emits agentguard_notify_events_dropped_total with the
// two-dimensional (notifier, reason) label. Always emits HELP/TYPE so a
// Prometheus scraper sees the metric even when no drops have happened.
func writeNotifyDropped(w io.Writer) {
	const name = "agentguard_notify_events_dropped_total"
	const help = "Notifier events dropped before delivery, by notifier type and reason (e.g. queue_full)."
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", name, help, name)
	notifyDroppedMu.Lock()
	snap := make(map[notifyDroppedKey]uint64, len(notifyDroppedCount))
	for k, v := range notifyDroppedCount {
		snap[k] = v
	}
	notifyDroppedMu.Unlock()
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

// writeRequestRejected emits the labeled rejection counter. Always emits the
// HELP/TYPE lines so scrapers see the metric even when no rejections have
// happened yet.
func writeRequestRejected(w io.Writer) {
	const name = "agentguard_request_rejected_total"
	const help = "Requests rejected before policy evaluation, by reason (e.g. body_too_large)."
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", name, help, name)
	requestRejectedMu.Lock()
	snap := make(map[string]uint64, len(requestRejectedCount))
	for k, v := range requestRejectedCount {
		snap[k] = v
	}
	requestRejectedMu.Unlock()
	if len(snap) == 0 {
		return
	}
	keys := make([]string, 0, len(snap))
	for k := range snap {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(w, "%s{reason=\"%s\"} %d\n", name, escapeLabel(k), snap[k])
	}
}

// writeDeprecations emits a labeled counter for every deprecated feature that
// has been used at least once in this process. Cardinality is bounded by the
// "feature" column in docs/DEPRECATIONS.md. Keys are sorted so the exposition
// order is stable across scrapes.
func writeDeprecations(w io.Writer) {
	snap := deprecation.Snapshot()
	const name = "agentguard_deprecations_used_total"
	const help = "Times a deprecated feature was used, labeled by stable feature key (see docs/DEPRECATIONS.md)."
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
		fmt.Fprintf(w, "%s{feature=\"%s\"} %d\n", name, escapeLabel(k), snap[k])
	}
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
