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

// durationBuckets are shared upper-bounds in milliseconds.
var durationBuckets = []float64{0.25, 0.5, 1, 2, 5, 10, 25, 50, 100, 250, 500, 1000}

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

	writeRequestRejected(w)
	writeDeprecations(w)
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
