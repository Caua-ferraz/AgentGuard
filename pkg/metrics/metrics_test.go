package metrics

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/deprecation"
)

func TestWritePrometheus_EmitsDeprecationCounters(t *testing.T) {
	deprecation.Reset()
	deprecation.Warn("test.metrics_alpha", "msg")
	deprecation.Warn("test.metrics_alpha", "msg")
	deprecation.Warn("test.metrics_beta", "msg")

	var buf bytes.Buffer
	WritePrometheus(&buf)
	out := buf.String()

	if !strings.Contains(out, "# TYPE agentguard_deprecations_used_total counter") {
		t.Fatalf("expected deprecation counter TYPE line, got:\n%s", out)
	}
	if !strings.Contains(out, `agentguard_deprecations_used_total{feature="test.metrics_alpha"} 2`) {
		t.Errorf("alpha counter missing or wrong value; output:\n%s", out)
	}
	if !strings.Contains(out, `agentguard_deprecations_used_total{feature="test.metrics_beta"} 1`) {
		t.Errorf("beta counter missing or wrong value; output:\n%s", out)
	}

	// Labels must appear in sorted order so scrape output is stable.
	alphaIdx := strings.Index(out, `feature="test.metrics_alpha"`)
	betaIdx := strings.Index(out, `feature="test.metrics_beta"`)
	if alphaIdx == -1 || betaIdx == -1 || alphaIdx >= betaIdx {
		t.Errorf("deprecation labels not in sorted order: alpha=%d beta=%d", alphaIdx, betaIdx)
	}
}

func TestWritePrometheus_NoDeprecationsEmitsHeaderOnly(t *testing.T) {
	deprecation.Reset()

	var buf bytes.Buffer
	WritePrometheus(&buf)
	out := buf.String()

	if !strings.Contains(out, "# TYPE agentguard_deprecations_used_total counter") {
		t.Fatalf("header must be present even when no features used, got:\n%s", out)
	}
	// No label lines should exist.
	if strings.Contains(out, "agentguard_deprecations_used_total{") {
		t.Errorf("unexpected deprecation label lines when no features used")
	}
}

// TestWritePrometheus_NotifyDroppedHeaderOnly: with no drops recorded, the
// exposition still includes HELP/TYPE so a scraper picks up the series
// definition. No label lines should appear.
func TestWritePrometheus_NotifyDroppedHeaderOnly(t *testing.T) {
	Reset() // isolate from whatever previous test ran

	var buf bytes.Buffer
	WritePrometheus(&buf)
	out := buf.String()

	if !strings.Contains(out, "# TYPE agentguard_notify_events_dropped_total counter") {
		t.Fatalf("TYPE header missing; got:\n%s", out)
	}
	if strings.Contains(out, "agentguard_notify_events_dropped_total{") {
		t.Errorf("unexpected label lines with empty counter, got:\n%s", out)
	}
}

// TestWritePrometheus_NotifyDroppedLabels: counters are emitted with the
// (notifier, reason) label pair and in sorted order for stable scrape
// output.
func TestWritePrometheus_NotifyDroppedLabels(t *testing.T) {
	Reset()

	IncNotifyDropped("webhook", NotifyDroppedQueueFull)
	IncNotifyDropped("webhook", NotifyDroppedQueueFull)
	IncNotifyDropped("slack", NotifyDroppedQueueFull)

	var buf bytes.Buffer
	WritePrometheus(&buf)
	out := buf.String()

	if !strings.Contains(out,
		`agentguard_notify_events_dropped_total{notifier="slack",reason="queue_full"} 1`) {
		t.Errorf("slack line missing or wrong count; got:\n%s", out)
	}
	if !strings.Contains(out,
		`agentguard_notify_events_dropped_total{notifier="webhook",reason="queue_full"} 2`) {
		t.Errorf("webhook line missing or wrong count; got:\n%s", out)
	}
	// slack < webhook alphabetically.
	slackIdx := strings.Index(out, `notifier="slack"`)
	webhookIdx := strings.Index(out, `notifier="webhook"`)
	if slackIdx == -1 || webhookIdx == -1 || slackIdx >= webhookIdx {
		t.Errorf("labels not sorted; slack=%d webhook=%d", slackIdx, webhookIdx)
	}
}

// TestWritePrometheus_ApprovalEvictedHeaderOnly: with no evictions recorded,
// the exposition still includes HELP/TYPE so a scraper picks up the series
// definition. No label lines should appear.
func TestWritePrometheus_ApprovalEvictedHeaderOnly(t *testing.T) {
	Reset()

	var buf bytes.Buffer
	WritePrometheus(&buf)
	out := buf.String()

	if !strings.Contains(out, "# TYPE agentguard_approvals_evicted_total counter") {
		t.Fatalf("TYPE header missing; got:\n%s", out)
	}
	if strings.Contains(out, "agentguard_approvals_evicted_total{") {
		t.Errorf("unexpected label lines with empty counter, got:\n%s", out)
	}
}

// TestWritePrometheus_ApprovalEvictedLabels: counters are emitted with the
// reason label and in sorted order for stable scrape output. Both reasons
// (lru_resolved, queue_full) must be present so operators can distinguish
// "need a bigger queue" from "need more approvers".
func TestWritePrometheus_ApprovalEvictedLabels(t *testing.T) {
	Reset()

	IncApprovalEvicted(ApprovalEvictedLRUResolved)
	IncApprovalEvicted(ApprovalEvictedLRUResolved)
	IncApprovalEvicted(ApprovalEvictedQueueFull)

	var buf bytes.Buffer
	WritePrometheus(&buf)
	out := buf.String()

	if !strings.Contains(out,
		`agentguard_approvals_evicted_total{reason="lru_resolved"} 2`) {
		t.Errorf("lru_resolved line missing or wrong count; got:\n%s", out)
	}
	if !strings.Contains(out,
		`agentguard_approvals_evicted_total{reason="queue_full"} 1`) {
		t.Errorf("queue_full line missing or wrong count; got:\n%s", out)
	}
	// lru_resolved < queue_full alphabetically. Anchor on the full metric
	// name so we don't accidentally match reason="queue_full" from the
	// notify_dropped series (which is emitted earlier in the exposition).
	lruIdx := strings.Index(out, `agentguard_approvals_evicted_total{reason="lru_resolved"}`)
	qfIdx := strings.Index(out, `agentguard_approvals_evicted_total{reason="queue_full"}`)
	if lruIdx == -1 || qfIdx == -1 || lruIdx >= qfIdx {
		t.Errorf("labels not sorted; lru=%d queue_full=%d", lruIdx, qfIdx)
	}
}

// TestWritePrometheus_RateLimitBucketsGauge: the gauge is always present so
// scrapers see the definition even before any bucket is created. Value must
// reflect the most recent SetRateLimitBuckets call.
func TestWritePrometheus_RateLimitBucketsGauge(t *testing.T) {
	SetRateLimitBuckets(42)
	defer SetRateLimitBuckets(0)

	var buf bytes.Buffer
	WritePrometheus(&buf)
	out := buf.String()

	if !strings.Contains(out, "# TYPE agentguard_ratelimit_buckets gauge") {
		t.Fatalf("gauge TYPE missing; got:\n%s", out)
	}
	if !strings.Contains(out, "agentguard_ratelimit_buckets 42") {
		t.Errorf("gauge value missing; got:\n%s", out)
	}
}

// TestWritePrometheus_RateLimitEvictedHeaderOnly: with nothing evicted,
// still emit HELP/TYPE and no label lines.
func TestWritePrometheus_RateLimitEvictedHeaderOnly(t *testing.T) {
	Reset()

	var buf bytes.Buffer
	WritePrometheus(&buf)
	out := buf.String()

	if !strings.Contains(out, "# TYPE agentguard_ratelimit_bucket_evictions_total counter") {
		t.Fatalf("TYPE header missing; got:\n%s", out)
	}
	if strings.Contains(out, "agentguard_ratelimit_bucket_evictions_total{") {
		t.Errorf("unexpected label lines with empty counter, got:\n%s", out)
	}
}

// TestWritePrometheus_RateLimitEvictedLabels: counters are emitted with the
// scope label and in sorted order for stable scrape output.
func TestWritePrometheus_RateLimitEvictedLabels(t *testing.T) {
	Reset()

	IncRateLimitBucketEvicted("shell")
	IncRateLimitBucketEvicted("shell")
	IncRateLimitBucketEvicted("network")

	var buf bytes.Buffer
	WritePrometheus(&buf)
	out := buf.String()

	if !strings.Contains(out,
		`agentguard_ratelimit_bucket_evictions_total{scope="network"} 1`) {
		t.Errorf("network line missing or wrong count; got:\n%s", out)
	}
	if !strings.Contains(out,
		`agentguard_ratelimit_bucket_evictions_total{scope="shell"} 2`) {
		t.Errorf("shell line missing or wrong count; got:\n%s", out)
	}
	// network < shell alphabetically — anchor on the full metric name to
	// avoid collisions with scope="..." labels on other series.
	netIdx := strings.Index(out, `agentguard_ratelimit_bucket_evictions_total{scope="network"}`)
	shellIdx := strings.Index(out, `agentguard_ratelimit_bucket_evictions_total{scope="shell"}`)
	if netIdx == -1 || shellIdx == -1 || netIdx >= shellIdx {
		t.Errorf("labels not sorted; network=%d shell=%d", netIdx, shellIdx)
	}
}

// TestWritePrometheus_AuditReplayAndRotations: all three audit-observability
// series are present (header + value) so scrapers can index them from the
// first scrape, even when replay has not yet run.
func TestWritePrometheus_AuditReplayAndRotations(t *testing.T) {
	Reset()

	AddAuditReplayEntries(1234)
	IncAuditRotation()
	IncAuditRotation()
	IncAuditRotation()
	SetAuditReplayDuration(750 * time.Millisecond)

	var buf bytes.Buffer
	WritePrometheus(&buf)
	out := buf.String()

	if !strings.Contains(out, "agentguard_audit_replay_entries_total 1234") {
		t.Errorf("replay entries counter missing; got:\n%s", out)
	}
	if !strings.Contains(out, "agentguard_audit_rotations_total 3") {
		t.Errorf("rotations counter missing; got:\n%s", out)
	}
	// 750ms = 0.75s; Prometheus %g formats 0.75 cleanly.
	if !strings.Contains(out, "agentguard_audit_replay_duration_seconds 0.75") {
		t.Errorf("replay duration gauge missing or wrong; got:\n%s", out)
	}
	if !strings.Contains(out, "# TYPE agentguard_audit_replay_entries_total counter") {
		t.Errorf("replay entries TYPE missing; got:\n%s", out)
	}
	if !strings.Contains(out, "# TYPE agentguard_audit_rotations_total counter") {
		t.Errorf("rotations TYPE missing; got:\n%s", out)
	}
	if !strings.Contains(out, "# TYPE agentguard_audit_replay_duration_seconds gauge") {
		t.Errorf("replay duration TYPE missing; got:\n%s", out)
	}
}

func TestEscapeLabel(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"plain", "plain"},
		{`with"quote`, `with\"quote`},
		{`with\back`, `with\\back`},
		{"with\nnewline", `with\nnewline`},
		{`a"b\c` + "\n" + "d", `a\"b\\c\nd`},
	}
	for _, c := range cases {
		if got := escapeLabel(c.in); got != c.want {
			t.Errorf("escapeLabel(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// -- Registry seam ---------------------------------------------------------------

// TestRegistry_Isolation: two registries never share series state — the
// whole point of the Registry seam. The package-level functions only touch
// Default.
func TestRegistry_Isolation(t *testing.T) {
	a := NewRegistry()
	b := NewRegistry()

	a.IncDecision("ALLOW")
	a.IncDecision("DENY")
	a.IncApprovalEvicted(ApprovalEvictedQueueFull)
	a.ObserveRequestDuration(1.5)
	a.SetPendingApprovals(7)

	if got := a.ChecksTotal(); got != 2 {
		t.Errorf("a.ChecksTotal = %d, want 2", got)
	}
	if got := b.ChecksTotal(); got != 0 {
		t.Errorf("b.ChecksTotal = %d, want 0 (registries must not share state)", got)
	}
	if got := b.ApprovalEvictedFor(ApprovalEvictedQueueFull); got != 0 {
		t.Errorf("b eviction count = %d, want 0", got)
	}

	var bufA, bufB bytes.Buffer
	a.WritePrometheus(&bufA)
	b.WritePrometheus(&bufB)
	if !strings.Contains(bufA.String(), "agentguard_checks_total 2") {
		t.Errorf("a output missing counted checks:\n%s", bufA.String())
	}
	if !strings.Contains(bufB.String(), "agentguard_checks_total 0") {
		t.Errorf("b output should be zeroed:\n%s", bufB.String())
	}
	if !strings.Contains(bufA.String(), "agentguard_pending_approvals 7") {
		t.Errorf("a gauge missing:\n%s", bufA.String())
	}
}

// TestRegistry_ResetMatchesFresh: a populated-then-Reset registry produces
// byte-identical exposition output to a brand-new one (modulo the shared
// deprecation series, which Reset documents as out of scope).
func TestRegistry_ResetMatchesFresh(t *testing.T) {
	deprecation.Reset()

	r := NewRegistry()
	r.IncDecision("ALLOW")
	r.IncRateLimited()
	r.IncApprovalReplayMismatch()
	r.IncRequestRejected(RejectedBodyTooLarge)
	r.IncApprovalEvicted(ApprovalEvictedLRUResolved)
	r.IncRateLimitBucketEvicted("shell")
	r.IncSSEEventDropped(SSEDroppedSlowConsumer)
	r.IncNotifyDropped("webhook", NotifyDroppedQueueFull)
	r.IncLLMProxyBufferOverflow("openai")
	r.IncLLMProxyNonStreamingOverflow("anthropic")
	r.IncLLMProxyProtocolViolation("openai")
	r.SetLLMProxyStreamsActive(3)
	r.IncLLMProxyStreamsRejected()
	r.IncAuditCorruptLine()
	r.AddAuditReplayEntries(10)
	r.IncAuditRotation()
	r.SetAuditReplayDuration(time.Second)
	r.SetMigrationStatus("v0.4.0", "v0.4.1", MigrationStatusRan, 1)
	r.SetNotifyQueueDepth(5)
	r.ObserveNotifyDispatch("webhook", 0.2)
	r.IncSSESubscribers()
	r.SetRateLimitBuckets(9)
	r.SetPendingApprovals(2)
	r.ObserveRequestDuration(1)
	r.ObservePolicyEvalDuration(0.5)
	r.ObserveAuditWriteDuration(0.25)

	r.Reset()

	var got, want bytes.Buffer
	r.WritePrometheus(&got)
	NewRegistry().WritePrometheus(&want)
	if got.String() != want.String() {
		t.Errorf("Reset() output differs from a fresh registry:\n--- got ---\n%s\n--- want ---\n%s",
			got.String(), want.String())
	}
}

// TestDefaultShims_HitDefaultRegistry: the package-level functions and the
// Default registry are the same state.
func TestDefaultShims_HitDefaultRegistry(t *testing.T) {
	Reset()
	IncDecision("ALLOW")
	if got := Default.ChecksTotal(); got != 1 {
		t.Errorf("Default.ChecksTotal = %d after package-level IncDecision, want 1", got)
	}
	if got := AllowedTotal(); got != 1 {
		t.Errorf("AllowedTotal() = %d, want 1", got)
	}
	Reset()
	if got := ChecksTotal(); got != 0 {
		t.Errorf("ChecksTotal after Reset = %d, want 0", got)
	}
}
