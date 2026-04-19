package metrics

import (
	"bytes"
	"strings"
	"testing"

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
	// Isolate: flush whatever previous test ran.
	notifyDroppedMu.Lock()
	notifyDroppedCount = map[notifyDroppedKey]uint64{}
	notifyDroppedMu.Unlock()

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
	notifyDroppedMu.Lock()
	notifyDroppedCount = map[notifyDroppedKey]uint64{}
	notifyDroppedMu.Unlock()

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
	approvalEvictedMu.Lock()
	approvalEvictedCount = map[string]uint64{}
	approvalEvictedMu.Unlock()

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
	approvalEvictedMu.Lock()
	approvalEvictedCount = map[string]uint64{}
	approvalEvictedMu.Unlock()

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
	rateLimitEvictedMu.Lock()
	rateLimitEvictedCount = map[string]uint64{}
	rateLimitEvictedMu.Unlock()

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
	rateLimitEvictedMu.Lock()
	rateLimitEvictedCount = map[string]uint64{}
	rateLimitEvictedMu.Unlock()

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
