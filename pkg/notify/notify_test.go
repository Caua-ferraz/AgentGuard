package notify

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/metrics"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
	"os"
	"path/filepath"
)

// countingNotifier is a test-only Notifier that records invocations.
type countingNotifier struct {
	mu    sync.Mutex
	calls int
	delay time.Duration
}

func (c *countingNotifier) Notify(event Event) error {
	c.mu.Lock()
	c.calls++
	c.mu.Unlock()
	if c.delay > 0 {
		time.Sleep(c.delay)
	}
	return nil
}

func (c *countingNotifier) Count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// TestDispatcher_DispatchTimeoutAppliedGlobally: a notifications.dispatch_timeout
// at the cfg level must propagate to the http.Client of every webhook/slack
// target that did not set its own `timeout` override.
func TestDispatcher_DispatchTimeoutAppliedGlobally(t *testing.T) {
	cfg := policy.NotificationCfg{
		DispatchTimeout: "1500ms",
		ApprovalRequired: []policy.NotifyTarget{
			{Type: "webhook", URL: "http://unused.test"},
		},
		OnDeny: []policy.NotifyTarget{
			{Type: "slack", URL: "http://unused.test"},
		},
	}
	d := NewDispatcher(cfg)
	defer d.Close()

	if n := len(d.notifiers); n != 2 {
		t.Fatalf("expected 2 notifiers, got %d", n)
	}
	wh, ok := d.notifiers[0].(*WebhookNotifier)
	if !ok {
		t.Fatalf("first notifier type = %T, want *WebhookNotifier", d.notifiers[0])
	}
	if got, want := wh.client.Timeout, 1500*time.Millisecond; got != want {
		t.Errorf("webhook timeout = %v, want %v (from dispatch_timeout)", got, want)
	}
	sl, ok := d.notifiers[1].(*SlackNotifier)
	if !ok {
		t.Fatalf("second notifier type = %T, want *SlackNotifier", d.notifiers[1])
	}
	if got, want := sl.client.Timeout, 1500*time.Millisecond; got != want {
		t.Errorf("slack timeout = %v, want %v (from dispatch_timeout)", got, want)
	}
}

// TestDispatcher_DispatchTimeoutPerTargetOverride: a per-target `timeout`
// wins over the dispatch-level default, and targets that omit `timeout`
// inherit the dispatch default. Protects the inheritance contract documented
// on NotifyTarget.Timeout.
func TestDispatcher_DispatchTimeoutPerTargetOverride(t *testing.T) {
	cfg := policy.NotificationCfg{
		DispatchTimeout: "2s",
		ApprovalRequired: []policy.NotifyTarget{
			{Type: "webhook", URL: "http://a.test", Timeout: "500ms"},
			{Type: "webhook", URL: "http://b.test"}, // inherits 2s
		},
	}
	d := NewDispatcher(cfg)
	defer d.Close()

	a := d.notifiers[0].(*WebhookNotifier)
	b := d.notifiers[1].(*WebhookNotifier)
	if got, want := a.client.Timeout, 500*time.Millisecond; got != want {
		t.Errorf("per-target override = %v, want %v", got, want)
	}
	if got, want := b.client.Timeout, 2*time.Second; got != want {
		t.Errorf("inherited default = %v, want %v", got, want)
	}
}

// TestDispatcher_DispatchTimeoutDefaultsWhenUnset: an empty DispatchTimeout
// must fall back to policy.DefaultNotifyDispatchTimeout so removing the
// config key restores v0.4.0 behavior exactly.
func TestDispatcher_DispatchTimeoutDefaultsWhenUnset(t *testing.T) {
	cfg := policy.NotificationCfg{
		ApprovalRequired: []policy.NotifyTarget{{Type: "webhook", URL: "http://x"}},
	}
	d := NewDispatcher(cfg)
	defer d.Close()
	wh := d.notifiers[0].(*WebhookNotifier)
	if got, want := wh.client.Timeout, policy.DefaultNotifyDispatchTimeout; got != want {
		t.Errorf("default dispatch timeout = %v, want %v", got, want)
	}
}

// TestDispatcher_DispatchTimeoutAbortsHangingWebhook is the behavioral anchor
// for the three structural timeout tests above: those assert the configured
// duration lands on wh.client.Timeout, but a refactor could move timeout
// handling elsewhere (a RoundTripper, a per-request context deadline) and keep
// the field while breaking the behavior. This test points a webhook at a server
// that never responds and proves the dispatch_timeout actually BOUNDS the call —
// Notify returns an error in well under the server's 10s hang, not the field
// value. Survives any mechanism change that preserves the contract.
func TestDispatcher_DispatchTimeoutAbortsHangingWebhook(t *testing.T) {
	// stop releases the handler at cleanup so httptest.Server.Close doesn't
	// block waiting on the still-hanging connection. Defers run LIFO, so close
	// (stop) fires before srv.Close().
	stop := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done(): // client gave up (timeout) → unblock
		case <-stop:
		}
	}))
	defer srv.Close()
	defer close(stop)

	const dispatchTimeout = 300 * time.Millisecond
	d := NewDispatcher(policy.NotificationCfg{
		DispatchTimeout: "300ms",
		OnDeny:          []policy.NotifyTarget{{Type: "webhook", URL: srv.URL}},
	})
	defer d.Close()

	wh, ok := d.notifiers[0].(*WebhookNotifier)
	if !ok {
		t.Fatalf("notifier[0] = %T, want *WebhookNotifier", d.notifiers[0])
	}

	start := time.Now()
	err := wh.Notify(Event{Type: "denied"})
	elapsed := time.Since(start)

	if err == nil {
		t.Error("expected a timeout error from the hanging webhook, got nil")
	}
	// Upper bound: must be bounded by the ~300ms timeout, not the server's 10s.
	// Generous to avoid CI flakiness — the point is "bounded", not exact.
	if elapsed > 3*time.Second {
		t.Errorf("Notify took %v; dispatch_timeout=%v failed to bound the call", elapsed, dispatchTimeout)
	}
	// Lower bound: it must have actually waited on the timeout, not failed
	// instantly (which would mean the timeout wasn't applied at all).
	if elapsed < dispatchTimeout/2 {
		t.Errorf("Notify returned in %v, faster than half the %v timeout — was the timeout applied?", elapsed, dispatchTimeout)
	}
}

func TestDispatcher_DispatchesAllEvents(t *testing.T) {
	d := NewDispatcherWithOpts(policy.NotificationCfg{}, 4, 64)
	defer d.Close()

	c := &countingNotifier{}
	d.notifiers = []Notifier{c}

	const n = 50
	for i := 0; i < n; i++ {
		d.Send(Event{Type: "denied"})
	}

	// Wait up to 2s for workers to drain the queue.
	deadline := time.Now().Add(2 * time.Second)
	for c.Count() < n && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := c.Count(); got != n {
		t.Errorf("expected %d deliveries, got %d", n, got)
	}
}

// TestDispatcher_BoundedConcurrency: when workers are slow and the queue is
// small, excess events are dropped and counted rather than blocking Send()
// or spawning unbounded goroutines.
func TestDispatcher_BoundedConcurrency(t *testing.T) {
	// Reset the package counter for an isolated assertion.
	atomic.StoreUint64(&DroppedEvents, 0)

	// 2 workers each sleeping 50ms, queue size 4 → first ~6 events buffered/in-flight,
	// the rest dropped.
	d := NewDispatcherWithOpts(policy.NotificationCfg{}, 2, 4)
	defer d.Close()

	slow := &countingNotifier{delay: 50 * time.Millisecond}
	d.notifiers = []Notifier{slow}

	const burst = 100
	start := time.Now()
	for i := 0; i < burst; i++ {
		d.Send(Event{Type: "denied"})
	}
	if dur := time.Since(start); dur > 500*time.Millisecond {
		t.Errorf("Send should be non-blocking, took %v for %d events", dur, burst)
	}

	if atomic.LoadUint64(&DroppedEvents) == 0 {
		t.Error("expected some dropped events when queue is saturated, got 0")
	}

	// Also: the delivered count is bounded by queue size + in-flight workers,
	// never the full burst.
	time.Sleep(300 * time.Millisecond)
	if slow.Count() >= burst {
		t.Errorf("slow notifier should have received far fewer than %d events, got %d",
			burst, slow.Count())
	}
}

// TestDispatcher_DroppedCounterIsLabeled: when the queue overflows the
// Prometheus counter agentguard_notify_events_dropped_total must get
// incremented with the correct notifier type label, not only the legacy
// unlabeled package atomic.
func TestDispatcher_DroppedCounterIsLabeled(t *testing.T) {
	before := metrics.NotifyDroppedFor("webhook", metrics.NotifyDroppedQueueFull)

	// 1 worker, queue=1, so a small burst overflows immediately.
	d := NewDispatcherWithOpts(policy.NotificationCfg{}, 1, 1)
	defer d.Close()

	// WebhookNotifier pointed at an unroutable loopback port; each Notify
	// will block on TCP until the short client Timeout expires, so the
	// worker is slow enough to let the queue fill.
	slow := &WebhookNotifier{
		URL:    "http://127.0.0.1:1",
		client: &http.Client{Timeout: 50 * time.Millisecond},
	}
	d.notifiers = []Notifier{slow}

	for i := 0; i < 64; i++ {
		d.Send(Event{Type: "denied"})
	}

	// A small delay is enough: drops happen synchronously inside Send
	// when the buffered channel is full, so the counter is already
	// incremented by the time Send returns.
	time.Sleep(10 * time.Millisecond)

	got := metrics.NotifyDroppedFor("webhook", metrics.NotifyDroppedQueueFull)
	if got <= before {
		t.Errorf("webhook-labeled drop counter did not increment; before=%d after=%d", before, got)
	}
}

// TestDispatcher_ObservesDispatchDuration: the worker loop must time each
// Notify() call and record it under the notifierType() label. We use
// LogNotifier because it's a bounded type ("log") and produces no network
// I/O, so the observation is fast and deterministic. We verify via the
// Prometheus output that the labeled histogram's _count has advanced by at
// least n.
func TestDispatcher_ObservesDispatchDuration(t *testing.T) {
	d := NewDispatcherWithOpts(policy.NotificationCfg{}, 1, 16)
	defer d.Close()

	// LogNotifier with a matching filter so Notify() actually runs.
	d.notifiers = []Notifier{&LogNotifier{Filter: "denied"}}

	const n = 5
	beforeCount := readHistogramCount(t, "log")

	for i := 0; i < n; i++ {
		d.Send(Event{Type: "denied"})
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if readHistogramCount(t, "log")-beforeCount >= uint64(n) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected log-histogram _count delta >= %d within 2s (before=%d final=%d)",
		n, beforeCount, readHistogramCount(t, "log"))
}

// readHistogramCount parses the Prometheus output for the current
// _count value of agentguard_notify_dispatch_duration_seconds{notifier=X}.
// Returns 0 if the series hasn't been emitted yet (no observation).
func readHistogramCount(t *testing.T, notifier string) uint64 {
	t.Helper()
	var buf strings.Builder
	metrics.WritePrometheus(&buf)
	out := buf.String()
	needle := "agentguard_notify_dispatch_duration_seconds_count{notifier=\"" + notifier + "\"} "
	idx := strings.Index(out, needle)
	if idx == -1 {
		return 0
	}
	rest := out[idx+len(needle):]
	nl := strings.Index(rest, "\n")
	if nl == -1 {
		t.Fatal("no newline after count value")
	}
	var n uint64
	if _, err := fmt.Sscanf(strings.TrimSpace(rest[:nl]), "%d", &n); err != nil {
		t.Fatalf("parse count: %v", err)
	}
	return n
}

// TestDispatcher_QueueDepthGaugeMoves: every successful enqueue must refresh
// the queue_depth gauge. We slow a notifier so the queue actually builds up.
func TestDispatcher_QueueDepthGaugeMoves(t *testing.T) {
	// 1 worker so enqueued events sit in the queue while the one worker is
	// blocked in Notify().
	d := NewDispatcherWithOpts(policy.NotificationCfg{}, 1, 16)
	defer d.Close()
	d.notifiers = []Notifier{&countingNotifier{delay: 50 * time.Millisecond}}

	// Burst of enqueues: after Send returns for the last one, queue_depth
	// must have been at least 1 at some point — we read the Prometheus
	// output to verify the gauge line exists and is emitted.
	for i := 0; i < 8; i++ {
		d.Send(Event{Type: "denied"})
	}

	var buf strings.Builder
	metrics.WritePrometheus(&buf)
	out := buf.String()
	if !strings.Contains(out, "# TYPE agentguard_notify_queue_depth gauge") {
		t.Fatalf("queue_depth gauge TYPE missing; got:\n%s", out)
	}
	if !strings.Contains(out, "\nagentguard_notify_queue_depth ") {
		t.Errorf("queue_depth gauge value line missing; got:\n%s", out)
	}
}

func TestDispatcher_Filter(t *testing.T) {
	d := NewDispatcherWithOpts(policy.NotificationCfg{}, 2, 16)
	defer d.Close()

	denyOnly := &countingNotifier{}
	approvalOnly := &countingNotifier{}
	d.notifiers = []Notifier{
		&filteringWrapper{inner: denyOnly, filter: "denied"},
		&filteringWrapper{inner: approvalOnly, filter: "approval_required"},
	}

	d.Send(Event{Type: "denied"})
	d.Send(Event{Type: "approval_required"})
	d.Send(Event{Type: "denied"})

	deadline := time.Now().Add(2 * time.Second)
	for (denyOnly.Count() < 2 || approvalOnly.Count() < 1) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	if denyOnly.Count() != 2 {
		t.Errorf("deny-only notifier expected 2 calls, got %d", denyOnly.Count())
	}
	if approvalOnly.Count() != 1 {
		t.Errorf("approval-only notifier expected 1 call, got %d", approvalOnly.Count())
	}
}

type filteringWrapper struct {
	inner  *countingNotifier
	filter string
}

func (f *filteringWrapper) Notify(event Event) error {
	if f.filter != "" && f.filter != event.Type {
		return nil
	}
	return f.inner.Notify(event)
}

// TestRedactor covers each built-in pattern.
func TestRedactor(t *testing.T) {
	r := DefaultRedactor()

	cases := []struct {
		in       string
		mustHide string // substring that must NOT appear in redacted output
	}{
		{"curl -H 'Authorization: Bearer abc.def.ghi' https://api", "abc.def.ghi"},
		{"aws s3 cp --access-key AKIAABCDEFGHIJKLMNOP", "AKIAABCDEFGHIJKLMNOP"},
		{"git push https://x:ghp_abcdefghijklmnopqrstuvwxyz0123456789A@github.com/a/b", "ghp_abcdefghijklmnopqrstuvwxyz0123456789A"},
		{"curl -H 'X-Api-Token: xoxb-1234567-abc'", "xoxb-1234567-abc"},
		{"echo SECRET=hunter2", "SECRET=hunter2"},
		{"TOKEN=abc123", "TOKEN=abc123"},
		{"password=swordfish", "password=swordfish"},
	}
	for _, c := range cases {
		out := r.redactString(c.in)
		if strings.Contains(out, c.mustHide) {
			t.Errorf("redactString(%q) still contains %q: output=%q", c.in, c.mustHide, out)
		}
		if !strings.Contains(out, "[REDACTED]") {
			t.Errorf("redactString(%q) did not insert [REDACTED]: output=%q", c.in, out)
		}
	}
}

func TestRedactor_WithExtraPatterns(t *testing.T) {
	r, err := DefaultRedactor().WithExtraPatterns([]string{
		`ACME_[A-Z0-9]{12}`, // hypothetical org-specific key prefix
	})
	if err != nil {
		t.Fatalf("WithExtraPatterns: %v", err)
	}

	got := r.redactString("leaked ACME_ABC123DEF456 here")
	if !strings.Contains(got, "[REDACTED]") || strings.Contains(got, "ACME_ABC123DEF456") {
		t.Errorf("extra pattern must redact ACME_* keys, got %q", got)
	}

	// Built-in patterns must still fire alongside the new one.
	if got := r.redactString("bearer abc.def"); got == "bearer abc.def" {
		t.Errorf("extra_patterns must not disable built-ins, got %q", got)
	}
}

func TestRedactor_WithExtraPatterns_EmptyIsNoop(t *testing.T) {
	r := DefaultRedactor()
	got, err := r.WithExtraPatterns(nil)
	if err != nil {
		t.Errorf("nil extras must not error: %v", err)
	}
	if got != r {
		t.Error("nil extras must return the same receiver")
	}
}

func TestRedactor_WithExtraPatterns_InvalidRegex(t *testing.T) {
	r := DefaultRedactor()
	before := len(r.patterns)
	_, err := r.WithExtraPatterns([]string{`[unclosed`})
	if err == nil {
		t.Fatal("invalid regex must return an error")
	}
	if len(r.patterns) != before {
		t.Errorf("pattern list should be unchanged after error; before=%d after=%d", before, len(r.patterns))
	}
}

func TestDispatcher_UsesExtraRedactionPatterns(t *testing.T) {
	cfg := policy.NotificationCfg{
		Redaction: policy.RedactionCfg{
			ExtraPatterns: []string{`ORG_[A-Z0-9]{8}`},
		},
	}
	d := NewDispatcherWithOpts(cfg, 1, 4)
	defer d.Close()

	captured := &capturingNotifier{}
	d.notifiers = []Notifier{captured}

	d.Send(Event{
		Type:    "denied",
		Request: policy.ActionRequest{Command: "upload ORG_ABCD1234 to s3"},
	})
	// Poll until the worker delivers the event rather than sleeping a fixed
	// 50ms: under load / -race the worker may not have drained the queue yet,
	// which would read an empty Command and fail spuriously (the redacted-check
	// would see "" and report a missing [REDACTED]). Mirrors the robust pattern
	// in TestDispatcher_RedactsBeforeDelivery.
	waitForCondition(t, time.Second, func() bool {
		return captured.Get().Request.Command != ""
	}, "extra-pattern redaction event to be delivered")

	got := captured.Get()
	if strings.Contains(got.Request.Command, "ORG_ABCD1234") {
		t.Errorf("extra pattern must redact ORG_* from command, got %q", got.Request.Command)
	}
	if !strings.Contains(got.Request.Command, "[REDACTED]") {
		t.Errorf("expected [REDACTED] in command, got %q", got.Request.Command)
	}
}

func TestRedactor_PreservesSafeStrings(t *testing.T) {
	r := DefaultRedactor()
	for _, s := range []string{
		"ls -la /tmp",
		"rm -rf /var/log",
		"https://example.com/path?q=1",
		"",
	} {
		if got := r.redactString(s); got != s {
			t.Errorf("redactString(%q) changed safe input to %q", s, got)
		}
	}
}

func TestDispatcher_RedactsBeforeDelivery(t *testing.T) {
	d := NewDispatcherWithOpts(policy.NotificationCfg{}, 1, 4)
	defer d.Close()

	captured := &capturingNotifier{}
	d.notifiers = []Notifier{captured}

	d.Send(Event{
		Type: "denied",
		Request: policy.ActionRequest{
			Command: "curl -H 'Authorization: Bearer leaked.token.here'",
			Meta:    map[string]string{"password": "password=hunter2"},
		},
	})

	deadline := time.Now().Add(time.Second)
	for captured.Get().Request.Command == "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	got := captured.Get()
	if strings.Contains(got.Request.Command, "leaked.token.here") {
		t.Errorf("bearer token survived redaction: %q", got.Request.Command)
	}
	if v, ok := got.Request.Meta["password"]; ok && strings.Contains(v, "hunter2") {
		t.Errorf("password survived redaction in Meta: %q", v)
	}
}

// TestDispatcher_RedactsPathInWebhookBody: secrets embedded in Request.Path
// must be scrubbed before the event leaves the process as webhook JSON
// (audit finding M4 — Redact previously skipped Path/Domain/Action).
func TestDispatcher_RedactsPathInWebhookBody(t *testing.T) {
	const token = "ghp_abcdef1234567890abcdef1234567890abcd"

	var mu sync.Mutex
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		body = string(b)
		mu.Unlock()
	}))
	defer srv.Close()

	cfg := policy.NotificationCfg{
		OnDeny: []policy.NotifyTarget{{Type: "webhook", URL: srv.URL}},
	}
	d := NewDispatcher(cfg)
	defer d.Close()

	d.Send(Event{
		Type: "denied",
		Request: policy.ActionRequest{
			Scope: "fs",
			Path:  "/bucket/report.csv?token=" + token,
		},
	})

	waitForCondition(t, time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return body != ""
	}, "webhook to receive the redacted event")

	mu.Lock()
	defer mu.Unlock()
	if strings.Contains(body, token) {
		t.Errorf("token in Path survived redaction into webhook body: %s", body)
	}
	if !strings.Contains(body, "[REDACTED]") {
		t.Errorf("expected [REDACTED] in webhook body, got %s", body)
	}
}

// TestDispatcher_RedactsPathInSlackPayload: the Slack notifier uses
// Request.Path as its display action when Command is empty, so a secret in
// Path would otherwise land verbatim in the Slack message text (M4).
func TestDispatcher_RedactsPathInSlackPayload(t *testing.T) {
	const token = "ghp_abcdef1234567890abcdef1234567890abcd"

	var mu sync.Mutex
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		body = string(b)
		mu.Unlock()
	}))
	defer srv.Close()

	cfg := policy.NotificationCfg{
		OnDeny: []policy.NotifyTarget{{Type: "slack", URL: srv.URL}},
	}
	d := NewDispatcher(cfg)
	defer d.Close()

	d.Send(Event{
		Type: "denied",
		Request: policy.ActionRequest{
			Scope: "fs",
			Path:  "/bucket/report.csv?token=" + token,
		},
	})

	waitForCondition(t, time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return body != ""
	}, "slack webhook to receive the redacted payload")

	mu.Lock()
	defer mu.Unlock()
	if strings.Contains(body, token) {
		t.Errorf("token in Path survived redaction into slack payload: %s", body)
	}
	if !strings.Contains(body, "[REDACTED]") {
		t.Errorf("expected [REDACTED] in slack payload, got %s", body)
	}
}

type capturingNotifier struct {
	mu sync.Mutex
	e  Event
}

func (c *capturingNotifier) Notify(event Event) error {
	c.mu.Lock()
	c.e = event
	c.mu.Unlock()
	return nil
}
func (c *capturingNotifier) Get() Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.e
}

// TestDispatcher_MultiAgentFanout is a forward-looking regression guard, NOT a
// duplicate of TestDispatcher_DispatchesAllEvents: it pins the contract that the
// dispatcher does NO per-agent_id filtering — every agent's events reach every
// notifier. If someone later adds per-agent routing/filtering at this layer,
// this fails even though basic delivery still works. The agent_id variety is
// the point; the overlap with the plain delivery test is deliberate.
func TestDispatcher_MultiAgentFanout(t *testing.T) {
	d := NewDispatcherWithOpts(policy.NotificationCfg{}, 4, 32)
	defer d.Close()

	c := &countingNotifier{}
	d.notifiers = []Notifier{c}

	agents := []string{"agent-a", "agent-b", "agent-c"}
	for i := 0; i < 30; i++ {
		d.Send(Event{
			Type:    "denied",
			Request: policy.ActionRequest{AgentID: agents[i%len(agents)]},
		})
	}

	deadline := time.Now().Add(2 * time.Second)
	for c.Count() < 30 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if c.Count() != 30 {
		t.Errorf("expected 30 deliveries across agents, got %d", c.Count())
	}
}

// TestDispatcherCloseDoubleCall closes R3 #6: Close must be idempotent.
// A second Close call used to panic on close-of-closed-channel; the
// sync.Once guard makes repeat calls a no-op.
//
// Intentional overlap with TestDispatcher_DoubleCloseRandomized (notify_
// property_test.go): this is the focused, deterministic pin tied to the R3 #6
// regression (sequential double-close); the property test adds the concurrent
// interleaving. Keep both — they fail for different reasons.
func TestDispatcherCloseDoubleCall(t *testing.T) {
	d := NewDispatcherWithOpts(policy.NotificationCfg{}, 1, 4)
	d.Close()
	// Second call must not panic.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("second Close panicked: %v", r)
		}
	}()
	d.Close()
}

// TestDispatcherCloseCancelsInflight closes R3 #7: an in-flight webhook
// roundtrip must be cancelled when the dispatcher Closes, so graceful
// shutdown is bounded by ctx-observation latency rather than the per-call
// HTTP timeout. The test fixture is a webhook target that hangs for 10
// seconds; a correctly wired Dispatcher.Close cancels the request and
// returns within ~250ms.
func TestDispatcherCloseCancelsInflight(t *testing.T) {
	// Slow server: blocks until the request context is cancelled OR 10s
	// elapses. With the v0.4.x build (no context plumbing) Close would
	// have to wait the full 10s; with the fix it returns immediately.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
	}))
	defer srv.Close()

	d := NewDispatcherWithOpts(policy.NotificationCfg{
		OnDeny: []policy.NotifyTarget{
			{Type: "webhook", URL: srv.URL},
		},
	}, 1, 4)

	// Kick off a denied event that the worker will pick up immediately.
	d.Send(Event{Type: "denied"})

	// Give the worker a moment to actually start the HTTP roundtrip.
	time.Sleep(50 * time.Millisecond)

	// Close should return promptly because the in-flight HTTP request
	// is cancelled by ctx, not bound to the http.Client.Timeout.
	closeStart := time.Now()
	d.Close()
	elapsed := time.Since(closeStart)
	if elapsed > 2*time.Second {
		t.Errorf("Close took %v; expected <2s with ctx cancellation (was the request not aborted?)", elapsed)
	}
}

// TestDispatcher_TimestampFilled verifies Send fills Timestamp if unset.
func TestDispatcher_TimestampFilled(t *testing.T) {
	d := NewDispatcherWithOpts(policy.NotificationCfg{}, 1, 4)
	defer d.Close()

	captured := &capturingNotifier{}
	d.notifiers = []Notifier{captured}

	before := time.Now().Add(-time.Second)
	d.Send(Event{Type: "denied"})

	deadline := time.Now().Add(500 * time.Millisecond)
	for captured.Get().Timestamp.IsZero() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if captured.Get().Timestamp.Before(before) {
		t.Errorf("timestamp was not filled: %v", captured.Get().Timestamp)
	}
}

// ---- spool-to-disk (queue overflow durability) -----------------------------

func waitForCondition(t *testing.T, timeout time.Duration, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

// TestDispatcher_SpoolOnSaturation_ThenRecoveryDelivers: queue-full
// events land in the spool instead of being dropped, and the recovery
// loop delivers every one of them once the worker frees up.
func TestDispatcher_SpoolOnSaturation_ThenRecoveryDelivers(t *testing.T) {
	spool := filepath.Join(t.TempDir(), "notify-spool.jsonl")
	droppedBefore := atomic.LoadUint64(&DroppedEvents)
	spooledBefore := metrics.NotifySpooledTotal()

	d := NewDispatcherWithOptions(policy.NotificationCfg{}, DispatcherOptions{
		Workers:          1,
		QueueSize:        1,
		SpoolPath:        spool,
		RecoveryInterval: 50 * time.Millisecond,
	})
	defer d.Close()
	counting := &countingNotifier{delay: 150 * time.Millisecond}
	d.notifiers = append(d.notifiers, counting)

	const total = 6
	for i := 0; i < total; i++ {
		d.Send(Event{Type: "denied"})
	}

	if got := metrics.NotifySpooledTotal() - spooledBefore; got == 0 {
		t.Fatal("expected at least one event spooled under saturation")
	}
	if got := atomic.LoadUint64(&DroppedEvents) - droppedBefore; got != 0 {
		t.Fatalf("spool enabled: %d events dropped, want 0", got)
	}

	waitForCondition(t, 20*time.Second, func() bool {
		counting.mu.Lock()
		defer counting.mu.Unlock()
		return counting.calls >= total
	}, "all spooled events delivered")

	if metrics.NotifyDespooledTotal() == 0 {
		t.Error("despooled counter never advanced")
	}
}

// TestDispatcher_SpoolDisabled_DropsAsBefore pins the legacy contract:
// without --notify-spool, queue overflow still drops and counts.
func TestDispatcher_SpoolDisabled_DropsAsBefore(t *testing.T) {
	droppedBefore := atomic.LoadUint64(&DroppedEvents)

	d := NewDispatcherWithOpts(policy.NotificationCfg{}, 1, 1)
	defer d.Close()
	d.notifiers = append(d.notifiers, &countingNotifier{delay: 200 * time.Millisecond})

	for i := 0; i < 6; i++ {
		d.Send(Event{Type: "denied"})
	}
	if got := atomic.LoadUint64(&DroppedEvents) - droppedBefore; got == 0 {
		t.Error("spool disabled: expected drops under saturation")
	}
}

// TestDispatcher_SpoolLeftoverFromPreviousProcessIsDelivered: a spool
// file written by a previous (crashed/stopped) process is picked up by
// the next dispatcher with the same path.
func TestDispatcher_SpoolLeftoverFromPreviousProcessIsDelivered(t *testing.T) {
	spool := filepath.Join(t.TempDir(), "notify-spool.jsonl")
	leftover := `{"notifier_index":0,"event":{"type":"denied","timestamp":"2026-06-12T00:00:00Z","request":{"scope":"shell","command":"rm -rf /"},"result":{"decision":"DENY","reason":"left over"}}}` + "\n"
	if err := os.WriteFile(spool, []byte(leftover), 0o600); err != nil {
		t.Fatalf("seed spool: %v", err)
	}

	// Inject capt via extraNotifiers so d.notifiers is fully built before the
	// spool-recovery goroutine starts reading it. Appending after construction
	// races with drainSpoolOnce (the seeded spool gives the loop work on its
	// first tick) — see DispatcherOptions.extraNotifiers.
	capt := &capturingNotifier{}
	d := NewDispatcherWithOptions(policy.NotificationCfg{}, DispatcherOptions{
		Workers:          2,
		QueueSize:        16,
		SpoolPath:        spool,
		RecoveryInterval: 50 * time.Millisecond,
		extraNotifiers:   []Notifier{capt},
	})
	defer d.Close()

	waitForCondition(t, 15*time.Second, func() bool {
		return capt.Get().Result.Reason == "left over"
	}, "leftover spooled event delivered")
}

// TestDispatcher_SpoolCorruptLineSkippedRemainderDelivered: a crashed process
// commonly leaves a truncated/garbage final frame in the spool. Recovery must
// skip the unparseable line and still deliver the well-formed records around it
// — never wedge the drain loop on a bad frame. drainSpoolOnce documents this
// "skip corrupt, continue" posture; this pins it so a refactor can't regress
// into aborting the whole drain (and silently losing every later event).
func TestDispatcher_SpoolCorruptLineSkippedRemainderDelivered(t *testing.T) {
	spool := filepath.Join(t.TempDir(), "notify-spool.jsonl")
	// Line 1: garbage/truncated (a partial write from a crash). Line 2: a valid
	// record that must still be delivered after the corrupt frame is skipped.
	content := "{not valid json — truncated frame\n" +
		`{"notifier_index":0,"event":{"type":"denied","timestamp":"2026-06-12T00:00:00Z","request":{"scope":"shell","command":"rm -rf /"},"result":{"decision":"DENY","reason":"after corrupt line"}}}` + "\n"
	if err := os.WriteFile(spool, []byte(content), 0o600); err != nil {
		t.Fatalf("seed spool: %v", err)
	}

	// extraNotifiers wires capt as notifier index 0 before the recovery loop
	// starts (see DispatcherOptions.extraNotifiers) — same pattern as the
	// leftover test above, which the seeded spool's first tick would otherwise
	// race.
	capt := &capturingNotifier{}
	d := NewDispatcherWithOptions(policy.NotificationCfg{}, DispatcherOptions{
		Workers:          2,
		QueueSize:        16,
		SpoolPath:        spool,
		RecoveryInterval: 50 * time.Millisecond,
		extraNotifiers:   []Notifier{capt},
	})
	defer d.Close()

	waitForCondition(t, 15*time.Second, func() bool {
		return capt.Get().Result.Reason == "after corrupt line"
	}, "valid spooled event following a corrupt line to be delivered")
}
