package notify

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
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

// TestDispatcher_MultiAgentFanout: events from different agent_ids must all
// reach every notifier (no per-agent filtering at the dispatcher layer).
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
