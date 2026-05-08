package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/metrics"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// DefaultHTTPTimeout is the timeout for webhook and Slack HTTP requests.
const DefaultHTTPTimeout = 10 * time.Second

// DefaultQueueSize is the buffered channel size for the dispatch worker pool.
// If notifications arrive faster than workers can send, excess events are
// dropped and DroppedEvents is incremented.
const DefaultQueueSize = 256

// DefaultWorkers is the number of concurrent dispatch goroutines.
const DefaultWorkers = 8

// DroppedEvents counts events discarded because the dispatch queue was full.
// Exposed as a package-level atomic so callers/metrics can observe it.
var DroppedEvents uint64

// Event describes something that happened in the system.
type Event struct {
	Type      string               `json:"type"` // "approval_required", "denied", "allowed"
	Timestamp time.Time            `json:"timestamp"`
	Request   policy.ActionRequest `json:"request"`
	Result    policy.CheckResult   `json:"result"`
	// ApprovalURL is set when Type == "approval_required".
	ApprovalURL string `json:"approval_url,omitempty"`
}

// Notifier delivers events to external systems.
type Notifier interface {
	Notify(event Event) error
}

// Dispatcher fans out events to multiple notifiers using a bounded worker pool.
//
// Lifecycle: NewDispatcher* spawns N worker goroutines and creates a
// cancellable context. Close cancels that context (so in-flight webhook /
// Slack HTTP requests unblock immediately) and is guarded by sync.Once so
// repeated calls — common in shutdown paths that defer Close from multiple
// owners — do not panic on a re-closed channel.
type Dispatcher struct {
	notifiers []Notifier
	queue     chan dispatchJob
	done      chan struct{}
	redactor  *Redactor
	// ctx is cancelled by Close; webhook/Slack notifiers attach it to their
	// outbound HTTP requests so a graceful shutdown unblocks within
	// milliseconds rather than waiting up to DefaultHTTPTimeout per
	// in-flight call.
	ctx       context.Context
	cancelCtx context.CancelFunc
	closeOnce sync.Once
}

type dispatchJob struct {
	notifier Notifier
	event    Event
}

// NewDispatcher builds a dispatcher from the policy notification config.
// The dispatcher starts DefaultWorkers goroutines that pull from a bounded
// queue. Send() never blocks the caller; overflowing events are dropped and
// counted in DroppedEvents.
func NewDispatcher(cfg policy.NotificationCfg) *Dispatcher {
	return NewDispatcherWithOpts(cfg, DefaultWorkers, DefaultQueueSize)
}

// NewDispatcherWithOpts allows tuning the worker count and queue size. Used
// primarily by tests.
func NewDispatcherWithOpts(cfg policy.NotificationCfg, workers, queueSize int) *Dispatcher {
	// Policy load has already validated that extra patterns compile, so any
	// error here is a programmer mistake (e.g. a caller that skipped
	// LoadFromFile). Surface it via log rather than silently dropping.
	redactor, err := DefaultRedactor().WithExtraPatterns(cfg.Redaction.ExtraPatterns)
	if err != nil {
		log.Printf("notify: ignoring extra_patterns (%v) — redactor will use defaults only", err)
		redactor = DefaultRedactor()
	}
	ctx, cancel := context.WithCancel(context.Background())
	d := &Dispatcher{
		queue:     make(chan dispatchJob, queueSize),
		done:      make(chan struct{}),
		redactor:  redactor,
		ctx:       ctx,
		cancelCtx: cancel,
	}

	// Resolve the dispatch-level timeout once. Per-target overrides are
	// resolved inside targetToNotifier against this value so operators who
	// set only `notifications.dispatch_timeout` get it applied uniformly.
	dispatchTimeout := policy.DefaultNotifyDispatchTimeout
	if s := cfg.DispatchTimeout; s != "" {
		if parsed, err := time.ParseDuration(s); err == nil && parsed > 0 {
			dispatchTimeout = parsed
		} else {
			log.Printf("notify: ignoring invalid dispatch_timeout %q (%v) — using %s", s, err, dispatchTimeout)
		}
	}

	for _, t := range cfg.ApprovalRequired {
		d.notifiers = append(d.notifiers, targetToNotifier(t, "approval_required", dispatchTimeout, ctx))
	}
	for _, t := range cfg.OnDeny {
		d.notifiers = append(d.notifiers, targetToNotifier(t, "denied", dispatchTimeout, ctx))
	}

	if workers < 1 {
		workers = 1
	}
	for i := 0; i < workers; i++ {
		// Wrap each worker in a recover so a panic inside any custom
		// notifier (or a stdlib http.Client.Do edge case) does not take
		// the whole process down.
		go workerWithRecover(d)
	}

	return d
}

// workerWithRecover runs the worker loop and recovers any panic. The
// dispatcher does NOT respawn — a panic exits one of `workers` goroutines,
// reducing throughput but not correctness; the dispatcher continues to
// drain the queue with the remaining workers. Operators see the panic in
// the log and can restart on the next deploy.
func workerWithRecover(d *Dispatcher) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("PANIC notify dispatcher worker: %v", rec)
		}
	}()
	d.worker()
}

func (d *Dispatcher) worker() {
	for {
		select {
		case <-d.done:
			return
		case job, ok := <-d.queue:
			if !ok {
				return
			}
			// Time each dispatch so operators can alert on slow webhooks
			// (default timeout is 10s — a p95 creeping past 1s usually
			// precedes outright timeouts). The label is bounded by
			// notifierType()'s closed switch.
			start := time.Now()
			err := job.notifier.Notify(job.event)
			metrics.ObserveNotifyDispatch(notifierType(job.notifier), time.Since(start).Seconds())
			if err != nil {
				log.Printf("notify error (%T): %v", job.notifier, err)
			}
		}
	}
}

// Close stops worker goroutines and cancels in-flight HTTP notifications.
//
// Idempotent: guarded by sync.Once so a deferred shutdown that calls Close
// twice (e.g. signal-handler + main return) does not panic on a re-closed
// channel. The cancellation also unblocks any webhook/Slack request still
// waiting on its remote, so graceful shutdown is bounded by the time a
// single Notify() takes to observe the context (typically µs–ms) rather
// than by DefaultHTTPTimeout per pending event.
func (d *Dispatcher) Close() {
	d.closeOnce.Do(func() {
		// Cancel first so workers and in-flight HTTP requests start
		// unwinding immediately; only then close `done` so the worker
		// loop's select fires on the same shutdown signal.
		if d.cancelCtx != nil {
			d.cancelCtx()
		}
		close(d.done)
	})
}

func targetToNotifier(t policy.NotifyTarget, eventFilter string, dispatchTimeout time.Duration, ctx context.Context) Notifier {
	// Only webhook/slack honor timeout — console and log are synchronous
	// and in-process, so a timeout has nothing to act on. Webhook and Slack
	// also receive the dispatcher's context so Close() can interrupt their
	// in-flight HTTP roundtrips.
	switch t.Type {
	case "webhook":
		return &WebhookNotifier{URL: t.URL, Filter: eventFilter, client: &http.Client{Timeout: t.ResolvedTimeout(dispatchTimeout)}, ctx: ctx}
	case "slack":
		return &SlackNotifier{WebhookURL: t.URL, Filter: eventFilter, client: &http.Client{Timeout: t.ResolvedTimeout(dispatchTimeout)}, ctx: ctx}
	case "console":
		return &ConsoleNotifier{Filter: eventFilter}
	case "log":
		return &LogNotifier{Level: t.Level, Filter: eventFilter}
	default:
		return &LogNotifier{Level: "warn", Filter: eventFilter}
	}
}

// Send queues an event for asynchronous dispatch to all matching notifiers.
// Non-blocking: if the queue is full, events are dropped and counted.
func (d *Dispatcher) Send(event Event) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	// Redact sensitive patterns before dispatching. Webhooks and Slack channels
	// are external systems; agent-supplied commands can contain secrets.
	if d.redactor != nil {
		event = d.redactor.Redact(event)
	}

	for _, n := range d.notifiers {
		select {
		case d.queue <- dispatchJob{notifier: n, event: event}:
			// Sampling the depth right after enqueue gives a
			// lock-free, enqueue-biased view — good enough for a gauge
			// whose purpose is to answer "is the queue filling up?".
			metrics.SetNotifyQueueDepth(len(d.queue))
		default:
			// Keep the package-level atomic around for anyone already reading
			// it directly; the Prometheus-labeled counter is the new surface.
			atomic.AddUint64(&DroppedEvents, 1)
			metrics.IncNotifyDropped(notifierType(n), metrics.NotifyDroppedQueueFull)
		}
	}
}

// notifierType maps a Notifier to the bounded-cardinality label used in
// Prometheus. Adding a new Notifier implementation requires a case here —
// unknowns land under "unknown" so an operator sees the drop rather than
// silently losing it.
func notifierType(n Notifier) string {
	switch n.(type) {
	case *WebhookNotifier:
		return "webhook"
	case *SlackNotifier:
		return "slack"
	case *ConsoleNotifier:
		return "console"
	case *LogNotifier:
		return "log"
	default:
		return "unknown"
	}
}

// --- Webhook ---

// WebhookNotifier posts JSON to an arbitrary URL.
//
// ctx is the dispatcher-scoped context. When the dispatcher is Closed, ctx
// is cancelled and any in-flight HTTP roundtrip returns immediately so
// graceful shutdown does not stall behind a slow webhook.
type WebhookNotifier struct {
	URL    string
	Filter string // only fire for this event type ("" = all)
	client *http.Client
	ctx    context.Context
}

func (w *WebhookNotifier) Notify(event Event) error {
	if w.Filter != "" && w.Filter != event.Type {
		return nil
	}
	body, err := json.Marshal(event)
	if err != nil {
		return err
	}
	ctx := w.ctx
	if ctx == nil {
		// Defensive: a WebhookNotifier constructed by hand (in tests) has
		// no dispatcher context. Fall back to Background.
		ctx = context.Background()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "AgentGuard/1.0")

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook POST %s: %w", w.URL, err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook %s returned %d", w.URL, resp.StatusCode)
	}
	return nil
}

// --- Slack ---

// SlackNotifier posts a formatted message to a Slack incoming webhook.
//
// ctx is the dispatcher-scoped context — see WebhookNotifier for details.
type SlackNotifier struct {
	WebhookURL string
	Filter     string
	client     *http.Client
	ctx        context.Context
}

func (s *SlackNotifier) Notify(event Event) error {
	if s.Filter != "" && s.Filter != event.Type {
		return nil
	}

	emoji := ":white_check_mark:"
	color := "#36a64f"
	switch event.Type {
	case "denied":
		emoji = ":no_entry:"
		color = "#e01e5a"
	case "approval_required":
		emoji = ":warning:"
		color = "#ecb22e"
	}

	action := event.Request.Command
	if action == "" {
		action = event.Request.Path
	}
	if action == "" {
		action = event.Request.Domain
	}

	text := fmt.Sprintf("%s *%s* | scope: `%s` | action: `%s`\n>%s",
		emoji, event.Result.Decision, event.Request.Scope, action, event.Result.Reason)

	if event.ApprovalURL != "" {
		text += fmt.Sprintf("\n><%s|Approve this action>", event.ApprovalURL)
	}

	payload := map[string]interface{}{
		"attachments": []map[string]interface{}{
			{
				"color":     color,
				"text":      text,
				"footer":    "AgentGuard",
				"ts":        event.Timestamp.Unix(),
				"mrkdwn_in": []string{"text"},
			},
		},
	}

	body, _ := json.Marshal(payload)
	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("slack POST: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("slack returned %d", resp.StatusCode)
	}
	return nil
}

// --- Console ---

// ConsoleNotifier prints events to stdout.
type ConsoleNotifier struct {
	Filter string
}

func (c *ConsoleNotifier) Notify(event Event) error {
	if c.Filter != "" && c.Filter != event.Type {
		return nil
	}
	action := event.Request.Command
	if action == "" {
		action = event.Request.Path
	}
	if action == "" {
		action = event.Request.Domain
	}

	fmt.Printf("[AgentGuard] %s | scope=%s action=%q agent=%s | %s\n",
		event.Result.Decision, event.Request.Scope, action,
		event.Request.AgentID, event.Result.Reason)

	if event.ApprovalURL != "" {
		fmt.Printf("  → Approve: %s\n", event.ApprovalURL)
	}
	return nil
}

// --- Log ---

// LogNotifier logs events via the standard logger.
type LogNotifier struct {
	Level  string
	Filter string
}

func (l *LogNotifier) Notify(event Event) error {
	if l.Filter != "" && l.Filter != event.Type {
		return nil
	}
	action := event.Request.Command
	if action == "" {
		action = event.Request.Path
	}
	if action == "" {
		action = event.Request.Domain
	}
	log.Printf("[%s] %s scope=%s action=%q agent=%s reason=%q",
		l.Level, event.Result.Decision, event.Request.Scope,
		action, event.Request.AgentID, event.Result.Reason)
	return nil
}

// --- Redaction ---

// Redactor scrubs obvious secret patterns from event payloads before they
// leave the process. This is a best-effort defense; the authoritative fix is
// for agents not to pass secrets through as command arguments.
type Redactor struct {
	patterns []*regexp.Regexp
}

// DefaultRedactor returns a Redactor pre-loaded with common secret patterns:
// bearer tokens, AWS-style access keys, GitHub/Slack tokens, and generic
// KEY=value pairs where the key name contains "secret"/"token"/"password".
func DefaultRedactor() *Redactor {
	return &Redactor{
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9_\-\.]+`),
			regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
			regexp.MustCompile(`ghp_[A-Za-z0-9]{36,}`),
			regexp.MustCompile(`xox[baprs]-[A-Za-z0-9\-]+`),
			regexp.MustCompile(`(?i)(secret|token|password|api[_\-]?key)\s*=\s*\S+`),
		},
	}
}

// WithExtraPatterns appends operator-supplied regexes to the redactor's
// pattern list and returns the receiver. An invalid pattern returns an error
// and leaves the receiver unmodified.
//
// Patterns are evaluated in order: built-in defaults first, then extras.
// A later pattern can overlap an earlier match — redaction is idempotent.
func (r *Redactor) WithExtraPatterns(extras []string) (*Redactor, error) {
	if len(extras) == 0 {
		return r, nil
	}
	compiled := make([]*regexp.Regexp, 0, len(extras))
	for i, p := range extras {
		re, err := regexp.Compile(p)
		if err != nil {
			return r, fmt.Errorf("extra_patterns[%d] %q: %w", i, p, err)
		}
		compiled = append(compiled, re)
	}
	r.patterns = append(r.patterns, compiled...)
	return r, nil
}

// Redact returns a copy of the event with sensitive substrings replaced by
// "[REDACTED]" in the command, URL, and reason fields.
func (r *Redactor) Redact(e Event) Event {
	e.Request.Command = r.redactString(e.Request.Command)
	e.Request.URL = r.redactString(e.Request.URL)
	e.Result.Reason = r.redactString(e.Result.Reason)
	if e.Request.Meta != nil {
		meta := make(map[string]string, len(e.Request.Meta))
		for k, v := range e.Request.Meta {
			meta[k] = r.redactString(v)
		}
		e.Request.Meta = meta
	}
	return e
}

func (r *Redactor) redactString(s string) string {
	if s == "" {
		return s
	}
	for _, p := range r.patterns {
		s = p.ReplaceAllString(s, "[REDACTED]")
	}
	return s
}
