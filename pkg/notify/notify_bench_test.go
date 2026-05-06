package notify

import (
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// blockingNotifier never returns from Notify. Used by the queue-full
// benchmark to wedge the single dispatcher worker so all subsequent
// Send() calls hit the drop path.
type blockingNotifier struct {
	hold chan struct{}
}

func (b *blockingNotifier) Notify(_ Event) error {
	<-b.hold // park here for the lifetime of the benchmark
	return nil
}

// BenchmarkDispatcher_Send_QueueFull measures Send() when every call hits
// the bounded-queue drop path. The dispatcher is built with one worker
// and a queue of size one; a blocking notifier wedges both, so every
// Send after the first two saturates and increments DroppedEvents.
//
// What we measure: the cost of the redaction pass + the per-notifier
// non-blocking select that decides between enqueue and drop. This is
// the steady-state hot path under overload — the system that protects
// the rest of AgentGuard from a slow webhook stalling /v1/check.
//
// Closes R4 S1 (notify ns/op + B/op baseline under saturation).
func BenchmarkDispatcher_Send_QueueFull(b *testing.B) {
	hold := make(chan struct{})
	bn := &blockingNotifier{hold: hold}
	b.Cleanup(func() { close(hold) })

	d := &Dispatcher{
		notifiers: []Notifier{bn},
		queue:     make(chan dispatchJob, 1),
		done:      make(chan struct{}),
		redactor:  DefaultRedactor(),
	}
	// One worker so the queue stays wedged the moment the worker picks up
	// the first job.
	go workerWithRecover(d)
	b.Cleanup(func() { d.Close() })

	// Pre-fill: first Send delivers to the worker (which then blocks),
	// second fills the size-1 queue. Everything after this benchmark loop
	// sees a full queue and takes the drop path.
	prime := Event{
		Type:      "denied",
		Timestamp: time.Now().UTC(),
		Request:   policy.ActionRequest{Scope: "shell", Command: "rm -rf /"},
		Result:    policy.CheckResult{Decision: policy.Deny, Reason: "destructive"},
	}
	d.Send(prime)
	d.Send(prime)

	evt := Event{
		Type:      "denied",
		Timestamp: time.Now().UTC(),
		Request:   policy.ActionRequest{Scope: "shell", Command: "rm -rf /var"},
		Result:    policy.CheckResult{Decision: policy.Deny, Reason: "destructive"},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Send(evt)
	}
}
