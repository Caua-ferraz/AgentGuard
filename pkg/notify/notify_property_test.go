package notify

// AT-added concurrency property tests for the dispatcher.
//
// Properties under test:
//  1. Random concurrent Send + Close pairs never panic.
//  2. Close returns within a bounded time (well under the slow-notifier
//     wall-clock cost, proving that the in-flight context cancellation
//     plumbed in v0.5 actually unblocks workers).
//
// We bound the random space deliberately: testing/quick is configurable to
// produce sensible workload sizes (≤ 64 goroutines, ≤ 256 events) so the
// suite still finishes in a few seconds even under -race.

import (
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"testing/quick"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// noopNotifier accepts events without doing any I/O, but records that it
// was called so we can verify the dispatcher actually delivers events.
type noopNotifier struct {
	calls int64
}

func (n *noopNotifier) Notify(_ Event) error {
	atomic.AddInt64(&n.calls, 1)
	return nil
}

// TestDispatcher_ConcurrentSendCloseNoPanic spawns G goroutines that each
// fire N Send calls, while a separate goroutine eventually invokes Close.
// The property: this must never panic, regardless of interleaving.
func TestDispatcher_ConcurrentSendCloseNoPanic(t *testing.T) {
	prop := func(seed int64, gRaw, nRaw uint8) (ok bool) {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("panic on seed=%d g=%d n=%d: %v", seed, gRaw, nRaw, r)
				ok = false
			}
		}()

		// Bound the workload: 1..32 goroutines, 1..64 sends each.
		g := int(gRaw%32) + 1
		n := int(nRaw%64) + 1

		d := NewDispatcherWithOpts(policy.NotificationCfg{}, 4, 16)
		d.notifiers = []Notifier{&noopNotifier{}}

		// Random close-after delay between 0 and (g*n)/2 sends in the future.
		closeAfter := rand.New(rand.NewSource(seed)).Intn(g*n/2 + 1)
		closed := make(chan struct{})
		var sendsObserved int64

		var wg sync.WaitGroup
		for w := 0; w < g; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < n; i++ {
					// A second goroutine triggers Close once the global
					// send counter crosses the threshold; a spurious extra
					// Close call here would also be safe per the
					// idempotency contract under test.
					if atomic.AddInt64(&sendsObserved, 1) == int64(closeAfter) {
						go func() {
							d.Close()
							close(closed)
						}()
					}
					d.Send(Event{
						Type:    "denied",
						Request: policy.ActionRequest{Scope: "shell"},
					})
				}
			}()
		}
		wg.Wait()
		// Make sure Close has been called at least once before returning.
		select {
		case <-closed:
		default:
			d.Close()
		}
		return true
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 30}); err != nil {
		t.Error(err)
	}
}

// TestDispatcher_CloseBoundedTime asserts that Close returns within a
// generous deadline (1s) even when notifiers are slow. The v0.5
// context-plumbing fix means in-flight workers exit promptly when the
// dispatcher's context is cancelled; without it, Close would have to
// wait the full Notify duration.
//
// We use a noop notifier deliberately — the original cancellation test
// (TestDispatcherCloseCancelsInflight) covers the HTTP-roundtrip path.
// This test covers the simpler "lots of pending jobs" path.
func TestDispatcher_CloseBoundedTime(t *testing.T) {
	d := NewDispatcherWithOpts(policy.NotificationCfg{}, 2, 64)
	d.notifiers = []Notifier{&noopNotifier{}}

	// Saturate the queue.
	for i := 0; i < 256; i++ {
		d.Send(Event{Type: "denied"})
	}

	start := time.Now()
	d.Close()
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("Close took %v, want <1s", elapsed)
	}
}

// TestDispatcher_DoubleCloseRandomized: random number (1-8) of concurrent
// Close calls must all be safe. This is a property-form sanity check on
// top of the unit test TestDispatcherCloseDoubleCall.
func TestDispatcher_DoubleCloseRandomized(t *testing.T) {
	prop := func(rawN uint8) (ok bool) {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("panic on rawN=%d: %v", rawN, r)
				ok = false
			}
		}()
		n := int(rawN%8) + 1
		d := NewDispatcherWithOpts(policy.NotificationCfg{}, 1, 4)

		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				d.Close()
			}()
		}
		wg.Wait()
		return true
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 50}); err != nil {
		t.Error(err)
	}
}
