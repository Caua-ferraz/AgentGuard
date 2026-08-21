package mcpgw

// Regression tests for the audit fixes applied to pkg/mcpgw that shipped
// without one: B16 (a failed first spawn left no supervisor), B19 (an explicit
// null JSON-RPC id was routed as a notification, so the caller got silence),
// and B24 (a delivered notification was reported as a failure).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"sync"
	"testing"
	"time"
)

// ----- B19: an explicit `"id": null` must be answered, not silently dropped -----

// dispatchOne runs a single frame through dispatchFrame against a bridge whose
// stdout is captured, and returns whatever was written back to the host.
func dispatchOne(t *testing.T, frame string) string {
	t.Helper()
	var out bytes.Buffer
	b := NewBridge(&Config{LogLevel: "info"}, io.Discard, "test")
	b.output = &out

	var wg sync.WaitGroup
	b.dispatchFrame(context.Background(), []byte(frame), &wg)
	wg.Wait()
	return out.String()
}

// TestDispatchFrame_ExplicitNullIDGetsAnError is the B19 regression test.
//
// The bug: `len(probe.ID) == 0 || string(probe.ID) == "null"` treated an
// explicit null id as a notification and routed it to handleNotification, which
// writes no response. A caller that sent `"id": null` and waited for a reply
// hung forever, and blamed the gateway.
//
// MCP forbids a null request id, so the frame is malformed either way — but
// answering with a protocol error is correct under every reading, and silence
// is correct under none.
func TestDispatchFrame_ExplicitNullIDGetsAnError(t *testing.T) {
	got := dispatchOne(t, `{"jsonrpc":"2.0","id":null,"method":"tools/call","params":{"name":"fs:read"}}`)
	if got == "" {
		t.Fatal("an explicit null id produced NO response; a caller that expected a reply hangs (B19)")
	}

	var resp Response
	if err := json.Unmarshal([]byte(got), &resp); err != nil {
		t.Fatalf("response is not valid JSON: %v (%q)", err, got)
	}
	if resp.Error == nil {
		t.Fatalf("response carries no error object: %q", got)
	}
	if resp.Error.Code != ErrCodeInvalidRequest {
		t.Errorf("error code = %d, want ErrCodeInvalidRequest (%d)", resp.Error.Code, ErrCodeInvalidRequest)
	}
	// The id must be echoed as null so the caller can correlate the failure
	// with the frame it sent.
	if resp.ID != nil {
		t.Errorf("echoed id = %v, want null", resp.ID)
	}
}

// TestDispatchFrame_AbsentIDIsStillANotification is the other half: the fix
// must NOT turn genuine notifications into responses. A frame with no id field
// is fire-and-forget and must stay silent.
func TestDispatchFrame_AbsentIDIsStillANotification(t *testing.T) {
	got := dispatchOne(t, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	if got != "" {
		t.Errorf("a notification (no id field) must produce no response, got %q", got)
	}
}

// ----- B24: a delivered notification must never be reported as failed -----

// captureWriter is an io.WriteCloser that records everything written to it, so
// a test can assert whether a frame actually reached the upstream's stdin.
type captureWriter struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	closed bool
}

func (c *captureWriter) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}

func (c *captureWriter) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func (c *captureWriter) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

// upstreamWithCapturedStdin returns an upstream wired to a capture buffer
// instead of a subprocess, so Notify's write is observable without spawning.
func upstreamWithCapturedStdin(t *testing.T) (*StdioUpstream, *captureWriter) {
	t.Helper()
	up := NewStdioUpstreamWithOptions(UpstreamSpec{Namespace: "cap", Command: "unused"},
		StdioUpstreamOptions{Logger: newTransportLogger(&bytes.Buffer{}, "info")})
	cw := &captureWriter{}
	up.mu.Lock()
	up.stdin = cw
	up.status = StatusOK
	up.mu.Unlock()
	return up, cw
}

// TestNotify_SucceedsWithLiveContext pins the happy path: a notification that
// is written must report success.
func TestNotify_SucceedsWithLiveContext(t *testing.T) {
	up, cw := upstreamWithCapturedStdin(t)

	err := up.Notify(context.Background(), &Notification{Method: "notifications/cancelled"})
	if err != nil {
		t.Fatalf("Notify with a live context = %v, want nil", err)
	}
	if !bytes.Contains([]byte(cw.String()), []byte("notifications/cancelled")) {
		t.Errorf("notification was not written to stdin: %q", cw.String())
	}
}

// TestNotify_ExpiredContextDoesNotDeliverThenFail is the B24 regression test.
//
// The bug: the ctx check ran AFTER writeFrame, so a context that expired around
// the write returned ctx.Err() for a notification whose bytes were already on
// the pipe. The caller recorded a failure for an operation that had actually
// happened — and for a non-idempotent notification, a retry would double-send.
//
// The invariant is "delivered XOR error", never both. Checking ctx before the
// write makes that deterministic, so this test asserts exactly it.
func TestNotify_ExpiredContextDoesNotDeliverThenFail(t *testing.T) {
	up, cw := upstreamWithCapturedStdin(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already expired before Notify is entered

	err := up.Notify(ctx, &Notification{Method: "notifications/cancelled"})

	if err == nil {
		// Returning nil would be acceptable only if it also delivered.
		if cw.String() == "" {
			t.Fatal("Notify reported success but wrote nothing")
		}
		return
	}
	// Reported a failure — then it must NOT have delivered.
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if got := cw.String(); got != "" {
		t.Errorf("Notify returned an error (%v) but the notification WAS written (%q) — "+
			"the caller records a failure for a delivered side effect and may double-send on retry (B24)", err, got)
	}
}

// ----- B16: a failed first spawn must still leave a supervisor running -----

// flakySpawnFactory fails the first `failures` spawn attempts, then delegates
// to a working factory. It models the real trigger: an `npx` cold start, a
// momentary exec error, a mount that is not ready yet.
func flakySpawnFactory(t *testing.T, failures int, then CommandFactory) (CommandFactory, func() int) {
	t.Helper()
	var mu sync.Mutex
	attempts := 0
	f := func(ctx context.Context, argv []string) (*exec.Cmd, error) {
		mu.Lock()
		attempts++
		n := attempts
		mu.Unlock()
		if n <= failures {
			return nil, errors.New("synthetic transient spawn failure")
		}
		return then(ctx, argv)
	}
	count := func() int {
		mu.Lock()
		defer mu.Unlock()
		return attempts
	}
	return f, count
}

// TestStart_FirstSpawnFailureStillSupervises is the B16 regression test.
//
// The bug: Start returned the spawn error BEFORE `go u.supervise(ctx)`, so an
// upstream whose very first spawn failed had no supervisor at all. Bridge
// logged the failure and kept the upstream in its map, and nothing ever retried
// it — every call to that namespace failed for the life of the process, even
// though a single retry would have worked.
//
// The assertion is behavioural, not structural: after a transient first
// failure the upstream must come back on its own and be usable.
func TestStart_FirstSpawnFailureStillSupervises(t *testing.T) {
	if testing.Short() {
		t.Skip("skip in short mode: builds and spawns the stub server")
	}

	factory, attempts := flakySpawnFactory(t, 1, stubFactory(t, "--name", "stub", "--tool", "echo"))

	up := NewStdioUpstreamWithOptions(UpstreamSpec{
		Namespace: "stub",
		Command:   "stub-server",
	}, StdioUpstreamOptions{
		Logger:         newTransportLogger(&bytes.Buffer{}, "info"),
		CommandFactory: factory,
		Backoff:        []time.Duration{20 * time.Millisecond},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start must still surface the error to its caller...
	if err := up.Start(ctx); err == nil {
		t.Fatal("Start should report the first-spawn failure to its caller")
	}
	t.Cleanup(func() { _ = up.Close() })

	// ...but a supervisor must nonetheless be running and retrying. Wait for a
	// process to exist, which only happens if something respawned it.
	deadline := time.Now().Add(20 * time.Second)
	for {
		up.mu.RLock()
		spawned := up.cmd != nil
		up.mu.RUnlock()
		if spawned {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("upstream never respawned after a transient first-spawn failure "+
				"(%d spawn attempts): Start returned before launching the supervisor, "+
				"so nothing owns the retry (B16)", attempts())
		}
		time.Sleep(20 * time.Millisecond)
	}

	// And the recovered upstream must actually be usable, not merely alive.
	ictx, icancel := context.WithTimeout(ctx, 20*time.Second)
	defer icancel()
	res, err := up.Initialize(ictx, "2025-11-25", map[string]interface{}{}, ClientInfo{Name: "test"})
	if err != nil {
		t.Fatalf("respawned upstream is not usable: Initialize: %v", err)
	}
	if res.ServerInfo.Name != "stub" {
		t.Errorf("serverInfo.name = %q, want %q", res.ServerInfo.Name, "stub")
	}
	if attempts() < 2 {
		t.Errorf("spawn attempts = %d, want >= 2 (one failure + one retry)", attempts())
	}
}
