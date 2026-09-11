package mcpgw

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Frame-size contract.
//
// MaxStdoutLineBytes caps a single JSON-RPC frame. What the gateway is
// SUPPOSED to guarantee when that cap is exceeded:
//
//   F1. One oversized frame is a per-frame failure, not a process-wide one.
//       The gateway keeps serving and later frames are still handled.
//   F2. A caller never waits forever for a frame the gateway refused. Silence
//       is not an acceptable handling of a frame it declined to process.
//   F3. An upstream that outlives its reader must not stay advertised as
//       usable. Either it recovers, or calls to it fail -- never hang.
//
// Deliberately NOT asserted: which error code comes back, whether recovery is
// by skip or by respawn, or how many frames are lost. Those are choices.
// ---------------------------------------------------------------------------

// F3: an upstream whose stdout reader dies while the subprocess is still alive
// must not remain in a state where calls are dispatched into the void.
func TestUpstream_SurvivesOversizedStdoutLine(t *testing.T) {
	if testing.Short() {
		t.Skip("skip in short mode")
	}

	logger := newTransportLogger(&bytes.Buffer{}, "info")
	up := NewStdioUpstreamWithOptions(UpstreamSpec{
		Namespace: "stub",
		Command:   "stub-server",
	}, StdioUpstreamOptions{
		Logger: logger,
		// Emit an oversized line after the first request (the initialize).
		CommandFactory: stubFactory(t, "-huge-line-after-n", "1", "-huge-line-bytes", "5242880"),
		Backoff:        []time.Duration{50 * time.Millisecond},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := up.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer up.Close()

	if _, err := up.Initialize(ctx, "2025-11-25", map[string]interface{}{}, ClientInfo{Name: "t", Version: "0"}); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	// The oversized line lands after that first request and kills the reader
	// while the subprocess keeps running.
	callCtx, callCancel := context.WithTimeout(ctx, 5*time.Second)
	defer callCancel()
	_, callErr := up.Send(callCtx, &Request{
		JSONRPC: JSONRPCVersion,
		ID:      2,
		Method:  MethodToolsList,
	})

	// The call may legitimately fail -- the reader did die. What must NOT
	// happen is that it hangs until the caller's own deadline while the
	// upstream still advertises itself as usable.
	if callErr != nil && callCtx.Err() != nil {
		t.Errorf("Send hung until the caller's deadline (%v) instead of failing fast; "+
			"readLoop exited on the oversized line but cmd.Wait() never returned, so status "+
			"stayed %q and nothing marked the upstream unusable", callErr, up.Status())
	}

	// F3: within a reasonable window the upstream must reach a state that is
	// honest -- either recovered (OK) or visibly unusable (degraded/stopped).
	// What it must not do is sit at OK while silently swallowing every call.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if s := up.Status(); s == StatusDegraded || s == StatusStopped {
			return // visibly unusable, or on its way back through respawn
		}
		// If it is OK, prove it: a call must actually work.
		probeCtx, probeCancel := context.WithTimeout(ctx, 2*time.Second)
		_, err := up.Send(probeCtx, &Request{JSONRPC: JSONRPCVersion, ID: 99, Method: MethodToolsList})
		probeCancel()
		if err == nil {
			return // genuinely recovered
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Errorf("upstream never became honest: status=%q but calls do not succeed; "+
		"it is wedged while still advertising itself as usable", up.Status())
}

// F1 + F2: one oversized HOST frame must not take the gateway down, and a
// caller that sent it must not be left waiting forever.
//
// Every write happens on a helper goroutine: stdin is an io.Pipe, so once
// Run returns nothing drains it and a write blocks forever. That blocking is
// itself part of the failure -- the test must survive it to report it.
func TestBridge_SurvivesOversizedHostFrame(t *testing.T) {
	up := newFakeUpstream("fs")
	b := newTestBridge(t, up)
	h := newBridgeHarness(t, b)

	h.send(map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2025-11-25",
			"clientInfo":      map[string]string{"name": "t", "version": "0"},
		},
	})
	if resp := h.readResponse(); resp.Error != nil {
		t.Fatalf("initialize: %+v", resp.Error)
	}

	// Marshal on the TEST goroutine -- h.send calls t.Fatalf, which is illegal
	// off it -- then write the raw bytes from a helper. The writes are what
	// block once Run stops draining stdin, and the test has to outlive that to
	// report it.
	oversized := mustMarshal(t, map[string]interface{}{
		"jsonrpc": "2.0", "id": 2, "method": "tools/call",
		"params": map[string]interface{}{
			"name":      "fs:echo",
			"arguments": map[string]interface{}{"text": strings.Repeat("A", MaxStdoutLineBytes+1024)},
		},
	})
	followup := mustMarshal(t, map[string]interface{}{"jsonrpc": "2.0", "id": 3, "method": "tools/list"})

	go func() {
		_, _ = h.stdinW.Write(append([]byte(oversized), '\n'))
		_, _ = h.stdinW.Write(append([]byte(followup), '\n'))
	}()

	// Decode straight off the pipe: the harness helper calls t.Fatalf, which
	// is illegal off the test goroutine.
	type frame struct {
		resp *Response
		err  error
	}
	frames := make(chan frame, 8)
	go func() {
		dec := json.NewDecoder(h.stdoutR)
		for {
			var r Response
			if err := dec.Decode(&r); err != nil {
				frames <- frame{err: err}
				return
			}
			frames <- frame{resp: &r}
		}
	}()

	// F1 is the load-bearing assertion: the frame BEHIND the oversized one
	// must still be served. An error reply for the oversized frame alone does
	// not prove the gateway survived -- it can be written on the way out.
	var sawOversizedReply, sawFollowup bool
	deadline := time.After(20 * time.Second)
	for !sawFollowup {
		select {
		case f := <-frames:
			if f.err != nil {
				t.Fatalf("gateway stopped serving after one oversized frame (%v): the valid "+
					"tools/list behind it was never answered. Run() returning on an oversized "+
					"frame becomes os.Exit(1) in main, so one client frame is a full-gateway "+
					"outage. oversized-frame reply seen: %v", f.err, sawOversizedReply)
			}
			switch idKey(f.resp.ID) {
			case idKey(float64(2)):
				sawOversizedReply = true
			case idKey(float64(3)):
				sawFollowup = true
			}
		case <-deadline:
			t.Fatalf("timed out waiting for the follow-up frame to be served "+
				"(oversized-frame reply seen: %v) — the gateway did not survive",
				sawOversizedReply)
		}
	}

	// F2: the caller that sent the oversized frame was answered rather than
	// left waiting on a frame the gateway silently refused.
	if !sawOversizedReply {
		t.Error("the oversized frame got no reply at all; a caller that sent one waits " +
			"forever on a frame the gateway declined to process")
	}
}
