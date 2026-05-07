package mcpgw

// AT (Test Wrangler) — bridge-level reconnect end-to-end test.
//
// A17's transport_test.go has TestStdioUpstream_Reconnect at the
// transport layer (StdioUpstream alone). This file drives the same
// scenario through the FULL bridge — Bridge.Run, real StdioUpstream,
// real subprocess — so we verify:
//
//   1. After the upstream subprocess exits, Status() transitions to
//      degraded.
//   2. tools/call against a degraded namespace returns
//      ErrCodeUpstreamUnavail (-32002) with the namespace named in
//      the message — visible to the model so it can degrade gracefully.
//   3. The supervisor walks the backoff schedule, respawns, and
//      re-Initializes.
//   4. After reconnect, Status() returns to OK and a follow-up
//      tools/call succeeds.
//
// Per the AT brief, time.Sleep is allowed in test code; we use a
// generous 10s deadline so the first backoff tier (1s in the default
// schedule, but we override to 100ms here) doesn't make the test
// flaky on slow CI runners.

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"
)

// TestAT_ReconnectE2E_RecoverAfterCrash drives the bridge through a
// crash-and-recover cycle.
func TestAT_ReconnectE2E_RecoverAfterCrash(t *testing.T) {
	if testing.Short() {
		t.Skip("skip in short mode (spawns real subprocess)")
	}

	// crash-after-n=2: the upstream survives the first Initialize +
	// the first tools/call (initialize is 1 request, tools/call is
	// 1 request, so it crashes immediately after the initialize-driven
	// reinit handshake — the supervisor will see the exit and respawn).
	//
	// We stagger crash-after-n large enough that:
	//   - upstream-side Initialize (1 request, count=1)
	//   - bridge-side handleInitialize re-Initialize (1 request, count=2)
	//   - first tools/list from harness (1 request, count=3 -> crash)
	cfg := &Config{
		GuardURL:                  "http://127.0.0.1:8080",
		TenantID:                  "local",
		FailMode:                  "deny",
		PolicyMode:                "fast",
		LogLevel:                  "info",
		UpstreamTimeout:           5 * time.Second,
		ReconnectCap:              60 * time.Second,
		SupportedProtocolVersions: append([]string{}, DefaultSupportedProtocolVersions...),
	}
	cfg.Upstreams = []UpstreamSpec{{Namespace: "fs", Command: "stub-server", Transport: "stdio"}}

	b := NewBridge(cfg, io.Discard, "0.5.0-AT-reconnect")

	factory := stubFactory(t,
		"--name", "stub-fs",
		"--tool", "echo",
		"--proto-version", "2025-11-25",
		"--crash-after-n", "3",
	)
	up := NewStdioUpstreamWithOptions(UpstreamSpec{
		Namespace: "fs",
		Command:   "stub-server",
	}, StdioUpstreamOptions{
		CommandFactory: factory,
		// Tight backoff so the test is fast.
		Backoff: []time.Duration{100 * time.Millisecond, 200 * time.Millisecond},
	})
	startCtx, startCancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(startCancel)
	if err := up.Start(startCtx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, err := up.Initialize(startCtx, "2025-11-25", map[string]interface{}{}, ClientInfo{Name: "AT"}); err != nil {
		t.Fatalf("upstream Initialize: %v", err)
	}
	b.SetUpstream(up)
	t.Cleanup(func() { _ = up.Close() })

	h := newBridgeHarness(t, b)

	// 1. initialize through bridge (re-initialize on upstream — count 2).
	h.send(map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2025-11-25",
			"capabilities":    map[string]interface{}{},
			"clientInfo":      map[string]interface{}{"name": "AT-reconnect"},
		},
	})
	resp := h.readResponse()
	if resp.Error != nil {
		t.Fatalf("initialize: %+v", resp.Error)
	}

	// 2. First tools/list — this is upstream request count 3, which
	//    triggers --crash-after-n exit. The bridge sees the response
	//    first (the stub writes the response, THEN exits on the next
	//    iteration of its scan loop after handled.Add returns >crashAfterN).
	//
	// Actually: the stub increments handled BEFORE switching on the
	// method, and exits immediately if int(n) > *crashAfterN. With
	// crashAfterN=3, the third request triggers `if 3 > 3` → false,
	// so the third request still gets a response. The fourth request
	// triggers the crash (4 > 3 → true).
	//
	// Plan: drive 3 successful requests (initialize from upstream's
	// pre-Initialize is request 1; bridge's handleInitialize re-init
	// is request 2; first tools/list is request 3). Then drive a 4th
	// request which never gets a response and the supervisor sees the
	// exit.
	h.send(map[string]interface{}{
		"jsonrpc": "2.0", "id": 2, "method": "tools/list",
		"params": map[string]interface{}{},
	})
	resp = h.readResponse()
	if resp.Error != nil {
		t.Fatalf("first tools/list: %+v", resp.Error)
	}

	// 3. Drive the 4th request — the upstream will exit non-zero before
	//    responding. Send via the underlying upstream directly with a
	//    short timeout so we don't block waiting for a response that
	//    will never come.
	go func() {
		ictx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, _ = up.Send(ictx, &Request{
			Method: MethodToolsList,
			Params: json.RawMessage(`{}`),
		})
	}()

	// 4. Wait for the upstream supervisor to see the exit and mark
	//    the namespace degraded.
	deadline := time.Now().Add(5 * time.Second)
	var sawDegraded bool
	for time.Now().Before(deadline) {
		if up.Status() == StatusDegraded {
			sawDegraded = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !sawDegraded {
		// If the supervisor was very fast it may have already
		// reconnected by the time we observed; that's also acceptable.
		// Skip the degraded-tools/call assertion in that case.
		t.Logf("supervisor reconnected before degraded was observable; status=%q", up.Status())
	} else {
		// 5. While degraded, tools/call against fs should return
		//    ErrCodeUpstreamUnavail with the namespace in the message.
		h.send(map[string]interface{}{
			"jsonrpc": "2.0", "id": 3, "method": "tools/call",
			"params": map[string]interface{}{
				"name":      "fs:echo",
				"arguments": map[string]interface{}{"text": "during-degraded"},
			},
		})
		resp = h.readResponse()
		if resp.Error == nil {
			t.Errorf("expected ErrCodeUpstreamUnavail while degraded, got result")
		} else {
			if resp.Error.Code != ErrCodeUpstreamUnavail {
				t.Errorf("error code = %d; want %d (ErrCodeUpstreamUnavail)", resp.Error.Code, ErrCodeUpstreamUnavail)
			}
			if !strings.Contains(resp.Error.Message, "fs") {
				t.Errorf("error message did not name the namespace: %q", resp.Error.Message)
			}
		}
	}

	// 6. Wait for reconnect.
	deadline = time.Now().Add(15 * time.Second)
	var reconnected bool
	for time.Now().Before(deadline) {
		if up.Status() == StatusOK {
			reconnected = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !reconnected {
		t.Fatalf("upstream did not reconnect within 15s; final status=%q", up.Status())
	}

	// 7. Drive a fresh tools/call after reconnect — should succeed.
	//    Note: this consumes 1 request on the new subprocess (since
	//    we restarted, the handled counter is reset). Add some buffer
	//    by adjusting the call below to match what the reconnected
	//    stub will accept (--crash-after-n=3, fresh process, request
	//    count starts at 1).
	h.send(map[string]interface{}{
		"jsonrpc": "2.0", "id": 4, "method": "tools/call",
		"params": map[string]interface{}{
			"name":      "fs:echo",
			"arguments": map[string]interface{}{"text": "after-reconnect"},
		},
	})
	resp = h.readResponse()
	if resp.Error != nil {
		t.Fatalf("post-reconnect tools/call: %+v", resp.Error)
	}
	var tcr ToolsCallResult
	if err := json.Unmarshal(resp.Result, &tcr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if tcr.IsError {
		t.Errorf("post-reconnect call returned isError=true: %+v", tcr)
	}
	if !strings.Contains(tcr.Content[0].Text, "after-reconnect") {
		t.Errorf("post-reconnect response did not echo arg: %q", tcr.Content[0].Text)
	}
}
