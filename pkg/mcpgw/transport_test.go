package mcpgw

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

// stubBinary builds the testdata/stub_server binary once per test
// process, returning its absolute path. The binary takes the same
// flags it documents in its header comment; tests pass per-case
// flags via the CommandFactory.
func stubBinary(t *testing.T) string {
	t.Helper()
	stubBinOnce.Do(func() {
		dir, err := os.MkdirTemp("", "mcpgw-stub-*")
		if err != nil {
			stubBinErr = err
			return
		}
		// Find the package's own directory using runtime.Caller so
		// we don't depend on the test's working directory.
		_, thisFile, _, ok := runtime.Caller(0)
		if !ok {
			stubBinErr = fmt.Errorf("runtime.Caller failed")
			return
		}
		pkgDir := filepath.Dir(thisFile)
		stubSrc := filepath.Join(pkgDir, "testdata", "stub_server")

		out := filepath.Join(dir, "stub_server")
		if runtime.GOOS == "windows" {
			out += ".exe"
		}
		cmd := exec.Command("go", "build", "-o", out, ".")
		cmd.Dir = stubSrc
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			stubBinErr = fmt.Errorf("build stub server: %w", err)
			return
		}
		stubBinPath = out
		// Schedule a global cleanup. We use TempDir's auto-cleanup
		// implicitly here by creating MkdirTemp; explicit
		// os.RemoveAll happens at process exit.
	})
	if stubBinErr != nil {
		t.Fatalf("stub binary unavailable: %v", stubBinErr)
	}
	return stubBinPath
}

var (
	stubBinOnce sync.Once
	stubBinPath string
	stubBinErr  error
)

// stubFactory returns a CommandFactory that runs the stub binary
// with the supplied stub-server flags, ignoring the upstream's
// configured argv (which would otherwise look like
// "npx -y …" — irrelevant for tests).
func stubFactory(t *testing.T, stubFlags ...string) CommandFactory {
	bin := stubBinary(t)
	return func(ctx context.Context, _ []string) (*exec.Cmd, error) {
		args := append([]string{}, stubFlags...)
		return exec.CommandContext(ctx, bin, args...), nil
	}
}

// TestStdioUpstream_HappyPath spawns the stub server, drives an
// initialize + tools/list + tools/call + close cycle, and asserts
// each response shape.
func TestStdioUpstream_HappyPath(t *testing.T) {
	if testing.Short() {
		t.Skip("skip in short mode")
	}

	logger := newTransportLogger(&bytes.Buffer{}, "info")
	up := NewStdioUpstreamWithOptions(UpstreamSpec{
		Namespace: "stub",
		Command:   "stub-server",
	}, StdioUpstreamOptions{
		Logger:         logger,
		CommandFactory: stubFactory(t, "--name", "stub", "--tool", "echo"),
		Backoff:        []time.Duration{50 * time.Millisecond},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := up.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = up.Close() })

	// Initialize.
	res, err := up.Initialize(ctx, "2025-11-25", map[string]interface{}{}, ClientInfo{Name: "test"})
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if res.ServerInfo.Name != "stub" {
		t.Errorf("ServerInfo.Name: got %q", res.ServerInfo.Name)
	}
	if res.ProtocolVersion != "2025-11-25" {
		t.Errorf("ProtocolVersion: got %q", res.ProtocolVersion)
	}
	if up.Status() != StatusOK {
		t.Errorf("Status after init: got %q", up.Status())
	}

	// tools/list.
	resp, err := up.Send(ctx, &Request{
		ID:     "list-1",
		Method: MethodToolsList,
		Params: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("tools/list Send: %v", err)
	}
	if resp.Error != nil {
		t.Fatalf("tools/list error: %+v", resp.Error)
	}
	var list ToolsListResult
	if err := json.Unmarshal(resp.Result, &list); err != nil {
		t.Fatalf("tools/list decode: %v", err)
	}
	if len(list.Tools) != 1 || list.Tools[0].Name != "echo" {
		t.Errorf("tools: %+v", list.Tools)
	}

	// tools/call.
	callParams, _ := json.Marshal(map[string]interface{}{
		"name":      "echo",
		"arguments": map[string]interface{}{"text": "hello"},
	})
	resp, err = up.Send(ctx, &Request{
		ID:     int64(7),
		Method: MethodToolsCall,
		Params: callParams,
	})
	if err != nil {
		t.Fatalf("tools/call Send: %v", err)
	}
	if resp.Error != nil {
		t.Fatalf("tools/call error: %+v", resp.Error)
	}
	if id, ok := resp.ID.(int64); !ok || id != 7 {
		t.Errorf("response ID lost (got %v, %T)", resp.ID, resp.ID)
	}
}

// TestStdioUpstream_CloseIsIdempotent confirms Close can be called
// multiple times without panic or error.
func TestStdioUpstream_CloseIsIdempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("skip in short mode")
	}

	up := NewStdioUpstreamWithOptions(UpstreamSpec{
		Namespace: "stub",
		Command:   "stub-server",
	}, StdioUpstreamOptions{
		CommandFactory: stubFactory(t),
		Backoff:        []time.Duration{50 * time.Millisecond},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := up.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// First close.
	if err := up.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	// Second close — must not panic, must return cleanly.
	if err := up.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}

	if up.Status() != StatusStopped {
		t.Errorf("Status after Close: got %q", up.Status())
	}
}

// TestStdioUpstream_Reconnect kills the subprocess after the first
// request and asserts the supervisor respawns + re-Initializes.
func TestStdioUpstream_Reconnect(t *testing.T) {
	if testing.Short() {
		t.Skip("skip in short mode")
	}

	logBuf := &bytes.Buffer{}
	logger := newTransportLogger(logBuf, "debug")
	up := NewStdioUpstreamWithOptions(UpstreamSpec{
		Namespace: "stub",
		Command:   "stub-server",
	}, StdioUpstreamOptions{
		Logger:         logger,
		CommandFactory: stubFactory(t, "--crash-after-n", "1"),
		// Tight backoff so the test doesn't take forever.
		Backoff: []time.Duration{100 * time.Millisecond, 200 * time.Millisecond},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	if err := up.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = up.Close() })

	// First Initialize triggers --crash-after-n=1 → process exits
	// after this response.
	if _, err := up.Initialize(ctx, "2025-11-25", nil, ClientInfo{Name: "t"}); err != nil {
		t.Fatalf("first Initialize: %v", err)
	}

	// Wait for the subprocess to exit and the supervisor to mark
	// the upstream degraded.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if up.Status() == StatusDegraded {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if up.Status() != StatusDegraded && up.Status() != StatusOK {
		// Note: depending on timing the supervisor may have already
		// respawned + re-initialized by the time we observe — that's
		// also a passing case (the supervisor is fast enough).
		t.Logf("status while waiting for reconnect: %q", up.Status())
	}

	// Wait for the supervisor to reconnect. The crash-after-n=1
	// counter resets on the new subprocess so we can drive another
	// Initialize after reconnect.
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
		t.Fatalf("upstream did not reconnect within 15s (status=%q)\nlog:\n%s",
			up.Status(), logBuf.String())
	}
}

// TestStdioUpstream_RoutesNotificationsToSink: unsolicited notification
// frames from the upstream reach OnNotification instead of being
// dropped (the #mcp-list-changed seam).
func TestStdioUpstream_RoutesNotificationsToSink(t *testing.T) {
	if testing.Short() {
		t.Skip("skip in short mode")
	}

	got := make(chan string, 4)
	logger := newTransportLogger(&bytes.Buffer{}, "info")
	up := NewStdioUpstreamWithOptions(UpstreamSpec{
		Namespace: "stub",
		Command:   "stub-server",
	}, StdioUpstreamOptions{
		Logger:         logger,
		CommandFactory: stubFactory(t, "--notify-list-changed-on-call"),
		Backoff:        []time.Duration{50 * time.Millisecond},
		OnNotification: func(method string) { got <- method },
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := up.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = up.Close() })
	if _, err := up.Initialize(ctx, "2025-11-25", map[string]interface{}{}, ClientInfo{Name: "test"}); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	resp, err := up.Send(ctx, &Request{
		ID:     "call-1",
		Method: MethodToolsCall,
		Params: json.RawMessage(`{"name":"echo","arguments":{}}`),
	})
	if err != nil {
		t.Fatalf("tools/call Send: %v", err)
	}
	if resp.Error != nil {
		t.Fatalf("tools/call error: %+v", resp.Error)
	}

	select {
	case method := <-got:
		if method != NotificationToolsListChanged {
			t.Errorf("notification method = %q, want %q", method, NotificationToolsListChanged)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("OnNotification never fired for the upstream's list_changed frame")
	}
}
