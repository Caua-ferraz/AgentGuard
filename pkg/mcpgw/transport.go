package mcpgw

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"
)

// Upstream status strings. Returned by Upstream.Status() so the
// bridge / health endpoint can chip the namespace's state without
// caring about the implementation details.
const (
	StatusStarting = "starting"
	StatusOK       = "ok"
	StatusDegraded = "degraded"
	StatusStopped  = "stopped"
)

// DefaultBackoffSchedule is the reconnect-backoff sequence the
// supervisor walks after an upstream subprocess exits unexpectedly.
// Steps progress through the slice; once we hit the last entry, we
// stay there (cap). Sourced from docs/MCP_GATEWAY.md § 7.
var DefaultBackoffSchedule = []time.Duration{
	1 * time.Second,
	2 * time.Second,
	5 * time.Second,
	30 * time.Second,
	60 * time.Second,
}

// MaxStdoutLineBytes bumps bufio.Scanner's per-line cap from the 64 KiB
// default to 4 MiB so tool argument JSON (legitimately large for some
// upstream responses, e.g., a filesystem read returning a big file)
// does not silently truncate.
const MaxStdoutLineBytes = 4 * 1024 * 1024

// Upstream is the gateway-side handle to one downstream MCP server.
// Implementations own the subprocess lifetime, manage reconnect, and
// offer a request/notification API to the bridge. Only stdio is
// supported in v0.5; HTTP transport is reserved for v0.6.
type Upstream interface {
	// Namespace returns the namespace label this upstream answers to
	// (e.g. "fs", "github").
	Namespace() string

	// Status returns one of the Status* constants.
	Status() string

	// Initialize handshakes the protocol version + capabilities with
	// the upstream. Called by the supervisor immediately after the
	// subprocess starts (and again on every reconnect). The
	// `clientCaps` arg is the host's capabilities, forwarded verbatim
	// per docs/MCP_GATEWAY.md § 3.2 step 3.
	Initialize(ctx context.Context, protocolVersion string, clientCaps map[string]interface{}, clientInfo ClientInfo) (*InitializeResult, error)

	// Send dispatches a request to the upstream and waits for its
	// matching response. The caller-supplied `req.ID` is replaced
	// with a gateway-internal id (the upstream's id space is per
	// connection); the original id is preserved so the bridge can
	// surface it back to the host. Honors ctx for cancellation.
	Send(ctx context.Context, req *Request) (*Response, error)

	// Notify dispatches a one-way notification (no response). The
	// upstream MUST NOT reply.
	Notify(ctx context.Context, n *Notification) error

	// Close terminates the upstream gracefully. Idempotent.
	Close() error
}

// StdioUpstream is the production Upstream impl: spawns the configured
// command, talks newline-delimited JSON-RPC over stdin/stdout, logs
// stderr to the gateway's logger, and reconnects on subprocess exit.
type StdioUpstream struct {
	spec UpstreamSpec

	// logger is the structured logger for transport-layer events. The
	// bridge sets this to its own debug-aware logger; tests can pass
	// a discarding logger via NewStdioUpstreamWithLogger.
	logger *transportLogger

	// Subprocess + I/O state. Guarded by mu to keep Close / restart
	// race-free with concurrent Send callers.
	mu      sync.RWMutex
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	stdout  io.ReadCloser
	stderr  io.ReadCloser
	status  string
	started bool

	// Pending request correlation. The map is keyed by the
	// upstream-facing JSON-RPC id (string form so int and string ids
	// don't collide in the map). The chan delivers exactly one
	// response then is closed by Send.
	pendMu  sync.Mutex
	pending map[string]chan *Response
	nextID  atomic.Int64

	// writeMu serialises stdin writes so concurrent Send / Notify
	// callers don't interleave bytes inside a single JSON frame.
	writeMu sync.Mutex

	// Lifecycle channels.
	closeOnce sync.Once
	done      chan struct{} // closed by Close to signal supervisor exit

	// procExited is closed by the supervisor when the current
	// subprocess's Wait() returns. Close waits on this so it can
	// return after the OS has reaped the process without itself
	// calling Wait() (which would race with the supervisor).
	procExitedMu sync.Mutex
	procExited   chan struct{}

	// Initialize state — captured at Initialize time and replayed on
	// reconnect so the supervisor can re-handshake without bothering
	// the bridge.
	initMu              sync.Mutex
	negotiatedProtoVer  string
	cachedClientCaps    map[string]interface{}
	cachedClientInfo    ClientInfo
	initializeCompleted bool

	// Backoff schedule (overridable in tests for fast iteration).
	backoff []time.Duration

	// Subprocess factory. Production uses execCommand (a thin wrapper
	// over exec.CommandContext). Tests inject a fake to spawn a
	// stub server without going through `npx`.
	commandFactory CommandFactory
}

// CommandFactory builds an *exec.Cmd from a parsed argv slice. The
// production factory is execCommand below; tests can swap in a
// no-network factory that runs a Go test binary with custom args.
type CommandFactory func(ctx context.Context, argv []string) (*exec.Cmd, error)

func execCommand(ctx context.Context, argv []string) (*exec.Cmd, error) {
	if len(argv) == 0 {
		return nil, errors.New("empty command argv")
	}
	return exec.CommandContext(ctx, argv[0], argv[1:]...), nil
}

// NewStdioUpstream constructs a StdioUpstream that runs the configured
// command. The subprocess is NOT started until Start() is called.
func NewStdioUpstream(spec UpstreamSpec) *StdioUpstream {
	return NewStdioUpstreamWithOptions(spec, StdioUpstreamOptions{})
}

// StdioUpstreamOptions configures non-default StdioUpstream behaviour
// (mainly for tests).
type StdioUpstreamOptions struct {
	Backoff        []time.Duration
	CommandFactory CommandFactory
	Logger         *transportLogger
}

// NewStdioUpstreamWithOptions is NewStdioUpstream with all knobs
// exposed. Pass a zero StdioUpstreamOptions to get the production
// defaults.
func NewStdioUpstreamWithOptions(spec UpstreamSpec, opts StdioUpstreamOptions) *StdioUpstream {
	backoff := opts.Backoff
	if len(backoff) == 0 {
		backoff = DefaultBackoffSchedule
	}
	factory := opts.CommandFactory
	if factory == nil {
		factory = execCommand
	}
	logger := opts.Logger
	if logger == nil {
		logger = newTransportLogger(io.Discard, "info")
	}
	return &StdioUpstream{
		spec:           spec,
		logger:         logger,
		status:         StatusStarting,
		pending:        map[string]chan *Response{},
		done:           make(chan struct{}),
		backoff:        backoff,
		commandFactory: factory,
	}
}

// Namespace returns the upstream's namespace label.
func (u *StdioUpstream) Namespace() string { return u.spec.Namespace }

// Status returns the current status string under a read lock.
func (u *StdioUpstream) Status() string {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.status
}

// Start spawns the subprocess for the first time and launches the
// reader/supervisor goroutines. Returns when the process is up and
// stdin/stdout are wired (BUT before Initialize runs — the bridge
// drives Initialize itself so it can capture the negotiated protocol
// version and forward it to the host).
func (u *StdioUpstream) Start(ctx context.Context) error {
	if err := u.spawnLocked(ctx); err != nil {
		return err
	}
	go u.supervise(ctx)
	return nil
}

// spawnLocked starts (or restarts) the subprocess. Caller must NOT
// hold u.mu — this method takes the write lock itself. Returns the
// error from exec.Start; the caller decides whether to retry via
// backoff or surface it as a hard failure.
func (u *StdioUpstream) spawnLocked(ctx context.Context) error {
	argv, err := SplitCommandLine(u.spec.Command)
	if err != nil {
		return fmt.Errorf("upstream %q: parse command: %w", u.spec.Namespace, err)
	}
	cmd, err := u.commandFactory(ctx, argv)
	if err != nil {
		return fmt.Errorf("upstream %q: build command: %w", u.spec.Namespace, err)
	}

	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("upstream %q: stdin pipe: %w", u.spec.Namespace, err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("upstream %q: stdout pipe: %w", u.spec.Namespace, err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("upstream %q: stderr pipe: %w", u.spec.Namespace, err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("upstream %q: start: %w", u.spec.Namespace, err)
	}

	procExited := make(chan struct{})
	u.mu.Lock()
	u.cmd = cmd
	u.stdin = stdinPipe
	u.stdout = stdoutPipe
	u.stderr = stderrPipe
	u.status = StatusStarting
	u.started = true
	u.mu.Unlock()

	u.procExitedMu.Lock()
	u.procExited = procExited
	u.procExitedMu.Unlock()

	// Reader goroutine: parse newline-delimited JSON-RPC from stdout,
	// route responses to pending[id] channels, log notifications to
	// stderr (the bridge does not forward upstream-side notifications
	// in v0.5 except for cancellation, which is initiated by the host
	// not the upstream).
	go u.readLoop(stdoutPipe)
	// Stderr drain: copy upstream stderr to the gateway's logger so
	// downstream warnings are visible to the operator without
	// blocking on a full pipe.
	go u.drainStderr(stderrPipe)

	return nil
}

// readLoop scans newline-delimited JSON frames from stdout and routes
// them to pending response channels. Exits when stdout EOFs (which
// happens on subprocess exit or when Close shuts down stdin/stdout).
func (u *StdioUpstream) readLoop(r io.Reader) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), MaxStdoutLineBytes)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		// Try Response first — it's the common case.
		var resp Response
		if err := json.Unmarshal(line, &resp); err == nil && resp.ID != nil {
			key := idKey(resp.ID)
			u.pendMu.Lock()
			ch, ok := u.pending[key]
			if ok {
				delete(u.pending, key)
			}
			u.pendMu.Unlock()
			if ok {
				// Use a defer-recover: a closed channel send would
				// panic, but we own the channel lifecycle so this
				// is purely defensive against future refactors.
				safeSend(ch, &resp)
			} else {
				u.logger.Debugf("upstream %q: response with unknown id %v dropped", u.spec.Namespace, resp.ID)
			}
			continue
		}
		// Treat as notification or unsolicited message; for v0.5 we
		// log and discard. (Future: route notifications/* to the
		// bridge's notification channel.)
		u.logger.Debugf("upstream %q: unsolicited frame dropped: %s", u.spec.Namespace, string(line))
	}
	if err := scanner.Err(); err != nil {
		u.logger.Infof("upstream %q: stdout reader exited: %v", u.spec.Namespace, err)
	}
	// Mark the upstream as needing reconnect. The supervisor picks
	// this up via cmd.Wait().
}

// safeSend pushes resp into ch without panicking if ch is closed.
func safeSend(ch chan *Response, resp *Response) {
	defer func() {
		_ = recover()
	}()
	select {
	case ch <- resp:
	default:
		// Receiver gave up (timeout). Drop.
	}
}

// drainStderr copies upstream stderr to the gateway's logger.
func (u *StdioUpstream) drainStderr(r io.Reader) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), MaxStdoutLineBytes)
	for scanner.Scan() {
		u.logger.Infof("upstream %q stderr: %s", u.spec.Namespace, scanner.Text())
	}
}

// supervise watches the subprocess; on exit, walks the backoff
// schedule and respawns. Exits when Close is called or ctx is
// cancelled.
//
// IMPORTANT: this function is the SOLE caller of cmd.Wait() on each
// subprocess. Close coordinates with us via the procExited channel
// instead of calling Wait() itself (which would race per
// os/exec.Cmd.Wait's documented contract — concurrent Waits are not
// safe).
func (u *StdioUpstream) supervise(ctx context.Context) {
	step := 0
	for {
		// Wait for the current cmd to exit.
		u.mu.RLock()
		cmd := u.cmd
		u.mu.RUnlock()
		if cmd == nil {
			return
		}
		err := cmd.Wait()

		// Signal everyone waiting on procExited (Close, primarily)
		// that the OS has reaped the process and pipes are drained.
		u.procExitedMu.Lock()
		exited := u.procExited
		u.procExited = nil
		u.procExitedMu.Unlock()
		if exited != nil {
			close(exited)
		}

		select {
		case <-u.done:
			return
		case <-ctx.Done():
			return
		default:
		}

		u.mu.Lock()
		u.status = StatusDegraded
		u.mu.Unlock()
		u.logger.Infof("upstream %q: subprocess exited (%v); reconnecting", u.spec.Namespace, err)

		// Drain pending requests so callers don't hang forever waiting
		// for a response from a dead subprocess. Each pending channel
		// gets a synthetic upstream-unavailable error response.
		u.failPending()

		// Walk the backoff schedule, capped at the last entry.
		wait := u.backoff[step]
		if step < len(u.backoff)-1 {
			step++
		}
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
		case <-u.done:
			timer.Stop()
			return
		case <-ctx.Done():
			timer.Stop()
			return
		}

		if err := u.spawnLocked(ctx); err != nil {
			u.logger.Infof("upstream %q: respawn failed: %v", u.spec.Namespace, err)
			continue
		}

		// Re-Initialize if we previously initialized successfully.
		// This is best-effort: on failure we mark degraded and the
		// next iteration of the loop walks backoff again.
		u.initMu.Lock()
		shouldReinit := u.initializeCompleted
		ver := u.negotiatedProtoVer
		caps := u.cachedClientCaps
		info := u.cachedClientInfo
		u.initMu.Unlock()
		if shouldReinit {
			ictx, cancel := context.WithTimeout(ctx, 30*time.Second)
			if _, err := u.Initialize(ictx, ver, caps, info); err != nil {
				cancel()
				u.logger.Infof("upstream %q: re-initialize failed: %v", u.spec.Namespace, err)
				// keep status degraded; next subprocess exit will
				// continue the loop.
				continue
			}
			cancel()
		}

		// Successful restart — reset backoff so a single hiccup
		// doesn't permanently slow recovery.
		step = 0
	}
}

// failPending wakes every blocked Send caller with a synthetic
// upstream-unavailable response. Called by the supervisor when the
// subprocess exits.
func (u *StdioUpstream) failPending() {
	u.pendMu.Lock()
	dead := u.pending
	u.pending = map[string]chan *Response{}
	u.pendMu.Unlock()
	for id, ch := range dead {
		// We can't reconstruct the original ID type from the string
		// key (we lost int-vs-string distinction). The bridge only
		// surfaces the original host id anyway — this synthetic
		// response is just to unblock the caller.
		_ = id
		resp := NewResponseError(nil, ErrCodeUpstreamUnavail,
			fmt.Sprintf("upstream %q unavailable", u.spec.Namespace), nil)
		safeSend(ch, resp)
	}
}

// Initialize sends `initialize` to the upstream and caches the
// negotiated state for reconnect.
func (u *StdioUpstream) Initialize(ctx context.Context, protocolVersion string, clientCaps map[string]interface{}, clientInfo ClientInfo) (*InitializeResult, error) {
	params := InitializeParams{
		ProtocolVersion: protocolVersion,
		Capabilities:    clientCaps,
		ClientInfo:      clientInfo,
	}
	rawParams, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("marshal initialize params: %w", err)
	}

	id := u.nextID.Add(1)
	req := &Request{
		JSONRPC: JSONRPCVersion,
		ID:      id,
		Method:  MethodInitialize,
		Params:  rawParams,
	}

	resp, err := u.send(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("initialize: upstream error: %s", resp.Error.Message)
	}

	var result InitializeResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, fmt.Errorf("initialize: decode result: %w", err)
	}

	// Send the `notifications/initialized` notification to complete
	// the handshake (per MCP lifecycle).
	if err := u.Notify(ctx, &Notification{
		JSONRPC: JSONRPCVersion,
		Method:  NotificationInitialized,
	}); err != nil {
		// Notification failure is logged but not fatal — some
		// upstreams accept tools/list without the notification.
		u.logger.Infof("upstream %q: notifications/initialized send failed: %v", u.spec.Namespace, err)
	}

	u.initMu.Lock()
	u.negotiatedProtoVer = result.ProtocolVersion
	u.cachedClientCaps = clientCaps
	u.cachedClientInfo = clientInfo
	u.initializeCompleted = true
	u.initMu.Unlock()

	u.mu.Lock()
	u.status = StatusOK
	u.mu.Unlock()

	return &result, nil
}

// Send dispatches a JSON-RPC request and waits for the matching
// response. Replaces the caller's req.ID with a gateway-internal id
// to avoid collisions with the host's id space.
func (u *StdioUpstream) Send(ctx context.Context, req *Request) (*Response, error) {
	id := u.nextID.Add(1)
	internal := *req
	internal.ID = id
	internal.JSONRPC = JSONRPCVersion
	resp, err := u.send(ctx, &internal)
	if err != nil {
		return nil, err
	}
	// Restore the caller-supplied id on the response.
	resp.ID = req.ID
	return resp, nil
}

// send is the unkeyed primitive used by Initialize and Send. It
// expects req.ID to be the upstream-facing id (already allocated).
func (u *StdioUpstream) send(ctx context.Context, req *Request) (*Response, error) {
	if u.Status() == StatusDegraded {
		return nil, fmt.Errorf("upstream %q is degraded", u.spec.Namespace)
	}

	respCh := make(chan *Response, 1)
	key := idKey(req.ID)
	u.pendMu.Lock()
	u.pending[key] = respCh
	u.pendMu.Unlock()

	// Defer cleanup so a context cancel mid-flight doesn't leak the
	// pending entry.
	defer func() {
		u.pendMu.Lock()
		delete(u.pending, key)
		u.pendMu.Unlock()
	}()

	if err := u.writeFrame(req); err != nil {
		return nil, fmt.Errorf("write request: %w", err)
	}

	select {
	case resp := <-respCh:
		if resp == nil {
			return nil, errors.New("upstream closed before response")
		}
		return resp, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-u.done:
		return nil, errors.New("upstream closed")
	}
}

// Notify sends a one-way notification.
func (u *StdioUpstream) Notify(ctx context.Context, n *Notification) error {
	if u.Status() == StatusDegraded {
		return fmt.Errorf("upstream %q is degraded", u.spec.Namespace)
	}
	n.JSONRPC = JSONRPCVersion
	if err := u.writeFrame(n); err != nil {
		return fmt.Errorf("write notification: %w", err)
	}
	// Honor ctx after the write — the write itself is small and
	// the OS pipe buffer absorbs it instantly in practice.
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

// writeFrame marshals v and writes it to stdin with a `\n`
// terminator. Holds writeMu so concurrent callers don't interleave.
func (u *StdioUpstream) writeFrame(v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	data = append(data, '\n')

	u.mu.RLock()
	w := u.stdin
	u.mu.RUnlock()
	if w == nil {
		return errors.New("upstream stdin closed")
	}

	u.writeMu.Lock()
	defer u.writeMu.Unlock()
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("write stdin: %w", err)
	}
	return nil
}

// Close terminates the upstream. Idempotent. After Close, Send /
// Notify return errors immediately.
//
// Concurrency: Close MUST NOT call cmd.Wait() — the supervisor
// goroutine already owns that call. We close stdin (so a well-behaved
// MCP server exits cleanly), then wait on procExited (closed by the
// supervisor when its Wait() returns). On timeout we Kill() the
// process so the supervisor's Wait() returns and unblocks us.
func (u *StdioUpstream) Close() error {
	var firstErr error
	u.closeOnce.Do(func() {
		close(u.done)

		u.mu.Lock()
		stdin := u.stdin
		cmd := u.cmd
		u.stdin = nil
		u.status = StatusStopped
		u.mu.Unlock()

		u.procExitedMu.Lock()
		exited := u.procExited
		u.procExitedMu.Unlock()

		// Closing stdin signals graceful shutdown for well-behaved
		// MCP servers. Best-effort.
		if stdin != nil {
			_ = stdin.Close()
		}

		// Wait briefly for the supervisor's Wait() to return (i.e.,
		// the OS reaped the process). On timeout, kill the process —
		// the supervisor's Wait() returns immediately after, closing
		// `exited`.
		if cmd != nil && cmd.Process != nil && exited != nil {
			select {
			case <-exited:
			case <-time.After(2 * time.Second):
				_ = cmd.Process.Kill()
				<-exited
			}
		}

		// Drain any remaining pending requests. The supervisor's
		// failPending also fires when the subprocess exits; calling
		// it again here is safe (the map is already empty).
		u.failPending()
	})
	return firstErr
}

// idKey converts a JSON-RPC id to a string key. Numeric ids
// (int / int64 / float64 produced by json.Unmarshal into interface{})
// canonicalise to the SAME key form so a request id of int64(1)
// matches a response id of float64(1) decoded from JSON. Non-numeric
// ids keep their type prefix to avoid string("1") colliding with
// numeric 1.
func idKey(id interface{}) string {
	switch v := id.(type) {
	case nil:
		return "n:"
	case string:
		return "s:" + v
	case int:
		return fmt.Sprintf("n:%d", v)
	case int64:
		return fmt.Sprintf("n:%d", v)
	case float64:
		// JSON-RPC ids that round-trip as floats are still integers
		// in MCP — the spec mandates Number or String. We format as
		// integer when v is whole, otherwise keep the float form.
		if v == float64(int64(v)) {
			return fmt.Sprintf("n:%d", int64(v))
		}
		return fmt.Sprintf("f:%g", v)
	default:
		return fmt.Sprintf("x:%v", v)
	}
}

// transportLogger is a tiny structured-ish logger used by the
// transport layer. Centralised here so the bridge can configure
// levels without each test caring. Writes plain text to its writer
// — never to stdout (which is reserved for JSON-RPC).
type transportLogger struct {
	w     io.Writer
	debug bool
	mu    sync.Mutex
}

func newTransportLogger(w io.Writer, level string) *transportLogger {
	return &transportLogger{w: w, debug: level == "debug"}
}

func (l *transportLogger) write(level, format string, args ...interface{}) {
	if l == nil || l.w == nil {
		return
	}
	if level == "debug" && !l.debug {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	ts := time.Now().UTC().Format(time.RFC3339)
	fmt.Fprintf(l.w, "%s %s mcpgw: %s\n", ts, level, fmt.Sprintf(format, args...))
}

func (l *transportLogger) Infof(format string, args ...interface{})  { l.write("info", format, args...) }
func (l *transportLogger) Debugf(format string, args ...interface{}) { l.write("debug", format, args...) }
