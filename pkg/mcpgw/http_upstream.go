package mcpgw

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

// HTTPUpstream is the Upstream for a remote MCP server reached over the
// MCP Streamable HTTP transport (protocol revision 2025-06-18,
// basic/transports): every JSON-RPC message is its own POST to one MCP
// endpoint, and the reply is either a single JSON object or an SSE
// stream that carries the response, possibly after notifications.
//
// Compared with StdioUpstream there is no process to supervise. The
// equivalent of "the subprocess exited" is "the server cannot be
// reached": a connection failure or a 502/503/504 marks the upstream
// degraded and a reconnect loop walks the same backoff schedule
// (--reconnect-cap), replaying the cached initialize until the server
// answers again.
//
// Header values (--upstream-header) may hold bearer tokens. They are
// never logged, and neither is the URL: net/http errors embed it, so
// transport errors are unwrapped before they reach a log line.
type HTTPUpstream struct {
	spec           UpstreamSpec
	headers        http.Header
	client         *http.Client
	logger         *transportLogger
	backoff        []time.Duration
	onNotification func(method string)

	// life is cancelled by Close. It aborts in-flight requests, the GET
	// listener and the reconnect loop.
	life       context.Context
	lifeCancel context.CancelFunc
	closeOnce  sync.Once

	nextID atomic.Int64

	// mu guards the fields below it.
	mu           sync.Mutex
	status       string
	sessionID    string // Mcp-Session-Id from the initialize response
	protoVer     string // negotiated version, sent as MCP-Protocol-Version
	reconnecting bool
	listenCancel context.CancelFunc

	// handshakeMu serialises initialize handshakes (from the bridge, the
	// reconnect loop and session renewal) and guards the cached
	// initialize parameters replayed by the latter two.
	handshakeMu sync.Mutex
	initCached  bool
	initVer     string
	initCaps    map[string]interface{}
	initInfo    ClientInfo
}

// HTTPUpstreamOptions configures an HTTPUpstream. The zero value gives
// the production defaults.
type HTTPUpstreamOptions struct {
	// Headers are sent on every request (--upstream-header), already
	// expanded.
	Headers http.Header

	// Backoff is the wait schedule between reconnect attempts.
	Backoff []time.Duration

	Logger *transportLogger

	// OnNotification receives the method of every notification the
	// server sends, on its own goroutine (see StdioUpstreamOptions).
	OnNotification func(method string)

	// Client overrides the HTTP client (tests). It should not follow
	// redirects; see newMCPHTTPClient.
	Client *http.Client
}

// NewHTTPUpstream constructs an HTTPUpstream for spec.URL. Nothing is
// sent until Initialize.
func NewHTTPUpstream(spec UpstreamSpec, opts HTTPUpstreamOptions) *HTTPUpstream {
	backoff := opts.Backoff
	if len(backoff) == 0 {
		backoff = DefaultBackoffSchedule
	}
	logger := opts.Logger
	if logger == nil {
		logger = newTransportLogger(io.Discard, "info")
	}
	client := opts.Client
	if client == nil {
		client = newMCPHTTPClient()
	}
	life, cancel := context.WithCancel(context.Background())
	return &HTTPUpstream{
		spec:           spec,
		headers:        opts.Headers.Clone(),
		client:         client,
		logger:         logger,
		backoff:        backoff,
		onNotification: opts.OnNotification,
		life:           life,
		lifeCancel:     cancel,
		status:         StatusStarting,
	}
}

// newMCPHTTPClient returns a client with no overall timeout (the GET
// stream is long-lived; requests are bounded by their contexts) that
// does not follow redirects: net/http forwards custom headers such as
// X-API-Key to a redirect target on another host, which would hand an
// --upstream-header token to whoever the server points at.
func newMCPHTTPClient() *http.Client {
	return &http.Client{
		Transport: http.DefaultTransport.(*http.Transport).Clone(),
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Namespace returns the upstream's namespace label.
func (u *HTTPUpstream) Namespace() string { return u.spec.Namespace }

// Status returns the current status string.
func (u *HTTPUpstream) Status() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.status
}

// sessionState is the per-session header state, snapshotted per request
// so a concurrent re-initialize cannot change it mid-request.
type sessionState struct {
	id    string
	proto string
}

func (u *HTTPUpstream) session() sessionState {
	u.mu.Lock()
	defer u.mu.Unlock()
	return sessionState{id: u.sessionID, proto: u.protoVer}
}

// Initialize starts a new session: POST initialize without a session
// id, keep the Mcp-Session-Id the server returns, then send
// notifications/initialized. The parameters are cached so a session
// that expires (HTTP 404) or a server that comes back after an outage
// can be re-initialized without the bridge.
func (u *HTTPUpstream) Initialize(ctx context.Context, protocolVersion string, clientCaps map[string]interface{}, clientInfo ClientInfo) (*InitializeResult, error) {
	if clientCaps == nil {
		clientCaps = map[string]interface{}{}
	}
	u.handshakeMu.Lock()
	defer u.handshakeMu.Unlock()
	u.initVer, u.initCaps, u.initInfo, u.initCached = protocolVersion, clientCaps, clientInfo, true
	result, err := u.handshakeLocked(ctx)
	if err != nil && isUnavailable(err) {
		// Cached above, so the reconnect loop can finish the handshake
		// once the server is up: a server that is down when the host
		// connects still joins the session later.
		u.degrade(err)
	}
	return result, err
}

// handshakeLocked runs one initialize exchange with the cached
// parameters. Caller holds handshakeMu.
func (u *HTTPUpstream) handshakeLocked(ctx context.Context) (*InitializeResult, error) {
	rawParams, err := json.Marshal(InitializeParams{
		ProtocolVersion: u.initVer,
		Capabilities:    u.initCaps,
		ClientInfo:      u.initInfo,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal initialize params: %w", err)
	}
	id := u.nextID.Add(1)
	req := &Request{JSONRPC: JSONRPCVersion, ID: id, Method: MethodInitialize, Params: rawParams}

	// A new session carries neither a session id nor a protocol-version
	// header: both come from this exchange.
	resp, hdr, err := u.roundTrip(ctx, req, id, sessionState{})
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
	sid := hdr.Get("Mcp-Session-Id")
	if !validSessionID(sid) {
		return nil, errors.New("initialize: upstream sent an Mcp-Session-Id with characters outside visible ASCII")
	}
	proto := result.ProtocolVersion
	if proto == "" {
		proto = u.initVer
	}
	sess := sessionState{id: sid, proto: proto}

	// Not through exchange: a 404 here must not trigger session renewal,
	// which would re-enter handshakeMu.
	if _, _, err := u.roundTrip(ctx, &Notification{JSONRPC: JSONRPCVersion, Method: NotificationInitialized}, nil, sess); err != nil {
		u.logger.Infof("upstream %q: notifications/initialized send failed: %v", u.spec.Namespace, err)
	}

	u.mu.Lock()
	if u.status == StatusStopped {
		u.mu.Unlock()
		return nil, errUpstreamClosed
	}
	u.sessionID, u.protoVer = sess.id, sess.proto
	u.status = StatusOK
	u.startListenerLocked(sess)
	u.mu.Unlock()
	return &result, nil
}

// validSessionID reports whether id uses only visible ASCII (0x21-0x7E),
// as the transport spec requires. Anything else could not be sent back
// in a header safely.
func validSessionID(id string) bool {
	for i := 0; i < len(id); i++ {
		if id[i] < 0x21 || id[i] > 0x7E {
			return false
		}
	}
	return true
}

// Send POSTs a request and returns its response. The caller's id is
// replaced with a gateway-internal one and restored on the response.
func (u *HTTPUpstream) Send(ctx context.Context, req *Request) (*Response, error) {
	id := u.nextID.Add(1)
	internal := *req
	internal.ID = id
	internal.JSONRPC = JSONRPCVersion
	resp, err := u.exchange(ctx, &internal, id)
	if err != nil {
		return nil, err
	}
	resp.ID = req.ID
	return resp, nil
}

// Notify POSTs a notification; the server answers 202 Accepted.
func (u *HTTPUpstream) Notify(ctx context.Context, n *Notification) error {
	n.JSONRPC = JSONRPCVersion
	_, err := u.exchange(ctx, n, nil)
	return err
}

// exchange sends one message on the current session. When the server
// answers 404 to a request carrying a session id, the session has
// expired: start a new one from the cached initialize and retry once.
// A 404 means the server never processed the message, so the retry
// cannot run a tool call twice.
func (u *HTTPUpstream) exchange(ctx context.Context, msg interface{}, wantID RequestID) (*Response, error) {
	switch u.Status() {
	case StatusStopped:
		return nil, errUpstreamClosed
	case StatusDegraded:
		return nil, fmt.Errorf("upstream %q is degraded", u.spec.Namespace)
	}
	sess := u.session()
	resp, _, err := u.roundTrip(ctx, msg, wantID, sess)
	if errors.Is(err, errSessionExpired) {
		u.logger.Infof("upstream %q: session expired; starting a new one", u.spec.Namespace)
		if rerr := u.renewSession(ctx, sess.id); rerr != nil {
			return nil, fmt.Errorf("session expired and a new one could not be started: %w", rerr)
		}
		resp, _, err = u.roundTrip(ctx, msg, wantID, u.session())
	}
	if err != nil && isUnavailable(err) {
		u.degrade(err)
	}
	return resp, err
}

// renewSession re-initializes after the server expired session stale.
// Concurrent callers that saw the same 404 wait on handshakeMu and then
// find the session already replaced. Any failure degrades the upstream:
// without a session it is unusable, and the reconnect loop retries on
// the backoff schedule.
func (u *HTTPUpstream) renewSession(ctx context.Context, stale string) error {
	u.handshakeMu.Lock()
	defer u.handshakeMu.Unlock()
	if u.session().id != stale {
		return nil
	}
	if !u.initCached {
		return errors.New("no initialize to replay")
	}
	_, err := u.handshakeLocked(ctx)
	if err != nil && !errors.Is(err, errUpstreamClosed) {
		u.degrade(err)
	}
	return err
}

var (
	errUpstreamClosed = errors.New("upstream closed")

	// errSessionExpired is HTTP 404 to a request that carried a session
	// id: the server ended the session.
	errSessionExpired = errors.New("upstream session expired")

	// errNoListenStream is HTTP 405 (or a non-SSE reply) to the GET: the
	// server does not offer a stream for server-initiated messages.
	errNoListenStream = errors.New("upstream offers no GET event stream")
)

// unavailableError marks a failure that means the server cannot be
// reached at all (as opposed to a failed request), which degrades the
// upstream and starts the reconnect loop.
type unavailableError struct{ err error }

func (e *unavailableError) Error() string { return "unreachable: " + e.err.Error() }
func (e *unavailableError) Unwrap() error { return e.err }

func isUnavailable(err error) bool {
	var ue *unavailableError
	return errors.As(err, &ue)
}

// roundTrip POSTs msg with the given session state. For a request
// (wantID non-nil) it returns the matching response; for a notification
// it returns nil once the server accepts it. The response headers are
// returned so initialize can read Mcp-Session-Id.
func (u *HTTPUpstream) roundTrip(ctx context.Context, msg interface{}, wantID RequestID, sess sessionState) (*Response, http.Header, error) {
	body, err := json.Marshal(msg)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal: %w", err)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(u.life, cancel) // Close aborts in-flight requests
	defer stop()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, u.spec.URL, bytes.NewReader(body))
	if err != nil {
		return nil, nil, fmt.Errorf("build request: %w", stripURL(err))
	}
	u.setHeaders(httpReq.Header, sess)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json, text/event-stream")

	resp, err := u.client.Do(httpReq)
	if err != nil {
		return nil, nil, u.requestError(ctx, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound && sess.id != "" {
		return nil, resp.Header, errSessionExpired
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, resp.Header, statusError(resp)
	}
	if wantID == nil {
		return nil, resp.Header, nil
	}
	if resp.StatusCode == http.StatusAccepted {
		return nil, resp.Header, errors.New("upstream accepted the request but sent no response")
	}

	mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	var out *Response
	switch mediaType {
	case "application/json":
		out, err = readJSONResponse(resp.Body, wantID)
	case "text/event-stream":
		out, err = u.readSSEResponse(resp.Body, wantID)
	default:
		err = fmt.Errorf("upstream replied with Content-Type %q; want application/json or text/event-stream", mediaType)
	}
	if err != nil && u.life.Err() != nil {
		err = errUpstreamClosed
	}
	return out, resp.Header, err
}

// setHeaders writes the operator's headers, then the session headers,
// which the config parser stops an operator header from overriding.
func (u *HTTPUpstream) setHeaders(h http.Header, sess sessionState) {
	h.Set("User-Agent", GatewayServerName+"/"+GatewayBuildVersion)
	for k, vs := range u.headers {
		h[k] = append([]string(nil), vs...)
	}
	if sess.id != "" {
		h.Set("Mcp-Session-Id", sess.id)
	}
	if sess.proto != "" {
		h.Set("MCP-Protocol-Version", sess.proto)
	}
}

// requestError classifies a client.Do failure. The caller's own
// deadline or cancellation is returned as is (a slow server is not a
// dead one, matching stdio); anything else means the server could not
// be reached.
func (u *HTTPUpstream) requestError(ctx context.Context, err error) error {
	switch {
	case u.life.Err() != nil:
		return errUpstreamClosed
	case ctx.Err() != nil:
		return ctx.Err()
	default:
		return &unavailableError{err: stripURL(err)}
	}
}

// stripURL drops the URL net/http puts in its errors: it may carry a
// token in its query string, and these errors are logged.
func stripURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s: %w", ue.Op, ue.Err)
	}
	return err
}

// statusError describes a non-2xx reply. 502/503/504 mean the server
// (or the proxy in front of it) is unavailable; other codes fail only
// this message. A JSON-RPC error message in the body is included, since
// servers use it to say what was wrong (e.g. an unsupported
// MCP-Protocol-Version).
func statusError(resp *http.Response) error {
	msg := fmt.Sprintf("HTTP %d", resp.StatusCode)
	switch resp.StatusCode {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return fmt.Errorf("%s: the server redirects; point --upstream-http at the final MCP endpoint", msg)
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return &unavailableError{err: errors.New(msg)}
	}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var probe struct {
		Error *Error `json:"error"`
	}
	if json.Unmarshal(data, &probe) == nil && probe.Error != nil && probe.Error.Message != "" {
		msg += ": " + probe.Error.Message
	}
	return errors.New(msg)
}

// readJSONResponse decodes a single-object reply, capped like a stdio
// frame.
func readJSONResponse(body io.Reader, wantID RequestID) (*Response, error) {
	data, err := io.ReadAll(io.LimitReader(body, MaxStdoutLineBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if len(data) > MaxStdoutLineBytes {
		return nil, fmt.Errorf("response exceeds %d bytes", MaxStdoutLineBytes)
	}
	var resp Response
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	// A JSON-RPC error with a null id is the server rejecting a request
	// it could not parse; surface it rather than calling it a mismatch.
	if resp.ID == nil && resp.Error != nil {
		return &resp, nil
	}
	if resp.ID == nil || idKey(resp.ID) != idKey(wantID) {
		return nil, errors.New("response id does not match the request")
	}
	return &resp, nil
}

// readSSEResponse reads a POST's event stream until the response to
// wantID arrives. Notifications and server-initiated requests sent
// before it are routed like those on the GET stream.
func (u *HTTPUpstream) readSSEResponse(body io.Reader, wantID RequestID) (*Response, error) {
	sr := newSSEReader(body, MaxStdoutLineBytes)
	for {
		ev, err := sr.next()
		if errors.Is(err, io.EOF) {
			return nil, errors.New("upstream closed the event stream before sending the response")
		}
		if err != nil {
			return nil, fmt.Errorf("read event stream: %w", err)
		}
		if ev.tooLarge {
			u.logger.Infof("upstream %q: dropping oversized event (cap %d bytes)", u.spec.Namespace, MaxStdoutLineBytes)
			continue
		}
		if resp := u.route(ev.data, wantID); resp != nil {
			return resp, nil
		}
	}
}

// route handles one JSON-RPC message from the server. It returns the
// message as a response if it answers wantID; otherwise notifications go
// to onNotification and everything else is dropped, exactly as
// StdioUpstream.readLoop does (server-initiated requests are not
// brokered; see docs/MCP_GATEWAY.md § 10).
func (u *HTTPUpstream) route(data []byte, wantID RequestID) *Response {
	var resp Response
	if err := json.Unmarshal(data, &resp); err == nil && resp.ID != nil {
		method := frameMethod(data)
		switch {
		case method == "" && wantID != nil && idKey(resp.ID) == idKey(wantID):
			return &resp
		case method != "":
			u.logger.Infof("upstream %q: unsupported server-initiated request %q (id %v) dropped — the gateway brokers tools only, not server->client requests", u.spec.Namespace, method, resp.ID)
		default:
			u.logger.Debugf("upstream %q: response with unknown id %v dropped", u.spec.Namespace, resp.ID)
		}
		return nil
	}
	var note Notification
	if err := json.Unmarshal(data, &note); err == nil && note.Method != "" {
		if u.onNotification != nil {
			go u.onNotification(note.Method)
			return nil
		}
		u.logger.Debugf("upstream %q: notification %q dropped (no sink)", u.spec.Namespace, note.Method)
		return nil
	}
	u.logger.Debugf("upstream %q: unsolicited message dropped", u.spec.Namespace)
	return nil
}

// startListenerLocked (re)starts the GET stream for sess, replacing the
// previous session's. Caller holds u.mu.
func (u *HTTPUpstream) startListenerLocked(sess sessionState) {
	if u.listenCancel != nil {
		u.listenCancel()
	}
	ctx, cancel := context.WithCancel(u.life)
	u.listenCancel = cancel
	go u.listen(ctx, sess)
}

// listen keeps the optional GET event stream open so the server can
// send notifications (tools/list_changed) outside any request. It stops
// for good when the server has no such stream (405) or the session
// expires (the next POST starts a new session and a new listener), and
// otherwise reconnects on the backoff schedule.
func (u *HTTPUpstream) listen(ctx context.Context, sess sessionState) {
	step := 0
	for {
		opened := time.Now()
		err := u.listenOnce(ctx, sess)
		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, errNoListenStream) || errors.Is(err, errSessionExpired) {
			u.logger.Debugf("upstream %q: GET stream: %v", u.spec.Namespace, err)
			return
		}
		u.logger.Debugf("upstream %q: GET stream ended: %v", u.spec.Namespace, err)
		if u.Status() != StatusOK {
			// The server is down; the handshake that brings it back
			// starts a new listener.
			return
		}
		// A stream that stayed up for a while was healthy: start the
		// schedule over rather than waiting the longest step.
		if time.Since(opened) > u.backoff[len(u.backoff)-1] {
			step = 0
		}
		wait := u.backoff[step]
		if step < len(u.backoff)-1 {
			step++
		}
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return
		}
	}
}

func (u *HTTPUpstream) listenOnce(ctx context.Context, sess sessionState) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.spec.URL, nil)
	if err != nil {
		return stripURL(err)
	}
	u.setHeaders(req.Header, sess)
	req.Header.Set("Accept", "text/event-stream")
	resp, err := u.client.Do(req)
	if err != nil {
		return stripURL(err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusMethodNotAllowed:
		return errNoListenStream
	case resp.StatusCode == http.StatusNotFound && sess.id != "":
		return errSessionExpired
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return statusError(resp)
	}
	if mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mt != "text/event-stream" {
		return errNoListenStream
	}
	sr := newSSEReader(resp.Body, MaxStdoutLineBytes)
	for {
		ev, err := sr.next()
		if err != nil {
			return err
		}
		if ev.tooLarge {
			u.logger.Infof("upstream %q: dropping oversized event (cap %d bytes)", u.spec.Namespace, MaxStdoutLineBytes)
			continue
		}
		u.route(ev.data, nil)
	}
}

// degrade marks the server unreachable and starts the reconnect loop if
// it is not already running.
func (u *HTTPUpstream) degrade(cause error) {
	u.mu.Lock()
	if u.status == StatusStopped {
		u.mu.Unlock()
		return
	}
	was := u.status
	u.status = StatusDegraded
	start := !u.reconnecting
	u.reconnecting = true
	u.mu.Unlock()
	if was != StatusDegraded {
		u.logger.Infof("upstream %q: %v; reconnecting", u.spec.Namespace, cause)
	}
	if start {
		go u.reconnect()
	}
}

// reconnect walks the backoff schedule, replaying the cached initialize
// until it succeeds. On success the host is told to re-pull tools/list:
// the namespace's tools were missing from any list built while the
// server was down.
func (u *HTTPUpstream) reconnect() {
	step := 0
	for {
		wait := u.backoff[step]
		if step < len(u.backoff)-1 {
			step++
		}
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
		case <-u.life.Done():
			timer.Stop()
			return
		}

		// The bridge may have re-initialized meanwhile. Checked under mu
		// together with clearing the flag, so a degrade racing this exit
		// either sees the flag still set (and this loop goes on) or
		// starts a new loop.
		u.mu.Lock()
		if u.status != StatusDegraded {
			u.reconnecting = false
			u.mu.Unlock()
			return
		}
		u.mu.Unlock()

		u.handshakeMu.Lock()
		if !u.initCached {
			u.handshakeMu.Unlock()
			u.mu.Lock()
			u.reconnecting = false
			u.mu.Unlock()
			return
		}
		ctx, cancel := context.WithTimeout(u.life, 30*time.Second)
		_, err := u.handshakeLocked(ctx)
		cancel()
		u.handshakeMu.Unlock()
		if err != nil {
			u.logger.Infof("upstream %q: reconnect failed: %v", u.spec.Namespace, err)
			continue
		}
		u.mu.Lock()
		if u.status != StatusOK { // degraded again already
			u.mu.Unlock()
			continue
		}
		u.reconnecting = false
		u.mu.Unlock()
		u.logger.Infof("upstream %q: reconnected", u.spec.Namespace)
		if u.onNotification != nil {
			go u.onNotification(NotificationToolsListChanged)
		}
		return
	}
}

// Close ends the session (DELETE with Mcp-Session-Id, as the transport
// spec asks of a client that is done) and stops all background work.
// Idempotent. A server that does not allow clients to end sessions
// answers 405, which is fine.
func (u *HTTPUpstream) Close() error {
	u.closeOnce.Do(func() {
		u.mu.Lock()
		sess := sessionState{id: u.sessionID, proto: u.protoVer}
		u.status = StatusStopped
		u.mu.Unlock()
		u.lifeCancel()
		if sess.id == "" {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u.spec.URL, nil)
		if err != nil {
			return
		}
		u.setHeaders(req.Header, sess)
		resp, err := u.client.Do(req)
		if err != nil {
			u.logger.Debugf("upstream %q: end session: %v", u.spec.Namespace, stripURL(err))
			return
		}
		_ = resp.Body.Close()
	})
	return nil
}

// sseEvent is one dispatched Server-Sent Event.
type sseEvent struct {
	data     []byte
	tooLarge bool // data exceeded the cap and was discarded
}

// sseReader parses a text/event-stream body. It is deliberately small:
// it handles data:, event: and comment lines and ignores id: and retry:
// (the gateway does not resume streams). Lines and whole events are
// capped at max bytes; an oversized event is reported once and skipped,
// and the reader stays usable, like readFrame on the stdio side.
type sseReader struct {
	r   *bufio.Reader
	max int
}

func newSSEReader(r io.Reader, max int) *sseReader {
	return &sseReader{r: bufio.NewReaderSize(r, 64*1024), max: max}
}

// next returns the next "message" event carrying data. Events of other
// types and events with no data are skipped, per the SSE dispatch rules.
// An event cut off by the end of the stream is discarded and io.EOF
// returned.
func (s *sseReader) next() (sseEvent, error) {
	var data []byte
	var haveData, over bool
	eventType := ""
	for {
		line, _, err := readFrame(s.r, s.max)
		if errors.Is(err, errFrameTooLong) {
			over = true
			continue
		}
		if err != nil {
			return sseEvent{}, err
		}
		if len(line) == 0 { // blank line: dispatch
			switch {
			case over:
				return sseEvent{tooLarge: true}, nil
			case haveData && (eventType == "" || eventType == "message"):
				return sseEvent{data: data}, nil
			}
			data, haveData, eventType = nil, false, ""
			continue
		}
		if line[0] == ':' { // comment / keep-alive
			continue
		}
		field, value := line, []byte(nil)
		if i := bytes.IndexByte(line, ':'); i >= 0 {
			field, value = line[:i], line[i+1:]
			if len(value) > 0 && value[0] == ' ' {
				value = value[1:]
			}
		}
		switch string(field) {
		case "data":
			if over {
				continue
			}
			if len(data)+len(value)+1 > s.max {
				over, data = true, nil
				continue
			}
			if haveData {
				data = append(data, '\n')
			}
			data = append(data, value...)
			haveData = true
		case "event":
			eventType = string(value)
		}
	}
}
