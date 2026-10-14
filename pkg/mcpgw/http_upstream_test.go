package mcpgw

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"
)

// mcpStub is a minimal Streamable HTTP MCP server: one endpoint, POST for
// messages, optional GET stream, DELETE to end a session. It records what
// it receives so tests can assert on headers and methods.
type mcpStub struct {
	srv *httptest.Server

	// sse makes every request reply an event stream; preEvents are sent
	// on it before the response.
	sse       bool
	preEvents []string

	// down makes every POST answer 503.
	down atomic.Bool

	// failInits answers that many initialize POSTs with HTTP 500;
	// slowInits makes that many wait 300ms first.
	failInits atomic.Int32
	slowInits atomic.Int32

	// slowNotes makes every notification wait 900ms before its 202.
	slowNotes atomic.Bool

	// onGet serves the GET stream; nil answers 405.
	onGet func(w http.ResponseWriter, r *http.Request)

	mu       sync.Mutex
	seq      int
	sessions map[string]bool
	posts    []stubPost
	deletes  []string
}

type stubPost struct {
	method string
	header http.Header
}

func newMCPStub(t *testing.T) *mcpStub {
	t.Helper()
	s := &mcpStub{sessions: map[string]bool{}}
	s.srv = httptest.NewServer(s)
	t.Cleanup(s.srv.Close)
	return s
}

func (s *mcpStub) url() string { return s.srv.URL + "/mcp" }

// expireSessions ends every session, as a server restart would.
func (s *mcpStub) expireSessions() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions = map[string]bool{}
}

func (s *mcpStub) methods() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.posts))
	for i, p := range s.posts {
		out[i] = p.method
	}
	return out
}

func (s *mcpStub) lastPost(method string) stubPost {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.posts) - 1; i >= 0; i-- {
		if s.posts[i].method == method {
			return s.posts[i]
		}
	}
	return stubPost{}
}

func (s *mcpStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if s.onGet == nil {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		s.onGet(w, r)
		return
	case http.MethodDelete:
		s.mu.Lock()
		s.deletes = append(s.deletes, r.Header.Get("Mcp-Session-Id"))
		s.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		return
	case http.MethodPost:
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if s.down.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if !strings.Contains(r.Header.Get("Accept"), "application/json") ||
		!strings.Contains(r.Header.Get("Accept"), "text/event-stream") ||
		r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "bad Accept or Content-Type", http.StatusBadRequest)
		return
	}
	var msg struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, "bad JSON", http.StatusBadRequest)
		return
	}

	if msg.Method == MethodInitialize {
		if s.slowInits.Add(-1) >= 0 {
			time.Sleep(300 * time.Millisecond)
		}
		if s.failInits.Add(-1) >= 0 {
			http.Error(w, "warming up", http.StatusInternalServerError)
			return
		}
	}

	s.mu.Lock()
	s.posts = append(s.posts, stubPost{method: msg.Method, header: r.Header.Clone()})
	sid := r.Header.Get("Mcp-Session-Id")
	var result string
	if msg.Method == MethodInitialize {
		s.seq++
		sid = fmt.Sprintf("sess-%d", s.seq)
		s.sessions[sid] = true
		w.Header().Set("Mcp-Session-Id", sid)
		result = `{"protocolVersion":"2025-06-18","capabilities":{"tools":{"listChanged":true}},"serverInfo":{"name":"stub","version":"0"}}`
	} else if !s.sessions[sid] {
		s.mu.Unlock()
		if sid == "" {
			http.Error(w, "missing Mcp-Session-Id", http.StatusBadRequest)
		} else {
			http.Error(w, "unknown session", http.StatusNotFound)
		}
		return
	}
	s.mu.Unlock()

	if msg.Method != MethodInitialize && r.Header.Get("MCP-Protocol-Version") != "2025-06-18" {
		http.Error(w, "bad MCP-Protocol-Version", http.StatusBadRequest)
		return
	}
	if len(msg.ID) == 0 { // notification
		if s.slowNotes.Load() {
			time.Sleep(900 * time.Millisecond)
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}
	switch msg.Method {
	case MethodInitialize:
	case MethodToolsList:
		result = `{"tools":[{"name":"echo","inputSchema":{"type":"object"}},{"name":"danger","inputSchema":{"type":"object"}}]}`
	case MethodToolsCall:
		result = fmt.Sprintf(`{"content":[{"type":"text","text":"called %s"}]}`, msg.Params.Name)
	default:
		result = `{}`
	}
	resp := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":%s}`, msg.ID, result)
	if !s.sse {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, resp)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	for _, ev := range s.preEvents {
		_, _ = fmt.Fprintf(w, "event: message\ndata: %s\n\n", ev)
	}
	_, _ = fmt.Fprintf(w, ": keep-alive\n\nid: 7\ndata: %s\n\n", resp)
}

// noteRecorder collects notification methods delivered via OnNotification.
type noteRecorder struct {
	mu   sync.Mutex
	seen []string
}

func (n *noteRecorder) record(method string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.seen = append(n.seen, method)
}

func (n *noteRecorder) waitFor(t *testing.T, method string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		n.mu.Lock()
		for _, m := range n.seen {
			if m == method {
				n.mu.Unlock()
				return
			}
		}
		n.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("notification %q never arrived", method)
}

func newTestHTTPUpstream(t *testing.T, rawURL string, opts HTTPUpstreamOptions) *HTTPUpstream {
	t.Helper()
	if opts.Backoff == nil {
		opts.Backoff = []time.Duration{10 * time.Millisecond}
	}
	up := NewHTTPUpstream(UpstreamSpec{Namespace: "docs", Transport: TransportHTTP, URL: rawURL}, opts)
	t.Cleanup(func() { _ = up.Close() })
	return up
}

func initUpstream(t *testing.T, up *HTTPUpstream) *InitializeResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	res, err := up.Initialize(ctx, "2025-11-25", nil, ClientInfo{Name: "test-host"})
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	return res
}

func sendToolsList(t *testing.T, up *HTTPUpstream) (*Response, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return up.Send(ctx, &Request{JSONRPC: JSONRPCVersion, ID: "host-7", Method: MethodToolsList, Params: json.RawMessage(`{}`)})
}

// A JSON reply: the session id from initialize and the negotiated version
// ride on every later request, and the host's id comes back.
func TestHTTPUpstream_JSONRepliesCarrySessionAndVersion(t *testing.T) {
	stub := newMCPStub(t)
	up := newTestHTTPUpstream(t, stub.url(), HTTPUpstreamOptions{})

	res := initUpstream(t, up)
	if res.ProtocolVersion != "2025-06-18" {
		t.Errorf("protocolVersion = %q", res.ProtocolVersion)
	}
	if up.Status() != StatusOK {
		t.Errorf("status = %q, want ok", up.Status())
	}
	resp, err := sendToolsList(t, up)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if resp.ID != "host-7" {
		t.Errorf("response id = %v, want the host's id back", resp.ID)
	}
	if !strings.Contains(string(resp.Result), `"echo"`) {
		t.Errorf("result = %s", resp.Result)
	}

	if got := stub.methods(); strings.Join(got, ",") != "initialize,notifications/initialized,tools/list" {
		t.Errorf("server saw %v", got)
	}
	init := stub.lastPost(MethodInitialize)
	if init.header.Get("Mcp-Session-Id") != "" || init.header.Get("MCP-Protocol-Version") != "" {
		t.Errorf("initialize must start a fresh session, got headers %v", init.header)
	}
	list := stub.lastPost(MethodToolsList)
	if got := list.header.Get("Mcp-Session-Id"); got != "sess-1" {
		t.Errorf("Mcp-Session-Id = %q, want sess-1", got)
	}
	if got := list.header.Get("MCP-Protocol-Version"); got != "2025-06-18" {
		t.Errorf("MCP-Protocol-Version = %q", got)
	}
}

// An SSE reply may carry notifications and server-initiated requests
// before the response: the response is still found, the notification is
// forwarded, and the server request is dropped.
func TestHTTPUpstream_SSEReplyWithNotificationBeforeResponse(t *testing.T) {
	stub := newMCPStub(t)
	stub.sse = true
	stub.preEvents = []string{
		`{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}`,
		`{"jsonrpc":"2.0","id":"srv-1","method":"roots/list"}`,
		`{"jsonrpc":"2.0","id":999,"result":{}}`,
	}
	notes := &noteRecorder{}
	up := newTestHTTPUpstream(t, stub.url(), HTTPUpstreamOptions{OnNotification: notes.record})

	initUpstream(t, up)
	resp, err := sendToolsList(t, up)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if resp.ID != "host-7" || !strings.Contains(string(resp.Result), `"danger"`) {
		t.Errorf("response = %+v", resp)
	}
	notes.waitFor(t, NotificationToolsListChanged)
}

// HTTP 404 to a request with a session id means the session expired: the
// upstream starts a new session from the cached initialize and retries
// the request once.
func TestHTTPUpstream_ExpiredSessionReinitializesAndRetries(t *testing.T) {
	stub := newMCPStub(t)
	up := newTestHTTPUpstream(t, stub.url(), HTTPUpstreamOptions{})
	initUpstream(t, up)

	stub.expireSessions()
	resp, err := sendToolsList(t, up)
	if err != nil {
		t.Fatalf("Send after expiry: %v", err)
	}
	if resp.Error != nil {
		t.Fatalf("response error: %+v", resp.Error)
	}
	got := strings.Join(stub.methods(), ",")
	want := "initialize,notifications/initialized,tools/list,initialize,notifications/initialized,tools/list"
	if got != want {
		t.Errorf("server saw\n %s\nwant\n %s", got, want)
	}
	if sid := stub.lastPost(MethodToolsList).header.Get("Mcp-Session-Id"); sid != "sess-2" {
		t.Errorf("retry used session %q, want the new sess-2", sid)
	}
	if up.Status() != StatusOK {
		t.Errorf("status = %q", up.Status())
	}
}

// Operator headers reach the server on every request, and neither their
// values nor the URL's query string show up in the logs.
func TestHTTPUpstream_SendsHeadersWithoutLoggingThem(t *testing.T) {
	stub := newMCPStub(t)
	headers, err := parseUpstreamHeaders(
		[]string{"docs:Authorization=Bearer ${TOKEN}", "docs:X-Team=platform"},
		[]UpstreamSpec{{Namespace: "docs", Transport: TransportHTTP}},
		func(name string) (string, bool) { return map[string]string{"TOKEN": "tok-123"}[name], name == "TOKEN" },
	)
	if err != nil {
		t.Fatalf("parseUpstreamHeaders: %v", err)
	}
	logs := &syncWriter{w: &bytes.Buffer{}}
	up := newTestHTTPUpstream(t, stub.url()+"?key=query-secret", HTTPUpstreamOptions{
		Headers: headers["docs"],
		Logger:  newTransportLogger(logs, "debug"),
	})
	initUpstream(t, up)
	if _, err := sendToolsList(t, up); err != nil {
		t.Fatalf("Send: %v", err)
	}
	for _, m := range []string{MethodInitialize, MethodToolsList} {
		h := stub.lastPost(m).header
		if h.Get("Authorization") != "Bearer tok-123" || h.Get("X-Team") != "platform" {
			t.Errorf("%s headers = %v", m, h)
		}
	}

	// Now make the server unreachable so errors get logged.
	stub.srv.Close()
	_, _ = sendToolsList(t, up)
	_ = up.Close()
	for _, secret := range []string{"tok-123", "query-secret"} {
		if strings.Contains(logs.String(), secret) {
			t.Errorf("logs contain %q:\n%s", secret, logs.String())
		}
	}
}

// A server that cannot be reached degrades the upstream; it comes back on
// its own once the server answers, and the host is told to re-pull tools.
func TestHTTPUpstream_UnreachableServerDegradesThenRecovers(t *testing.T) {
	stub := newMCPStub(t)
	stub.down.Store(true)
	notes := &noteRecorder{}
	up := newTestHTTPUpstream(t, stub.url(), HTTPUpstreamOptions{OnNotification: notes.record})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := up.Initialize(ctx, "2025-11-25", nil, ClientInfo{}); err == nil {
		t.Fatal("Initialize against a 503 server succeeded")
	}
	if up.Status() != StatusDegraded {
		t.Fatalf("status = %q, want degraded", up.Status())
	}
	if _, err := sendToolsList(t, up); err == nil {
		t.Fatal("Send on a degraded upstream succeeded")
	}

	stub.down.Store(false)
	notes.waitFor(t, NotificationToolsListChanged)
	if up.Status() != StatusOK {
		t.Fatalf("status after recovery = %q", up.Status())
	}
	if _, err := sendToolsList(t, up); err != nil {
		t.Fatalf("Send after recovery: %v", err)
	}
}

// A server that fails the first initialize in a way that does not look
// like an outage (a timeout while it cold-starts, an HTTP 500) still
// joins the session once it answers: the reconnect loop retries it.
func TestHTTPUpstream_FailedFirstInitializeRecovers(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*mcpStub)
	}{
		{"HTTP 500", func(s *mcpStub) { s.failInits.Store(1) }},
		{"timeout", func(s *mcpStub) { s.slowInits.Store(1) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := newMCPStub(t)
			tc.setup(stub)
			notes := &noteRecorder{}
			up := newTestHTTPUpstream(t, stub.url(), HTTPUpstreamOptions{OnNotification: notes.record})

			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			if _, err := up.Initialize(ctx, "2025-11-25", nil, ClientInfo{}); err == nil {
				t.Fatal("the first Initialize succeeded")
			}
			if up.Status() != StatusDegraded {
				t.Fatalf("status = %q, want degraded", up.Status())
			}
			notes.waitFor(t, NotificationToolsListChanged)
			if _, err := sendToolsList(t, up); err != nil {
				t.Fatalf("Send after recovery: %v", err)
			}
		})
	}
}

// A redirect is refused rather than followed: net/http would forward
// custom headers (tokens) to the redirect target.
func TestHTTPUpstream_DoesNotFollowRedirects(t *testing.T) {
	var hit atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit.Store(true) }))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	up := newTestHTTPUpstream(t, redirector.URL, HTTPUpstreamOptions{})
	_, err := up.Initialize(context.Background(), "2025-11-25", nil, ClientInfo{})
	if err == nil || !strings.Contains(err.Error(), "redirects") {
		t.Errorf("err = %v, want a redirect refusal", err)
	}
	if hit.Load() {
		t.Error("the redirect target was contacted")
	}
}

// Close ends the session with DELETE and the upstream stays closed.
func TestHTTPUpstream_CloseSendsDelete(t *testing.T) {
	stub := newMCPStub(t)
	up := newTestHTTPUpstream(t, stub.url(), HTTPUpstreamOptions{})
	initUpstream(t, up)

	_ = up.Close()
	_ = up.Close() // idempotent
	stub.mu.Lock()
	deletes := append([]string(nil), stub.deletes...)
	stub.mu.Unlock()
	if len(deletes) != 1 || deletes[0] != "sess-1" {
		t.Errorf("DELETEs = %v, want one for sess-1", deletes)
	}
	if up.Status() != StatusStopped {
		t.Errorf("status = %q", up.Status())
	}
	if _, err := sendToolsList(t, up); err == nil {
		t.Error("Send after Close succeeded")
	}
}

// The GET stream delivers notifications sent outside any request.
func TestHTTPUpstream_GetStreamForwardsNotifications(t *testing.T) {
	stub := newMCPStub(t)
	stub.onGet = func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Mcp-Session-Id") == "" || !strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}
	notes := &noteRecorder{}
	up := newTestHTTPUpstream(t, stub.url(), HTTPUpstreamOptions{OnNotification: notes.record})
	initUpstream(t, up)
	notes.waitFor(t, NotificationToolsListChanged)
}

// Through the bridge: tools/list aggregates the HTTP upstream with a stdio
// one, tools/call is gated before anything reaches the server, and an
// unreachable HTTP upstream answers ErrCodeUpstreamUnavail.
func TestBridge_HTTPUpstreamListsGatesAndFails(t *testing.T) {
	stub := newMCPStub(t)
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL + "/mcp"
	dead.Close()

	t.Setenv("MCPGW_TEST_BRIDGE_TOKEN", "bridge-token")
	cfg, err := ParseConfig([]string{
		"--upstream-http", "docs:" + stub.url(),
		"--upstream-header", "docs:Authorization=Bearer ${MCPGW_TEST_BRIDGE_TOKEN}",
		"--upstream-http", "gone:" + deadURL,
		"--policy-mode", "fast",
		"--upstream-timeout", "2s",
		"--reconnect-cap", "50ms",
	})
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	b := NewBridge(cfg, io.Discard, "test")
	b.SetUpstream(newFakeUpstream("fs"))
	b.PolicyCheck = func(_ context.Context, req *ToolsCallRequest) (Decision, error) {
		if req.ToolName == "danger" {
			return Decision{Allow: false, Rule: "deny:test", Reason: "no"}, nil
		}
		return Decision{Allow: true, Rule: "allow:test"}, nil
	}
	h := newBridgeHarness(t, b)

	h.send(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]interface{}{
		"protocolVersion": "2025-06-18", "capabilities": map[string]interface{}{}, "clientInfo": map[string]interface{}{"name": "host"},
	}})
	if resp := h.readResponse(); resp.Error != nil {
		t.Fatalf("initialize: %+v", resp.Error)
	}
	if got := stub.lastPost(MethodInitialize).header.Get("Authorization"); got != "Bearer bridge-token" {
		t.Errorf("Authorization at the server = %q", got)
	}

	h.send(map[string]interface{}{"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
	resp := h.readResponse()
	var list ToolsListResult
	if err := json.Unmarshal(resp.Result, &list); err != nil {
		t.Fatalf("tools/list result: %v (%s)", err, resp.Result)
	}
	names := map[string]bool{}
	for _, tool := range list.Tools {
		names[tool.Name] = true
	}
	if !names["docs:echo"] || !names["docs:danger"] {
		t.Errorf("tools/list = %v, want docs:echo and docs:danger", names)
	}

	h.send(map[string]interface{}{"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": map[string]interface{}{"name": "docs:danger"}})
	resp = h.readResponse()
	var denied ToolsCallResult
	if err := json.Unmarshal(resp.Result, &denied); err != nil || !denied.IsError {
		t.Errorf("denied call = %+v (%v)", resp, err)
	}
	if stub.lastPost(MethodToolsCall).method != "" {
		t.Error("a denied tools/call reached the HTTP server")
	}

	h.send(map[string]interface{}{"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": map[string]interface{}{"name": "docs:echo"}})
	resp = h.readResponse()
	if resp.Error != nil || !strings.Contains(string(resp.Result), "called echo") {
		t.Errorf("allowed call = %+v", resp)
	}

	h.send(map[string]interface{}{"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": map[string]interface{}{"name": "gone:echo"}})
	resp = h.readResponse()
	if resp.Error == nil || resp.Error.Code != ErrCodeUpstreamUnavail {
		t.Errorf("call to an unreachable upstream = %+v, want error %d", resp, ErrCodeUpstreamUnavail)
	}
}

// The SSE reader: field parsing, multi-line data, comments, other event
// types, CRLF line endings, and bounded events that do not kill the reader.
func TestSSEReader(t *testing.T) {
	big := strings.Repeat("x", 64)
	cases := []struct {
		name   string
		stream string
		want   []string // data of each event; "!" marks an oversized one
	}{
		{"one event", "data: {\"a\":1}\n\n", []string{`{"a":1}`}},
		{"no space after colon", "data:{}\n\n", []string{`{}`}},
		{"multi-line data joins with newline", "data: a\ndata: b\n\n", []string{"a\nb"}},
		{"comments and id lines are ignored", ": ping\nid: 4\ndata: x\n\n", []string{"x"}},
		{"named event types other than message are skipped", "event: other\ndata: x\n\nevent: message\ndata: y\n\n", []string{"y"}},
		{"CRLF line endings", "data: x\r\n\r\n", []string{"x"}},
		{"CR-only line endings", "data: a\rdata: b\r\rdata: c\r\r", []string{"a\nb", "c"}},
		{"mixed line endings", "data: a\r\ndata: b\n\r", []string{"a\nb"}},
		{"a leading BOM is dropped", "\ufeffdata: x\n\n", []string{"x"}},
		{"a BOM later in the stream is data", "data: x\n\n\ufeffdata: y\n\n", []string{"x"}},
		{"blank lines without data dispatch nothing", "\n\n\ndata: x\n\n", []string{"x"}},
		{"an event cut off by EOF is dropped", "data: x\n\ndata: partial\n", []string{"x"}},
		{"an oversized event is skipped and the next one read", "data: " + big + "\n\ndata: ok\n\n", []string{"!", "ok"}},
		{"oversized across lines", "data: " + big[:20] + "\ndata: " + big[:20] + "\n\ndata: ok\n\n", []string{"!", "ok"}},
	}
	for _, tc := range cases {
		for _, oneByte := range []bool{false, true} {
			name := tc.name
			var r io.Reader = strings.NewReader(tc.stream)
			if oneByte {
				// One byte per read: a CRLF split across reads is still
				// one line ending.
				name += " (one byte per read)"
				r = iotest.OneByteReader(r)
			}
			t.Run(name, func(t *testing.T) {
				testSSEStream(t, r, tc.want)
			})
		}
	}
}

func testSSEStream(t *testing.T, r io.Reader, want []string) {
	t.Helper()
	sr := newSSEReader(r, 32)
	var got []string
	for {
		ev, err := sr.next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("next: %v", err)
		}
		if ev.tooLarge {
			got = append(got, "!")
		} else {
			got = append(got, string(ev.data))
		}
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("events = %q, want %q", got, want)
	}
}

// syncWriter makes a bytes.Buffer safe for the logger's concurrent writers
// and the test's final read.
type syncWriter struct {
	mu sync.Mutex
	w  *bytes.Buffer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

func (s *syncWriter) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.String()
}

// A host frame without an id is forwarded only if it is a notification:
// an id-less tools/call must not reach the server ungated. Notifications
// are sent off the frame loop, so a slow server does not hold up the
// frames behind one.
func TestBridge_IDlessRequestDroppedAndNotificationsDoNotBlock(t *testing.T) {
	stub := newMCPStub(t)
	cfg, err := ParseConfig([]string{
		"--upstream-http", "docs:" + stub.url(),
		"--policy-mode", "fast",
		"--upstream-timeout", "2s",
	})
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	b := NewBridge(cfg, io.Discard, "test")
	var checks atomic.Int32
	b.PolicyCheck = func(context.Context, *ToolsCallRequest) (Decision, error) {
		checks.Add(1)
		return Decision{Allow: false, Rule: "deny:test", Reason: "no"}, nil
	}
	h := newBridgeHarness(t, b)
	h.send(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]interface{}{
		"protocolVersion": "2025-06-18", "capabilities": map[string]interface{}{}, "clientInfo": map[string]interface{}{"name": "host"},
	}})
	if resp := h.readResponse(); resp.Error != nil {
		t.Fatalf("initialize: %+v", resp.Error)
	}

	stub.slowNotes.Store(true)
	h.send(map[string]interface{}{"jsonrpc": "2.0", "method": "tools/call", "params": map[string]interface{}{"name": "danger"}})
	h.send(map[string]interface{}{"jsonrpc": "2.0", "method": "notifications/cancelled", "params": map[string]interface{}{"requestId": 9}})
	start := time.Now()
	h.send(map[string]interface{}{"jsonrpc": "2.0", "id": 2, "method": "ping"})
	if resp := h.readResponse(); resp.Error != nil {
		t.Fatalf("ping: %+v", resp.Error)
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Errorf("ping answered after %v: the notification blocked the frame loop", d)
	}

	deadline := time.Now().Add(3 * time.Second)
	for stub.lastPost(NotificationCancelled).method == "" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if stub.lastPost(NotificationCancelled).method == "" {
		t.Error("notifications/cancelled never reached the server")
	}
	if stub.lastPost(MethodToolsCall).method != "" {
		t.Error("an id-less tools/call reached the server")
	}
	if n := checks.Load(); n != 0 {
		t.Errorf("policy checks = %d, want 0 (the frame is dropped, not gated)", n)
	}
}
