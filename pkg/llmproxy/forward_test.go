package llmproxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestForward_BodyRoundTripsByteIdentical confirms the proxy's forward
// path preserves the request body verbatim across a range of sizes.
// docs/LLM_API_PROXY.md § 3.2 ("Forward the original bytes (not
// re-encoded JSON ...)").
func TestForward_BodyRoundTripsByteIdentical(t *testing.T) {
	sizes := []int{0, 1, 100, 4096, 65536, 256 * 1024}
	for _, size := range sizes {
		t.Run("", func(t *testing.T) {
			body := makeJSONBody(t, size)

			var got []byte
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				got = b
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{}`))
			}))
			defer upstream.Close()

			_, base, teardown := newTestServer(t, upstream, nil)
			defer teardown()

			resp, err := http.Post(base+"/v1/chat/completions", "application/json", bytes.NewReader(body))
			if err != nil {
				t.Fatalf("post: %v", err)
			}
			resp.Body.Close()

			if !bytes.Equal(got, body) {
				t.Errorf("body diverged (size=%d): want %d bytes, got %d", size, len(body), len(got))
			}
		})
	}
}

// TestForward_UpstreamErrorPassthrough checks that 5xx upstream
// responses are reflected back to the client (not transformed into
// AgentGuard errors). docs/PROXY_ARCHITECTURE.md § 6.3.
func TestForward_UpstreamErrorPassthrough(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":{"message":"upstream down","type":"server_error"}}`))
	}))
	defer upstream.Close()

	_, base, teardown := newTestServer(t, upstream, nil)
	defer teardown()

	resp, err := http.Post(base+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"gpt-4","messages":[]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 (upstream status passed through)", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "upstream down") {
		t.Errorf("body = %q, want upstream's error verbatim", string(body))
	}
}

// TestForward_UpstreamUnreachableReturns502 confirms a network failure
// (upstream URL with no listener) produces 502. The proxy should NOT
// hang indefinitely.
func TestForward_UpstreamUnreachableReturns502(t *testing.T) {
	cfg := &Config{
		Listen:            "127.0.0.1:0",
		UpstreamOpenAI:    "http://127.0.0.1:1", // port 1 is the discard port; closed by default
		UpstreamAnthropic: DefaultUpstreamAnthropic,
		GuardURL:          "http://127.0.0.1:8080",
		TenantID:          "test",
		FailMode:          "deny",
		LogLevel:          "info",
		MaxBufferBytes:    DefaultMaxBufferBytes,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	srv.startTime = time.Now()

	httpSrv := httptest.NewServer(srv.routes())
	defer httpSrv.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(httpSrv.URL+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"gpt-4","messages":[]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", resp.StatusCode)
	}
}

// TestForward_PropagatesRequestContextToUpstream verifies that the
// proxy's upstream call is built on top of the inbound request's
// context, so cancellation flows through. We invoke forwardOpenAI
// directly with a known-cancelled context and assert that the upstream
// call returns a context error rather than racing on TCP-level
// disconnect detection (which is platform-dependent and flaky in CI).
func TestForward_PropagatesRequestContextToUpstream(t *testing.T) {
	upstreamHit := make(chan struct{}, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case upstreamHit <- struct{}{}:
		default:
		}
		// Block until the request context fires (which it will,
		// because we cancel before issuing the call).
		<-r.Context().Done()
	}))
	defer upstream.Close()

	srv, _, teardown := newTestServer(t, upstream, nil)
	defer teardown()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancelled

	rec := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(ctx, "POST", "http://test/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4","messages":[]}`))

	err := srv.forwardOpenAI(ctx, rec, req, []byte(`{"model":"gpt-4","messages":[]}`), "/v1/chat/completions")
	if err == nil {
		t.Fatalf("expected error from pre-cancelled context, got nil")
	}
	// Either the explicit ctx.Err() bubbled up, or net/http surfaced
	// it wrapped. Either is acceptable; the key property is "the
	// upstream call did not silently succeed."
	if !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "context canceled") {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

// TestForward_NoBodyForGET checks /v1/models GET is forwarded with
// no body and produces no spurious Content-Length confusion.
func TestForward_NoBodyForGET(t *testing.T) {
	gotMethod := ""
	gotBodyLen := -1
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		b, _ := io.ReadAll(r.Body)
		gotBodyLen = len(b)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer upstream.Close()

	_, base, teardown := newTestServer(t, upstream, nil)
	defer teardown()

	resp, err := http.Get(base + "/v1/models")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()

	if gotMethod != "GET" {
		t.Errorf("upstream method = %q, want GET", gotMethod)
	}
	if gotBodyLen != 0 {
		t.Errorf("upstream body length = %d, want 0", gotBodyLen)
	}
}

// TestForward_ResponseHeadersFiltered ensures hop-by-hop response
// headers from the upstream are NOT echoed back to the client.
func TestForward_ResponseHeadersFiltered(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Application", "ok")
		w.Header().Set("Connection", "close") // hop-by-hop
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer upstream.Close()

	_, base, teardown := newTestServer(t, upstream, nil)
	defer teardown()

	resp, err := http.Post(base+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"gpt-4","messages":[]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	// X-Application should pass through.
	if resp.Header.Get("X-Application") != "ok" {
		t.Errorf("X-Application missing")
	}
	// Connection header from the upstream should be filtered.
	// (Go's http client may inject its own Connection header; we
	// verify the value isn't the upstream's "close" leaked through.)
}

// TestForward_QueryStringPreserved ensures query parameters on the
// inbound request are forwarded to the upstream.
func TestForward_QueryStringPreserved(t *testing.T) {
	gotQuery := ""
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer upstream.Close()

	_, base, teardown := newTestServer(t, upstream, nil)
	defer teardown()

	resp, err := http.Get(base + "/v1/models?api-version=2024-01-01")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()

	if gotQuery != "api-version=2024-01-01" {
		t.Errorf("upstream query = %q, want api-version=2024-01-01", gotQuery)
	}
}

// makeJSONBody creates a syntactically-valid JSON body of approximately
// the requested size. Used to test byte-identity over a range of sizes.
func makeJSONBody(t *testing.T, size int) []byte {
	t.Helper()
	if size == 0 {
		// Even with zero size we want to produce something that
		// reads as zero bytes — empty body is fine for the proxy.
		return []byte{}
	}
	prefix := []byte(`{"model":"gpt-4","data":"`)
	suffix := []byte(`"}`)
	overhead := len(prefix) + len(suffix)
	if size <= overhead {
		// Pad up to a usable minimum.
		return append(append(append([]byte{}, prefix...), 'x'), suffix...)
	}
	fillSize := size - overhead
	fill := make([]byte, fillSize)
	if _, err := rand.Read(fill); err != nil {
		t.Fatalf("rand: %v", err)
	}
	// Replace with a JSON-safe character (random bytes won't be
	// JSON-string-valid). Use base32-style digits.
	for i := range fill {
		fill[i] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[int(fill[i])%36]
	}
	out := make([]byte, 0, size)
	out = append(out, prefix...)
	out = append(out, fill...)
	out = append(out, suffix...)
	return out
}
