package llmproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// newTestServer builds a Server pointed at the given upstream test
// servers. Returns the server and a func that starts it on a random
// loopback port and a teardown func.
func newTestServer(t *testing.T, openai, anthropic *httptest.Server, mutators ...func(*Config)) (*Server, string, func()) {
	t.Helper()

	openaiURL := DefaultUpstreamOpenAI
	if openai != nil {
		openaiURL = openai.URL
	}
	anthropicURL := DefaultUpstreamAnthropic
	if anthropic != nil {
		anthropicURL = anthropic.URL
	}

	cfg := &Config{
		Listen:            "127.0.0.1:0",
		UpstreamOpenAI:    openaiURL,
		UpstreamAnthropic: anthropicURL,
		GuardURL:          "http://127.0.0.1:8080",
		TenantID:          "test",
		FailMode:          "deny",
		LogLevel:          "info",
		MaxBufferBytes:    DefaultMaxBufferBytes,
	}
	for _, m := range mutators {
		m(cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	httpSrv := &http.Server{Handler: srv.routes(), ReadHeaderTimeout: 5 * time.Second}
	srv.startTime = time.Now()

	go func() { _ = httpSrv.Serve(ln) }()

	teardown := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(ctx)
	}

	return srv, "http://" + ln.Addr().String(), teardown
}

// ----- /healthz -----

func TestServer_Healthz(t *testing.T) {
	BuildVersion = "test-1.2.3"
	defer func() { BuildVersion = "dev" }()

	_, base, teardown := newTestServer(t, nil, nil)
	defer teardown()

	resp, err := http.Get(base + "/healthz")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("status = %v, want ok", body["status"])
	}
	if body["version"] != "test-1.2.3" {
		t.Errorf("version = %v, want test-1.2.3", body["version"])
	}
	if body["transport"] != "llm_api_proxy" {
		t.Errorf("transport = %v, want llm_api_proxy", body["transport"])
	}
}

// ----- streaming routes to the streaming pipeline -----

// Streaming requests route through pkg/llmproxy/streaming.go which
// pause/resume/rewrites tool_calls and forwards content deltas byte-
// identical to the client. Detailed streaming behaviour (byte-identity,
// deny path, overflow) lives in streaming_test.go; here we only verify
// the wire-up: the upstream is hit with stream:true and the proxy
// returns the upstream bytes.
func TestServer_StreamingRoutesThroughUpstream(t *testing.T) {
	upstreamCalled := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"},\"finish_reason\":null}]}\n\ndata: [DONE]\n\n"))
	}))
	defer upstream.Close()

	_, base, teardown := newTestServer(t, upstream, nil)
	defer teardown()

	body := `{"model":"gpt-4","messages":[{"role":"user","content":"hi"}],"stream":true}`
	req, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 (streaming wired)", resp.StatusCode)
	}
	if !upstreamCalled {
		t.Errorf("upstream should be called; A22 wired streaming")
	}
	data, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(data), "[DONE]") {
		t.Errorf("expected [DONE] terminator; got %q", string(data))
	}
}

func TestServer_StreamingDetectionViaAcceptHeader(t *testing.T) {
	// stream:false in the body but Accept: text/event-stream still
	// triggers streaming per docs/LLM_API_PROXY.md § 3.2.
	upstreamCalled := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	}))
	defer upstream.Close()

	_, base, teardown := newTestServer(t, upstream, nil)
	defer teardown()

	body := `{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}`
	req, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if !upstreamCalled {
		t.Errorf("upstream should be called when Accept indicates streaming")
	}
}

// ----- Non-streaming chat completion forwarding -----

func TestServer_NonStreamingChatCompletion_ForwardsCorrectly(t *testing.T) {
	upstreamPath := ""
	upstreamMethod := ""
	upstreamBody := ""
	upstreamAuth := ""

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamPath = r.URL.Path
		upstreamMethod = r.Method
		upstreamAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		upstreamBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Custom-Upstream", "yes")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"chatcmpl-x","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}]}`))
	}))
	defer upstream.Close()

	_, base, teardown := newTestServer(t, upstream, nil)
	defer teardown()

	body := `{"model":"gpt-4","messages":[{"role":"user","content":"ping"}]}`
	req, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer sk-user-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, mustReadAll(t, resp.Body))
	}
	if upstreamPath != "/v1/chat/completions" {
		t.Errorf("upstream path = %q, want /v1/chat/completions", upstreamPath)
	}
	if upstreamMethod != "POST" {
		t.Errorf("upstream method = %q, want POST", upstreamMethod)
	}
	if upstreamBody != body {
		t.Errorf("upstream body = %q, want %q (must be byte-identical)", upstreamBody, body)
	}
	if upstreamAuth != "Bearer sk-user-token" {
		t.Errorf("upstream Authorization = %q, want pass-through", upstreamAuth)
	}
	if resp.Header.Get("X-Custom-Upstream") != "yes" {
		t.Errorf("response missing X-Custom-Upstream header")
	}
}

func TestServer_AnthropicMessages_ForwardsCorrectly(t *testing.T) {
	upstreamPath := ""
	upstreamHeader := ""
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamPath = r.URL.Path
		upstreamHeader = r.Header.Get("X-Api-Key")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"msg_x","type":"message","role":"assistant","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn"}`))
	}))
	defer upstream.Close()

	_, base, teardown := newTestServer(t, nil, upstream)
	defer teardown()

	body := `{"model":"claude-3","messages":[{"role":"user","content":"ping"}]}`
	req, _ := http.NewRequest("POST", base+"/v1/messages", strings.NewReader(body))
	req.Header.Set("X-Api-Key", "ant-key-xyz")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if upstreamPath != "/v1/messages" {
		t.Errorf("upstream path = %q, want /v1/messages", upstreamPath)
	}
	if upstreamHeader != "ant-key-xyz" {
		t.Errorf("X-Api-Key not forwarded; got %q", upstreamHeader)
	}
}

// ----- Pass-through routes -----

func TestServer_PassThroughEmbeddings(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/embeddings" {
			t.Errorf("path = %q, want /v1/embeddings", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer upstream.Close()

	_, base, teardown := newTestServer(t, upstream, nil)
	defer teardown()

	resp, err := http.Post(base+"/v1/embeddings", "application/json", strings.NewReader(`{"input":"x","model":"text-embedding-3-small"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestServer_PassThroughModels(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			t.Errorf("path = %q, want /v1/models", r.URL.Path)
		}
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
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

// ----- Header passthrough / hop-by-hop stripping -----

func TestServer_HopByHopHeadersStripped(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Connection / Keep-Alive / etc. must not propagate.
		// http.Server may set its own Connection header on the
		// upstream side, so we only check that ours wasn't
		// forwarded — i.e., the value "should-be-stripped" doesn't
		// appear.
		if v := r.Header.Get("Keep-Alive"); v != "" {
			t.Errorf("Keep-Alive forwarded with value %q", v)
		}
		if v := r.Header.Get("Proxy-Authorization"); v != "" {
			t.Errorf("Proxy-Authorization forwarded with value %q", v)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	_, base, teardown := newTestServer(t, upstream, nil)
	defer teardown()

	req, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(`{"model":"gpt-4","messages":[]}`))
	req.Header.Set("Connection", "should-be-stripped")
	req.Header.Set("Keep-Alive", "should-be-stripped")
	req.Header.Set("Proxy-Authorization", "should-be-stripped")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
}

func TestServer_UserAgentRewritten(t *testing.T) {
	BuildVersion = "1.0.0-test"
	defer func() { BuildVersion = "dev" }()

	gotUA := ""
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	_, base, teardown := newTestServer(t, upstream, nil)
	defer teardown()

	req, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(`{"model":"gpt-4","messages":[]}`))
	req.Header.Set("User-Agent", "openai-python/1.2.3")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()

	if !strings.Contains(gotUA, "agentguard-llm-proxy/1.0.0-test") {
		t.Errorf("UA = %q, want contains agentguard-llm-proxy/1.0.0-test", gotUA)
	}
	if !strings.Contains(gotUA, "openai-python/1.2.3") {
		t.Errorf("UA = %q, want preserves original openai-python suffix", gotUA)
	}
}

// ----- Body too large -----

func TestServer_BodyTooLarge(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("upstream should NOT be called when body exceeds cap")
	}))
	defer upstream.Close()

	_, base, teardown := newTestServer(t, upstream, nil, func(c *Config) {
		c.MaxBufferBytes = 256 // tight cap for the test
	})
	defer teardown()

	// 512-byte body, more than 256.
	body := `{"model":"gpt-4","messages":[{"role":"user","content":"` + strings.Repeat("x", 512) + `"}]}`
	resp, err := http.Post(base+"/v1/chat/completions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", resp.StatusCode)
	}
}

// ----- Proxy auth -----

func TestServer_ProxyAPIKeyAuth(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Should never be called when auth fails.
		if r.Header.Get(ProxyAuthHeader) != "" {
			t.Errorf("ProxyAuthHeader leaked to upstream: %q", r.Header.Get(ProxyAuthHeader))
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer upstream.Close()

	_, base, teardown := newTestServer(t, upstream, nil, func(c *Config) {
		c.ProxyAPIKey = "shhh-secret"
	})
	defer teardown()

	body := `{"model":"gpt-4","messages":[]}`

	t.Run("no-auth-header-401", func(t *testing.T) {
		resp, err := http.Post(base+"/v1/chat/completions", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", resp.StatusCode)
		}
	})

	t.Run("wrong-key-401", func(t *testing.T) {
		req, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(ProxyAuthHeader, "wrong")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", resp.StatusCode)
		}
	})

	t.Run("correct-key-passes", func(t *testing.T) {
		req, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(ProxyAuthHeader, "shhh-secret")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			t.Errorf("status = %d, want 200; body=%s", resp.StatusCode, string(b))
		}
	})

	t.Run("bearer-prefix-tolerated", func(t *testing.T) {
		req, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(ProxyAuthHeader, "Bearer shhh-secret")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200 with Bearer prefix", resp.StatusCode)
		}
	})

	t.Run("healthz-bypasses-auth", func(t *testing.T) {
		// /healthz must remain reachable without proxy auth so
		// load balancers and supervisors can probe it.
		resp, err := http.Get(base + "/healthz")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("/healthz status = %d, want 200", resp.StatusCode)
		}
	})
}

// ----- Method-not-allowed (mux pattern fast-fail) -----

func TestServer_GET_OnPostOnlyRoute_404(t *testing.T) {
	// /v1/chat/completions is registered with method-prefix POST.
	// A GET should miss the pattern and return 405 (Go 1.22+ mux
	// returns 405 for known paths with wrong method).
	_, base, teardown := newTestServer(t, nil, nil)
	defer teardown()

	resp, err := http.Get(base + "/v1/chat/completions")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
}

// ----- mustReadAll helper -----

func mustReadAll(t *testing.T, r io.Reader) string {
	t.Helper()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(b)
}

// ----- NewServer URL parsing edge cases -----

func TestServer_NewServer_RejectsInvalidURLs(t *testing.T) {
	cfg := &Config{
		Listen:            "127.0.0.1:8081",
		UpstreamOpenAI:    "https://api.openai.com",
		UpstreamAnthropic: "https://api.anthropic.com",
		GuardURL:          "http://127.0.0.1:8080",
		TenantID:          "test",
		FailMode:          "deny",
		LogLevel:          "info",
		MaxBufferBytes:    DefaultMaxBufferBytes,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if s.openaiURL == nil || s.anthropicURL == nil {
		t.Errorf("URLs not stashed")
	}
	if _, err := NewServer(nil); err == nil {
		t.Errorf("nil config should error")
	}
}

// Ensure the server's URLs preserve the path prefix when set.
func TestServer_URLPathJoining(t *testing.T) {
	if got := joinPath("", "/v1/x"); got != "/v1/x" {
		t.Errorf("joinPath(\"\", \"/v1/x\") = %q", got)
	}
	if got := joinPath("/", "/v1/x"); got != "/v1/x" {
		t.Errorf("joinPath(\"/\", \"/v1/x\") = %q", got)
	}
	if got := joinPath("/api", "/v1/x"); got != "/api/v1/x" {
		t.Errorf("joinPath(\"/api\", \"/v1/x\") = %q", got)
	}
	if got := joinPath("/api/", "/v1/x"); got != "/api/v1/x" {
		t.Errorf("joinPath(\"/api/\", \"/v1/x\") = %q", got)
	}
	if got := joinPath("/api", "v1/x"); got != "/api/v1/x" {
		t.Errorf("joinPath(\"/api\", \"v1/x\") = %q", got)
	}
}

// Ensure the server URL with a path prefix routes correctly. Some
// OpenAI-compatible upstreams (Azure OpenAI, vLLM proxies) insert a
// path prefix.
func TestServer_UpstreamWithPathPrefix(t *testing.T) {
	gotPath := ""
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer upstream.Close()

	prefixedURL := upstream.URL + "/openai-prefix"

	cfg := &Config{
		Listen:            "127.0.0.1:0",
		UpstreamOpenAI:    prefixedURL,
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

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	httpSrv := &http.Server{Handler: srv.routes()}
	go func() { _ = httpSrv.Serve(ln) }()
	defer func() { _ = httpSrv.Shutdown(context.Background()) }()

	resp, err := http.Post("http://"+ln.Addr().String()+"/v1/chat/completions", "application/json",
		bytes.NewReader([]byte(`{"model":"gpt-4","messages":[]}`)))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()

	if !strings.HasSuffix(gotPath, "/openai-prefix/v1/chat/completions") {
		t.Errorf("upstream path = %q, want suffix /openai-prefix/v1/chat/completions", gotPath)
	}
}

// Sanity-check that the test server's URL parsing is compatible with
// our Validate() rules.
func TestServer_TestServerURLValidates(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	if err := validateBaseURL("--upstream-openai", upstream.URL); err != nil {
		t.Errorf("validateBaseURL: %v", err)
	}
	// And the parsed URL should have a host and scheme.
	u, _ := url.Parse(upstream.URL)
	if u.Host == "" || u.Scheme == "" {
		t.Errorf("test upstream URL missing host/scheme: %v", u)
	}
}
