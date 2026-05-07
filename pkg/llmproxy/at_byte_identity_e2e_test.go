package llmproxy

// at_byte_identity_e2e_test.go is the AT-added full-server byte-
// identity invariant test. A22's TestStreamingAllowPath_ByteIdentity
// drives the streaming pipeline at the parser level; this file boots
// the full Server through the same routes the binary serves and
// confirms that on the ALLOW path the bytes a real HTTP client
// receives are byte-identical to the upstream's SSE payload, AND on
// the DENY path the upstream tool_call deltas never leak through.
//
// Byte-level normalization considerations (documented per the AT brief):
//   - Go's net/http server uses chunked transfer-encoding for streaming
//     responses. Chunk boundaries (the `<hex>\r\n<chunk>\r\n` framing)
//     are added by net/http and stripped by the standard client. Both
//     ends are using net/http so the chunk-boundary overhead cancels
//     out at the application layer; bytes.Equal(got, fixture) works
//     directly without any normalization.
//   - SSE event payloads (the actual `data: ...\n\n` blocks) survive
//     through the full pipe unchanged on the ALLOW path.

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestAT_E2E_ByteIdentity_ALLOW boots the full Server (mux), routes
// a streaming /v1/chat/completions through it to a captured-fixture
// upstream, and asserts the test client receives bytes byte-identical
// to the upstream payload. This is the highest-fidelity coupon for
// the byte-identity invariant on the ALLOW path.
func TestAT_E2E_ByteIdentity_ALLOW(t *testing.T) {
	for _, fx := range []string{
		"openai_streaming_text_only.txt",
		"openai_streaming_single_tool_call.txt",
		"openai_streaming_multi_tool_call.txt",
		"openai_streaming_mixed_text_and_tool.txt",
	} {
		t.Run(fx, func(t *testing.T) {
			fixture := readFixture(t, fx)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(fixture)
			}))
			defer upstream.Close()

			base, teardown := newStreamingTestServer(t, upstream)
			defer teardown()

			body := `{"model":"gpt-4","messages":[],"stream":true}`
			req, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("post: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", resp.StatusCode)
			}
			got, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if !bytes.Equal(got, fixture) {
				t.Errorf("byte-identity violated for %s: got %d bytes, fixture %d bytes",
					fx, len(got), len(fixture))
				if len(got) < 4096 && len(fixture) < 4096 {
					t.Errorf("got =%q\nwant=%q", string(got), string(fixture))
				}
			}
		})
	}
}

// TestAT_E2E_ByteIdentity_DENY_DoesNotLeakUpstreamToolCalls drives
// the same fixtures with a PolicyCheck that DENYs and asserts the
// upstream tool_call ids never leak into the client's bytes.
func TestAT_E2E_ByteIdentity_DENY_DoesNotLeakUpstreamToolCalls(t *testing.T) {
	cases := []struct {
		fx          string
		secretIDs   []string // ids that MUST NOT appear in client bytes
		fingerprint string   // a substring from the fixture body that MUST NOT leak
	}{
		{
			fx:          "openai_streaming_single_tool_call.txt",
			secretIDs:   []string{"call_abc123"},
			fingerprint: `"name":"bash"`,
		},
		{
			fx:          "openai_streaming_multi_tool_call.txt",
			secretIDs:   []string{"call_a", "call_b"},
			fingerprint: `"path":"/tmp/x"`,
		},
	}
	for _, c := range cases {
		t.Run(c.fx, func(t *testing.T) {
			fixture := readFixture(t, c.fx)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(fixture)
			}))
			defer upstream.Close()

			base, teardown := newStreamingTestServer(t, upstream, func(s *Server) {
				s.PolicyCheck = func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
					return Decision{Allow: false, Reason: "policy denies " + tc.ToolName, Rule: "deny:test"}, nil
				}
			})
			defer teardown()

			body := `{"model":"gpt-4","messages":[],"stream":true}`
			req, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(body))
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("post: %v", err)
			}
			defer resp.Body.Close()
			got, _ := io.ReadAll(resp.Body)

			// Sanity: fixture truly contains the secrets we're checking against.
			fixtureStr := string(fixture)
			for _, id := range c.secretIDs {
				if !strings.Contains(fixtureStr, id) {
					t.Fatalf("fixture %s does not contain expected id %q (test invariant broken)", c.fx, id)
				}
			}
			gotStr := string(got)
			for _, id := range c.secretIDs {
				if strings.Contains(gotStr, id) {
					t.Errorf("upstream tool_call id %q leaked into DENY-path client bytes", id)
				}
			}
			if strings.Contains(gotStr, c.fingerprint) {
				t.Errorf("upstream fingerprint %q leaked into DENY-path client bytes", c.fingerprint)
			}
			// Refusal terminator.
			if !strings.Contains(gotStr, "[DONE]") {
				t.Errorf("expected [DONE] in OpenAI refusal; got %q", gotStr)
			}
		})
	}
}

// TestAT_E2E_ByteIdentity_DENY_Anthropic_NoLeak — same as above for
// Anthropic. Ensures the buffered tool_use id never reaches the client
// when the gate denies.
func TestAT_E2E_ByteIdentity_DENY_Anthropic_NoLeak(t *testing.T) {
	fixture := readFixture(t, "anthropic_streaming_single_tool_use.txt")
	if !strings.Contains(string(fixture), "toolu_xyz") {
		t.Fatalf("fixture provenance changed: expected toolu_xyz in fixture")
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fixture)
	}))
	defer upstream.Close()

	base, teardown := newStreamingTestServer(t, upstream, func(s *Server) {
		s.PolicyCheck = func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
			return Decision{Allow: false, Reason: "shell denied", Rule: "deny:shell"}, nil
		}
	})
	defer teardown()

	body := `{"model":"claude-3","messages":[],"stream":true}`
	req, _ := http.NewRequest("POST", base+"/v1/messages", strings.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	gotStr := string(got)

	if strings.Contains(gotStr, "toolu_xyz") {
		t.Errorf("Anthropic tool_use id leaked into DENY path: %q", gotStr)
	}
	if strings.Contains(gotStr, `"name":"bash"`) {
		t.Errorf("Anthropic tool_use name leaked into DENY path: %q", gotStr)
	}
	if !strings.Contains(gotStr, "stop_reason") {
		t.Errorf("expected stop_reason rewrite in Anthropic refusal; got %q", gotStr)
	}
}

// TestAT_E2E_ByteIdentity_SSEPayloadEquality drills into the SSE-
// payload-level equality (vs gross byte-equality) so the test is
// resilient to any future intermediary that re-chunks or normalizes
// chunk boundaries (which Go's net/http does NOT today, but a future
// revproxy in front would). Asserts that the sequence of `data: ...`
// lines the client sees equals the upstream's sequence on ALLOW.
func TestAT_E2E_ByteIdentity_SSEPayloadEquality(t *testing.T) {
	fixture := readFixture(t, "openai_streaming_single_tool_call.txt")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fixture)
	}))
	defer upstream.Close()

	base, teardown := newStreamingTestServer(t, upstream)
	defer teardown()

	body := `{"model":"gpt-4","messages":[],"stream":true}`
	req, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)

	gotData := extractDataLines(got)
	wantData := extractDataLines(fixture)
	if len(gotData) != len(wantData) {
		t.Fatalf("data-line count mismatch: got=%d want=%d", len(gotData), len(wantData))
	}
	for i := range gotData {
		if gotData[i] != wantData[i] {
			t.Errorf("data line %d mismatch:\n got=%q\nwant=%q", i, gotData[i], wantData[i])
		}
	}
}

func extractDataLines(b []byte) []string {
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "data: ") || strings.HasPrefix(line, "data:") {
			out = append(out, line)
		}
	}
	return out
}
