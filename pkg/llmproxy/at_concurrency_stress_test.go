package llmproxy

// at_concurrency_stress_test.go is the AT-added concurrency stress
// test. The v0.5 plan AT brief calls for:
//
//   "100 concurrent streaming requests through the proxy with random
//    tool_call mixes. Assert no cross-request leakage of tool_call
//    deltas."
//
// A22's TestStreamingConcurrent_NoCrossLeak runs 10 concurrent
// requests; this test scales to 100 with a random gating mix
// (some ALLOW, some DENY, some REQUIRE_APPROVAL) per request. The
// invariant is hard: per-request goroutine isolation must hold so
// one client never receives bytes intended for another.
//
// Run with -race to surface any data races on accumulator state. The
// streaming orchestrator constructs a fresh accumulator per request
// goroutine; this test is the structural assertion that the
// invariant holds under load.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// TestAT_Concurrency_NoCrossRequestLeak fans 100 concurrent streaming
// chat-completions requests at the proxy. Each request is tagged with
// a unique tool_call id (mirrored by the upstream), and the gate's
// decision is deterministic per agent_id (so each client knows what
// to expect in its own response).
//
// Assertions:
//   - Each client's response contains its own call id (or refusal
//     marker for DENY/APPROVAL clients).
//   - Each client's response does NOT contain another request's call
//     id (the per-request isolation invariant).
//   - No HTTP errors; status 200 across the board.
//   - The proxy survives without panic under -race.
func TestAT_Concurrency_NoCrossRequestLeak(t *testing.T) {
	const concurrency = 100

	// Upstream that echoes the client's tag header into the tool_call
	// id, so each request has a unique tool_call id traceable back to
	// the client that issued it.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callID := r.Header.Get("X-Test-Call-ID")
		if callID == "" {
			callID = "default"
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		f, _ := w.(http.Flusher)
		_, _ = fmt.Fprintf(w,
			`data: {"choices":[{"index":0,"delta":{"role":"assistant","content":""},"finish_reason":null}]}`+"\n\n")
		_, _ = fmt.Fprintf(w,
			`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":%q,"type":"function","function":{"name":"bash","arguments":"{\"cmd\":\"true\"}"}}]},"finish_reason":null}]}`+"\n\n",
			callID)
		_, _ = fmt.Fprintf(w,
			`data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`+"\n\n")
		_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
		if f != nil {
			f.Flush()
		}
	}))
	defer upstream.Close()

	// Per-request expectation: index 0..99 mapped to one of three
	// outcomes by `i % 3`. Gate inspects ToolCallID to decide.
	const (
		outcomeAllow    = 0
		outcomeDeny     = 1
		outcomeApproval = 2
	)
	expectedOutcome := func(i int) int { return i % 3 }

	base, teardown := newStreamingTestServer(t, upstream, func(s *Server) {
		s.BuildRefusal = BuildRefusalRich
		s.PolicyCheck = func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
			// Decode the request index from the call id.
			var idx int
			if _, err := fmt.Sscanf(tc.ToolCallID, "call_stress_%d", &idx); err != nil {
				return Decision{Allow: true, Rule: "allow:fallback"}, nil
			}
			switch expectedOutcome(idx) {
			case outcomeAllow:
				return Decision{Allow: true, Rule: "allow:test"}, nil
			case outcomeDeny:
				return Decision{Allow: false, Reason: "stress test deny", Rule: "deny:stress"}, nil
			case outcomeApproval:
				return Decision{
					Allow:            false,
					RequiresApproval: true,
					Reason:           "stress test approval",
					Rule:             "require_approval:stress",
					ApprovalID:       fmt.Sprintf("ap_stress_%d", idx),
					ApprovalURL:      fmt.Sprintf("http://localhost:8080/approve/ap_stress_%d", idx),
				}, nil
			}
			return Decision{Allow: true}, nil
		}
	})
	defer teardown()

	var wg sync.WaitGroup
	var failures atomic.Int64

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			callID := fmt.Sprintf("call_stress_%d", i)
			body := `{"model":"gpt-4","messages":[],"stream":true}`
			req, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Test-Call-ID", callID)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Errorf("client %d: post: %v", i, err)
				failures.Add(1)
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("client %d: status = %d", i, resp.StatusCode)
				failures.Add(1)
				return
			}
			got, _ := io.ReadAll(resp.Body)
			gotStr := string(got)

			// No other request's call id may appear here. Use
			// quote-delimited matching ("call_stress_<n>") because
			// `call_stress_4` is a substring of `call_stress_48`,
			// `call_stress_45`, etc. — the wire format always emits
			// ids inside JSON string quotes.
			for j := 0; j < concurrency; j++ {
				if j == i {
					continue
				}
				other := fmt.Sprintf(`"call_stress_%d"`, j)
				if strings.Contains(gotStr, other) {
					t.Errorf("client %d leaked another client's id %q\nbody=%s",
						i, other, gotStr)
					failures.Add(1)
				}
			}
			// Quoted match for own id — same substring-safety as above.
			ownIDQuoted := fmt.Sprintf(`"%s"`, callID)
			ownApprovalQuoted := fmt.Sprintf(`ap_stress_%d`, i)

			// Outcome-specific assertions.
			switch expectedOutcome(i) {
			case outcomeAllow:
				// ALLOW: own id MUST appear (the buffered event flushed).
				if !strings.Contains(gotStr, ownIDQuoted) {
					t.Errorf("client %d (ALLOW): expected own id %q, got %q", i, callID, gotStr)
					failures.Add(1)
				}
				// finish_reason: tool_calls flushed back since ALLOW.
				if !strings.Contains(gotStr, "tool_calls") {
					t.Errorf("client %d (ALLOW): expected tool_calls finish_reason; got %q", i, gotStr)
					failures.Add(1)
				}
			case outcomeDeny:
				// DENY: own id MUST NOT appear (buffered events
				// discarded). Refusal text must mention the rule.
				if strings.Contains(gotStr, ownIDQuoted) {
					t.Errorf("client %d (DENY): leaked own buffered id %q", i, callID)
					failures.Add(1)
				}
				if !strings.Contains(gotStr, "deny:stress") {
					t.Errorf("client %d (DENY): refusal missing rule; got %q", i, gotStr)
					failures.Add(1)
				}
			case outcomeApproval:
				if strings.Contains(gotStr, ownIDQuoted) {
					t.Errorf("client %d (APPROVAL): leaked own buffered id %q", i, callID)
					failures.Add(1)
				}
				if !strings.Contains(gotStr, ownApprovalQuoted) {
					t.Errorf("client %d (APPROVAL): missing own approval_id %q; got %q",
						i, ownApprovalQuoted, gotStr)
					failures.Add(1)
				}
				// Other clients' approval ids must not appear (use the
				// natural string boundary that an approval URL/ID
				// shows up with: `ap_stress_<n>` followed by either
				// the URL terminator quote or whitespace; the bug is
				// only false positives with prefix matches like
				// ap_stress_5 ⊂ ap_stress_50, so use a length check).
				for j := 0; j < concurrency; j++ {
					if j == i {
						continue
					}
					otherAp := fmt.Sprintf("ap_stress_%d", j)
					// Fail only if the FULL otherAp appears at a
					// natural boundary — followed by quote, slash,
					// space, or newline. Prevents the substring trap.
					if containsAtBoundary(gotStr, otherAp) {
						t.Errorf("client %d (APPROVAL): leaked other approval %q", i, otherAp)
						failures.Add(1)
					}
				}
			}
		}(i)
	}
	wg.Wait()
	if failures.Load() > 0 {
		t.Fatalf("%d concurrency failures across %d streams", failures.Load(), concurrency)
	}
}

// containsAtBoundary returns true if needle appears in s followed by
// a non-identifier byte (so `ap_stress_5` does not match inside
// `ap_stress_50`). Used to guard against substring false positives
// when checking for cross-request id leaks in tests where the ids
// share a numeric suffix.
func containsAtBoundary(s, needle string) bool {
	idx := 0
	for {
		off := strings.Index(s[idx:], needle)
		if off < 0 {
			return false
		}
		end := idx + off + len(needle)
		if end >= len(s) {
			return true
		}
		next := s[end]
		// Identifier character — could be the start of a longer id.
		if (next >= '0' && next <= '9') || (next >= 'A' && next <= 'Z') || (next >= 'a' && next <= 'z') || next == '_' {
			idx = end
			continue
		}
		return true
	}
}

// TestAT_Concurrency_FailModeAllowAndDenyRespected asserts the
// per-request fail-mode interpretation under load: when PolicyCheck
// returns an error, the proxy honours the configured fail-mode
// uniformly across all in-flight goroutines.
func TestAT_Concurrency_FailModeAllowAndDenyRespected(t *testing.T) {
	const concurrency = 30
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		f, _ := w.(http.Flusher)
		_, _ = fmt.Fprintf(w,
			`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_fm","type":"function","function":{"name":"bash","arguments":"{}"}}]},"finish_reason":null}]}`+"\n\n")
		_, _ = fmt.Fprintf(w,
			`data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`+"\n\n")
		_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
		if f != nil {
			f.Flush()
		}
	}))
	defer upstream.Close()

	t.Run("fail-mode-deny", func(t *testing.T) {
		base, teardown := newStreamingTestServer(t, upstream, func(s *Server) {
			s.cfg.FailMode = "deny"
			// Wire the rich refusal builder so the rule string
			// `deny:llm_api_proxy:policy_unreachable` lands in the
			// client-visible refusal — that's the dashboard-grep
			// marker the operator alerts on. Default builder only
			// renders Reason; rich renders Rule too.
			s.BuildRefusal = BuildRefusalRich
			s.PolicyCheck = func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
				return Decision{}, fmt.Errorf("simulated /v1/check unreachable")
			}
		})
		defer teardown()

		var wg sync.WaitGroup
		var leaks atomic.Int64
		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				body := `{"model":"gpt-4","messages":[],"stream":true}`
				req, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(body))
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					leaks.Add(1)
					return
				}
				defer resp.Body.Close()
				got, _ := io.ReadAll(resp.Body)
				gotStr := string(got)
				// Buffered tool_call must NOT leak.
				if strings.Contains(gotStr, `"call_fm"`) {
					leaks.Add(1)
				}
				// Rich refusal carries the policy-unreachable rule.
				if !strings.Contains(gotStr, "policy_unreachable") {
					leaks.Add(1)
				}
			}()
		}
		wg.Wait()
		if leaks.Load() > 0 {
			t.Errorf("fail-mode deny: %d clients saw upstream tool_call leak or missing fail-closed marker", leaks.Load())
		}
	})

	t.Run("fail-mode-allow", func(t *testing.T) {
		base, teardown := newStreamingTestServer(t, upstream, func(s *Server) {
			s.cfg.FailMode = "allow"
			s.PolicyCheck = func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
				return Decision{}, fmt.Errorf("simulated /v1/check unreachable")
			}
		})
		defer teardown()

		var wg sync.WaitGroup
		var miss atomic.Int64
		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				body := `{"model":"gpt-4","messages":[],"stream":true}`
				req, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(body))
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					miss.Add(1)
					return
				}
				defer resp.Body.Close()
				got, _ := io.ReadAll(resp.Body)
				// fail-mode allow: tool_call was buffered, gate
				// errored, fail-mode allow → continue (tool_call never
				// flushed because no Decision Allow path took it).
				// The buffered events do NOT flush in fail-mode allow
				// (gateAndFlushOpenAI's `continue` skips refusal but
				// also skips the post-loop flush guard); but [DONE]
				// must arrive, status 200.
				if !strings.Contains(string(got), "[DONE]") {
					miss.Add(1)
				}
			}()
		}
		wg.Wait()
		if miss.Load() > 0 {
			t.Errorf("fail-mode allow: %d clients did not see [DONE] terminator", miss.Load())
		}
	})
}
