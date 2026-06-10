package llmproxy

// security_audit_test.go holds regression tests for the 2026-06 internal
// security audit findings (docs/audit/2026-06-INTERNAL-AUDIT.md). Each test
// fails against the pre-fix code and passes after the corresponding fix.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Caua-ferraz/AgentGuard/pkg/metrics"
)

// H1: an Anthropic stream that opens a SECOND tool_use content block before
// closing the first must not let the second block reach the client ungated.
//
// Pre-fix: the accumulator only gates the first (active) tool_use; on ALLOW
// the orchestrator flushes all buffered bytes (including the second block's
// start) and Reset()s, after which the second block's remaining deltas/stop
// pass through ungated. So the denied `bash` call's bytes reach the client.
//
// Post-fix: the second tool_use start signals a ProtocolViolation and the
// whole stream is refused fail-closed — the client never sees `bash`.
func TestAudit_H1_AnthropicInterleavedToolUse_DoesNotBypassGate(t *testing.T) {
	// Interleaved: tool_use idx0 (read_file) opens and gets a delta, THEN
	// tool_use idx1 (bash) opens before idx0 closes.
	const interleaved = "event: message_start\n" +
		`data: {"type":"message_start","message":{"id":"msg_1"}}` + "\n\n" +
		"event: content_block_start\n" +
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_read","name":"read_file","input":{}}}` + "\n\n" +
		"event: content_block_delta\n" +
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"path\":\"/tmp/ok\"}"}}` + "\n\n" +
		"event: content_block_start\n" +
		`data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_bash","name":"bash","input":{}}}` + "\n\n" +
		"event: content_block_delta\n" +
		`data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"command\":\"rm -rf /\"}"}}` + "\n\n" +
		"event: content_block_stop\n" +
		`data: {"type":"content_block_stop","index":0}` + "\n\n" +
		"event: content_block_stop\n" +
		`data: {"type":"content_block_stop","index":1}` + "\n\n" +
		"event: message_stop\n" +
		`data: {"type":"message_stop"}` + "\n\n"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, interleaved)
	}))
	defer upstream.Close()

	before := metrics.LLMProxyProtocolViolationFor("anthropic")

	base, teardown := newStreamingTestServer(t, upstream, func(s *Server) {
		s.PolicyCheck = func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
			// read_file is fine; bash is denied. The whole point is that
			// bash must never reach the client.
			if tc.ToolName == "bash" {
				return Decision{Allow: false, Reason: "shell denied", Rule: "deny:shell"}, nil
			}
			return Decision{Allow: true, Rule: "allow:fs"}, nil
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

	// The denied bash tool_use must NOT have reached the client, in any form.
	if strings.Contains(gotStr, "toolu_bash") {
		t.Errorf("H1 BYPASS: denied bash tool_use id leaked to client: %q", gotStr)
	}
	if strings.Contains(gotStr, "rm -rf") {
		t.Errorf("H1 BYPASS: denied bash arguments leaked to client: %q", gotStr)
	}
	// The stream must have been refused (fail-closed).
	if !strings.Contains(gotStr, "AgentGuard denied") {
		t.Errorf("expected a synthetic refusal in the response; got %q", gotStr)
	}
	if after := metrics.LLMProxyProtocolViolationFor("anthropic"); after != before+1 {
		t.Errorf("protocol_violation metric = %d, want %d", after, before+1)
	}
}

// H2: an Anthropic tool_use whose real arguments are delivered in the
// content_block_start.input field (with no input_json_delta) must be gated on
// those arguments, not on an empty {}.
//
// Pre-fix: the parser discarded content_block.input and accumulated only
// input_json_delta fragments; with none present the gate saw "{}" → ALLOW,
// while the client executed the real (start-provided) arguments.
//
// Post-fix: the start input seeds the buffer, so the gate evaluates the real
// arguments and the deny fires.
func TestAudit_H2_AnthropicStartInputGated(t *testing.T) {
	// Real dangerous args live in the start block's `input`; NO delta follows.
	const startOnly = "event: message_start\n" +
		`data: {"type":"message_start","message":{"id":"msg_1"}}` + "\n\n" +
		"event: content_block_start\n" +
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_x","name":"bash","input":{"command":"rm -rf /"}}}` + "\n\n" +
		"event: content_block_stop\n" +
		`data: {"type":"content_block_stop","index":0}` + "\n\n" +
		"event: message_stop\n" +
		`data: {"type":"message_stop"}` + "\n\n"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, startOnly)
	}))
	defer upstream.Close()

	var sawArgs string
	base, teardown := newStreamingTestServer(t, upstream, func(s *Server) {
		s.PolicyCheck = func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
			if cmd, ok := tc.Arguments["command"].(string); ok {
				sawArgs = cmd
			}
			// Deny anything that tries to run a destructive command.
			if cmd, _ := tc.Arguments["command"].(string); strings.Contains(cmd, "rm -rf") {
				return Decision{Allow: false, Reason: "destructive shell denied", Rule: "deny:shell"}, nil
			}
			return Decision{Allow: true, Rule: "allow:shell"}, nil
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

	if sawArgs != "rm -rf /" {
		t.Errorf("H2: gate saw arguments %q, want %q — start.input was not gated", sawArgs, "rm -rf /")
	}
	if strings.Contains(gotStr, "toolu_x") {
		t.Errorf("H2 BYPASS: denied tool_use reached client: %q", gotStr)
	}
	if !strings.Contains(gotStr, "AgentGuard denied") {
		t.Errorf("expected refusal; got %q", gotStr)
	}
}

// H2 negative: a conformant stream (start input == {}, args via deltas) must
// still be gated exactly as before — start-seeding must not change the
// common-case behavior or the ALLOW-path byte identity.
func TestAudit_H2_ConformantStreamStillGatesViaDeltas(t *testing.T) {
	const conformant = "event: content_block_start\n" +
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_c","name":"bash","input":{}}}` + "\n\n" +
		"event: content_block_delta\n" +
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"command\":\"ls\"}"}}` + "\n\n" +
		"event: content_block_stop\n" +
		`data: {"type":"content_block_stop","index":0}` + "\n\n"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, conformant)
	}))
	defer upstream.Close()

	var sawArgs string
	base, teardown := newStreamingTestServer(t, upstream, func(s *Server) {
		s.PolicyCheck = func(ctx context.Context, tc *ToolCallCheck) (Decision, error) {
			sawArgs, _ = tc.Arguments["command"].(string)
			return Decision{Allow: true, Rule: "allow:shell"}, nil
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
	_, _ = io.ReadAll(resp.Body)

	if sawArgs != "ls" {
		t.Errorf("conformant stream: gate saw %q, want \"ls\"", sawArgs)
	}
}
