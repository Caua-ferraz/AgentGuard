package llmproxy

import (
	"context"
	"net/http/httptest"
	"testing"
)

// The X-AgentGuard-Parent-Session header reaches /v1/check as
// parent_session_id, for non-streaming responses of both providers, and is
// left off the request when the header is absent.
func TestParentSessionHeader_ReachesTheCheck(t *testing.T) {
	s := &Server{cfg: &Config{TenantID: "local"}}
	for _, tc := range []struct {
		name, header, want string
	}{
		{"header set", "orch-1", "orch-1"},
		{"header padded", "  orch-1  ", "orch-1"},
		{"no header", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
			r.Header.Set("X-Session-ID", "sub-1")
			if tc.header != "" {
				r.Header.Set(ParentSessionHeader, tc.header)
			}
			openai := buildOpenAINonStreamingCheck(s, r, &ChatCompletionResponse{},
				&ChatCompletionToolCallEcho{ID: "c1", Function: ChatCompletionToolEcho{Name: "bash", Arguments: `{"command":"ls"}`}})
			anthropic := buildAnthropicNonStreamingCheck(s, r, &AnthropicMessagesResponse{},
				&AnthropicContentBlock{Type: "tool_use", ID: "t1", Name: "bash"})
			for _, c := range []ToolCallCheck{openai, anthropic} {
				if c.ParentSessionID != tc.want || c.SessionID != "sub-1" {
					t.Errorf("%s: session %q parent %q, want sub-1 / %q", c.Provider, c.SessionID, c.ParentSessionID, tc.want)
				}
			}

			m := newMockGuardServer(t)
			gate := newGateForTest(t, m, "deny", nil)
			if _, err := gate.Check(context.Background(), &openai); err != nil {
				t.Fatal(err)
			}
			if got := m.Received()[0]; got.ParentSessionID != tc.want || got.SessionID != "sub-1" {
				t.Errorf("/v1/check got session %q parent %q", got.SessionID, got.ParentSessionID)
			}
		})
	}
}
