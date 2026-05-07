package llmproxy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestProtocol_ChatCompletionRequest_StreamingDetection verifies the
// minimal struct decodes the `stream` field correctly across the
// three on-wire shapes (true, false, omitted).
func TestProtocol_ChatCompletionRequest_StreamingDetection(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		expected bool
	}{
		{"stream-true", `{"model":"gpt-4","messages":[],"stream":true}`, true},
		{"stream-false", `{"model":"gpt-4","messages":[],"stream":false}`, false},
		{"stream-omitted", `{"model":"gpt-4","messages":[]}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var req ChatCompletionRequest
			if err := json.Unmarshal([]byte(tc.body), &req); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if req.Stream != tc.expected {
				t.Errorf("Stream = %v, want %v", req.Stream, tc.expected)
			}
		})
	}
}

// TestProtocol_ChatCompletionRequest_ToolDefinitions verifies the
// `tools` array decodes with name + parameters preserved as raw
// JSON. Parameters are not parsed — A23's scope mapping operates
// on the tool name; the schema is forwarded untouched.
func TestProtocol_ChatCompletionRequest_ToolDefinitions(t *testing.T) {
	body := `{
		"model": "gpt-4",
		"messages": [],
		"tools": [
			{"type": "function", "function": {"name": "read_file", "description": "read a file", "parameters": {"type": "object", "properties": {"path": {"type": "string"}}}}},
			{"type": "function", "function": {"name": "bash", "parameters": {"type": "object"}}}
		]
	}`
	var req ChatCompletionRequest
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := len(req.Tools); got != 2 {
		t.Fatalf("len(Tools) = %d, want 2", got)
	}
	if req.Tools[0].Function.Name != "read_file" {
		t.Errorf("Tools[0].Function.Name = %q, want read_file", req.Tools[0].Function.Name)
	}
	if req.Tools[1].Function.Name != "bash" {
		t.Errorf("Tools[1].Function.Name = %q, want bash", req.Tools[1].Function.Name)
	}
	// Parameters round-trip as raw JSON.
	if len(req.Tools[0].Function.Parameters) == 0 {
		t.Errorf("Tools[0].Function.Parameters is empty; expected raw JSON")
	}
}

// TestProtocol_AnthropicMessagesRequest_StreamingDetection mirrors
// the OpenAI variant.
func TestProtocol_AnthropicMessagesRequest_StreamingDetection(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		expected bool
	}{
		{"stream-true", `{"model":"claude","messages":[],"stream":true}`, true},
		{"stream-false", `{"model":"claude","messages":[],"stream":false}`, false},
		{"stream-omitted", `{"model":"claude","messages":[]}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var req AnthropicMessagesRequest
			if err := json.Unmarshal([]byte(tc.body), &req); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if req.Stream != tc.expected {
				t.Errorf("Stream = %v, want %v", req.Stream, tc.expected)
			}
		})
	}
}

// TestProtocol_OpenAIChatResponse_Fixture verifies the
// non-streaming OpenAI response fixture decodes with content
// preserved.
func TestProtocol_OpenAIChatResponse_Fixture(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "openai_chat_response.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var resp ChatCompletionResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.ID == "" {
		t.Errorf("ID empty")
	}
	if len(resp.Choices) != 1 {
		t.Fatalf("Choices = %d, want 1", len(resp.Choices))
	}
	if resp.Choices[0].FinishReason != "stop" {
		t.Errorf("FinishReason = %q, want stop", resp.Choices[0].FinishReason)
	}
	if resp.Choices[0].Message.Content == nil || *resp.Choices[0].Message.Content == "" {
		t.Errorf("Content empty")
	}
	if len(resp.Choices[0].Message.ToolCalls) != 0 {
		t.Errorf("ToolCalls non-empty in plain text response")
	}
}

// TestProtocol_OpenAIChatResponse_ToolCalls verifies the tool-call
// fixture decodes with the JSON-string-arguments shape preserved.
func TestProtocol_OpenAIChatResponse_ToolCalls(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "openai_with_tool_calls.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var resp ChatCompletionResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Choices) != 1 {
		t.Fatalf("Choices = %d, want 1", len(resp.Choices))
	}
	if resp.Choices[0].FinishReason != "tool_calls" {
		t.Errorf("FinishReason = %q, want tool_calls", resp.Choices[0].FinishReason)
	}
	tcs := resp.Choices[0].Message.ToolCalls
	if len(tcs) != 1 {
		t.Fatalf("ToolCalls = %d, want 1", len(tcs))
	}
	if tcs[0].ID == "" {
		t.Errorf("tool_call.id empty")
	}
	if tcs[0].Function.Name != "read_file" {
		t.Errorf("tool_call.function.name = %q, want read_file", tcs[0].Function.Name)
	}
	// arguments is a JSON-encoded STRING per the OpenAI wire format.
	if tcs[0].Function.Arguments != `{"path":"/tmp/x"}` {
		t.Errorf("tool_call.function.arguments = %q, want {\"path\":\"/tmp/x\"}", tcs[0].Function.Arguments)
	}
}

// TestProtocol_AnthropicMessagesResponse_Fixture verifies the
// content-block discriminator works across heterogeneous block types.
func TestProtocol_AnthropicMessagesResponse_Fixture(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "anthropic_messages_response.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var resp AnthropicMessagesResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.ID == "" {
		t.Errorf("ID empty")
	}
	if resp.StopReason != "tool_use" {
		t.Errorf("StopReason = %q, want tool_use", resp.StopReason)
	}
	if len(resp.Content) != 2 {
		t.Fatalf("Content = %d, want 2", len(resp.Content))
	}
	if resp.Content[0].Type != "text" {
		t.Errorf("Content[0].Type = %q, want text", resp.Content[0].Type)
	}
	if resp.Content[1].Type != "tool_use" {
		t.Errorf("Content[1].Type = %q, want tool_use", resp.Content[1].Type)
	}
	if resp.Content[1].Name != "read_file" {
		t.Errorf("Content[1].Name = %q, want read_file", resp.Content[1].Name)
	}
	if string(resp.Content[1].Input) != `{"path": "/tmp/x"}` {
		t.Errorf("Content[1].Input = %q, want {\"path\": \"/tmp/x\"}", string(resp.Content[1].Input))
	}
}

// TestProtocol_RoundTrip_Tools confirms a request with tool
// definitions can be unmarshalled and re-marshalled without losing
// fields. The proxy NEVER re-encodes the body in production (it
// forwards the original bytes), but the inspection types should
// still be self-consistent.
func TestProtocol_RoundTrip_Tools(t *testing.T) {
	original := ChatCompletionRequest{
		Model:  "gpt-4",
		Stream: true,
		Tools: []ChatCompletionTool{
			{Type: "function", Function: ChatCompletionToolFunc{
				Name:        "read_file",
				Description: "read a file",
				Parameters:  json.RawMessage(`{"type":"object"}`),
			}},
		},
	}
	enc, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var roundtrip ChatCompletionRequest
	if err := json.Unmarshal(enc, &roundtrip); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if roundtrip.Model != original.Model {
		t.Errorf("Model lost: %q vs %q", roundtrip.Model, original.Model)
	}
	if roundtrip.Stream != original.Stream {
		t.Errorf("Stream lost")
	}
	if len(roundtrip.Tools) != 1 || roundtrip.Tools[0].Function.Name != "read_file" {
		t.Errorf("Tools lost")
	}
}
