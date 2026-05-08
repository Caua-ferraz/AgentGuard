package llmproxy

// protocol.go defines the minimal request/response types the proxy
// inspects. The proxy is a dumb-forward by design: bodies pass through
// upstream as the original bytes. These structs exist only for the
// inspection step (streaming detection + tool definitions for scope
// mapping). Unknown fields round-trip transparently because we never
// re-encode the body.
//
// Wire-format references:
//
//   - OpenAI Chat Completions:
//     https://platform.openai.com/docs/api-reference/chat/create
//   - Anthropic Messages:
//     https://platform.claude.com/docs/en/api/messages
//
// Streaming-shape types live in the SSE parsers (openai_parser.go,
// anthropic_parser.go); the non-streaming response shape modelled
// here is stable and well-known.

import (
	"encoding/json"
)

// ----- OpenAI Chat Completions -----

// ChatCompletionRequest is the OpenAI /v1/chat/completions request
// body, parsed only to the depth the proxy needs. The Messages slice
// is kept as raw JSON because the proxy never inspects message
// content; tools are parsed so the scope-mapping layer can name-match
// them against the policy scope map.
type ChatCompletionRequest struct {
	Model    string               `json:"model"`
	Stream   bool                 `json:"stream,omitempty"`
	Messages []json.RawMessage    `json:"messages,omitempty"`
	Tools    []ChatCompletionTool `json:"tools,omitempty"`
}

// ChatCompletionTool models one element of the request's `tools`
// array. Only "function" type is defined in the OpenAI spec.
type ChatCompletionTool struct {
	Type     string                 `json:"type"`
	Function ChatCompletionToolFunc `json:"function"`
}

// ChatCompletionToolFunc carries the function-tool definition. The
// JSON-Schema parameters object is kept raw — the proxy does not
// validate arguments, only forwards them.
type ChatCompletionToolFunc struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
}

// ChatCompletionResponse is the non-streaming response. Modelled to
// the depth the gate needs (choices[i].message.tool_calls) plus
// passthrough-style fields the proxy might surface in audit meta
// (id, model, usage).
type ChatCompletionResponse struct {
	ID      string                 `json:"id"`
	Object  string                 `json:"object"`
	Created int64                  `json:"created"`
	Model   string                 `json:"model"`
	Choices []ChatCompletionChoice `json:"choices"`
	Usage   *ChatCompletionUsage   `json:"usage,omitempty"`
}

// ChatCompletionChoice is one candidate in the response.
type ChatCompletionChoice struct {
	Index        int                   `json:"index"`
	Message      ChatCompletionMessage `json:"message"`
	FinishReason string                `json:"finish_reason"`
}

// ChatCompletionMessage carries the assistant turn — content (string
// or null when there are tool calls) and zero-or-more tool_calls.
type ChatCompletionMessage struct {
	Role      string                       `json:"role"`
	Content   *string                      `json:"content,omitempty"`
	ToolCalls []ChatCompletionToolCallEcho `json:"tool_calls,omitempty"`
}

// ChatCompletionToolCallEcho is the response-side shape of a tool
// call: the model picked a function and synthesised arguments. The
// `arguments` field on the wire is a JSON-encoded STRING (yes — a
// string holding JSON) per the OpenAI spec. The proxy preserves it
// as-is so re-parsing happens at the policy-gate boundary.
type ChatCompletionToolCallEcho struct {
	ID       string                  `json:"id"`
	Type     string                  `json:"type"`
	Function ChatCompletionToolEcho  `json:"function"`
}

// ChatCompletionToolEcho is the (name, JSON-string-arguments) pair.
type ChatCompletionToolEcho struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// ChatCompletionUsage is the token-usage report. Optional in
// streaming and absent from intermediate chunks.
type ChatCompletionUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// ----- Anthropic Messages -----

// AnthropicMessagesRequest is the /v1/messages request body. Like
// the OpenAI struct, only fields the proxy reads are typed; the
// rest passes through in the original bytes.
type AnthropicMessagesRequest struct {
	Model    string            `json:"model"`
	Stream   bool              `json:"stream,omitempty"`
	Messages []json.RawMessage `json:"messages,omitempty"`
	Tools    []AnthropicTool   `json:"tools,omitempty"`
}

// AnthropicTool describes one tool the model can call.
type AnthropicTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema,omitempty"`
}

// AnthropicMessagesResponse is the non-streaming response. The
// content array is heterogeneous (text blocks, tool_use blocks); the
// proxy parses the type discriminator on each block and walks
// tool_use blocks for gating.
type AnthropicMessagesResponse struct {
	ID         string                  `json:"id"`
	Type       string                  `json:"type"`
	Role       string                  `json:"role"`
	Model      string                  `json:"model"`
	Content    []AnthropicContentBlock `json:"content"`
	StopReason string                  `json:"stop_reason"`
	Usage      *AnthropicUsage         `json:"usage,omitempty"`
}

// AnthropicContentBlock is one element of the response content
// array. Text blocks carry `text`; tool_use blocks carry
// `id`, `name`, `input`. Other types (e.g. image) round-trip
// untouched because the gating logic only acts on tool_use.
type AnthropicContentBlock struct {
	Type string `json:"type"`

	// type=="text"
	Text string `json:"text,omitempty"`

	// type=="tool_use"
	ID    string          `json:"id,omitempty"`
	Name  string          `json:"name,omitempty"`
	Input json.RawMessage `json:"input,omitempty"`
}

// AnthropicUsage mirrors the Anthropic billing report.
type AnthropicUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}
