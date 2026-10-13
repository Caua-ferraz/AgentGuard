// Package configs holds the policies that ship with AgentGuard. The starter
// policy is embedded so `agentguard setup` can write it on any machine,
// including `go install` and source builds that have no release archive.
package configs

import _ "embed"

// Default is configs/default.yaml, the starter policy.
//
//go:embed default.yaml
var Default []byte

// ClaudeCode is the policy block for Claude Code (agent "claude-code"): one
// entry under `agents:`, indented for that position. The starter policy
// ends with it; `agentguard setup` adds it to an older policy on request.
//
//go:embed claude-code.yaml
var ClaudeCode []byte

// Cursor, GeminiCLI and Codex are the same rules as ClaudeCode for agents
// "cursor", "gemini-cli" and "codex", in the same position. The starter
// policy has only the Claude Code block; `agentguard setup` adds one of
// these when that agent is connected, on request.
//
//go:embed cursor.yaml
var Cursor []byte

//go:embed gemini-cli.yaml
var GeminiCLI []byte

//go:embed codex.yaml
var Codex []byte
