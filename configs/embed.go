// Package configs holds the policies that ship with AgentGuard. The starter
// policy is embedded so `agentguard setup` can write it on any machine,
// including `go install` and source builds that have no release archive.
package configs

import _ "embed"

// Default is configs/default.yaml, the starter policy.
//
//go:embed default.yaml
var Default []byte
