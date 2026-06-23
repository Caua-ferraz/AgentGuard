package gateclient

// fallback.go closes the fail-closed-with-audit gap: when the central
// server is unreachable, the gate itself appends a local audit record so
// operators can reconstruct the deny chain for the outage window instead
// of relying on metrics + stderr alone. Entries use the canonical
// audit.Entry JSONL shape, so the fallback file greps and parses exactly
// like the server-side audit log.

import (
	"encoding/json"
	"log"
	"os"
	"sync"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// FallbackFileMode matches the audit overflow file's permissions.
const FallbackFileMode = 0o600

// FallbackAuditWriter appends deny records to a local JSONL file. A nil
// writer is valid and records nothing — callers never need to nil-check.
//
// The writer only runs on the /v1/check FAILURE path (central server
// unreachable), so the file append is not hot-path work. Append failures
// are logged to stderr (once per process, then counted silently) and
// never affect the policy decision.
type FallbackAuditWriter struct {
	mu       sync.Mutex
	path     string
	warnOnce sync.Once
}

// NewFallbackAuditWriter returns a writer appending to path, or nil when
// path is empty (feature disabled).
func NewFallbackAuditWriter(path string) *FallbackAuditWriter {
	if path == "" {
		return nil
	}
	return &FallbackAuditWriter{path: path}
}

// Record appends one audit entry for a fail-mode decision. transport is
// the proxy's audit transport tag ("llm_api_proxy" / "mcp_gateway");
// tenantID is the gate's configured tenant.
func (w *FallbackAuditWriter) Record(ar policy.ActionRequest, d Decision, transport, tenantID string) {
	if w == nil {
		return
	}
	decision := policy.Deny
	if d.Allow {
		decision = policy.Allow
	}
	entry := audit.Entry{
		Timestamp: time.Now().UTC(),
		AgentID:   ar.AgentID,
		SessionID: ar.SessionID,
		TenantID:  tenantID,
		Transport: transport,
		Request:   ar,
		Result: policy.CheckResult{
			Decision: decision,
			Reason:   d.Reason,
			Rule:     d.Rule,
		},
	}

	line, err := json.Marshal(entry)
	if err != nil {
		w.warn("encode fallback audit entry", err)
		return
	}
	line = append(line, '\n')

	w.mu.Lock()
	defer w.mu.Unlock()
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, FallbackFileMode)
	if err != nil {
		w.warn("open fallback audit file", err)
		return
	}
	defer f.Close()
	if _, err := f.Write(line); err != nil {
		w.warn("append fallback audit entry", err)
	}
}

// warn logs the first failure per process; subsequent failures stay
// quiet so a broken disk doesn't flood stderr during an outage.
func (w *FallbackAuditWriter) warn(what string, err error) {
	w.warnOnce.Do(func() {
		log.Printf("WARNING: fail-audit: %s: %v (further fallback-write failures suppressed)", what, err)
	})
}
