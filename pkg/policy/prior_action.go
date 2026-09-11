package policy

import (
	"log"
	"sync"
	"time"
)

// PriorActionQuerier answers a require_prior condition directly, scoped to a
// tenant.
//
// It exists alongside HistoryQuerier rather than replacing it because
// HistoryQuerier is frozen v1.0 surface (CLAUDE.md §4) and cannot grow a
// parameter. Everything wrong with the old interface is fixed here:
//
//   - The tenant is a required parameter. HistoryQuerier had nowhere to put
//     one, so the shipped adapter left the audit filter's TenantID empty and
//     both backends read that as "all tenants" — one tenant's history could
//     satisfy another's condition.
//   - It returns a bool, not a slice. The old shape built an unbounded
//     []HistoryEntry per call, on the hot path, only for the caller to loop
//     over it and throw it away.
//   - Pattern matching moves to the implementation, which can index for it
//     instead of scanning.
//
// PriorActionIndex is the in-tree implementation. An embedder may supply its
// own; if it supplies only a HistoryQuerier, Engine falls back to the legacy
// path and says so loudly (see Engine.checkRequirePrior).
type PriorActionQuerier interface {
	// HasPriorAllow reports whether an action matching pattern was ALLOWed for
	// (tenantID, agentID, scope) at or after since.
	HasPriorAllow(tenantID, agentID, scope, pattern string, since time.Time) (bool, error)
}

// SetPriorActionQuerier installs the tenant-scoped querier used to evaluate
// require_prior conditions. It takes precedence over any HistoryQuerier set
// via SetHistoryQuerier.
//
// Additive: existing callers that wire only SetHistoryQuerier keep working.
func (e *Engine) SetPriorActionQuerier(q PriorActionQuerier) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.priorQuerier = q
}

// legacyHistoryWarnOnce ensures the tenant-blind fallback is announced exactly
// once per process rather than on every evaluation.
var legacyHistoryWarnOnce sync.Once

// warnLegacyHistoryPath reports that require_prior is being evaluated through
// the tenant-blind HistoryQuerier. This is a security-relevant degradation, so
// it is stated in those terms: an operator who sees it in a multi-tenant
// deployment is exposed to cross-tenant history and needs to wire a
// PriorActionQuerier.
func warnLegacyHistoryPath() {
	legacyHistoryWarnOnce.Do(func() {
		log.Printf("WARNING: require_prior is being evaluated through the legacy HistoryQuerier, " +
			"which carries no tenant and whose audit backends treat an absent tenant as ALL tenants. " +
			"In a multi-tenant deployment another tenant's history can satisfy this tenant's condition, " +
			"and the lookup reads the audit log synchronously on the /v1/check path. " +
			"Wire a PriorActionQuerier (see policy.NewPriorActionIndex) to close both.")
	})
}
