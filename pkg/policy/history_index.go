package policy

import (
	"strings"
	"sync"
	"time"
)

// PriorActionIndex answers the only question require_prior actually asks:
// "was an action matching this pattern ALLOWed for this (tenant, agent, scope)
// since time T?"
//
// WHY AN INDEX AND NOT A HISTORY BUFFER.
//
// The previous implementation answered that question by querying the audit
// log: FileLogger.Query opened the file and JSON-parsed every line, and it did
// so while Engine.Check held e.mu — synchronous, unbounded disk I/O on a path
// budgeted at 3ms p99 (B1). It also dropped the tenant on the way in, and both
// audit backends read an empty tenant filter as "all tenants", so one tenant's
// history could satisfy another tenant's condition (B27).
//
// Keeping the history in memory would fix the I/O but not the shape: any
// buffer still has to be SCANNED to answer the question. So this stores the
// derived predicate rather than the history —
//
//	{tenant, agent, scope} -> {action or command -> newest ALLOW timestamp}
//
// which makes the common case an O(1) map hit with no allocation, puts the
// tenant in the key by construction (B27 cannot recur without deleting a
// struct field), and discards everything checkRequirePrior never reads.
// Ordering is irrelevant to the predicate, and EstCost was dead weight.
//
// BOUNDEDNESS. The keys are client-chosen strings (agent_id, tool names), so
// this map has exactly the shape that made ratelimit's bucket map
// unbounded. It therefore ships with a TTL and hard caps from day one, and
// the sweep runs off the request path.
type PriorActionIndex struct {
	mu sync.RWMutex
	// entries maps a (tenant, agent, scope) triple to the newest ALLOW time
	// per action/command string.
	entries map[historyKey]map[string]time.Time

	// ttl bounds how far back the index stays meaningful. Entries older than
	// this can never satisfy a condition, so they are swept.
	ttl time.Duration

	// maxKeys caps the number of distinct (tenant, agent, scope) triples;
	// maxPerKey caps the actions remembered within one triple. Both exist so a
	// caller that invents identifiers cannot grow this without bound.
	maxKeys   int
	maxPerKey int

	// dropped counts records rejected because a cap was hit. Exposed for tests
	// and operator visibility: silently forgetting history turns a legitimate
	// require_prior ALLOW into a denial, so it must not be invisible.
	dropped uint64
}

type historyKey struct {
	tenant string
	agent  string
	scope  string
}

// Index defaults. Deliberately generous: the failure mode of a too-small index
// is a legitimate action getting denied, which is worse than a few MB of map.
const (
	// DefaultPriorActionTTL is how long an ALLOW stays eligible to satisfy a
	// require_prior condition when the caller does not specify otherwise.
	DefaultPriorActionTTL       = 24 * time.Hour
	defaultPriorActionMaxKeys   = 10000
	defaultPriorActionMaxPerKey = 256
)

// NewPriorActionIndex builds an index with the given retention window. A
// non-positive ttl falls back to DefaultPriorActionTTL.
func NewPriorActionIndex(ttl time.Duration) *PriorActionIndex {
	if ttl <= 0 {
		ttl = DefaultPriorActionTTL
	}
	return &PriorActionIndex{
		entries:   make(map[historyKey]map[string]time.Time),
		ttl:       ttl,
		maxKeys:   defaultPriorActionMaxKeys,
		maxPerKey: defaultPriorActionMaxPerKey,
	}
}

// Record notes that an action was ALLOWed.
//
// Callers must record ONLY allow decisions. A denied action can never satisfy
// require_prior, and recording one would let a blocked attempt unlock a later
// gate — the exact inversion this condition exists to prevent.
//
// Both action and command are recorded because checkRequirePrior matches the
// pattern against either. Empty strings are skipped.
//
// Called from the audit-write boundary after the decision is made, never from
// inside Engine.Check.
func (idx *PriorActionIndex) Record(tenantID, agentID, scope, action, command string, at time.Time) {
	if idx == nil || (action == "" && command == "") {
		return
	}
	key := historyKey{tenant: effectiveTenantID(tenantID), agent: agentID, scope: scope}

	idx.mu.Lock()
	defer idx.mu.Unlock()

	inner, ok := idx.entries[key]
	if !ok {
		if len(idx.entries) >= idx.maxKeys {
			// At cap. Sweeping under the lock we already hold reclaims expired
			// triples; if that frees nothing the record is dropped and counted
			// rather than growing the map without bound.
			idx.sweepLocked(at)
			if len(idx.entries) >= idx.maxKeys {
				idx.dropped++
				return
			}
		}
		inner = make(map[string]time.Time, 4)
		idx.entries[key] = inner
	}

	for _, v := range [2]string{action, command} {
		if v == "" {
			continue
		}
		prev, exists := inner[v]
		if !exists && len(inner) >= idx.maxPerKey {
			idx.dropped++
			continue
		}
		// Keep the NEWEST timestamp: an out-of-order record must never move a
		// prior action backwards out of a caller's lookback window.
		if !exists || at.After(prev) {
			inner[v] = at
		}
	}
}

// HasPriorAllow reports whether an ALLOW matching pattern was recorded for
// (tenantID, agentID, scope) at or after since.
//
// Semantics are pinned to the audit-scan implementation this replaces: the
// pattern matches when it equals, or globs against, either the recorded action
// or the recorded command.
func (idx *PriorActionIndex) HasPriorAllow(tenantID, agentID, scope, pattern string, since time.Time) (bool, error) {
	if idx == nil || pattern == "" {
		return false, nil
	}
	key := historyKey{tenant: effectiveTenantID(tenantID), agent: agentID, scope: scope}

	idx.mu.RLock()
	defer idx.mu.RUnlock()

	inner, ok := idx.entries[key]
	if !ok {
		return false, nil
	}

	// Fast path: an exact hit. globMatch delegates to wildcardMatch for any
	// pattern without a double star, and wildcardMatch on a pattern with no
	// star or question mark reduces to string equality — so for a literal
	// pattern this lookup is not merely a shortcut, it is COMPLETE, and the
	// scan below can be skipped outright.
	if t, hit := inner[pattern]; hit && !t.Before(since) {
		return true, nil
	}
	if !strings.ContainsAny(pattern, "*?") {
		return false, nil
	}

	// Glob pattern: scan this triple's actions only. Bounded by maxPerKey and,
	// in practice, by the handful of distinct actions one agent takes in one
	// scope — never by the size of the audit log.
	for action, t := range inner {
		if t.Before(since) {
			continue
		}
		if globMatch(pattern, action) {
			return true, nil
		}
	}
	return false, nil
}

// Sweep drops entries older than the retention window. Intended for a
// background ticker: it takes the write lock for an O(n) pass and must never
// run on the request path.
func (idx *PriorActionIndex) Sweep(now time.Time) {
	if idx == nil {
		return
	}
	idx.mu.Lock()
	defer idx.mu.Unlock()
	idx.sweepLocked(now)
}

// sweepLocked is Sweep's body. Caller must hold idx.mu for write.
func (idx *PriorActionIndex) sweepLocked(now time.Time) {
	cutoff := now.Add(-idx.ttl)
	for key, inner := range idx.entries {
		for action, t := range inner {
			if t.Before(cutoff) {
				delete(inner, action)
			}
		}
		if len(inner) == 0 {
			delete(idx.entries, key)
		}
	}
}

// Len returns the number of tracked (tenant, agent, scope) triples.
func (idx *PriorActionIndex) Len() int {
	if idx == nil {
		return 0
	}
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return len(idx.entries)
}

// Dropped returns how many records a cap rejected.
func (idx *PriorActionIndex) Dropped() uint64 {
	if idx == nil {
		return 0
	}
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return idx.dropped
}

// effectiveTenantID normalizes the empty tenant to the local sentinel so an
// unset tenant and an explicit "local" address the same bucket, matching how
// the rest of the system treats it.
func effectiveTenantID(tenantID string) string {
	if tenantID == "" {
		return LocalTenantID
	}
	return tenantID
}
