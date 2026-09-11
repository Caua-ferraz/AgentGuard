package policy

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// PolicySource supplies per-tenant policy documents from a durable backend.
// Defined here (consumed by MultiTenantProvider) so pkg/policy does not depend
// on pkg/store — *store.SQLiteStore satisfies it structurally.
type PolicySource interface {
	// GetPolicyYAML returns the raw policy document for a tenant. ok=false when
	// the tenant has no stored policy (not an error).
	GetPolicyYAML(ctx context.Context, tenantID string) ([]byte, bool, error)
	// ListPolicyTenants returns every tenant id with a stored policy.
	ListPolicyTenants(ctx context.Context) ([]string, error)
}

// MultiTenantProvider serves the local tenant from a base PolicyProvider
// (typically a FilePolicyProvider reading --policy) and every OTHER tenant from
// a PolicySource (the durable store). Non-local policies are parsed, validated,
// and cached in memory, so Get is an in-memory map lookup after the boot-time
// eager load and never touches the store on the request hot path.
//
// It satisfies PolicyProvider, so Engine/Server consume it unchanged.
type MultiTenantProvider struct {
	base   PolicyProvider
	source PolicySource

	mu     sync.RWMutex
	cache  map[string]*Policy // non-local tenant -> parsed policy
	closed atomic.Bool

	// Auto-refresh state. refreshStop is created by StartAutoRefresh and
	// closed by it or by Close, whichever runs first; both are guarded so a
	// double stop cannot close it twice.
	refreshOnce sync.Once
	refreshStop chan struct{}
	stopOnce    sync.Once
	// lastRefresh is the wall-clock time of the last COMPLETED Refresh, in
	// unix nanoseconds. Written only by the refresh path, read lock-free.
	lastRefresh atomic.Int64
}

// NewMultiTenantProvider wraps base (local tenant) and source (other tenants),
// eager-loading every stored tenant policy so the hot path is cache-only.
func NewMultiTenantProvider(base PolicyProvider, source PolicySource) (*MultiTenantProvider, error) {
	if base == nil || source == nil {
		return nil, fmt.Errorf("policy: NewMultiTenantProvider requires non-nil base and source")
	}
	p := &MultiTenantProvider{base: base, source: source, cache: map[string]*Policy{}}
	if err := p.Refresh(context.Background()); err != nil {
		return nil, err
	}
	return p, nil
}

// Refresh reloads every non-local tenant policy from the source into the cache.
// Called once at construction and may be re-invoked (e.g. by an admin endpoint
// or a periodic ticker) to pick up tenant policy changes.
//
// Fault isolation: a load or parse error for ONE tenant no longer
// aborts the whole refresh. Previously any single failure returned before the
// cache swap, so one tenant's bad edit froze policy propagation for EVERY
// tenant — a stale-everywhere failure whose only signal was the returned error.
// Now a failing tenant keeps its previously cached policy (last-good, never a
// torn or empty entry) and every other tenant still updates. The accumulated
// errors are still returned, so the construction-time call in
// NewMultiTenantProvider continues to fail startup loudly on a bad policy
// (unchanged behavior) while a periodic/admin refresh now degrades per-tenant
// instead of cluster-wide.
func (p *MultiTenantProvider) Refresh(ctx context.Context) error {
	tenants, err := p.source.ListPolicyTenants(ctx)
	if err != nil {
		return fmt.Errorf("policy: list tenants: %w", err)
	}

	// Snapshot the current cache so a failing tenant can retain its last-good
	// policy instead of vanishing from the swapped-in map.
	p.mu.RLock()
	prev := p.cache
	p.mu.RUnlock()

	fresh := make(map[string]*Policy, len(tenants))
	var errs []error
	for _, t := range tenants {
		if t == LocalTenantID || t == "" {
			continue // local is the base provider's responsibility
		}
		raw, ok, err := p.source.GetPolicyYAML(ctx, t)
		if err != nil {
			errs = append(errs, fmt.Errorf("policy: load tenant %q: %w", t, err))
			if old, had := prev[t]; had {
				fresh[t] = old
			}
			continue
		}
		if !ok {
			continue
		}
		pol, err := parsePolicyBytes(raw)
		if err != nil {
			errs = append(errs, fmt.Errorf("policy: tenant %q: %w", t, err))
			if old, had := prev[t]; had {
				fresh[t] = old
			}
			continue
		}
		fresh[t] = pol
	}

	p.mu.Lock()
	p.cache = fresh
	p.mu.Unlock()
	p.lastRefresh.Store(time.Now().UnixNano())
	return errors.Join(errs...)
}

// LastRefresh reports when the last Refresh completed, or the zero time if
// none has. Lock-free (single atomic load), so it is safe to consult from any
// goroutine including a request path.
func (p *MultiTenantProvider) LastRefresh() time.Time {
	ns := p.lastRefresh.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

// minRefreshTimeout floors the per-tick refresh deadline so a very small
// interval cannot deadline a refresh before the store can answer.
const minRefreshTimeout = 5 * time.Second

// StartAutoRefresh runs Refresh on a ticker until the returned stop function
// (or Close) is called. It returns a no-op stop when interval <= 0, and is
// idempotent: a second call is ignored and returns a stop for the first.
//
// WHY THIS EXISTS. Refresh was written to be re-invoked "e.g. by an admin
// endpoint or a periodic ticker" — and nothing ever did. The cache was built
// once in NewMultiTenantProvider and never rebuilt, with two consequences:
//
//   - A non-local tenant's policy could be updated in the store (`agentguard
//     tenant put`) and the running process would serve the boot-time copy
//     forever. Get returns the cached entry, and Watch is a documented no-op
//     for non-local tenants, so there was NO mechanism by which an updated
//     tenant policy reached a running server short of a restart.
//   - The lazy-load miss path in Get was therefore not a rare-race safety net
//     but the ONLY way a tenant added after boot was ever served — which is
//     why removing it (treating a miss as an immediate ErrTenantNotFound)
//     would break tenant onboarding outright.
//
// HOT-PATH NOTE (CLAUDE.md §1). Get is on the /v1/check hot path and reads
// p.cache under RLock. This adds a periodic writer to that same lock, so the
// contention it introduces is bounded deliberately: the replacement map is
// built entirely OUTSIDE the lock (see Refresh), and the write lock is held
// for exactly one pointer assignment, once per interval. No store I/O, no
// parsing, and no allocation happens under the lock. That is the same lock
// discipline the construction-time Refresh already used.
func (p *MultiTenantProvider) StartAutoRefresh(interval time.Duration) func() {
	if interval <= 0 {
		return func() {}
	}
	started := false
	p.refreshOnce.Do(func() {
		started = true
		p.refreshStop = make(chan struct{})
		timeout := interval
		if timeout < minRefreshTimeout {
			timeout = minRefreshTimeout
		}
		stop := p.refreshStop
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-stop:
					return
				case <-ticker.C:
					// A refresh that outruns the interval simply drops ticks
					// (time.Ticker semantics), so passes never overlap.
					ctx, cancel := context.WithTimeout(context.Background(), timeout)
					err := p.Refresh(ctx)
					cancel()
					if err != nil {
						// B22 fault isolation means a per-tenant failure no
						// longer aborts the swap: every healthy tenant still
						// updated, and the failing ones kept last-good. Log
						// rather than retry-storm.
						log.Printf("WARNING: tenant policy refresh completed with errors: %v", err)
					}
				}
			}
		}()
	})
	if !started {
		log.Printf("WARNING: StartAutoRefresh called more than once; ignoring the later call")
	}
	return p.stopAutoRefresh
}

// stopAutoRefresh halts the ticker goroutine. Safe to call multiple times and
// safe when StartAutoRefresh was never called.
func (p *MultiTenantProvider) stopAutoRefresh() {
	p.stopOnce.Do(func() {
		if p.refreshStop != nil {
			close(p.refreshStop)
		}
	})
}

// Get returns the policy for tenantID. Local goes to the base provider; other
// tenants are served from the in-memory cache. A cache miss (a tenant added
// after the last Refresh) lazily loads it once — the only path that touches the
// store, and never for an already-known tenant.
func (p *MultiTenantProvider) Get(tenantID string) (*Policy, error) {
	if tenantID == "" || tenantID == LocalTenantID {
		return p.base.Get(tenantID)
	}
	p.mu.RLock()
	pol, ok := p.cache[tenantID]
	p.mu.RUnlock()
	if ok {
		return pol, nil
	}
	// Cache miss: lazily load a tenant added since the last Refresh.
	raw, found, err := p.source.GetPolicyYAML(context.Background(), tenantID)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrTenantNotFound
	}
	pol, err = parsePolicyBytes(raw)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.cache[tenantID] = pol
	p.mu.Unlock()
	return pol, nil
}

// Watch delegates local-tenant watching to the base provider (so file
// hot-reload still works). Non-local tenants have no push channel — their
// changes are picked up by the StartAutoRefresh ticker rebuilding the cache
// (the engine re-Gets the tenant policy on every Check) — so a no-op stop is
// returned to satisfy the interface. NOTE: without StartAutoRefresh wired,
// non-local policy updates never reach a running process at all; see that
// method's doc comment.
func (p *MultiTenantProvider) Watch(tenantID string, cb func(*Policy)) (func(), error) {
	if tenantID == "" || tenantID == LocalTenantID {
		return p.base.Watch(tenantID, cb)
	}
	if cb == nil {
		return nil, fmt.Errorf("policy: Watch callback must not be nil")
	}
	return func() {}, nil
}

// Validate parses+validates raw YAML without committing it.
func (p *MultiTenantProvider) Validate(policyBytes []byte) error {
	return validatePolicyBytes(policyBytes)
}

// Close stops the auto-refresh ticker (if running) and closes the base
// provider. The PolicySource (store) lifecycle is owned by whoever opened it.
// Idempotent.
func (p *MultiTenantProvider) Close() error {
	if p.closed.CompareAndSwap(false, true) {
		p.stopAutoRefresh()
		return p.base.Close()
	}
	return nil
}
