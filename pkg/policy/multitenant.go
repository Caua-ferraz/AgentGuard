package policy

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
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
// or a periodic ticker) to pick up tenant policy changes. A parse/validation
// error in ANY tenant aborts the refresh without mutating the live cache, so a
// bad edit to one tenant never tears down the others.
func (p *MultiTenantProvider) Refresh(ctx context.Context) error {
	tenants, err := p.source.ListPolicyTenants(ctx)
	if err != nil {
		return fmt.Errorf("policy: list tenants: %w", err)
	}
	fresh := make(map[string]*Policy, len(tenants))
	for _, t := range tenants {
		if t == LocalTenantID || t == "" {
			continue // local is the base provider's responsibility
		}
		raw, ok, err := p.source.GetPolicyYAML(ctx, t)
		if err != nil {
			return fmt.Errorf("policy: load tenant %q: %w", t, err)
		}
		if !ok {
			continue
		}
		pol, err := parsePolicyBytes(raw)
		if err != nil {
			return fmt.Errorf("policy: tenant %q: %w", t, err)
		}
		fresh[t] = pol
	}
	p.mu.Lock()
	p.cache = fresh
	p.mu.Unlock()
	return nil
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
// changes are observed via Get after Refresh (the engine re-Gets the tenant
// policy on every Check) — so a no-op stop is returned to satisfy the interface.
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

// Close closes the base provider. The PolicySource (store) lifecycle is owned
// by whoever opened it. Idempotent.
func (p *MultiTenantProvider) Close() error {
	if p.closed.CompareAndSwap(false, true) {
		return p.base.Close()
	}
	return nil
}
