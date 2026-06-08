package policy

import (
	"context"
	"sort"
	"sync"
	"testing"
)

// fakeSource is an in-memory PolicySource (avoids importing pkg/store, which
// would create a cycle for this white-box test).
type fakeSource struct {
	mu       sync.Mutex
	policies map[string][]byte
}

func (f *fakeSource) GetPolicyYAML(_ context.Context, tenantID string) ([]byte, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	y, ok := f.policies[tenantID]
	return y, ok, nil
}

func (f *fakeSource) ListPolicyTenants(_ context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.policies))
	for k := range f.policies {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}

func shellAllow(name, pattern string) []byte {
	return []byte("version: \"1\"\nname: \"" + name + "\"\nrules:\n  - scope: shell\n    allow:\n      - pattern: \"" + pattern + "\"\n")
}

func TestMultiTenantProvider_GetAndRefresh(t *testing.T) {
	base := NewStaticPolicyProvider(&Policy{Version: "1", Name: "local"})
	src := &fakeSource{policies: map[string][]byte{
		"acme":   shellAllow("acme", "deploy *"),
		"globex": shellAllow("globex", "backup *"),
	}}
	p, err := NewMultiTenantProvider(base, src)
	if err != nil {
		t.Fatalf("NewMultiTenantProvider: %v", err)
	}
	defer p.Close()

	// local -> base
	if pol, err := p.Get(LocalTenantID); err != nil || pol.Name != "local" {
		t.Errorf("Get(local) = %v, %v; want name=local", pol, err)
	}
	// non-local -> cache
	if pol, err := p.Get("acme"); err != nil || pol.Name != "acme" {
		t.Errorf("Get(acme) = %v, %v; want name=acme", pol, err)
	}
	// unknown -> ErrTenantNotFound
	if _, err := p.Get("ghost"); err != ErrTenantNotFound {
		t.Errorf("Get(ghost) err = %v, want ErrTenantNotFound", err)
	}

	// Add a tenant after construction, Refresh picks it up.
	src.mu.Lock()
	src.policies["initech"] = shellAllow("initech", "build *")
	src.mu.Unlock()
	if err := p.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if pol, err := p.Get("initech"); err != nil || pol.Name != "initech" {
		t.Errorf("Get(initech) after refresh = %v, %v", pol, err)
	}

	// A malformed tenant policy aborts Refresh without tearing down the live cache.
	src.mu.Lock()
	src.policies["broken"] = []byte("not: valid: policy: missing version")
	src.mu.Unlock()
	if err := p.Refresh(context.Background()); err == nil {
		t.Error("Refresh with a broken tenant policy should error")
	}
	if _, err := p.Get("acme"); err != nil {
		t.Errorf("a broken tenant must not invalidate good tenants: Get(acme) err=%v", err)
	}
}

// TestEngine_PerTenantPolicyEvaluation is the core correctness test for the
// v0.6 multi-tenant fix: the same request gets DIFFERENT decisions under
// different tenants, because the engine evaluates each tenant's OWN policy.
func TestEngine_PerTenantPolicyEvaluation(t *testing.T) {
	base := NewStaticPolicyProvider(&Policy{
		Version: "1", Name: "local",
		Rules: []RuleSet{{Scope: "shell", Allow: []Rule{{Pattern: "ls *"}}}},
	})
	src := &fakeSource{policies: map[string][]byte{
		"acme":   shellAllow("acme", "deploy *"),
		"globex": shellAllow("globex", "backup *"),
	}}
	prov, err := NewMultiTenantProvider(base, src)
	if err != nil {
		t.Fatalf("NewMultiTenantProvider: %v", err)
	}
	eng, err := NewEngine(prov)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer eng.Close()

	cases := []struct {
		command string
		tenant  string
		want    Decision
	}{
		{"deploy app", "acme", Allow},  // acme allows deploy
		{"deploy app", "globex", Deny}, // globex does not
		{"deploy app", "local", Deny},  // local does not
		{"backup db", "globex", Allow}, // globex allows backup
		{"backup db", "acme", Deny},    // acme does not
		{"ls -la", "local", Allow},     // local allows ls
		{"ls -la", "acme", Deny},       // acme does not
		{"deploy app", "ghost", Deny},  // unknown tenant -> deny:tenant:not_found
	}
	for _, c := range cases {
		got := eng.Check(ActionRequest{Scope: "shell", Command: c.command}, c.tenant)
		if got.Decision != c.want {
			t.Errorf("Check(%q, tenant=%q) = %s (rule=%s), want %s",
				c.command, c.tenant, got.Decision, got.Rule, c.want)
		}
	}
}

// TestEngine_PerTenantRateLimitConfig confirms rate-limit config is resolved
// against the tenant's own policy.
func TestEngine_PerTenantRateLimitConfig(t *testing.T) {
	base := NewStaticPolicyProvider(&Policy{
		Version: "1", Name: "local",
		Rules: []RuleSet{{Scope: "network", RateLimit: &RateLimitCfg{MaxRequests: 5, Window: "1m"}}},
	})
	src := &fakeSource{policies: map[string][]byte{
		"acme": []byte("version: \"1\"\nname: acme\nrules:\n  - scope: network\n    rate_limit:\n      max_requests: 99\n      window: 1m\n"),
	}}
	prov, _ := NewMultiTenantProvider(base, src)
	eng, _ := NewEngine(prov)
	defer eng.Close()

	if rl := eng.RateLimitConfig("network", "", LocalTenantID); rl == nil || rl.MaxRequests != 5 {
		t.Errorf("local rate limit = %+v, want max=5", rl)
	}
	if rl := eng.RateLimitConfig("network", "", "acme"); rl == nil || rl.MaxRequests != 99 {
		t.Errorf("acme rate limit = %+v, want max=99 (its own policy, not local's)", rl)
	}
}

// TestEngine_PerTenantConcurrent drives Check across tenants concurrently to
// shake out data races (run with -race).
func TestEngine_PerTenantConcurrent(t *testing.T) {
	base := NewStaticPolicyProvider(&Policy{
		Version: "1", Name: "local",
		Rules: []RuleSet{
			{Scope: "shell", Allow: []Rule{{Pattern: "ls *"}}},
			{Scope: "cost", Limits: &CostLimits{MaxPerSession: "$10.00"}},
		},
	})
	src := &fakeSource{policies: map[string][]byte{
		"acme": shellAllow("acme", "deploy *"),
	}}
	prov, _ := NewMultiTenantProvider(base, src)
	eng, _ := NewEngine(prov)
	defer eng.Close()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			eng.Check(ActionRequest{Scope: "shell", Command: "ls -la"}, "local")
			eng.Check(ActionRequest{Scope: "shell", Command: "deploy x"}, "acme")
			eng.Check(ActionRequest{Scope: "cost", EstCost: 0.5, SessionID: "s"}, "local")
		}(i)
	}
	wg.Wait()
}
