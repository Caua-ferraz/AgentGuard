package policy

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSource is an in-memory PolicySource (avoids importing pkg/store, which
// would create a cycle for this white-box test).
//
// loadErrs injects a per-tenant GetPolicyYAML error so the refresh fault-
// isolation tests can distinguish a LOAD failure from a PARSE failure — B22
// has a separate branch for each and both must retain last-good.
// lists counts ListPolicyTenants calls, which is one refresh pass, so the
// auto-refresh tests can assert the ticker actually fires and actually stops.
type fakeSource struct {
	mu       sync.Mutex
	policies map[string][]byte
	loadErrs map[string]error
	lists    int
}

func (f *fakeSource) GetPolicyYAML(_ context.Context, tenantID string) ([]byte, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err, bad := f.loadErrs[tenantID]; bad {
		return nil, false, err
	}
	y, ok := f.policies[tenantID]
	return y, ok, nil
}

func (f *fakeSource) ListPolicyTenants(_ context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lists++
	out := make([]string, 0, len(f.policies))
	for k := range f.policies {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}

// set replaces one tenant's stored policy under the source lock.
func (f *fakeSource) set(tenant string, yaml []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.policies[tenant] = yaml
}

// failLoad makes GetPolicyYAML return err for tenant until cleared.
func (f *fakeSource) failLoad(tenant string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.loadErrs == nil {
		f.loadErrs = map[string]error{}
	}
	f.loadErrs[tenant] = err
}

// listCount reports how many refresh passes have started.
func (f *fakeSource) listCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lists
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

	// A malformed tenant policy is reported but must not tear down the live
	// cache. (Pre-B22 this aborted the whole refresh before the swap; see
	// TestMultiTenantProvider_RefreshFaultIsolation for the propagation half.)
	src.set("broken", []byte("not: valid: policy: missing version"))
	if err := p.Refresh(context.Background()); err == nil {
		t.Error("Refresh with a broken tenant policy should error")
	}
	if _, err := p.Get("acme"); err != nil {
		t.Errorf("a broken tenant must not invalidate good tenants: Get(acme) err=%v", err)
	}
}

// TestMultiTenantProvider_RefreshFaultIsolation is the B22 regression test.
//
// Before the fix, ANY tenant's parse or load failure returned from Refresh
// BEFORE the cache swap, so one tenant's bad edit froze policy propagation for
// every other tenant. The assertion that matters is not "the error is
// returned" (it always was) but "everyone else still updated".
func TestMultiTenantProvider_RefreshFaultIsolation(t *testing.T) {
	base := NewStaticPolicyProvider(&Policy{Version: "1", Name: "local"})
	src := &fakeSource{policies: map[string][]byte{
		"acme":   shellAllow("acme-v1", "deploy *"),
		"globex": shellAllow("globex-v1", "backup *"),
	}}
	p, err := NewMultiTenantProvider(base, src)
	if err != nil {
		t.Fatalf("NewMultiTenantProvider: %v", err)
	}
	defer p.Close()

	// One tenant goes bad (unparseable), and BOTH healthy tenants get edits in
	// the same window.
	src.set("broken", []byte("not: valid: policy: missing version"))
	src.set("acme", shellAllow("acme-v2", "deploy *"))
	src.set("globex", shellAllow("globex-v2", "backup *"))

	err = p.Refresh(context.Background())
	if err == nil {
		t.Fatal("Refresh must still report the broken tenant")
	}
	if !strings.Contains(err.Error(), "broken") {
		t.Errorf("Refresh error should name the failing tenant, got %v", err)
	}

	// The point of B22: the healthy tenants' edits landed anyway.
	for tenant, want := range map[string]string{"acme": "acme-v2", "globex": "globex-v2"} {
		pol, gErr := p.Get(tenant)
		if gErr != nil {
			t.Fatalf("Get(%s) after partial-failure refresh: %v", tenant, gErr)
		}
		if pol.Name != want {
			t.Errorf("Get(%s).Name = %q, want %q — one bad tenant froze propagation for the others (B22)", tenant, pol.Name, want)
		}
	}
}

// TestMultiTenantProvider_RefreshKeepsLastGoodOnFailure covers the other half
// of B22: a tenant that fails must keep serving its PREVIOUS policy rather than
// vanishing from the swapped-in map. Exercised for both failure branches — a
// load error and a parse error.
func TestMultiTenantProvider_RefreshKeepsLastGoodOnFailure(t *testing.T) {
	for _, tc := range []struct {
		name   string
		break_ func(src *fakeSource)
	}{
		{"parse error", func(src *fakeSource) { src.set("acme", []byte("not: valid: policy: missing version")) }},
		{"load error", func(src *fakeSource) { src.failLoad("acme", errors.New("store unreachable")) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := NewStaticPolicyProvider(&Policy{Version: "1", Name: "local"})
			src := &fakeSource{policies: map[string][]byte{
				"acme":   shellAllow("acme-good", "deploy *"),
				"globex": shellAllow("globex-v1", "backup *"),
			}}
			p, err := NewMultiTenantProvider(base, src)
			if err != nil {
				t.Fatalf("NewMultiTenantProvider: %v", err)
			}
			defer p.Close()

			tc.break_(src)
			src.set("globex", shellAllow("globex-v2", "backup *"))

			if err := p.Refresh(context.Background()); err == nil {
				t.Fatal("Refresh should report the failing tenant")
			}

			// acme keeps its last-good policy: still served, still the old one.
			pol, gErr := p.Get("acme")
			if gErr != nil {
				t.Fatalf("a failing tenant must keep serving last-good, got err=%v", gErr)
			}
			if pol.Name != "acme-good" {
				t.Errorf("Get(acme).Name = %q, want last-good %q", pol.Name, "acme-good")
			}
			// globex still moved forward.
			if pol, gErr := p.Get("globex"); gErr != nil || pol.Name != "globex-v2" {
				t.Errorf("Get(globex) = %v, %v; want globex-v2", pol, gErr)
			}
		})
	}
}

// TestMultiTenantProvider_AutoRefreshPropagatesUpdates is the regression test
// for the gap found in review: Refresh had exactly one caller — the constructor
// — so the tenant cache was whatever the process loaded at boot. A policy
// updated in the store for an ALREADY-CACHED tenant could never reach a running
// server, because Get returns the cached entry and Watch is a no-op for
// non-local tenants.
func TestMultiTenantProvider_AutoRefreshPropagatesUpdates(t *testing.T) {
	base := NewStaticPolicyProvider(&Policy{Version: "1", Name: "local"})
	src := &fakeSource{policies: map[string][]byte{
		"acme": shellAllow("acme-v1", "deploy *"),
	}}
	p, err := NewMultiTenantProvider(base, src)
	if err != nil {
		t.Fatalf("NewMultiTenantProvider: %v", err)
	}
	defer p.Close()

	// Cache the tenant, so this exercises the UPDATE path and not the
	// lazy-load-on-miss path (which always worked).
	if pol, gErr := p.Get("acme"); gErr != nil || pol.Name != "acme-v1" {
		t.Fatalf("Get(acme) = %v, %v; want acme-v1", pol, gErr)
	}

	stop := p.StartAutoRefresh(20 * time.Millisecond)
	defer stop()

	src.set("acme", shellAllow("acme-v2", "deploy *"))

	deadline := time.Now().Add(3 * time.Second)
	for {
		pol, gErr := p.Get("acme")
		if gErr == nil && pol.Name == "acme-v2" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("tenant policy update never propagated: Get(acme).Name = %q, want acme-v2", pol.Name)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// LastRefresh must advance past construction.
	if p.LastRefresh().IsZero() {
		t.Error("LastRefresh should be set after a refresh")
	}
}

// TestMultiTenantProvider_AutoRefreshStops asserts the ticker honours both stop
// paths — the returned stop func and Close — and that neither double-closes the
// stop channel when they overlap.
func TestMultiTenantProvider_AutoRefreshStops(t *testing.T) {
	base := NewStaticPolicyProvider(&Policy{Version: "1", Name: "local"})
	src := &fakeSource{policies: map[string][]byte{"acme": shellAllow("acme", "deploy *")}}
	p, err := NewMultiTenantProvider(base, src)
	if err != nil {
		t.Fatalf("NewMultiTenantProvider: %v", err)
	}

	stop := p.StartAutoRefresh(10 * time.Millisecond)

	// Wait for the ticker to actually fire at least twice.
	deadline := time.Now().Add(3 * time.Second)
	for src.listCount() < 3 { // 1 from construction + >=2 ticks
		if time.Now().After(deadline) {
			t.Fatalf("auto-refresh never fired: listCount=%d", src.listCount())
		}
		time.Sleep(5 * time.Millisecond)
	}

	stop()
	time.Sleep(50 * time.Millisecond)
	settled := src.listCount()
	time.Sleep(100 * time.Millisecond) // ~10 ticks' worth
	if got := src.listCount(); got != settled {
		t.Errorf("refresh kept running after stop(): %d -> %d", settled, got)
	}

	// Both are idempotent, and Close after stop() must not panic on a
	// re-closed channel.
	stop()
	if err := p.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

// TestMultiTenantProvider_AutoRefreshIdempotent guards against a second call
// spawning a second ticker goroutine against the same provider.
func TestMultiTenantProvider_AutoRefreshIdempotent(t *testing.T) {
	base := NewStaticPolicyProvider(&Policy{Version: "1", Name: "local"})
	src := &fakeSource{policies: map[string][]byte{"acme": shellAllow("acme", "deploy *")}}
	p, err := NewMultiTenantProvider(base, src)
	if err != nil {
		t.Fatalf("NewMultiTenantProvider: %v", err)
	}
	defer p.Close()

	stop1 := p.StartAutoRefresh(10 * time.Millisecond)
	stop2 := p.StartAutoRefresh(10 * time.Millisecond)

	deadline := time.Now().Add(3 * time.Second)
	for src.listCount() < 3 {
		if time.Now().After(deadline) {
			t.Fatal("auto-refresh never fired")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// The first stop must halt everything; if the second call had spawned its
	// own goroutine, refreshes would continue.
	stop1()
	time.Sleep(50 * time.Millisecond)
	settled := src.listCount()
	time.Sleep(100 * time.Millisecond)
	if got := src.listCount(); got != settled {
		t.Errorf("a second StartAutoRefresh spawned an extra ticker: %d -> %d", settled, got)
	}
	stop2()
}

// TestMultiTenantProvider_AutoRefreshDisabled: a non-positive interval must not
// start anything, and its stop func must be safe to call.
func TestMultiTenantProvider_AutoRefreshDisabled(t *testing.T) {
	base := NewStaticPolicyProvider(&Policy{Version: "1", Name: "local"})
	src := &fakeSource{policies: map[string][]byte{"acme": shellAllow("acme", "deploy *")}}
	p, err := NewMultiTenantProvider(base, src)
	if err != nil {
		t.Fatalf("NewMultiTenantProvider: %v", err)
	}
	defer p.Close()

	before := src.listCount()
	stop := p.StartAutoRefresh(0)
	time.Sleep(80 * time.Millisecond)
	if got := src.listCount(); got != before {
		t.Errorf("interval<=0 must not start a ticker: %d -> %d", before, got)
	}
	stop() // must not panic on a nil stop channel
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
