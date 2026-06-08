package policy

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// errSource is a PolicySource whose per-tenant lookup always fails (DB-down
// simulation), to exercise the provider-error deny path.
type errSource struct{}

func (errSource) GetPolicyYAML(context.Context, string) ([]byte, bool, error) {
	return nil, false, fmt.Errorf("simulated store failure")
}
func (errSource) ListPolicyTenants(context.Context) ([]string, error) { return nil, nil }

// TestEngine_PerTenantCostIsolation drives the cost-scope reserve through the
// refactored Check for a NON-local tenant and confirms the accumulator is
// partitioned per tenant (same session_id, independent budgets).
func TestEngine_PerTenantCostIsolation(t *testing.T) {
	costPol := func(name string) []byte {
		return []byte("version: \"1\"\nname: \"" + name + "\"\nrules:\n  - scope: cost\n    limits:\n      max_per_session: \"$10.00\"\n")
	}
	base := NewStaticPolicyProvider(&Policy{
		Version: "1", Name: "local",
		Rules: []RuleSet{{Scope: "cost", Limits: &CostLimits{MaxPerSession: "$10.00"}}},
	})
	src := &fakeSource{policies: map[string][]byte{"acme": costPol("acme")}}
	prov, _ := NewMultiTenantProvider(base, src)
	eng, _ := NewEngine(prov)
	defer eng.Close()

	// Reserve $9 under acme/session "s".
	if r := eng.Check(ActionRequest{Scope: "cost", EstCost: 9, SessionID: "s"}, "acme"); r.Decision != Allow {
		t.Fatalf("acme reserve $9: %s %s", r.Decision, r.Reason)
	}
	// Same session under local is an INDEPENDENT budget: $9 also allowed.
	if r := eng.Check(ActionRequest{Scope: "cost", EstCost: 9, SessionID: "s"}, "local"); r.Decision != Allow {
		t.Fatalf("local reserve $9 must be independent of acme: %s", r.Decision)
	}
	// acme already holds $9; +$2 exceeds the $10 cap -> DENY (per-tenant total).
	if r := eng.Check(ActionRequest{Scope: "cost", EstCost: 2, SessionID: "s"}, "acme"); r.Decision != Deny {
		t.Errorf("acme +$2 over cap should DENY, got %s", r.Decision)
	}
}

// TestEngine_ProviderErrorDenies confirms a non-NotFound provider error
// (infrastructure failure) yields a distinct deny:tenant:provider_error.
func TestEngine_ProviderErrorDenies(t *testing.T) {
	base := NewStaticPolicyProvider(&Policy{Version: "1", Name: "local"})
	prov, err := NewMultiTenantProvider(base, errSource{})
	if err != nil {
		t.Fatalf("NewMultiTenantProvider: %v", err)
	}
	eng, _ := NewEngine(prov)
	defer eng.Close()

	r := eng.Check(ActionRequest{Scope: "shell", Command: "x"}, "acme")
	if r.Decision != Deny || r.Rule != "deny:tenant:provider_error" {
		t.Errorf("provider error should DENY with deny:tenant:provider_error, got %s / %s", r.Decision, r.Rule)
	}
}

func TestMultiTenantProvider_WatchValidateClose(t *testing.T) {
	base := NewStaticPolicyProvider(&Policy{Version: "1", Name: "local"})
	p, _ := NewMultiTenantProvider(base, &fakeSource{policies: map[string][]byte{}})

	if err := p.Validate(shellAllow("x", "ls *")); err != nil {
		t.Errorf("Validate good: %v", err)
	}
	if err := p.Validate([]byte("not a policy")); err == nil {
		t.Error("Validate bad should error")
	}

	// Local Watch delegates to the base provider; fires on UpdatePolicy.
	fired := make(chan *Policy, 1)
	stop, err := p.Watch(LocalTenantID, func(pol *Policy) {
		select {
		case fired <- pol:
		default:
		}
	})
	if err != nil {
		t.Fatalf("Watch(local): %v", err)
	}
	base.UpdatePolicy(&Policy{Version: "1", Name: "local-v2"})
	select {
	case <-fired:
	case <-time.After(2 * time.Second):
		t.Error("local Watch callback did not fire on UpdatePolicy")
	}
	stop()

	// Non-local Watch returns a no-op stop, no error, no panic.
	stop2, err := p.Watch("acme", func(*Policy) {})
	if err != nil {
		t.Errorf("Watch(non-local): %v", err)
	}
	stop2()

	// Close is idempotent.
	if err := p.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Errorf("Close (2nd): %v", err)
	}
}
