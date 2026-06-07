package policy

// Verifies the v0.6 cost accumulator is partitioned by (tenant, session): two
// tenants reusing the same session_id keep independent budgets, and the
// preserved single-tenant accessors resolve to LocalTenantID. See
// docs/v0.6-ARCHITECTURE-PLAN.md § 3.4 (#6).

import "testing"

func TestSessionCostTenantIsolation(t *testing.T) {
	engine := NewEngineFromPolicy(&Policy{
		Version: "1",
		Name:    "cost-tenant-isolation",
		Rules: []RuleSet{{
			Scope:  "cost",
			Limits: &CostLimits{MaxPerSession: "$100.00"},
		}},
	})

	// Same session_id, two different tenants — must not share a budget.
	engine.recordCost("tenant-a", "shared-session", 5.00)
	engine.recordCost("tenant-b", "shared-session", 3.00)

	engine.mu.RLock()
	a := engine.sessionCosts[sessionCostKey{tenant: "tenant-a", session: "shared-session"}].cost
	b := engine.sessionCosts[sessionCostKey{tenant: "tenant-b", session: "shared-session"}].cost
	engine.mu.RUnlock()

	if a != 5.00 {
		t.Errorf("tenant-a accumulated cost = %.2f, want 5.00", a)
	}
	if b != 3.00 {
		t.Errorf("tenant-b accumulated cost = %.2f, want 3.00 (isolated from tenant-a)", b)
	}

	// The preserved single-tenant accessor reads the LOCAL tenant and must not
	// observe either non-local tenant's spend.
	if got := engine.SessionCost("shared-session"); got != 0 {
		t.Errorf("local SessionCost(shared-session) = %.2f, want 0 (tenant-isolated)", got)
	}

	// All three are distinct map entries.
	if got := engine.SessionCostCount(); got != 2 {
		t.Errorf("SessionCostCount = %d, want 2 (one per tenant)", got)
	}
}

// TestCheckCostTenantIsolation drives the hot-path reserve through Check for
// the local tenant and confirms a non-local tenant's pre-seeded spend does not
// count against the local session's per-session cap.
func TestCheckCostTenantIsolation(t *testing.T) {
	engine := NewEngineFromPolicy(&Policy{
		Version: "1",
		Name:    "cost-check-tenant",
		Rules: []RuleSet{{
			Scope:  "cost",
			Limits: &CostLimits{MaxPerSession: "$10.00"},
		}},
	})

	// Pre-seed a different tenant at the cap under the same session_id.
	engine.recordCost("other-tenant", "sess", 10.00)

	// The local tenant's session is still empty, so a $9 reserve must ALLOW.
	r := engine.Check(ActionRequest{Scope: "cost", EstCost: 9.00, SessionID: "sess"}, LocalTenantID)
	if r.Decision != Allow {
		t.Fatalf("local reserve should ALLOW despite other-tenant being at cap, got %s: %s", r.Decision, r.Reason)
	}
	if got := engine.SessionCost("sess"); got != 9.00 {
		t.Errorf("local session cost = %.2f, want 9.00", got)
	}
}
