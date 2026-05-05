package policy

import (
	"testing"
	"time"
)

// TestSessionCostTTLEviction is the wall-clock variant of
// TestSweepSessionCosts_EvictsStale (engine_extended_test.go). The extended
// test backdates lastUpdated to skip the sleep; this one runs with a real
// 100 ms TTL and a 200 ms sleep so the eviction path is also exercised
// without test-only state surgery. Closes R4 F1.
//
// time.Sleep is used because we are explicitly verifying TTL semantics
// against wall-clock time. Per project conventions sleeps are allowed in
// _test.go files only — never in production code (the sweeper goroutine
// itself uses time.NewTicker + ctx.Done, see pkg/proxy/server.go).
func TestSessionCostTTLEviction(t *testing.T) {
	pol := &Policy{
		Version: "1",
		Name:    "session-cost-ttl",
		Rules: []RuleSet{
			{
				Scope: "cost",
				Limits: &CostLimits{
					MaxPerAction:  "$10.00",
					MaxPerSession: "$1000.00",
				},
			},
		},
	}
	engine := NewEngine(pol)

	// Reserve $5 against session "to-evict".
	r := engine.Check(ActionRequest{
		Scope:     "cost",
		EstCost:   5.00,
		SessionID: "to-evict",
	})
	if r.Decision != Allow {
		t.Fatalf("expected ALLOW, got %s: %s", r.Decision, r.Reason)
	}
	if got := engine.SessionCost("to-evict"); got != 5.00 {
		t.Fatalf("expected $5.00 reserved, got $%.2f", got)
	}
	if got := engine.SessionCostCount(); got != 1 {
		t.Fatalf("expected 1 entry tracked, got %d", got)
	}

	// Sleep past the TTL so the entry is unambiguously stale.
	const ttl = 100 * time.Millisecond
	time.Sleep(2 * ttl)

	// Trigger eviction directly (no goroutine needed for the unit test —
	// SweepSessionCosts is the same primitive the proxy's runSessionCostSweeper
	// invokes on each tick).
	n := engine.SweepSessionCosts(ttl)
	if n != 1 {
		t.Errorf("expected 1 eviction, got %d", n)
	}
	if got := engine.SessionCost("to-evict"); got != 0 {
		t.Errorf("evicted session must report $0 reserved, got $%.2f", got)
	}
	if got := engine.SessionCostCount(); got != 0 {
		t.Errorf("expected 0 tracked entries after eviction, got %d", got)
	}
}
