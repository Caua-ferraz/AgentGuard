package policy

import (
	"testing"
	"time"
)

func TestEngineCostSnapshotRestore(t *testing.T) {
	src := NewEngineFromPolicy(&Policy{Version: "1", Name: "snap"})
	now := time.Now().UTC()
	src.recordCost("local", "s1", 4.00)
	src.recordCost("acme", "s1", 9.00) // same session id, different tenant
	src.recordCost("acme", "s2", 1.50)

	snaps := src.SnapshotCosts()
	if len(snaps) != 3 {
		t.Fatalf("SnapshotCosts got %d, want 3", len(snaps))
	}
	// Sanity: timestamps are populated.
	for _, s := range snaps {
		if s.LastUpdated.Before(now.Add(-time.Minute)) {
			t.Errorf("snapshot %+v has stale/zero LastUpdated", s)
		}
	}

	dst := NewEngineFromPolicy(&Policy{Version: "1", Name: "snap2"})
	dst.RestoreCosts(snaps)
	if got := dst.SessionCostCount(); got != 3 {
		t.Fatalf("after RestoreCosts count = %d, want 3", got)
	}
	if got := dst.SessionCost("s1"); got != 4.00 { // SessionCost reads the local tenant
		t.Errorf("restored local s1 cost = %.2f, want 4.00", got)
	}
	// Verify the acme partition restored independently of local.
	dst.mu.RLock()
	acme := dst.sessionCosts[sessionCostKey{tenant: "acme", session: "s1"}].cost
	dst.mu.RUnlock()
	if acme != 9.00 {
		t.Errorf("restored acme s1 cost = %.2f, want 9.00 (must not collide with local s1)", acme)
	}
}
