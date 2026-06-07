package proxy

// White-box tests for v0.6 approval-queue tenant isolation: Lookup/Resolve/List
// must be scoped to the owning tenant (no cross-tenant oracle or resolve), the
// local tenant is stored as "" for wire byte-identity, and SSE events route
// only to same-tenant subscribers. See docs/v0.6-ARCHITECTURE-PLAN.md § 3.4 (#7).

import (
	"testing"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

func newTenantTestQueue() *ApprovalQueue {
	return &ApprovalQueue{pending: make(map[string]*PendingAction), maxSize: MaxPendingApprovals}
}

func TestApprovalQueueTenantIsolation(t *testing.T) {
	q := newTenantTestQueue()
	req := policy.ActionRequest{Scope: "shell", Command: "ls"}
	res := policy.CheckResult{Decision: policy.RequireApproval}

	paA, err := q.Add(req, res, "tenant-a")
	if err != nil {
		t.Fatalf("Add tenant-a: %v", err)
	}
	if _, err := q.Add(req, res, "tenant-b"); err != nil {
		t.Fatalf("Add tenant-b: %v", err)
	}

	// Lookup is tenant-scoped (hot-path retry isolation).
	if _, ok := q.Lookup(paA.ID, "tenant-a"); !ok {
		t.Error("tenant-a must find its own approval")
	}
	if _, ok := q.Lookup(paA.ID, "tenant-b"); ok {
		t.Error("tenant-b must NOT find tenant-a's approval (cross-tenant leak)")
	}

	// List is tenant-scoped.
	if got := len(q.List("tenant-a")); got != 1 {
		t.Errorf("List(tenant-a) = %d, want 1", got)
	}
	if got := len(q.List("tenant-b")); got != 1 {
		t.Errorf("List(tenant-b) = %d, want 1", got)
	}

	// Resolve is tenant-scoped: a foreign tenant cannot resolve and is told
	// "not found" (no existence oracle).
	if err := q.Resolve(paA.ID, policy.Allow, "tenant-b"); err == nil {
		t.Error("tenant-b must NOT resolve tenant-a's approval")
	}
	if pa, ok := q.Lookup(paA.ID, "tenant-a"); !ok || pa.Resolved {
		t.Error("tenant-a's approval must remain pending after a foreign resolve attempt")
	}
	if err := q.Resolve(paA.ID, policy.Allow, "tenant-a"); err != nil {
		t.Errorf("tenant-a must resolve its own approval: %v", err)
	}
}

func TestApprovalQueueLocalTenantNormalization(t *testing.T) {
	q := newTenantTestQueue()
	pa, err := q.Add(policy.ActionRequest{Scope: "shell"}, policy.CheckResult{}, "local")
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if pa.TenantID != "" {
		t.Errorf("local tenant must be stored as %q for wire byte-identity, got %q", "", pa.TenantID)
	}
	// Both "local" and "" (the legacy-route default) resolve to the same entry.
	if _, ok := q.Lookup(pa.ID, "local"); !ok {
		t.Error(`Lookup("local") must find the entry`)
	}
	if _, ok := q.Lookup(pa.ID, ""); !ok {
		t.Error(`Lookup("") (normalized to local) must find the entry`)
	}
}

func TestApprovalQueueSSETenantRouting(t *testing.T) {
	q := newTenantTestQueue()
	chA := q.Subscribe("tenant-a")
	chB := q.Subscribe("tenant-b")

	q.Broadcast(AuditEvent{Type: "check", Tenant: "tenant-a"})

	select {
	case ev := <-chA:
		if ev.Tenant != "tenant-a" {
			t.Errorf("tenant-a watcher got tenant %q, want tenant-a", ev.Tenant)
		}
	default:
		t.Error("tenant-a watcher should have received the tenant-a event")
	}
	select {
	case ev := <-chB:
		t.Errorf("tenant-b watcher must NOT receive a tenant-a event, got %+v", ev)
	default:
		// expected: no event routed to the other tenant
	}
}
