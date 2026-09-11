package proxy

// End-to-end wiring for the require_prior index (audit B27 + B1).
//
// pkg/policy proves the index's LOGIC. This file proves the SERVER actually
// wires it: that NewServer installs it on the engine, that logAndRespond feeds
// it on ALLOW (and only on ALLOW), and that a later /v1/check therefore sees
// the prior action. A correct index that nothing populates would pass every
// unit test in pkg/policy and deny every gated action in production.

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// newGatedServer builds a proxy whose shell ALLOW for "write *" is gated on a
// prior "read *", while "read *" is allowed outright.
func newGatedServer(t *testing.T) *Server {
	t.Helper()
	srv := newTestServer(t, func(cfg *Config) {
		cfg.Engine = policy.NewEngineFromPolicy(&policy.Policy{
			Version: "1", Name: "gated",
			Rules: []policy.RuleSet{{
				Scope: "shell",
				Allow: []policy.Rule{
					{Pattern: "read *"},
					{
						Pattern:    "write *",
						Conditions: []policy.Condition{{RequirePrior: "read *", TimeWindow: "1h"}},
					},
				},
			}},
		})
	})
	if srv.priorIndex == nil {
		t.Fatal("NewServer did not install a prior-action index; require_prior would fall back " +
			"to the tenant-blind audit scan")
	}
	return srv
}

func shellBody(command, agent string) string {
	return fmt.Sprintf(`{"scope":"shell","command":%q,"agent_id":%q}`, command, agent)
}

// TestPriorIndex_FedByAllowedCheck proves the full loop through the real
// handler: an allowed action is recorded, and a later gated action sees it.
func TestPriorIndex_FedByAllowedCheck(t *testing.T) {
	srv := newGatedServer(t)

	// Before the prerequisite, the gated action must be denied.
	got, code := driveCheckViaMux(t, srv, http.MethodPost, "/v1/check", shellBody("write out.txt", "agent-1"))
	if code != http.StatusOK {
		t.Fatalf("HTTP %d", code)
	}
	if got.Decision == policy.Allow {
		t.Fatalf("gated action allowed with no prior (rule=%q)", got.Rule)
	}

	// Perform the prerequisite through the same endpoint.
	got, _ = driveCheckViaMux(t, srv, http.MethodPost, "/v1/check", shellBody("read in.txt", "agent-1"))
	if got.Decision != policy.Allow {
		t.Fatalf("prerequisite was not allowed: %s (rule=%q)", got.Decision, got.Rule)
	}

	// Now the gate opens — proving logAndRespond fed the index.
	got, _ = driveCheckViaMux(t, srv, http.MethodPost, "/v1/check", shellBody("write out.txt", "agent-1"))
	if got.Decision != policy.Allow {
		t.Errorf("gated action still denied after the prerequisite ran: %s (rule=%q) — "+
			"logAndRespond is not feeding the prior-action index", got.Decision, got.Rule)
	}
}

// TestPriorIndex_DeniedActionIsNotRecorded is the security half. A DENIED
// attempt must never satisfy a later require_prior: if it did, an agent could
// unlock a gate simply by attempting the prerequisite and being refused, which
// inverts the entire point of the condition.
func TestPriorIndex_DeniedActionIsNotRecorded(t *testing.T) {
	srv := newGatedServer(t)

	// "delete *" matches no allow rule, so default-deny applies.
	got, _ := driveCheckViaMux(t, srv, http.MethodPost, "/v1/check", shellBody("delete everything", "agent-1"))
	if got.Decision == policy.Allow {
		t.Fatalf("precondition: this action was supposed to be denied, got %s", got.Decision)
	}

	ok, err := srv.priorIndex.HasPriorAllow(policy.LocalTenantID, "agent-1", "shell", "*", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("a DENIED action was recorded as prior history — a blocked attempt could then " +
			"satisfy a require_prior gate, inverting the condition")
	}
}

// TestPriorIndex_TenantScopedThroughRoutes drives the real handler and asserts
// the recorded history is scoped to the tenant the request was evaluated
// under — B27 at the HTTP boundary rather than the engine boundary.
func TestPriorIndex_TenantScopedThroughRoutes(t *testing.T) {
	srv := newGatedServer(t)

	got, _ := driveCheckViaMux(t, srv, http.MethodPost, "/v1/check", shellBody("read in.txt", "shared"))
	if got.Decision != policy.Allow {
		t.Fatalf("prerequisite not allowed: %s", got.Decision)
	}

	// Visible to the tenant that created it...
	ok, err := srv.priorIndex.HasPriorAllow(policy.LocalTenantID, "shared", "shell", "read *", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("the local tenant cannot see history it just created")
	}

	// ...and invisible to another tenant, despite the identical agent_id.
	ok, err = srv.priorIndex.HasPriorAllow("tenant-b", "shared", "shell", "read *", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("another tenant can see this tenant's prior action at the same agent_id")
	}
}
