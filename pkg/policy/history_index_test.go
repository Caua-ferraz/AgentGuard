package policy

// Tests for the require_prior evaluation path (audit B27 + B1).
//
// The headline test is TestCheck_RequirePriorIsTenantScoped: it drives the
// production Engine.Check and asserts that one tenant's history cannot satisfy
// another tenant's condition. Nothing in the tree asserted that before — the
// only HistoryQuerier test double implemented the same tenant-less signature
// as production, so the mock reproduced the blind spot instead of exposing it.

import (
	"errors"
	"testing"
	"time"
)

// gatedPolicyYAML is a stored policy whose shell ALLOW is gated on a prior
// action — the documented pattern ("allow write only if read was recently
// allowed"), as YAML so it can be served through a real PolicySource.
const gatedPolicyYAML = `version: "1"
name: "gated"
rules:
  - scope: shell
    allow:
      - pattern: "write *"
        conditions:
          - require_prior: "read *"
            time_window: 1h
`

// priorPolicy builds the same rule as a Policy literal, for tests that only
// need the local tenant.
func priorPolicy(t *testing.T, requirePrior string) *Policy {
	t.Helper()
	return &Policy{
		Version: "1", Name: "prior-test",
		Rules: []RuleSet{{
			Scope: "shell",
			Allow: []Rule{{
				Pattern:    "write *",
				Conditions: []Condition{{RequirePrior: requirePrior, TimeWindow: "1h"}},
			}},
		}},
	}
}

// TestCheck_RequirePriorIsTenantScoped is the B27 regression test.
//
// Before the fix, the tenant never reached the history lookup: HistoryQuerier
// had no tenant parameter, the adapter left the audit filter's TenantID empty,
// and BOTH audit backends read an empty tenant as "all tenants". So tenant-b
// performing `read x` would satisfy tenant-a's require_prior on the same
// agent_id and scope — a cross-tenant fail-open, and a direct breach of
// CLAUDE.md invariant #3.
//
// An agent_id collision across tenants is the precondition, and it is not
// exotic: agent ids are client-chosen and default-ish values collide readily.
func TestCheck_RequirePriorIsTenantScoped(t *testing.T) {
	// Two REAL tenants, each with its own stored policy, so a denial can only
	// come from the condition — not from tenant resolution. (A static-policy
	// engine denies every non-local tenant with deny:tenant:not_found, and the
	// test would then pass for entirely the wrong reason.)
	gated := []byte(gatedPolicyYAML)
	src := &fakeSource{policies: map[string][]byte{"tenant-a": gated, "tenant-b": gated}}
	prov, err := NewMultiTenantProvider(NewStaticPolicyProvider(&Policy{Version: "1", Name: "local"}), src)
	if err != nil {
		t.Fatalf("NewMultiTenantProvider: %v", err)
	}
	eng, err := NewEngine(prov)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer eng.Close()

	idx := NewPriorActionIndex(time.Hour)
	eng.SetPriorActionQuerier(idx)

	const sharedAgent = "claude-code" // the realistic collision

	// tenant-b did the prerequisite. tenant-a did NOT.
	idx.Record("tenant-b", sharedAgent, "shell", "", "read secrets.txt", time.Now())

	req := ActionRequest{Scope: "shell", Command: "write payload", AgentID: sharedAgent}

	got := eng.Check(req, "tenant-a")
	if got.Decision == Allow {
		t.Fatalf("tenant-a was ALLOWED on tenant-b's history (rule=%q) — cross-tenant "+
			"require_prior leak, CLAUDE.md invariant #3 (audit B27)", got.Rule)
	}
	if got.Rule == "deny:tenant:not_found" {
		t.Fatalf("tenant-a was denied for the wrong reason (%q): this test must exercise the "+
			"condition, not tenant resolution", got.Rule)
	}

	// Control: the tenant that actually did the prerequisite IS allowed, so
	// this proves isolation rather than that everything denies.
	if got := eng.Check(req, "tenant-b"); got.Decision != Allow {
		t.Errorf("tenant-b performed the prerequisite and must be allowed; got %s (rule=%q)",
			got.Decision, got.Rule)
	}
}

// TestCheck_RequirePriorLocalTenantNormalization pins that "" and "local"
// address the same history, so the legacy /v1/check route and the tenant-aware
// /v1/t/local/check route see one another's prior actions.
func TestCheck_RequirePriorLocalTenantNormalization(t *testing.T) {
	eng := NewEngineFromPolicy(priorPolicy(t, "read *"))
	idx := NewPriorActionIndex(time.Hour)
	eng.SetPriorActionQuerier(idx)

	idx.Record("", "agent-1", "shell", "", "read a.txt", time.Now())

	req := ActionRequest{Scope: "shell", Command: "write b.txt", AgentID: "agent-1"}
	for _, tenant := range []string{"", LocalTenantID} {
		if got := eng.Check(req, tenant); got.Decision != Allow {
			t.Errorf("tenant %q: got %s, want Allow — empty and %q must be the same bucket",
				tenant, got.Decision, LocalTenantID)
		}
	}
}

// TestCheck_RequirePriorRespectsTimeWindow: an ALLOW older than the rule's
// time_window must not satisfy the condition.
func TestCheck_RequirePriorRespectsTimeWindow(t *testing.T) {
	eng := NewEngineFromPolicy(priorPolicy(t, "read *"))
	idx := NewPriorActionIndex(24 * time.Hour)
	eng.SetPriorActionQuerier(idx)

	// Inside the index TTL but outside the rule's 1h time_window.
	idx.Record("local", "agent-1", "shell", "", "read a.txt", time.Now().Add(-2*time.Hour))

	req := ActionRequest{Scope: "shell", Command: "write b.txt", AgentID: "agent-1"}
	if got := eng.Check(req, "local"); got.Decision == Allow {
		t.Error("an ALLOW older than the rule's time_window must not satisfy require_prior")
	}
}

// TestCheck_RequirePriorScopeAndAgentScoped: history is partitioned by agent
// and scope as well as by tenant.
func TestCheck_RequirePriorScopeAndAgentScoped(t *testing.T) {
	req := ActionRequest{Scope: "shell", Command: "write b.txt", AgentID: "agent-1"}

	for _, tc := range []struct {
		name                   string
		agent, scope, priorCmd string
	}{
		{"different agent", "agent-2", "shell", "read a.txt"},
		{"different scope", "agent-1", "network", "read a.txt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eng := NewEngineFromPolicy(priorPolicy(t, "read *"))
			idx := NewPriorActionIndex(time.Hour)
			eng.SetPriorActionQuerier(idx)
			idx.Record("local", tc.agent, tc.scope, "", tc.priorCmd, time.Now())

			if got := eng.Check(req, "local"); got.Decision == Allow {
				t.Errorf("history recorded under a %s must not satisfy the condition", tc.name)
			}
		})
	}
}

// ----- index unit behaviour -----

// TestPriorActionIndex_ExactAndGlob pins the matching semantics against the
// audit-scan implementation this replaced: the pattern matches when it equals
// or globs against either the recorded action or the recorded command.
func TestPriorActionIndex_ExactAndGlob(t *testing.T) {
	now := time.Now()
	since := now.Add(-time.Hour)

	idx := NewPriorActionIndex(time.Hour)
	idx.Record("t1", "a1", "shell", "read_file", "cat /etc/hosts", now)

	for _, tc := range []struct {
		pattern string
		want    bool
		why     string
	}{
		{"read_file", true, "exact match on the action"},
		{"cat /etc/hosts", true, "exact match on the command"},
		{"read_*", true, "glob against the action"},
		{"cat *", true, "glob against the command"},
		{"*", true, "bare star matches anything recorded"},
		{"write_file", false, "unrelated literal"},
		{"write_*", false, "unrelated glob"},
		{"read_fil", false, "prefix without a wildcard must not match"},
		{"read_file?", false, "trailing ? requires one more char"},
	} {
		got, err := idx.HasPriorAllow("t1", "a1", "shell", tc.pattern, since)
		if err != nil {
			t.Fatalf("pattern %q: %v", tc.pattern, err)
		}
		if got != tc.want {
			t.Errorf("pattern %q = %v, want %v (%s)", tc.pattern, got, tc.want, tc.why)
		}
	}
}

// TestPriorActionIndex_HonorsSinceOnBothPaths pins the lookback bound on BOTH
// matching paths.
//
// HasPriorAllow has two: an O(1) exact-map hit for literal patterns and a scan
// for globs. They check `since` independently, so a test that only uses a glob
// pattern leaves the exact path's bound unverified — mutation testing caught
// exactly that, by deleting the exact path's check with every test still green.
// An unbounded exact path would let an ancient ALLOW satisfy a rule whose
// time_window expired hours ago.
func TestPriorActionIndex_HonorsSinceOnBothPaths(t *testing.T) {
	now := time.Now()
	idx := NewPriorActionIndex(24 * time.Hour)
	idx.Record("t1", "a1", "shell", "read_file", "", now.Add(-3*time.Hour))

	// since is AFTER the record, so nothing may match on either path.
	since := now.Add(-time.Hour)

	for _, tc := range []struct{ name, pattern string }{
		{"exact path (literal pattern)", "read_file"},
		{"scan path (glob pattern)", "read_*"},
	} {
		got, err := idx.HasPriorAllow("t1", "a1", "shell", tc.pattern, since)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got {
			t.Errorf("%s: an ALLOW older than `since` satisfied the condition", tc.name)
		}
	}

	// Control: widen the window and both paths must find it, so the test is
	// proving the bound rather than that lookups never succeed.
	wide := now.Add(-4 * time.Hour)
	for _, pattern := range []string{"read_file", "read_*"} {
		if got, _ := idx.HasPriorAllow("t1", "a1", "shell", pattern, wide); !got {
			t.Errorf("pattern %q: record inside the window was not found", pattern)
		}
	}
}

// TestPriorActionIndex_KeepsNewestTimestamp: re-recording an action out of
// order must never move it backwards out of a caller's lookback window.
func TestPriorActionIndex_KeepsNewestTimestamp(t *testing.T) {
	now := time.Now()
	idx := NewPriorActionIndex(24 * time.Hour)

	idx.Record("t1", "a1", "shell", "read_file", "", now)
	idx.Record("t1", "a1", "shell", "read_file", "", now.Add(-3*time.Hour)) // older, out of order

	got, err := idx.HasPriorAllow("t1", "a1", "shell", "read_file", now.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !got {
		t.Error("an out-of-order older record overwrote a newer one, hiding a recent ALLOW")
	}
}

// TestPriorActionIndex_SweepEvictsExpired: the index is keyed by client-chosen
// strings, so it must not grow without bound (the lesson of audit B3).
func TestPriorActionIndex_SweepEvictsExpired(t *testing.T) {
	now := time.Now()
	idx := NewPriorActionIndex(time.Hour)

	idx.Record("t1", "old", "shell", "read_file", "", now.Add(-2*time.Hour))
	idx.Record("t1", "new", "shell", "read_file", "", now)
	if idx.Len() != 2 {
		t.Fatalf("Len = %d, want 2 before sweep", idx.Len())
	}

	idx.Sweep(now)

	if idx.Len() != 1 {
		t.Errorf("Len = %d after sweep, want 1 (the expired triple must be gone)", idx.Len())
	}
	if ok, _ := idx.HasPriorAllow("t1", "new", "shell", "read_file", now.Add(-time.Minute)); !ok {
		t.Error("sweep evicted a live entry")
	}
}

// TestPriorActionIndex_BoundedByMaxKeys proves the cap actually binds. B3
// shipped a MaxBuckets that bounded nothing, because eviction could free zero
// and the insert happened anyway; this asserts the opposite.
func TestPriorActionIndex_BoundedByMaxKeys(t *testing.T) {
	now := time.Now()
	idx := NewPriorActionIndex(time.Hour)
	idx.maxKeys = 50 // shrink so the test stays fast

	// Every record is fresh, so nothing is sweepable — the cap is the only
	// thing standing between this loop and unbounded growth.
	for i := 0; i < 500; i++ {
		agent := "agent-" + string(rune('A'+i%26)) + string(rune('a'+i/26))
		idx.Record("t1", agent, "shell", "read_file", "", now)
	}

	if idx.Len() > idx.maxKeys {
		t.Errorf("Len = %d exceeds maxKeys = %d — the cap does not bind (audit B3's failure mode)",
			idx.Len(), idx.maxKeys)
	}
	if idx.Dropped() == 0 {
		t.Error("records were rejected by the cap but Dropped() reports 0; the loss must be observable")
	}
}

// TestPriorActionIndex_NilSafe: the index is optional, so every method must
// tolerate a nil receiver rather than panicking on a path where it was never
// wired.
func TestPriorActionIndex_NilSafe(t *testing.T) {
	var idx *PriorActionIndex
	idx.Record("t", "a", "s", "act", "cmd", time.Now())
	idx.Sweep(time.Now())
	if got, err := idx.HasPriorAllow("t", "a", "s", "p", time.Now()); got || err != nil {
		t.Errorf("nil index: got (%v, %v), want (false, nil)", got, err)
	}
	if idx.Len() != 0 || idx.Dropped() != 0 {
		t.Error("nil index must report zero")
	}
}

// ----- legacy fallback -----

// erroringQuerier drives the querier-error path directly.
type erroringQuerier struct{ err error }

func (e erroringQuerier) HasPriorAllow(_, _, _, _ string, _ time.Time) (bool, error) {
	return false, e.err
}

// TestCheck_PriorQuerierErrorDoesNotAllow: a querier error must not satisfy a
// gated ALLOW. (The full polarity-aware posture is audit B2, deliberately out
// of scope here; this pins the half that is a security property.)
func TestCheck_PriorQuerierErrorDoesNotAllow(t *testing.T) {
	eng := NewEngineFromPolicy(priorPolicy(t, "read *"))
	eng.SetPriorActionQuerier(erroringQuerier{err: errors.New("backend down")})

	req := ActionRequest{Scope: "shell", Command: "write b.txt", AgentID: "agent-1"}
	if got := eng.Check(req, "local"); got.Decision == Allow {
		t.Error("a require_prior-gated ALLOW fired despite the querier erroring")
	}
}

// TestCheck_FallsBackToLegacyHistoryQuerier: an embedder that wired only the
// frozen HistoryQuerier must keep working. This is the compatibility half of
// keeping that interface alive instead of changing it.
func TestCheck_FallsBackToLegacyHistoryQuerier(t *testing.T) {
	eng := NewEngineFromPolicy(priorPolicy(t, "read *"))
	eng.SetHistoryQuerier(&mockHistory{entries: []HistoryEntry{
		{Command: "read a.txt", Decision: Allow},
	}})

	req := ActionRequest{Scope: "shell", Command: "write b.txt", AgentID: "agent-1"}
	if got := eng.Check(req, "local"); got.Decision != Allow {
		t.Errorf("legacy HistoryQuerier path regressed: got %s (rule=%q)", got.Decision, got.Rule)
	}
}

// explodingHistory fails the test if the legacy audit-scan path is ever taken.
type explodingHistory struct{ t *testing.T }

func (e explodingHistory) RecentActions(string, string, time.Time) ([]HistoryEntry, error) {
	e.t.Error("HistoryQuerier.RecentActions was called while a PriorActionQuerier was wired — " +
		"this is the synchronous audit-log scan under e.mu that audit B1 exists to remove")
	return nil, nil
}

// TestCheck_NoAuditScanWhenIndexWired is the B1 regression test.
//
// B1 was not "the query is slow", it was "Engine.Check performs unbounded
// synchronous disk I/O while holding e.mu": FileLogger.Query opened the audit
// file and JSON-parsed every line, with the defaults putting that at up to
// ~100 MiB, on a path budgeted at 3ms p99. It could also block on the audit
// logger's own mutex mid-rotation, stalling every concurrent Check behind a
// gzip.
//
// Asserting a latency number here would be flaky. Asserting that the call
// never happens is exact — so this wires a HistoryQuerier that fails on
// contact and drives both the satisfied and unsatisfied paths.
func TestCheck_NoAuditScanWhenIndexWired(t *testing.T) {
	eng := NewEngineFromPolicy(priorPolicy(t, "read *"))
	eng.SetHistoryQuerier(explodingHistory{t: t})

	idx := NewPriorActionIndex(time.Hour)
	eng.SetPriorActionQuerier(idx)

	req := ActionRequest{Scope: "shell", Command: "write b.txt", AgentID: "agent-1"}

	// Condition unsatisfied: must deny without consulting the audit log.
	if got := eng.Check(req, "local"); got.Decision == Allow {
		t.Fatalf("unexpected allow with an empty index (rule=%q)", got.Rule)
	}

	// Condition satisfied: must allow, still without consulting the audit log.
	idx.Record("local", "agent-1", "shell", "", "read a.txt", time.Now())
	if got := eng.Check(req, "local"); got.Decision != Allow {
		t.Fatalf("expected allow after recording the prerequisite; got %s (rule=%q)", got.Decision, got.Rule)
	}
}

// TestCheck_PriorQuerierWinsOverLegacy: when both are wired the tenant-scoped
// querier is authoritative, so installing the index actually closes B27 rather
// than merely adding a second opinion.
func TestCheck_PriorQuerierWinsOverLegacy(t *testing.T) {
	eng := NewEngineFromPolicy(priorPolicy(t, "read *"))
	// Legacy says yes (tenant-blind); the index has nothing for this tenant.
	eng.SetHistoryQuerier(&mockHistory{entries: []HistoryEntry{
		{Command: "read a.txt", Decision: Allow},
	}})
	eng.SetPriorActionQuerier(NewPriorActionIndex(time.Hour))

	req := ActionRequest{Scope: "shell", Command: "write b.txt", AgentID: "agent-1"}
	if got := eng.Check(req, "local"); got.Decision == Allow {
		t.Error("the legacy tenant-blind querier overrode the tenant-scoped one; B27 would still be open")
	}
}
