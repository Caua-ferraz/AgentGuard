package proxy

// Approval state-machine invariant tests.
//
// These pin the three security properties of the approval lifecycle —
// PENDING → RESOLVED (write-once) → CONSUMED (one-shot ALLOW) — as
// OBSERVABLE BEHAVIOR, deliberately not as implementation detail: they
// drive the queue API and the HTTP handlers exactly the way operators,
// SDK poll loops, and the /v1/check replay path do. A refactor that keeps
// the internals but reopens any of these holes fails here:
//
//	P1  A resolved decision can never be flipped (a DENY on "rm -rf" can
//	    never later read as ALLOW through any surface: 409 on the wire,
//	    status poll, or replay short-circuit).
//	P2  One human approval authorizes at most ONE execution (the replay
//	    short-circuit honors a resolved ALLOW exactly once, including
//	    under concurrent replays).
//	P3  Honoring a resolution is time-boxed (past ApprovalValidity the
//	    replay falls back into the approval flow) and read-only surfaces
//	    (status polls) never spend the capability.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/metrics"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// --- queue-level invariants -------------------------------------------------

func addPendingShell(t *testing.T, q *ApprovalQueue, tenant string) *PendingAction {
	t.Helper()
	pa, err := q.Add(
		policy.ActionRequest{Scope: "shell", Command: "rm -rf ./old_data", AgentID: "sm-test"},
		policy.CheckResult{Decision: policy.RequireApproval},
		tenant,
	)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	return pa
}

// TestApprovalResolve_WriteOnce pins P1 at the queue layer: the first
// decision stands forever. Repeating it is an idempotent no-op (retried
// HTTP requests must be harmless); the opposite decision is rejected with
// *ApprovalConflictError and mutates nothing — not the decision, not the
// timestamp, not the actor stamp.
func TestApprovalResolve_WriteOnce(t *testing.T) {
	q := NewApprovalQueue(0)
	pa := addPendingShell(t, q, "")

	if err := q.ResolveWithActor(pa.ID, policy.Deny, "", "bearer", "10.0.0.1"); err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	first, _ := q.Lookup(pa.ID, "")

	// Idempotent repeat: same decision, nil error, nothing mutated.
	if err := q.ResolveWithActor(pa.ID, policy.Deny, "", "session", "10.9.9.9"); err != nil {
		t.Fatalf("idempotent repeat must not error: %v", err)
	}
	after, _ := q.Lookup(pa.ID, "")
	if !after.ResolvedAt.Equal(first.ResolvedAt) || after.ResolvedVia != "bearer" || after.ResolvedFrom != "10.0.0.1" {
		t.Errorf("idempotent repeat mutated the record: first=%+v after=%+v", first, after)
	}

	// Conflicting flip: typed error, nothing mutated.
	err := q.ResolveWithActor(pa.ID, policy.Allow, "", "bearer", "10.0.0.2")
	conflict, ok := err.(*ApprovalConflictError)
	if !ok {
		t.Fatalf("flip must return *ApprovalConflictError, got %T (%v)", err, err)
	}
	if conflict.Existing != string(policy.Deny) || conflict.ID != pa.ID {
		t.Errorf("conflict payload = %+v, want Existing=DENY ID=%s", conflict, pa.ID)
	}
	final, _ := q.Lookup(pa.ID, "")
	if final.Decision != string(policy.Deny) || !final.ResolvedAt.Equal(first.ResolvedAt) {
		t.Errorf("flip mutated the record: %+v", final)
	}
}

// TestApprovalResolve_NoDuplicateBroadcast: exactly one SSE "resolved"
// event per approval, no matter how many times the resolution request is
// retried. Duplicate events would make dashboards re-render (cosmetic) but
// more importantly would mask a real double-resolution bug.
func TestApprovalResolve_NoDuplicateBroadcast(t *testing.T) {
	q := NewApprovalQueue(0)
	pa := addPendingShell(t, q, "")
	ch := q.Subscribe(policy.LocalTenantID)

	_ = q.Resolve(pa.ID, policy.Deny, "")
	_ = q.Resolve(pa.ID, policy.Deny, "")   // idempotent repeat
	_ = q.Resolve(pa.ID, policy.Allow, "")  // rejected flip
	pa2 := addPendingShell(t, q, "")        // unrelated marker event…
	_ = q.Resolve(pa2.ID, policy.Allow, "") // …to bound the wait

	var resolvedForPA int
	deadline := time.After(2 * time.Second)
	for {
		select {
		case ev := <-ch:
			if ev.Type == "resolved" && ev.Request.Command == "rm -rf ./old_data" {
				resolvedForPA++
			}
			if ev.Type == "resolved" && resolvedForPA >= 1 && ev.Result.Decision == policy.Allow {
				// marker's resolution arrived — everything before it is in.
				if resolvedForPA != 2 { // pa (1) + marker (1)
					t.Errorf("expected exactly 1 resolved event for the approval + 1 marker, counted %d total", resolvedForPA)
				}
				return
			}
		case <-deadline:
			t.Fatal("timed out waiting for SSE resolution events")
		}
	}
}

// TestConsumeResolved_AllowIsOneShot pins P2 at the queue layer.
func TestConsumeResolved_AllowIsOneShot(t *testing.T) {
	q := NewApprovalQueue(0)
	pa := addPendingShell(t, q, "")
	_ = q.Resolve(pa.ID, policy.Allow, "")

	now := time.Now().UTC()
	cp, outcome := q.ConsumeResolved(pa.ID, "", now, 0)
	if outcome != consumeHonored || cp == nil || cp.ConsumedAt.IsZero() {
		t.Fatalf("first consume: outcome=%v cp=%+v, want Honored with ConsumedAt set", outcome, cp)
	}
	if _, outcome := q.ConsumeResolved(pa.ID, "", now, 0); outcome != consumeAlreadyConsumed {
		t.Errorf("second consume: outcome=%v, want AlreadyConsumed", outcome)
	}
}

// TestConsumeResolved_ConcurrentReplaysExactlyOneHonored is the strongest
// form of P2: under 64 racing replays of one approved id, exactly one may
// be honored. Run with -race in CI; any locking regression in
// ConsumeResolved shows up here as either a race report or honored != 1.
func TestConsumeResolved_ConcurrentReplaysExactlyOneHonored(t *testing.T) {
	q := NewApprovalQueue(0)
	pa := addPendingShell(t, q, "")
	_ = q.Resolve(pa.ID, policy.Allow, "")

	const replays = 64
	var wg sync.WaitGroup
	var mu sync.Mutex
	counts := map[consumeOutcome]int{}
	start := make(chan struct{})
	for i := 0; i < replays; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, outcome := q.ConsumeResolved(pa.ID, "", time.Now().UTC(), 0)
			mu.Lock()
			counts[outcome]++
			mu.Unlock()
		}()
	}
	close(start)
	wg.Wait()

	if counts[consumeHonored] != 1 {
		t.Errorf("exactly 1 of %d concurrent replays may be honored, got %d (all: %v)", replays, counts[consumeHonored], counts)
	}
	if counts[consumeAlreadyConsumed] != replays-1 {
		t.Errorf("expected %d AlreadyConsumed, got %d (all: %v)", replays-1, counts[consumeAlreadyConsumed], counts)
	}
}

// TestConsumeResolved_DenyStickyWithinValidity: a resolved DENY is honored
// repeatedly (replaying a denial is harmless and keeps a retrying model on
// an immediate deny) — consumption is an ALLOW-only concept.
func TestConsumeResolved_DenyStickyWithinValidity(t *testing.T) {
	q := NewApprovalQueue(0)
	pa := addPendingShell(t, q, "")
	_ = q.Resolve(pa.ID, policy.Deny, "")

	for i := 0; i < 3; i++ {
		cp, outcome := q.ConsumeResolved(pa.ID, "", time.Now().UTC(), time.Hour)
		if outcome != consumeHonored || cp.Decision != string(policy.Deny) || !cp.ConsumedAt.IsZero() {
			t.Fatalf("deny replay %d: outcome=%v cp=%+v, want Honored DENY with zero ConsumedAt", i, outcome, cp)
		}
	}
}

// TestConsumeResolved_StateEdges covers the remaining transitions: pending
// entries are reported (not consumed), tenant mismatches leak nothing, a
// backdated resolution past the validity window is Expired, and validity 0
// disables the expiry bound.
func TestConsumeResolved_StateEdges(t *testing.T) {
	q := newTenantTestQueue()
	pa := addPendingShell(t, q, "tenant-a")

	if cp, outcome := q.ConsumeResolved(pa.ID, "tenant-a", time.Now().UTC(), time.Hour); outcome != consumePending || cp.Resolved {
		t.Errorf("pending entry: outcome=%v cp=%+v, want Pending unconsumed", outcome, cp)
	}
	if _, outcome := q.ConsumeResolved(pa.ID, "tenant-b", time.Now().UTC(), time.Hour); outcome != consumeNotFound {
		t.Errorf("cross-tenant consume: outcome=%v, want NotFound (no oracle)", outcome)
	}

	_ = q.Resolve(pa.ID, policy.Allow, "tenant-a")
	// Backdate the resolution instead of sleeping: deterministic expiry.
	q.mu.Lock()
	q.pending[pa.ID].ResolvedAt = time.Now().UTC().Add(-time.Hour)
	q.mu.Unlock()

	if _, outcome := q.ConsumeResolved(pa.ID, "tenant-a", time.Now().UTC(), time.Minute); outcome != consumeExpired {
		t.Errorf("stale resolution: outcome=%v, want Expired", outcome)
	}
	if _, outcome := q.ConsumeResolved(pa.ID, "tenant-a", time.Now().UTC(), 0); outcome != consumeHonored {
		t.Errorf("validity 0 must disable expiry: outcome=%v, want Honored", outcome)
	}
}

// TestApprovalStateSurvivesSnapshotRestore: a consumed ALLOW must stay
// consumed across write-behind persistence — otherwise a restart would
// resurrect a spent approval as replayable (P2 across process lifetimes).
// The actor stamp must survive for the same incident-forensics reason.
func TestApprovalStateSurvivesSnapshotRestore(t *testing.T) {
	q := NewApprovalQueue(0)
	pa := addPendingShell(t, q, "")
	_ = q.ResolveWithActor(pa.ID, policy.Allow, "", "session", "192.0.2.7")
	if _, outcome := q.ConsumeResolved(pa.ID, "", time.Now().UTC(), 0); outcome != consumeHonored {
		t.Fatalf("setup consume failed: %v", outcome)
	}

	q2 := NewApprovalQueue(0)
	q2.Restore(q.Snapshot())

	cp, ok := q2.Lookup(pa.ID, "")
	if !ok || cp.ConsumedAt.IsZero() || cp.ResolvedVia != "session" || cp.ResolvedFrom != "192.0.2.7" {
		t.Fatalf("restored entry lost state: ok=%v cp=%+v", ok, cp)
	}
	if _, outcome := q2.ConsumeResolved(pa.ID, "", time.Now().UTC(), 0); outcome != consumeAlreadyConsumed {
		t.Errorf("restored consumed ALLOW must stay spent: outcome=%v, want AlreadyConsumed", outcome)
	}
}

// --- HTTP-level invariants ---------------------------------------------------

// smCheck POSTs a /v1/check and decodes the result.
func smCheck(t *testing.T, srv *Server, body string) policy.CheckResult {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/check", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handleCheck(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("check returned %d: %s", w.Code, w.Body.String())
	}
	var res policy.CheckResult
	if err := json.NewDecoder(w.Body).Decode(&res); err != nil {
		t.Fatalf("decode check result: %v", err)
	}
	return res
}

// smResolve POSTs approve/deny with a Bearer header and returns the recorder.
func smResolve(t *testing.T, srv *Server, verb, id string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/"+verb+"/"+id, nil)
	req.Header.Set("Authorization", "Bearer test-secret")
	w := httptest.NewRecorder()
	switch verb {
	case "approve":
		srv.handleApprove(w, req)
	case "deny":
		srv.handleDeny(w, req)
	default:
		t.Fatalf("bad verb %q", verb)
	}
	return w
}

const smSudo = `{"scope":"shell","command":"sudo make sandwich","agent_id":"sm-agent"}`

func smSudoWithApproval(id string) string {
	return fmt.Sprintf(`{"scope":"shell","command":"sudo make sandwich","agent_id":"sm-agent","approval_id":"%s"}`, id)
}

// TestDeniedApprovalCanNeverBecomeExecutable is THE regression test for
// the last-write-wins flip: once a human denies, no later approve call —
// mistaken, duplicated, or malicious — may make the action executable
// through any surface.
func TestDeniedApprovalCanNeverBecomeExecutable(t *testing.T) {
	srv := newTestServer(t)

	res := smCheck(t, srv, smSudo)
	if res.Decision != policy.RequireApproval || res.ApprovalID == "" {
		t.Fatalf("setup: expected REQUIRE_APPROVAL with id, got %+v", res)
	}
	id := res.ApprovalID

	if w := smResolve(t, srv, "deny", id); w.Code != http.StatusOK {
		t.Fatalf("deny returned %d: %s", w.Code, w.Body.String())
	}

	// The flip attempt must be rejected with 409 and a structured body.
	w := smResolve(t, srv, "approve", id)
	if w.Code != http.StatusConflict {
		t.Fatalf("approve-after-deny returned %d, want 409: %s", w.Code, w.Body.String())
	}
	var conflict map[string]string
	if err := json.NewDecoder(w.Body).Decode(&conflict); err != nil {
		t.Fatalf("decode 409 body: %v", err)
	}
	if conflict["error"] != "already resolved" || conflict["status"] != "denied" || conflict["id"] != id {
		t.Errorf("409 body = %v, want {error: already resolved, status: denied, id: %s}", conflict, id)
	}

	// Status must still read DENY.
	sreq := httptest.NewRequest(http.MethodGet, "/v1/status/"+id, nil)
	sw := httptest.NewRecorder()
	srv.handleStatus(sw, sreq)
	if !strings.Contains(sw.Body.String(), `"resolved"`) || !strings.Contains(sw.Body.String(), string(policy.Deny)) {
		t.Errorf("status after flip attempt = %s, want resolved DENY", sw.Body.String())
	}

	// And the replay path must yield DENY — never ALLOW.
	replay := smCheck(t, srv, smSudoWithApproval(id))
	if replay.Decision == policy.Allow {
		t.Fatalf("SECURITY: denied approval became executable via replay: %+v", replay)
	}
}

// TestApprovedActionExecutesExactlyOnce pins P2 end-to-end: the first
// matching replay is honored via rule allow:approved; the second falls
// back into the approval flow under a FRESH id (never a repeat ALLOW).
func TestApprovedActionExecutesExactlyOnce(t *testing.T) {
	srv := newTestServer(t)

	res := smCheck(t, srv, smSudo)
	id := res.ApprovalID
	if w := smResolve(t, srv, "approve", id); w.Code != http.StatusOK {
		t.Fatalf("approve returned %d", w.Code)
	}

	consumedBefore := metrics.ApprovalReplayRefusedTotal("consumed")

	first := smCheck(t, srv, smSudoWithApproval(id))
	if first.Decision != policy.Allow || first.Rule != "allow:approved" {
		t.Fatalf("first replay: %+v, want ALLOW allow:approved", first)
	}

	second := smCheck(t, srv, smSudoWithApproval(id))
	if second.Decision == policy.Allow {
		t.Fatalf("SECURITY: one approval authorized a second execution: %+v", second)
	}
	if second.Decision != policy.RequireApproval || second.ApprovalID == "" || second.ApprovalID == id {
		t.Errorf("second replay must re-enter the approval flow under a fresh id: %+v", second)
	}
	if got := metrics.ApprovalReplayRefusedTotal("consumed"); got != consumedBefore+1 {
		t.Errorf("refused{consumed} counter delta = %d, want 1", got-consumedBefore)
	}
}

// TestStatusPollingDoesNotConsumeApproval: the SDK poll loop and dashboards
// read /v1/status freely; only the replay path may spend the capability.
func TestStatusPollingDoesNotConsumeApproval(t *testing.T) {
	srv := newTestServer(t)

	res := smCheck(t, srv, smSudo)
	id := res.ApprovalID
	_ = smResolve(t, srv, "approve", id)

	for i := 0; i < 5; i++ {
		sreq := httptest.NewRequest(http.MethodGet, "/v1/status/"+id, nil)
		sw := httptest.NewRecorder()
		srv.handleStatus(sw, sreq)
		if sw.Code != http.StatusOK {
			t.Fatalf("status poll %d returned %d", i, sw.Code)
		}
	}

	replay := smCheck(t, srv, smSudoWithApproval(id))
	if replay.Decision != policy.Allow {
		t.Errorf("status polls must not consume the approval; replay got %+v", replay)
	}
}

// TestStaleResolutionFallsBackToApprovalFlow pins P3: past
// Config.ApprovalValidity, a resolved approval is no longer honored — the
// replay re-enters the approval flow instead of executing.
func TestStaleResolutionFallsBackToApprovalFlow(t *testing.T) {
	srv := newTestServer(t, func(c *Config) { c.ApprovalValidity = time.Minute })

	res := smCheck(t, srv, smSudo)
	id := res.ApprovalID
	_ = smResolve(t, srv, "approve", id)

	// Backdate the resolution instead of sleeping: deterministic.
	srv.approval.mu.Lock()
	srv.approval.pending[id].ResolvedAt = time.Now().UTC().Add(-2 * time.Minute)
	srv.approval.mu.Unlock()

	expiredBefore := metrics.ApprovalReplayRefusedTotal("expired")
	replay := smCheck(t, srv, smSudoWithApproval(id))
	if replay.Decision == policy.Allow {
		t.Fatalf("SECURITY: stale resolution was honored: %+v", replay)
	}
	if replay.Decision != policy.RequireApproval || replay.ApprovalID == id {
		t.Errorf("stale replay must re-enter the approval flow under a fresh id: %+v", replay)
	}
	if got := metrics.ApprovalReplayRefusedTotal("expired"); got != expiredBefore+1 {
		t.Errorf("refused{expired} counter delta = %d, want 1", got-expiredBefore)
	}
}

// TestApprovalActorStamped: resolutions record how they arrived. Not
// identity (single-key auth has none) but enough to reconstruct an
// incident; the write-once latch makes the stamp trustworthy.
func TestApprovalActorStamped(t *testing.T) {
	srv := newTestServer(t)

	res := smCheck(t, srv, smSudo)
	id := res.ApprovalID
	_ = smResolve(t, srv, "approve", id) // Bearer header path

	pa, ok := srv.approval.Lookup(id, policy.LocalTenantID)
	if !ok {
		t.Fatal("approval vanished")
	}
	if pa.ResolvedVia != "bearer" || pa.ResolvedFrom == "" {
		t.Errorf("actor stamp = via=%q from=%q, want via=bearer with non-empty from", pa.ResolvedVia, pa.ResolvedFrom)
	}
}
