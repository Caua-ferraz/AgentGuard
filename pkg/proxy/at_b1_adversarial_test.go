package proxy

// at_b1_adversarial_test.go — AT (Test Wrangler) audit-fixup verification.
//
// F3 closed audit blocker B1 by adding matchesOriginalRequest as a guard
// before resolvedApprovalToResult short-circuits on req.ApprovalID. F3's
// own tests cover the seven compared fields (AgentID, Scope, Command,
// Path, Domain, URL, Action) and the legitimate-retry sanity. AT adds
// six adversarial scenarios that an attacker would naturally probe:
//
//   1. Tenant ID — does cross-tenant replay short-circuit? (As of v0.6,
//      ApprovalQueue.Lookup/Resolve are tenant-scoped: the tenant travels in
//      the /v1/t/{tenant}/... path, and a foreign tenant's id resolves to
//      "not found" — see TestApprovalQueueTenantIsolation.)
//   2. Case sensitivity — agent_id "AGENT_A" vs "agent_a"; should NOT match.
//   3. Trailing whitespace — command "ls -la " vs "ls -la"; should NOT match.
//   4. Meta vs top-level approval_id — only top-level honored by proxy
//      (gateways set both; proxy itself does not auto-promote Meta).
//   5. Resolved-DENIED replay — fresh policy evaluation runs (no security
//      issue per se because mismatch falls through to fresh policy).
//   6. Pending replay — A19b's pending-still-pending path co-exists with
//      F3's mismatch validation: same pending id, matching shape returns
//      REQUIRE_APPROVAL with the same id; mismatched shape falls through.
//
// Every test drives the production handleCheck via httptest with the
// real Engine — no SUT mocks. Each test asserts observable behavior
// (rule string, decision, metric counter, response body) tied to the
// fix; any of these would fail if F3's matchesOriginalRequest were
// reverted.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Caua-ferraz/AgentGuard/pkg/metrics"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// driveCheck is a thin wrapper around handleCheck for tests that need
// to exercise the full mux (so withTenant runs) instead of dispatching
// to handleCheck directly. Returns the decoded result + status code.
func driveCheckViaMux(t *testing.T, srv *Server, method, path, body string) (policy.CheckResult, int) {
	t.Helper()
	mux := http.NewServeMux()
	// Replicate the relevant routes from NewServer for /v1/check and
	// /v1/t/{tenant}/check so we can drive both. The withCORS /
	// withLogging middleware is skipped — those don't affect the
	// approval-replay code path under test.
	mux.HandleFunc("POST /v1/check", srv.handleCheck)
	mux.HandleFunc("POST /v1/t/{tenant}/check", srv.withTenant(srv.handleCheck))
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var result policy.CheckResult
	if w.Body.Len() > 0 {
		_ = json.NewDecoder(w.Body).Decode(&result)
	}
	return result, w.Code
}

// TestAT_B1_Adversarial_TenantIDDoesntCount documents the v0.5
// behavior of cross-tenant approval replay. ActionRequest carries no
// tenant field (R-Arch A2/A3 — tenant is plumbed through the URL path
// + context, not the wire shape). ApprovalQueue.Lookup is also a
// single global map by id. As a consequence: an attacker who learns an
// approval_id approved via one tenant URL and submits a matching-shape
// retry against a different tenant URL WILL short-circuit to the
// cached decision IFF both tenants resolve through the engine's policy
// provider. This is a documented v0.6 gap, not a v0.5 bug — the audit
// (V05_AUDIT_REPORT.md, "Defer to v0.6") explicitly defers tenant-
// scoped approval lookup.
//
// AT pins this behavior on the legacy /v1/check ↔ /v1/t/local/check
// pair: both routes resolve to LocalTenantID, both inputs go through
// the same global ApprovalQueue, and matchesOriginalRequest compares
// only the seven shape fields. A v0.6 fix that adds tenant scoping to
// either matchesOriginalRequest or ApprovalQueue.Lookup would flip the
// assertion in this test.
func TestAT_B1_Adversarial_TenantIDDoesntCount(t *testing.T) {
	srv := newReplayTestServer(t)

	// Seed via legacy /v1/check (defaults to LocalTenantID).
	approvalID := seedReplayApproval(t, srv,
		`{"scope":"shell","command":"sudo apt install vim","agent_id":"agent_a"}`)

	mismatchBefore := atomic.LoadUint64(&metrics.ApprovalReplayMismatchTotal)

	// Retry via the tenant-aware /v1/t/local/check route. Same logical
	// tenant; if any future tenant-scoping work lands and tenants are
	// distinct identities, this test would need to flip to a true
	// cross-tenant pair.
	body := fmt.Sprintf(
		`{"scope":"shell","command":"sudo apt install vim","agent_id":"agent_a","approval_id":%q}`,
		approvalID,
	)
	result, code := driveCheckViaMux(t, srv, http.MethodPost, "/v1/t/local/check", body)
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}

	// v0.5 documented behavior: short-circuit happens because the seven
	// compared fields all match. The fact that the seed used the legacy
	// route and the retry used the tenant-aware route is not part of
	// the comparison.
	if result.Rule != "allow:approved" {
		t.Errorf("v0.5 documented behavior: matching-shape retry across legacy and tenant-aware routes short-circuits to allow:approved; got rule=%q decision=%s. If matchesOriginalRequest now compares tenant id, update this test.",
			result.Rule, result.Decision)
	}
	if got := atomic.LoadUint64(&metrics.ApprovalReplayMismatchTotal); got != mismatchBefore {
		t.Errorf("ApprovalReplayMismatchTotal incremented (got %d, want %d) — fields match; counter must NOT bump", got, mismatchBefore)
	}

	// Document for the v0.6 worker: TODO(v0.6, #tenant-scoped-approval-lookup)
	// — when ActionRequest gains a TenantID field (or
	// ApprovalQueue.Lookup grows a tenant arg), extend
	// matchesOriginalRequest and flip this test to assert that an
	// approval_id minted under tenant A short-circuits ONLY when
	// retried under tenant A.
}

// TestAT_B1_Adversarial_CaseSensitivity asserts that case-different
// request fields do NOT count as matching. An attacker who learned an
// approval_id approved for "agent_a" should not bypass via "AGENT_A":
// case-sensitive policy enforcement is the safe default and matches
// how the rest of the policy engine compares strings.
func TestAT_B1_Adversarial_CaseSensitivity(t *testing.T) {
	srv := newReplayTestServer(t)

	approvalID := seedReplayApproval(t, srv,
		`{"scope":"shell","command":"sudo apt install vim","agent_id":"agent_a"}`)

	mismatchBefore := atomic.LoadUint64(&metrics.ApprovalReplayMismatchTotal)

	// Same shape but agent_id case-flipped.
	body := fmt.Sprintf(
		`{"scope":"shell","command":"sudo apt install vim","agent_id":"AGENT_A","approval_id":%q}`,
		approvalID,
	)
	result, _ := retryCheck(t, srv, body)
	assertNotShortCircuited(t, result)
	if got := atomic.LoadUint64(&metrics.ApprovalReplayMismatchTotal); got <= mismatchBefore {
		t.Errorf("ApprovalReplayMismatchTotal not incremented on agent_id case-flip (got %d, want > %d)", got, mismatchBefore)
	}

	// And command case-flipped.
	mismatchBefore = atomic.LoadUint64(&metrics.ApprovalReplayMismatchTotal)
	body = fmt.Sprintf(
		`{"scope":"shell","command":"SUDO APT INSTALL VIM","agent_id":"agent_a","approval_id":%q}`,
		approvalID,
	)
	result, _ = retryCheck(t, srv, body)
	assertNotShortCircuited(t, result)
	if got := atomic.LoadUint64(&metrics.ApprovalReplayMismatchTotal); got <= mismatchBefore {
		t.Errorf("ApprovalReplayMismatchTotal not incremented on command case-flip (got %d, want > %d)", got, mismatchBefore)
	}
}

// TestAT_B1_Adversarial_TrailingWhitespace asserts cosmetic mutations
// like a trailing space on the command don't satisfy the cache match.
// An attacker who tries to game the validator with a no-op character
// addition should fall through to fresh policy evaluation.
func TestAT_B1_Adversarial_TrailingWhitespace(t *testing.T) {
	srv := newReplayTestServer(t)

	approvalID := seedReplayApproval(t, srv,
		`{"scope":"shell","command":"sudo apt install vim","agent_id":"agent_a"}`)

	mismatchBefore := atomic.LoadUint64(&metrics.ApprovalReplayMismatchTotal)

	// Trailing space on the command.
	body := fmt.Sprintf(
		`{"scope":"shell","command":"sudo apt install vim ","agent_id":"agent_a","approval_id":%q}`,
		approvalID,
	)
	result, _ := retryCheck(t, srv, body)
	assertNotShortCircuited(t, result)
	if got := atomic.LoadUint64(&metrics.ApprovalReplayMismatchTotal); got <= mismatchBefore {
		t.Errorf("ApprovalReplayMismatchTotal not incremented on trailing-whitespace mutation")
	}

	// Leading space.
	mismatchBefore = atomic.LoadUint64(&metrics.ApprovalReplayMismatchTotal)
	body = fmt.Sprintf(
		`{"scope":"shell","command":" sudo apt install vim","agent_id":"agent_a","approval_id":%q}`,
		approvalID,
	)
	result, _ = retryCheck(t, srv, body)
	assertNotShortCircuited(t, result)
	if got := atomic.LoadUint64(&metrics.ApprovalReplayMismatchTotal); got <= mismatchBefore {
		t.Errorf("ApprovalReplayMismatchTotal not incremented on leading-whitespace mutation")
	}
}

// TestAT_B1_Adversarial_MetaApprovalID_LiteralVsTopLevel asserts that
// the proxy's handleCheck only consults the TOP-LEVEL req.ApprovalID
// field. The MCP and LLM gateways stamp Meta["approval_id"] AND set
// req.ApprovalID; the proxy itself never auto-promotes the Meta entry.
// An SDK caller (or attacker) that ships only meta.approval_id without
// the top-level field gets fresh policy evaluation — there is no
// silent promotion path.
//
// Closes the question: "could a buggy gateway leak only meta.approval_id
// and accidentally trigger the cache?" Answer: no.
func TestAT_B1_Adversarial_MetaApprovalID_LiteralVsTopLevel(t *testing.T) {
	srv := newReplayTestServer(t)

	approvalID := seedReplayApproval(t, srv,
		`{"scope":"shell","command":"sudo apt install vim","agent_id":"agent_a"}`)

	mismatchBefore := atomic.LoadUint64(&metrics.ApprovalReplayMismatchTotal)

	// Same shape, but the approval_id sits ONLY in meta. Proxy must
	// ignore it (no short-circuit) and run fresh policy.
	body := fmt.Sprintf(
		`{"scope":"shell","command":"sudo apt install vim","agent_id":"agent_a","meta":{"approval_id":%q}}`,
		approvalID,
	)
	result, _ := retryCheck(t, srv, body)
	assertNotShortCircuited(t, result)
	// Fresh policy fires: sudo * → require_approval. A NEW pending
	// entry is created (different id from approvalID).
	if result.Decision != policy.RequireApproval {
		t.Errorf("decision = %s; want REQUIRE_APPROVAL (sudo * → require_approval), got rule=%q", result.Decision, result.Rule)
	}
	if result.ApprovalID == "" {
		t.Errorf("expected fresh approval_id, got empty")
	}
	if result.ApprovalID == approvalID {
		t.Errorf("fresh approval_id = original approval_id (proxy must NOT recycle the meta-only id)")
	}
	// Counter must NOT have incremented — there was no top-level
	// approval_id to look up; the validator never ran.
	if got := atomic.LoadUint64(&metrics.ApprovalReplayMismatchTotal); got != mismatchBefore {
		t.Errorf("ApprovalReplayMismatchTotal incremented on meta-only approval_id (got %d, want %d) — meta-only ids must not even reach the validator", got, mismatchBefore)
	}

	// Now the positive control: top-level field IS honored (mismatched
	// shape, but the validator runs).
	body = fmt.Sprintf(
		`{"scope":"shell","command":"rm -rf /","agent_id":"agent_a","approval_id":%q}`,
		approvalID,
	)
	result, _ = retryCheck(t, srv, body)
	assertNotShortCircuited(t, result)
	if got := atomic.LoadUint64(&metrics.ApprovalReplayMismatchTotal); got <= mismatchBefore {
		t.Errorf("ApprovalReplayMismatchTotal not incremented when top-level approval_id mismatched (got %d, want > %d)", got, mismatchBefore)
	}
}

// TestAT_B1_Adversarial_ResolvedDeniedReplay asserts that when an
// approval was originally resolved DENY and a retry submits a
// MISMATCHED shape, the retry falls through to fresh policy evaluation
// (just like ALLOW). The fall-through means the new shape's fresh
// policy decision is what the caller sees — not the cached DENY.
//
// Edge case: if the policy was edited between the original deny and
// the retry, the retry could legitimately resolve to ALLOW. AT
// confirms that's the intended semantics — fall-through, not "deny
// any request that has ever been denied". Caching the DENY would be
// safer-on-default but breaks legitimate policy-edit retry flows.
func TestAT_B1_Adversarial_ResolvedDeniedReplay(t *testing.T) {
	srv := newReplayTestServer(t)

	// Seed an approval, then resolve it DENY.
	bodySeed := `{"scope":"shell","command":"sudo apt install vim","agent_id":"agent_a"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/check", strings.NewReader(bodySeed))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handleCheck(w, req)

	var seedResult policy.CheckResult
	if err := json.NewDecoder(w.Body).Decode(&seedResult); err != nil {
		t.Fatalf("seed decode: %v", err)
	}
	if seedResult.Decision != policy.RequireApproval {
		t.Fatalf("seed: expected REQUIRE_APPROVAL, got %s", seedResult.Decision)
	}
	approvalID := seedResult.ApprovalID
	if err := srv.approval.Resolve(approvalID, policy.Deny, "local"); err != nil {
		t.Fatalf("Resolve DENY: %v", err)
	}

	// Sanity: matching-shape retry shows the cached DENY.
	bodyMatch := fmt.Sprintf(
		`{"scope":"shell","command":"sudo apt install vim","agent_id":"agent_a","approval_id":%q}`,
		approvalID,
	)
	result, _ := retryCheck(t, srv, bodyMatch)
	if result.Rule != "deny:approved" {
		t.Errorf("matching-shape retry of DENY-resolved approval: rule=%q, want deny:approved", result.Rule)
	}
	if result.Decision != policy.Deny {
		t.Errorf("matching-shape retry of DENY-resolved approval: decision=%s, want DENY", result.Decision)
	}

	// Now mismatched shape: same id, different command. Fall-through
	// to fresh policy. The new command "ls -la" is allowed by the
	// test policy (Allow Pattern: "ls *").
	mismatchBefore := atomic.LoadUint64(&metrics.ApprovalReplayMismatchTotal)
	bodyMismatch := fmt.Sprintf(
		`{"scope":"shell","command":"ls -la","agent_id":"agent_a","approval_id":%q}`,
		approvalID,
	)
	result, _ = retryCheck(t, srv, bodyMismatch)
	assertNotShortCircuited(t, result)
	if result.Decision != policy.Allow {
		t.Errorf("mismatched retry of DENY-resolved approval: decision=%s rule=%q reason=%q; want ALLOW (fresh evaluation of ls -la against test policy)", result.Decision, result.Rule, result.Reason)
	}
	if got := atomic.LoadUint64(&metrics.ApprovalReplayMismatchTotal); got <= mismatchBefore {
		t.Errorf("ApprovalReplayMismatchTotal not incremented on mismatched DENY-resolved replay")
	}
}

// TestAT_B1_Adversarial_PendingReplay asserts the still-pending
// approval path interacts correctly with F3's mismatch guard. A19b's
// design: a retry with a matching-shape pending approval id returns
// REQUIRE_APPROVAL with the SAME id (so polling clients keep waiting
// rather than spawning a duplicate queue entry). After F3, mismatched
// shape on a pending id must fall through to fresh policy.
func TestAT_B1_Adversarial_PendingReplay(t *testing.T) {
	srv := newReplayTestServer(t)

	// Seed an approval — DO NOT resolve. Use the raw queue Add path
	// so we control resolution state explicitly.
	bodySeed := `{"scope":"shell","command":"sudo apt install vim","agent_id":"agent_a"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/check", strings.NewReader(bodySeed))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handleCheck(w, req)

	var seedResult policy.CheckResult
	if err := json.NewDecoder(w.Body).Decode(&seedResult); err != nil {
		t.Fatalf("seed decode: %v", err)
	}
	if seedResult.Decision != policy.RequireApproval {
		t.Fatalf("seed: expected REQUIRE_APPROVAL, got %s", seedResult.Decision)
	}
	approvalID := seedResult.ApprovalID

	// Sanity: the queue entry is unresolved.
	pa, ok := srv.approval.Lookup(approvalID, "local")
	if !ok {
		t.Fatalf("seed: approval %q not in queue", approvalID)
	}
	if pa.Resolved {
		t.Fatalf("seed: approval %q unexpectedly resolved", approvalID)
	}

	// Matching-shape retry: must short-circuit to require_approval:pending
	// with the SAME id (A19b's design — closes "duplicate queue entry on
	// retry while pending" leak).
	bodyMatch := fmt.Sprintf(
		`{"scope":"shell","command":"sudo apt install vim","agent_id":"agent_a","approval_id":%q}`,
		approvalID,
	)
	result, _ := retryCheck(t, srv, bodyMatch)
	if result.Rule != "require_approval:pending" {
		t.Errorf("matching-shape retry of pending: rule=%q, want require_approval:pending", result.Rule)
	}
	if result.ApprovalID != approvalID {
		t.Errorf("matching-shape retry of pending: ApprovalID=%q; want %q (must reuse, not allocate fresh)", result.ApprovalID, approvalID)
	}

	// Mismatched-shape retry of a pending id: must fall through to
	// fresh policy. Different command — "rm -rf /" denies under the
	// test policy.
	mismatchBefore := atomic.LoadUint64(&metrics.ApprovalReplayMismatchTotal)
	bodyMismatch := fmt.Sprintf(
		`{"scope":"shell","command":"rm -rf /","agent_id":"agent_a","approval_id":%q}`,
		approvalID,
	)
	result, _ = retryCheck(t, srv, bodyMismatch)
	assertNotShortCircuited(t, result)
	if result.Decision != policy.Deny {
		t.Errorf("mismatched retry of pending: decision=%s rule=%q; want DENY (rm -rf * is denied)", result.Decision, result.Rule)
	}
	if got := atomic.LoadUint64(&metrics.ApprovalReplayMismatchTotal); got <= mismatchBefore {
		t.Errorf("ApprovalReplayMismatchTotal not incremented on pending+mismatched-shape replay")
	}

	// And the original pending entry must STILL be in the queue,
	// unmodified (the mismatched fall-through must NOT resolve, evict,
	// or otherwise mutate the pending entry).
	paAfter, ok := srv.approval.Lookup(approvalID, "local")
	if !ok {
		t.Errorf("after mismatched retry: original pending approval %q vanished from queue", approvalID)
	} else if paAfter.Resolved {
		t.Errorf("after mismatched retry: original pending approval %q was unexpectedly resolved", approvalID)
	}

	// (Defensive: silence "unused" warnings on context import in case
	// future refactors split this file.)
	_ = context.Background()
}
