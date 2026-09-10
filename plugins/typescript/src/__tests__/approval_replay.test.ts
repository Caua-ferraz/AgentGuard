/**
 * Approval replay and request-timeout coverage (review findings R1, R5).
 *
 * R1 contract: after `waitForApproval` resolves ALLOW, `guarded(...,
 * { waitForApproval: true })` must replay the approval through `/v1/check`
 * with `approval_id` set — the only call that spends the one-shot
 * capability, applies `--approval-validity`, reserves cost and audits the
 * execution — and must run the wrapped function only if that replay allows.
 * Every test asserts the exact sequence of fetch calls, so a wrapper that
 * runs straight off the read-only status poll (the pre-fix behaviour) fails.
 *
 * R5 contract: every request the SDK makes is bounded by `timeout`, and the
 * bound covers the body read, not just the headers.
 */

import {
  AgentGuard,
  guarded,
  AgentGuardDeniedError,
  AgentGuardApprovalRequiredError,
} from "../index";

type FetchArgs = [string | URL, RequestInit?];
type FetchMock = jest.Mock<Promise<Response>, FetchArgs>;

function installFetchMock(): FetchMock {
  const m = jest.fn() as unknown as FetchMock;
  (globalThis as { fetch: unknown }).fetch = m;
  return m;
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

const REQUIRE_FIRST = {
  decision: "REQUIRE_APPROVAL",
  reason: "needs review",
  approval_id: "ap_first",
  approval_url: "http://localhost:8080/v1/approve/ap_first",
};
const RESOLVED_ALLOW = {
  id: "ap_first",
  status: "resolved",
  decision: "ALLOW",
  reason: "human approved",
};

/** Decoded bodies of every POST /v1/check the mock saw, in order. */
function checkBodies(m: FetchMock): Record<string, unknown>[] {
  return m.mock.calls
    .filter(([url, init]) => String(url).endsWith("/v1/check") && init?.method === "POST")
    .map(([, init]) => JSON.parse(String(init?.body)) as Record<string, unknown>);
}

function calledPaths(m: FetchMock): string[] {
  return m.mock.calls.map(([url, init]) => `${init?.method ?? "GET"} ${new URL(String(url)).pathname}`);
}

type AnyAsyncFn = (...args: unknown[]) => Promise<unknown>;

describe("check() carries approval_id on the wire", () => {
  test("sends approval_id when given", async () => {
    const m = installFetchMock();
    m.mockResolvedValueOnce(jsonResponse({ decision: "ALLOW", reason: "ok" }));
    const guard = new AgentGuard({ agentId: "bot" });
    await guard.check("shell", { command: "ls", approvalId: "ap_xyz" });
    const body = checkBodies(m)[0];
    expect(body.approval_id).toBe("ap_xyz");
    expect(body.scope).toBe("shell");
    expect(body.command).toBe("ls");
  });

  test("omits approval_id by default", async () => {
    const m = installFetchMock();
    m.mockResolvedValueOnce(jsonResponse({ decision: "ALLOW", reason: "ok" }));
    await new AgentGuard().check("shell", { command: "ls" });
    expect(checkBodies(m)[0]).not.toHaveProperty("approval_id");
  });

  test("omits an empty approval_id", async () => {
    const m = installFetchMock();
    m.mockResolvedValueOnce(jsonResponse({ decision: "ALLOW", reason: "ok" }));
    await new AgentGuard().check("shell", { command: "ls", approvalId: "" });
    expect(checkBodies(m)[0]).not.toHaveProperty("approval_id");
  });

  test("uses snake_case on the wire (approvalId is never sent verbatim)", async () => {
    const m = installFetchMock();
    m.mockResolvedValueOnce(jsonResponse({ decision: "ALLOW", reason: "ok" }));
    await new AgentGuard().check("shell", { command: "ls", approvalId: "ap_1" });
    expect(checkBodies(m)[0]).not.toHaveProperty("approvalId");
  });
});

describe("guarded() replays the approval", () => {
  test("replays with approval_id before running the function", async () => {
    const m = installFetchMock();
    m.mockResolvedValueOnce(jsonResponse(REQUIRE_FIRST));
    m.mockResolvedValueOnce(jsonResponse(RESOLVED_ALLOW));
    m.mockResolvedValueOnce(
      jsonResponse({ decision: "ALLOW", reason: "approved", matched_rule: "allow:approved" })
    );
    const guard = new AgentGuard({ agentId: "bot" });
    const fn = jest.fn(async (...args) => `ran ${String(args[0])}`);
    const safe = guarded(guard, "shell", fn as unknown as AnyAsyncFn, {
      waitForApproval: true,
      approvalTimeoutMs: 2000,
      approvalPollIntervalMs: 5,
    });

    await expect(safe("sudo deploy")).resolves.toBe("ran sudo deploy");
    expect(fn).toHaveBeenCalledTimes(1);

    const bodies = checkBodies(m);
    expect(bodies).toHaveLength(2);
    const [first, replay] = bodies;
    expect(first).not.toHaveProperty("approval_id");
    expect(replay.approval_id).toBe("ap_first");
    // Same shape as the original so the server's shape guard matches.
    expect(replay.scope).toBe(first.scope);
    expect(replay.command).toBe(first.command);
    expect(replay.agent_id).toBe(first.agent_id);
    // Order: check → status poll → replay.
    expect(calledPaths(m)).toEqual([
      "POST /v1/check",
      "GET /v1/status/ap_first",
      "POST /v1/check",
    ]);
  });

  test("replay carries the getCheckOptions payload", async () => {
    const m = installFetchMock();
    m.mockResolvedValueOnce(jsonResponse(REQUIRE_FIRST));
    m.mockResolvedValueOnce(jsonResponse(RESOLVED_ALLOW));
    m.mockResolvedValueOnce(jsonResponse({ decision: "ALLOW", reason: "ok" }));
    const guard = new AgentGuard();
    const fn = jest.fn(async () => "spent");
    const safe = guarded(guard, "cost", fn as unknown as AnyAsyncFn, {
      getCheckOptions: () => ({ estCost: 12.5, sessionId: "sess-9" }),
      waitForApproval: true,
      approvalTimeoutMs: 2000,
      approvalPollIntervalMs: 5,
    });

    await expect(safe("train")).resolves.toBe("spent");
    const [first, replay] = checkBodies(m);
    for (const body of [first, replay]) {
      expect(body.est_cost).toBe(12.5);
      expect(body.session_id).toBe("sess-9");
    }
    expect(replay.approval_id).toBe("ap_first");
  });

  test("a denied replay never runs the function", async () => {
    const m = installFetchMock();
    m.mockResolvedValueOnce(jsonResponse(REQUIRE_FIRST));
    m.mockResolvedValueOnce(jsonResponse(RESOLVED_ALLOW));
    m.mockResolvedValueOnce(
      jsonResponse({ decision: "DENY", reason: "policy changed", matched_rule: "deny:shell:sudo" })
    );
    const guard = new AgentGuard();
    const fn = jest.fn(async () => "should not run");
    const safe = guarded(guard, "shell", fn as unknown as AnyAsyncFn, {
      waitForApproval: true,
      approvalTimeoutMs: 2000,
      approvalPollIntervalMs: 5,
    });

    let caught: unknown;
    try {
      await safe("sudo deploy");
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(AgentGuardDeniedError);
    expect((caught as AgentGuardDeniedError).message).toMatch(/policy changed/);
    expect(fn).not.toHaveBeenCalled();
    expect(checkBodies(m)).toHaveLength(2);
  });

  test("a refused replay surfaces the new id and never waits again", async () => {
    const m = installFetchMock();
    m.mockResolvedValueOnce(jsonResponse(REQUIRE_FIRST));
    m.mockResolvedValueOnce(jsonResponse(RESOLVED_ALLOW));
    // The server refused the replay (consumed/expired) and re-entered the
    // approval flow under a new id.
    m.mockResolvedValueOnce(
      jsonResponse({
        decision: "REQUIRE_APPROVAL",
        reason: "needs review",
        approval_id: "ap_second",
        approval_url: "http://localhost:8080/v1/approve/ap_second",
      })
    );
    // If the wrapper waited a second time this would let it through — the
    // assertions below prove it does not.
    m.mockResolvedValue(
      jsonResponse({ id: "ap_second", status: "resolved", decision: "ALLOW" })
    );
    const guard = new AgentGuard();
    const fn = jest.fn(async () => "should not run");
    const safe = guarded(guard, "shell", fn as unknown as AnyAsyncFn, {
      waitForApproval: true,
      approvalTimeoutMs: 2000,
      approvalPollIntervalMs: 5,
    });

    let caught: unknown;
    try {
      await safe("sudo deploy");
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(AgentGuardApprovalRequiredError);
    const err = caught as AgentGuardApprovalRequiredError;
    expect(err.approvalId).toBe("ap_second");
    expect(err.approvalUrl).toMatch(/ap_second/);
    expect(fn).not.toHaveBeenCalled();
    expect(checkBodies(m)).toHaveLength(2); // no third check: no loop
    const polls = calledPaths(m).filter((p) => p.startsWith("GET /v1/status/"));
    expect(polls).toEqual(["GET /v1/status/ap_first"]);
  });

  test("a human DENY resolution needs no replay", async () => {
    const m = installFetchMock();
    m.mockResolvedValueOnce(jsonResponse(REQUIRE_FIRST));
    m.mockResolvedValueOnce(
      jsonResponse({ id: "ap_first", status: "resolved", decision: "DENY", reason: "human denied" })
    );
    const guard = new AgentGuard();
    const fn = jest.fn(async () => "should not run");
    const safe = guarded(guard, "shell", fn as unknown as AnyAsyncFn, {
      waitForApproval: true,
      approvalTimeoutMs: 2000,
      approvalPollIntervalMs: 5,
    });

    await expect(safe("sudo deploy")).rejects.toBeInstanceOf(AgentGuardDeniedError);
    expect(checkBodies(m)).toHaveLength(1);
    expect(fn).not.toHaveBeenCalled();
  });

  test("without waitForApproval the HOF throws immediately and never replays", async () => {
    const m = installFetchMock();
    m.mockResolvedValueOnce(jsonResponse(REQUIRE_FIRST));
    const guard = new AgentGuard();
    const fn = jest.fn(async () => "should not run");
    const safe = guarded(guard, "shell", fn as unknown as AnyAsyncFn);

    await expect(safe("sudo deploy")).rejects.toBeInstanceOf(AgentGuardApprovalRequiredError);
    expect(checkBodies(m)).toHaveLength(1);
    expect(fn).not.toHaveBeenCalled();
  });
});

// =========================================================================
// R5 — every request is bounded by `timeout`, body read included
// =========================================================================

/**
 * A fetch mock that only ever settles when the caller's AbortSignal fires.
 * A request made WITHOUT a signal hangs forever, so a regression that drops
 * the timeout fails the test by jest timeout instead of passing quietly.
 */
function installStallingFetch(): FetchMock {
  const m = installFetchMock();
  m.mockImplementation(
    (_url, init) =>
      new Promise<Response>((_resolve, reject) => {
        const signal = init?.signal;
        if (!signal) return; // no timeout wired → hang (test fails loudly)
        signal.addEventListener("abort", () => reject(new Error("aborted by timeout")));
      })
  );
  return m;
}

describe("request timeouts", () => {
  test("every request carries an AbortSignal", async () => {
    const m = installFetchMock();
    m.mockResolvedValue(jsonResponse({ decision: "ALLOW", reason: "ok" }));
    const guard = new AgentGuard({ timeout: 500 });
    await guard.check("shell", { command: "ls" });
    await guard.approve("ap_1");
    await guard.deny("ap_1");
    await guard.waitForApproval("ap_1", 20, 5);

    expect(m.mock.calls.length).toBeGreaterThanOrEqual(4);
    for (const [url, init] of m.mock.calls) {
      expect(init?.signal).toBeDefined();
      expect(String(url)).toMatch(/^http/);
    }
  });

  test("check() falls through to fail-mode when the server stalls", async () => {
    installStallingFetch();
    const guard = new AgentGuard({ timeout: 50 });
    const started = Date.now();
    const r = await guard.check("shell", { command: "ls" });
    expect(r.denied).toBe(true);
    expect(Date.now() - started).toBeLessThan(3000);
  });

  test("check() timeout covers the BODY read, not just the headers", async () => {
    // Headers arrive immediately; the body never does. Before the fix the
    // abort timer was cleared the moment the response resolved, so this
    // hung forever.
    const m = installFetchMock();
    m.mockImplementation(async (_url, init) => {
      const signal = init?.signal;
      return {
        ok: true,
        status: 200,
        headers: new Headers({ "Content-Type": "application/json" }),
        json: () =>
          new Promise((_resolve, reject) => {
            if (!signal) return; // no live timer → hang (test fails loudly)
            signal.addEventListener("abort", () => reject(new Error("aborted mid-body")));
          }),
      } as unknown as Response;
    });

    const guard = new AgentGuard({ timeout: 50 });
    const started = Date.now();
    const r = await guard.check("shell", { command: "ls" });
    expect(r.denied).toBe(true);
    expect(Date.now() - started).toBeLessThan(3000);
  });

  test("check() stall with failMode allow still opens (fail-mode is honoured)", async () => {
    installStallingFetch();
    const guard = new AgentGuard({ timeout: 50, failMode: "allow" });
    const r = await guard.check("shell", { command: "ls" });
    expect(r.allowed).toBe(true);
  });

  test("approve() and deny() return false instead of hanging", async () => {
    installStallingFetch();
    const guard = new AgentGuard({ timeout: 50 });
    await expect(guard.approve("ap_1")).resolves.toBe(false);
    await expect(guard.deny("ap_1")).resolves.toBe(false);
  });

  test("waitForApproval() keeps polling through stalls and times out cleanly", async () => {
    const m = installStallingFetch();
    const guard = new AgentGuard({ timeout: 20 });
    const r = await guard.waitForApproval("ap_1", 150, 5);
    expect(r.denied).toBe(true);
    expect(r.reason).toMatch(/timed out/i);
    // A per-poll timeout must not end the loop after one attempt.
    expect(m.mock.calls.length).toBeGreaterThan(1);
  });

  test("waitForApproval() retries a non-JSON status body instead of rejecting", async () => {
    const m = installFetchMock();
    m.mockResolvedValueOnce(
      new Response("<html>gateway error</html>", {
        status: 200,
        headers: { "Content-Type": "text/html" },
      })
    );
    m.mockResolvedValueOnce(jsonResponse(RESOLVED_ALLOW));
    const guard = new AgentGuard({ timeout: 500 });
    const r = await guard.waitForApproval("ap_first", 2000, 5);
    expect(r.allowed).toBe(true);
    expect(m.mock.calls.length).toBe(2);
  });
});
