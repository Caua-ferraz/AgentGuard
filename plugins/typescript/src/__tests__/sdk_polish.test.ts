/**
 * SDK polish tests added in v0.5 (worker A15).
 *
 * Closes:
 *  - R5 E8  / S13 — content-type / status-shape validation in check().
 *  - R5 E10 / E11  — invalid failMode rejected at construction.
 *  - R5 E14 — jitter on waitForApproval polling.
 *  - R5 E15 — unknown options rejected on AgentGuard ctor and guarded().
 *  - R5 P9  — distinguish HTTP 401/403 (AgentGuardAuthError) from
 *             approval-poll timeout.
 */

import {
  AgentGuard,
  AgentGuardAuthError,
  AgentGuardError,
  guarded,
} from "../index";

// ---------------------------------------------------------------------------
// fetch mock plumbing (mirrors index.test.ts)
// ---------------------------------------------------------------------------

type FetchArgs = [string | URL, RequestInit?];
type FetchMock = jest.Mock<Promise<Response>, FetchArgs>;

function installFetchMock(): FetchMock {
  const m = jest.fn() as unknown as FetchMock;
  (globalThis as { fetch: unknown }).fetch = m;
  return m;
}

function jsonResponse(body: unknown, init: ResponseInit = { status: 200 }): Response {
  return new Response(JSON.stringify(body), {
    status: init.status ?? 200,
    headers: { "Content-Type": "application/json", ...(init.headers ?? {}) },
  });
}

const ORIGINAL_ENV = { ...process.env };

beforeEach(() => {
  delete process.env.AGENTGUARD_URL;
  delete process.env.AGENTGUARD_API_KEY;
  delete process.env.AGENTGUARD_TENANT_ID;
});

afterAll(() => {
  process.env = ORIGINAL_ENV;
});

// ===========================================================================
// failMode validation (R5 E10 / E11)
// ===========================================================================

describe("failMode validation", () => {
  test("invalid failMode at construction throws TypeError", () => {
    expect(
      () => new AgentGuard({ failMode: "always" as unknown as "deny" })
    ).toThrow(TypeError);
    expect(
      () => new AgentGuard({ failMode: "always" as unknown as "deny" })
    ).toThrow(/invalid failMode/);
  });

  test("explicit deny is accepted", () => {
    expect(() => new AgentGuard({ failMode: "deny" })).not.toThrow();
  });

  test("explicit allow is accepted", () => {
    expect(() => new AgentGuard({ failMode: "allow" })).not.toThrow();
  });

  test("default (no failMode) defaults to deny", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockRejectedValueOnce(new Error("ECONNREFUSED"));
    const g = new AgentGuard();
    const r = await g.check("shell", { command: "ls" });
    expect(r.denied).toBe(true);
  });

  test("string-form ctor cannot specify failMode (defaults to deny)", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockRejectedValueOnce(new Error("nope"));
    const g = new AgentGuard("http://localhost:8080");
    const r = await g.check("shell", { command: "ls" });
    expect(r.denied).toBe(true);
  });
});

// ===========================================================================
// Unknown-options rejection (R5 E15)
// ===========================================================================

describe("unknown options rejection", () => {
  test("AgentGuard ctor rejects unknown keys", () => {
    // Build the bad options as a Record<string,unknown> first, then double-cast
    // through unknown to the ctor parameter type. This sidesteps TS's
    // "no excess property" check (which would forbid `agnetId` literal) and
    // exercises the runtime guard instead.
    const bad = {
      baseUrl: "http://localhost:8080",
      agnetId: "x",
    } as unknown as ConstructorParameters<typeof AgentGuard>[0];
    expect(() => new AgentGuard(bad)).toThrow(TypeError);
  });

  test("AgentGuard ctor names valid options in the error message", () => {
    const bad = { bogus: 1 } as unknown as ConstructorParameters<typeof AgentGuard>[0];
    let caught: unknown;
    try {
      new AgentGuard(bad);
    } catch (e) {
      caught = e;
    }
    const msg = (caught as TypeError).message;
    expect(msg).toMatch(/bogus/);
    expect(msg).toMatch(/baseUrl/); // valid options listed
  });

  test("guarded() rejects unknown option keys", () => {
    const g = new AgentGuard();
    const fn = async () => "ran";
    const badOpts = { waitForApprovel: true } as unknown as Parameters<
      typeof guarded
    >[3];
    expect(() =>
      guarded(
        g,
        "shell",
        fn as unknown as (...args: unknown[]) => Promise<unknown>,
        badOpts
      )
    ).toThrow(TypeError);
  });

  test("guarded() accepts known keys", () => {
    const g = new AgentGuard();
    const fn = async () => "ran";
    expect(() =>
      guarded(g, "shell", fn as unknown as (...args: unknown[]) => Promise<unknown>, {
        waitForApproval: true,
        approvalTimeoutMs: 1000,
        approvalPollIntervalMs: 5,
      })
    ).not.toThrow();
  });
});

// ===========================================================================
// Content-type / status-shape validation in check() (R5 E8 / S13)
// ===========================================================================

describe("check() response shape validation", () => {
  test("non-JSON Content-Type falls through to failMode", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(
      new Response("<html>oops</html>", {
        status: 200,
        headers: { "Content-Type": "text/html" },
      })
    );
    const g = new AgentGuard({ failMode: "deny" });
    const r = await g.check("shell", { command: "ls" });
    expect(r.denied).toBe(true);
    expect(r.reason.toLowerCase()).toContain("content-type");
  });

  test("non-JSON Content-Type with failMode=allow allows", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(
      new Response("oops", {
        status: 200,
        headers: { "Content-Type": "text/plain" },
      })
    );
    const g = new AgentGuard({ failMode: "allow" });
    const r = await g.check("shell", { command: "ls" });
    expect(r.allowed).toBe(true);
  });

  test("application/json with charset suffix is accepted", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ decision: "ALLOW", reason: "ok" }), {
        status: 200,
        headers: { "Content-Type": "application/json; charset=utf-8" },
      })
    );
    const g = new AgentGuard();
    const r = await g.check("shell", { command: "ls" });
    expect(r.allowed).toBe(true);
  });

  test("malformed body missing 'decision' falls through", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ reason: "no decision here" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      })
    );
    const g = new AgentGuard();
    const r = await g.check("shell", { command: "ls" });
    expect(r.denied).toBe(true);
    expect(r.reason.toLowerCase()).toMatch(/malformed|decision/);
  });

  test("garbage JSON falls through cleanly", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(
      new Response("not json", {
        status: 200,
        headers: { "Content-Type": "application/json" },
      })
    );
    const g = new AgentGuard();
    const r = await g.check("shell", { command: "ls" });
    expect(r.denied).toBe(true);
  });

  test("non-2xx still surfaces a clean reason (status code echoed)", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ decision: "ALLOW", reason: "sneaky" }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      })
    );
    const g = new AgentGuard();
    const r = await g.check("shell", { command: "ls" });
    expect(r.denied).toBe(true);
    expect(r.reason).toMatch(/500/);
  });
});

// ===========================================================================
// Auth error on 401/403 from waitForApproval (R5 P9)
// ===========================================================================

describe("waitForApproval auth-error", () => {
  test("401 throws AgentGuardAuthError immediately", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValue(
      new Response("", { status: 401, headers: { "Content-Type": "application/json" } })
    );
    const g = new AgentGuard({ apiKey: "bad" });
    let caught: unknown;
    try {
      await g.waitForApproval("ap_x", 5_000, 1);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(AgentGuardAuthError);
    expect((caught as AgentGuardAuthError).status).toBe(401);
  });

  test("403 throws AgentGuardAuthError immediately", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValue(
      new Response("", { status: 403, headers: { "Content-Type": "application/json" } })
    );
    const g = new AgentGuard({ apiKey: "bad" });
    let caught: unknown;
    try {
      await g.waitForApproval("ap_x", 5_000, 1);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(AgentGuardAuthError);
    expect((caught as AgentGuardAuthError).status).toBe(403);
  });

  test("AgentGuardAuthError extends AgentGuardError and Error", () => {
    const e = new AgentGuardAuthError("test", 401);
    expect(e).toBeInstanceOf(AgentGuardError);
    expect(e).toBeInstanceOf(Error);
    expect(e.status).toBe(401);
  });

  test("transient 500 keeps polling until timeout", async () => {
    const fetchMock = installFetchMock();
    // Always 500 — the SDK must NOT abort; it should poll until the deadline.
    fetchMock.mockResolvedValue(
      new Response("oh no", { status: 500, headers: { "Content-Type": "application/json" } })
    );
    const g = new AgentGuard();
    const start = Date.now();
    const r = await g.waitForApproval("ap_x", 30, 1);
    const elapsed = Date.now() - start;
    expect(r.denied).toBe(true);
    expect(r.reason).toMatch(/timed out/i);
    // Loop ran for ~30ms, not aborted prematurely.
    expect(elapsed).toBeGreaterThanOrEqual(20);
  });
});

// ===========================================================================
// waitForApproval jitter (R5 E14)
// ===========================================================================

describe("waitForApproval jitter", () => {
  test("setTimeout durations sit in the [0.8, 1.2] * pollInterval band", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ id: "ap_x", status: "pending" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      })
    );

    // Spy on setTimeout to capture every delay the SDK requests.
    const origSetTimeout = global.setTimeout;
    const sleeps: number[] = [];
    const spy = jest
      .spyOn(global, "setTimeout")
      .mockImplementation(((cb: () => void, ms: number) => {
        sleeps.push(ms);
        // Schedule the callback as a microtask so the loop progresses fast.
        return origSetTimeout(cb, 0);
      }) as typeof global.setTimeout);

    try {
      const g = new AgentGuard({ apiKey: "k" });
      const r = await g.waitForApproval("ap_x", 30, 100);
      expect(r.denied).toBe(true);
    } finally {
      spy.mockRestore();
    }

    expect(sleeps.length).toBeGreaterThan(0);
    for (const s of sleeps) {
      expect(s).toBeGreaterThanOrEqual(80);
      expect(s).toBeLessThanOrEqual(120);
    }
  });

  test("jitter actually varies across iterations", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ id: "ap_x", status: "pending" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      })
    );
    const origSetTimeout = global.setTimeout;
    const sleeps: number[] = [];
    const spy = jest
      .spyOn(global, "setTimeout")
      .mockImplementation(((cb: () => void, ms: number) => {
        sleeps.push(ms);
        return origSetTimeout(cb, 0);
      }) as typeof global.setTimeout);

    try {
      const g = new AgentGuard();
      await g.waitForApproval("ap_x", 30, 100);
    } finally {
      spy.mockRestore();
    }

    if (sleeps.length >= 2) {
      const unique = new Set(sleeps);
      // Astronomically unlikely to collide on a real RNG; if the jitter
      // dropped to a constant we'd see size === 1.
      expect(unique.size).toBeGreaterThan(1);
    }
  });
});
