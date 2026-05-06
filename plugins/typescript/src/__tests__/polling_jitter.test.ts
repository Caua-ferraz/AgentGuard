/**
 * Statistical contract test for `AgentGuard.waitForApproval` jitter (AT, Phase 3).
 *
 * Lock the population statistics of the jitter loop:
 *
 *   - Capture every `setTimeout` delay across >=30 polls.
 *   - Assert each delay is in the ±25% band of `pollIntervalMs`.
 *   - Assert coefficient-of-variation > 0.05 (the jitter is real, not pinned).
 *   - Assert >=5 distinct values in 30 samples (rules out fixed-noise stubs).
 *
 * Complements `sdk_polish.test.ts::"waitForApproval jitter"`, which checks
 * the per-iteration band but doesn't probe the distribution. The
 * contribution of this file is the population-level shape.
 *
 * Why spy on `setTimeout`?
 * ------------------------
 * The SDK calls `await new Promise(resolve => setTimeout(resolve, ms))`.
 * We replace `setTimeout` with a recording spy that schedules the
 * callback as a microtask (delay 0) so the loop progresses fast — the
 * test runs in tens of ms wall-clock instead of hundreds of seconds.
 */

import { AgentGuard } from "../index";

// ---------------------------------------------------------------------------
// fetch + setTimeout plumbing
// ---------------------------------------------------------------------------

type FetchArgs = [string | URL, RequestInit?];
type FetchMock = jest.Mock<Promise<Response>, FetchArgs>;

function installFetchMock(): FetchMock {
  const m = jest.fn() as unknown as FetchMock;
  (globalThis as { fetch: unknown }).fetch = m;
  return m;
}

function pendingResponse(): Response {
  return new Response(JSON.stringify({ id: "ap_jit", status: "pending" }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

function resolvedAllowResponse(): Response {
  return new Response(
    JSON.stringify({
      id: "ap_jit",
      status: "resolved",
      decision: "ALLOW",
      reason: "test-resolve",
    }),
    {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }
  );
}

/**
 * Wire up a fetch mock that returns "pending" until at least `target`
 * polls have happened, then flips to "resolved" so the loop returns
 * cleanly. This is the only way to bound the loop quickly without
 * waiting for the wall-clock deadline.
 */
function pendingThenResolvedFetch(target: number, sleeps: number[]): FetchMock {
  const m = installFetchMock();
  m.mockImplementation(async () => {
    if (sleeps.length >= target) {
      return resolvedAllowResponse();
    }
    return pendingResponse();
  });
  return m;
}

interface CapturedSleeps {
  sleeps: number[];
  restore: () => void;
}

/**
 * Spy on setTimeout to capture every requested delay. Always schedule
 * the callback with delay 0 so the loop progresses at microtask speed.
 * The fetch mock side flips to "resolved" once `target` samples have
 * been recorded, which is what unwinds `waitForApproval` cleanly.
 */
function spyOnSetTimeout(): CapturedSleeps {
  const sleeps: number[] = [];
  const original = global.setTimeout;
  const spy = jest
    .spyOn(global, "setTimeout")
    .mockImplementation(((cb: () => void, ms: number) => {
      sleeps.push(ms);
      // Always schedule with delay 0 so the loop runs at microtask speed.
      return original(cb, 0);
    }) as typeof global.setTimeout);
  return { sleeps, restore: () => spy.mockRestore() };
}

const ORIGINAL_ENV = { ...process.env };

beforeEach(() => {
  delete process.env.AGENTGUARD_URL;
  delete process.env.AGENTGUARD_API_KEY;
});

afterAll(() => {
  process.env = ORIGINAL_ENV;
});

// ---------------------------------------------------------------------------
// Statistical helpers
// ---------------------------------------------------------------------------

function mean(xs: number[]): number {
  return xs.reduce((a, b) => a + b, 0) / xs.length;
}

function pstdev(xs: number[]): number {
  const mu = mean(xs);
  const v = xs.reduce((acc, x) => acc + (x - mu) * (x - mu), 0) / xs.length;
  return Math.sqrt(v);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("waitForApproval jitter — distribution shape", () => {
  test("durations are bounded and coefficient-of-variation > 0.05", async () => {
    const POLL = 100; // ms — chosen so the bounds [80, 120] are integer-friendly
    const TARGET = 30;
    const { sleeps, restore } = spyOnSetTimeout();
    pendingThenResolvedFetch(TARGET, sleeps);

    try {
      const g = new AgentGuard({ apiKey: "k" });
      // The fetch mock flips to "resolved" once TARGET sleeps have been
      // recorded, so the loop exits well before timeoutMs.
      await g.waitForApproval("ap_jit", 30_000, POLL);
    } finally {
      restore();
    }

    expect(sleeps.length).toBeGreaterThanOrEqual(TARGET);

    // Each sample must lie in [0.75 * POLL, 1.25 * POLL] — the brief's ±25%
    // contract. The SDK actually uses ±20%, so the test is intentionally
    // looser than the implementation.
    const lo = 0.75 * POLL;
    const hi = 1.25 * POLL;
    for (const s of sleeps) {
      expect(s).toBeGreaterThanOrEqual(lo);
      expect(s).toBeLessThanOrEqual(hi);
    }

    // Coefficient of variation > 0.05.
    const sample = sleeps.slice(0, TARGET);
    const mu = mean(sample);
    const sigma = pstdev(sample);
    const cov = mu > 0 ? sigma / mu : 0;

    expect(cov).toBeGreaterThan(0.05);
  });

  test("at least 5 distinct durations across 30 samples", async () => {
    const TARGET = 30;
    const { sleeps, restore } = spyOnSetTimeout();
    pendingThenResolvedFetch(TARGET, sleeps);

    try {
      const g = new AgentGuard({ apiKey: "k" });
      await g.waitForApproval("ap_jit", 30_000, 100);
    } finally {
      restore();
    }

    const sample = sleeps.slice(0, TARGET);
    const distinct = new Set(sample).size;
    // A pinned (constant) jitter would give distinct === 1. A reasonable
    // RNG over a continuous interval gives ~30 distinct floats. Threshold
    // is forgiving for any pathological-but-still-random RNG.
    expect(distinct).toBeGreaterThanOrEqual(5);
  });

  test("mean delay across 60 samples is within 10% of pollIntervalMs", async () => {
    const POLL = 100;
    const TARGET = 60;
    const { sleeps, restore } = spyOnSetTimeout();
    pendingThenResolvedFetch(TARGET, sleeps);

    try {
      const g = new AgentGuard({ apiKey: "k" });
      await g.waitForApproval("ap_jit", 30_000, POLL);
    } finally {
      restore();
    }

    const sample = sleeps.slice(0, TARGET);
    const mu = mean(sample);
    // Theoretical mean for uniform [0.8 * POLL, 1.2 * POLL] is exactly POLL.
    // 60 samples gives a standard error of ~POLL * 0.115 / sqrt(60) ≈ 1.5 ms.
    // Allowing 10% (10 ms) means a >5σ window — robust against flake.
    expect(Math.abs(mu - POLL)).toBeLessThan(POLL * 0.1);
  });
});
