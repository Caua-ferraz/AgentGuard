/**
 * Tests for the v0.5+ tenantId option on the AgentGuard TypeScript SDK.
 *
 * Mirrors plugins/python/tests/test_tenant_routing.py: the SDK accepts
 * an optional `tenantId` constructor field that controls whether HTTP
 * calls go to the legacy `/v1/...` URLs or the tenant-aware
 * `/v1/t/{tenantId}/...` family added in v0.5 (worker A7).
 *
 * The Go-side routing is covered by pkg/proxy/tenant_routing_test.go;
 * here we only verify the URL builder via a `globalThis.fetch` mock.
 */

import { AgentGuard, LOCAL_TENANT_ID } from "../index";

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
  // Wipe AgentGuard-controlled env vars before every test so one test's
  // setting cannot leak into another.
  delete process.env.AGENTGUARD_URL;
  delete process.env.AGENTGUARD_API_KEY;
  delete process.env.AGENTGUARD_TENANT_ID;
});

afterAll(() => {
  process.env = ORIGINAL_ENV;
});

describe("AgentGuard tenantId — URL builder", () => {
  test("legacy URL when no tenantId", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(jsonResponse({ decision: "ALLOW", reason: "ok" }));
    const guard = new AgentGuard({ baseUrl: "http://example.test:8080" });
    await guard.check("shell", { command: "ls" });
    expect(String(fetchMock.mock.calls[0][0])).toBe(
      "http://example.test:8080/v1/check"
    );
  });

  test("tenantId=\"local\" is an alias for the legacy URL family", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(jsonResponse({ decision: "ALLOW", reason: "ok" }));
    const guard = new AgentGuard({
      baseUrl: "http://example.test:8080",
      tenantId: LOCAL_TENANT_ID,
    });
    await guard.check("shell", { command: "ls" });
    expect(String(fetchMock.mock.calls[0][0])).toBe(
      "http://example.test:8080/v1/check"
    );
  });

  test("custom tenantId routes through /v1/t/{tenantId}/check", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(jsonResponse({ decision: "ALLOW", reason: "ok" }));
    const guard = new AgentGuard({
      baseUrl: "http://example.test:8080",
      tenantId: "acme",
    });
    await guard.check("shell", { command: "ls" });
    expect(String(fetchMock.mock.calls[0][0])).toBe(
      "http://example.test:8080/v1/t/acme/check"
    );
  });

  test("tenantId is URL-encoded", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(jsonResponse({ decision: "ALLOW", reason: "ok" }));
    const guard = new AgentGuard({
      baseUrl: "http://example.test:8080",
      tenantId: "weird/tenant",
    });
    await guard.check("shell", { command: "ls" });
    // The slash is escaped to %2F so the proxy sees a single tenant
    // segment, not a path-traversal forgery.
    expect(String(fetchMock.mock.calls[0][0])).toBe(
      "http://example.test:8080/v1/t/weird%2Ftenant/check"
    );
  });

  test("AGENTGUARD_TENANT_ID env populates tenantId by default", async () => {
    process.env.AGENTGUARD_TENANT_ID = "fromenv";
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(jsonResponse({ decision: "ALLOW", reason: "ok" }));
    const guard = new AgentGuard({ baseUrl: "http://example.test:8080" });
    await guard.check("shell", { command: "ls" });
    expect(String(fetchMock.mock.calls[0][0])).toBe(
      "http://example.test:8080/v1/t/fromenv/check"
    );
  });

  test("explicit tenantId wins over env", async () => {
    process.env.AGENTGUARD_TENANT_ID = "fromenv";
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(jsonResponse({ decision: "ALLOW", reason: "ok" }));
    const guard = new AgentGuard({
      baseUrl: "http://example.test:8080",
      tenantId: "explicit",
    });
    await guard.check("shell", { command: "ls" });
    expect(String(fetchMock.mock.calls[0][0])).toBe(
      "http://example.test:8080/v1/t/explicit/check"
    );
  });

  test("explicit tenantId=\"\" suppresses env var", async () => {
    process.env.AGENTGUARD_TENANT_ID = "fromenv";
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(jsonResponse({ decision: "ALLOW", reason: "ok" }));
    const guard = new AgentGuard({
      baseUrl: "http://example.test:8080",
      tenantId: "",
    });
    await guard.check("shell", { command: "ls" });
    expect(String(fetchMock.mock.calls[0][0])).toBe(
      "http://example.test:8080/v1/check"
    );
  });

  test("string-form constructor honors AGENTGUARD_TENANT_ID env", async () => {
    process.env.AGENTGUARD_TENANT_ID = "fromenv";
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(jsonResponse({ decision: "ALLOW", reason: "ok" }));
    const guard = new AgentGuard("http://example.test:8080");
    await guard.check("shell", { command: "ls" });
    expect(String(fetchMock.mock.calls[0][0])).toBe(
      "http://example.test:8080/v1/t/fromenv/check"
    );
  });
});

describe("AgentGuard tenantId — propagates to all endpoints", () => {
  test("approve uses tenant-aware path", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ status: "approved", id: "ap_xyz" })
    );
    const guard = new AgentGuard({
      baseUrl: "http://example.test:8080",
      tenantId: "acme",
      apiKey: "k",
    });
    await guard.approve("ap_xyz");
    expect(String(fetchMock.mock.calls[0][0])).toBe(
      "http://example.test:8080/v1/t/acme/approve/ap_xyz"
    );
  });

  test("deny uses tenant-aware path", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ status: "denied", id: "ap_xyz" })
    );
    const guard = new AgentGuard({
      baseUrl: "http://example.test:8080",
      tenantId: "acme",
      apiKey: "k",
    });
    await guard.deny("ap_xyz");
    expect(String(fetchMock.mock.calls[0][0])).toBe(
      "http://example.test:8080/v1/t/acme/deny/ap_xyz"
    );
  });

  test("waitForApproval uses tenant-aware status path", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(
      jsonResponse({
        id: "ap_xyz",
        status: "resolved",
        decision: "ALLOW",
        reason: "ok",
      })
    );
    const guard = new AgentGuard({
      baseUrl: "http://example.test:8080",
      tenantId: "acme",
      apiKey: "k",
    });
    await guard.waitForApproval("ap_xyz", 1000, 50);
    expect(String(fetchMock.mock.calls[0][0])).toBe(
      "http://example.test:8080/v1/t/acme/status/ap_xyz"
    );
  });

  test("legacy URL family is used when tenantId omitted (backward compat)", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ status: "approved", id: "ap_xyz" })
    );
    const guard = new AgentGuard({
      baseUrl: "http://example.test:8080",
      apiKey: "k",
    });
    await guard.approve("ap_xyz");
    expect(String(fetchMock.mock.calls[0][0])).toBe(
      "http://example.test:8080/v1/approve/ap_xyz"
    );
  });
});
